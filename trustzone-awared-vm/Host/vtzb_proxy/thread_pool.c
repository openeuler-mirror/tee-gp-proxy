#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include "thread_pool.h"
#include "serial_port.h"
#include "process_data.h"
#include "vtzb_proxy.h"
#include "debug.h"
#include "vm.h"

extern ThreadPool g_pool;
ThreadFuncArgs g_thd_args[THREAD_POOL_SIZE];
TimeOut g_time_out[THREAD_POOL_SIZE];
static cpu_set_t g_cpuset;

/* Custom signal handler for killing zombie threads. */
void signal_handler(int signum) {
    (void)signum;
    tlogd("thread %lu got sig exited\n", pthread_self());
    pthread_exit(NULL);
}

static void init_cpu_set()
{
    int cpu_num = get_nprocs();
    CPU_ZERO(&g_cpuset);
    for (int i = 1; i <= CPU_SET_NUM && i < cpu_num; i++) {
        CPU_SET(cpu_num - i, &g_cpuset);
    }
}

#define CPU_SET_AFFINITY() \
do { \
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &g_cpuset)) { \
        tloge("set cpu affinity failed\n"); \
    } \
} while(0)


/* Initialize the thread pool. */
int thread_pool_init(ThreadPool *pool)
{
    char name[THREAD_NAME_LEN] = {0};
    pool->task_cnt = 0;
    pool->busy_cnt = 0;
    pool->front = pool->rear = 0;
    pool->destroying = 0;
    memset(pool->task_queue, 0, sizeof(Task) * TASK_QUEUE_SIZE);
    memset(pool->kill_flag, 0, sizeof(bool) * THREAD_POOL_SIZE);
    memset(pool->session_ids, 0, sizeof(unsigned int) * THREAD_POOL_SIZE);
    init_cpu_set();
    CPU_SET_AFFINITY();
    pthread_create(&pool->admin_tid, NULL, admin_thread, pool);
    pthread_setname_np(pool->admin_tid, "adminer");
    pthread_mutex_init(&pool->task_mutex, NULL);
    pthread_mutex_init(&pool->session_mutex, NULL);
    pthread_mutex_init(&pool->time_mutex, NULL);
    pthread_mutex_init(&pool->busy_mutex, NULL);
    pthread_cond_init(&pool->queue_not_empty, NULL);
    pthread_cond_init(&pool->queue_not_full, NULL);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        g_thd_args[i].index = i;
        g_thd_args[i].pool = pool;
        pthread_create(&pool->threads[i], NULL, thread_func, &g_thd_args[i]);
        sprintf(name, "worker_%d", i);
        pthread_setname_np(pool->threads[i], name);
        pthread_detach(pool->threads[i]);
    }
    return 0;
}

/* Recreate a new thread to fill the gap in the thread pool after killing a thread. */
void replenish_thread_pool(ThreadPool *pool, pthread_t thd, char *name)
{
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            g_thd_args[i].index = i;
            g_thd_args[i].pool = pool;
            pthread_create(&pool->threads[i], NULL, thread_func, &g_thd_args[i]);
            pthread_setname_np(pool->threads[i], name);
            pthread_detach(pool->threads[i]);
            pool->kill_flag[i] = false;
            tlogv("thread %s : old id %lu, new id %lu\n", name, thd, pool->threads[i]);
            return;
        }
    }
    tloge("can't found the killed thread %lu\n", thd);
}

void restart_pool_thread(ThreadPool *pool, pthread_t tid)
{
    char name[THREAD_NAME_LEN] = {0};
    int result;

    pthread_getname_np(tid, name, THREAD_NAME_LEN);
    tlogv("try to kill thread %s: %lu\n", name, tid);
    result = pthread_kill(tid, SIGUSR1);
    if (result != 0) {
        tloge("try to kill thread failed, ret %d\n", result);
        return;
    }
    pthread_mutex_lock(&pool->busy_mutex);
    pool->busy_cnt--;
    pthread_mutex_unlock(&pool->busy_mutex);
    replenish_thread_pool(pool, tid, name);
}

/* Thread function */
void *thread_func(void *arg)
{
    ThreadFuncArgs *thd_args = (ThreadFuncArgs *)arg;
    ThreadPool *pool = thd_args->pool;
    int index = thd_args->index;
    if (signal(SIGUSR1, signal_handler) == SIG_ERR) {
        return NULL;
    }

    CPU_SET_AFFINITY();
    while (1) {
        pthread_mutex_lock(&pool->task_mutex);

        /* Wait for the task queue to become non-empty. */
        while (pool->task_cnt == 0 && !pool->destroying) {
            pthread_cond_wait(&pool->queue_not_empty, &pool->task_mutex);
        }

        /* If the thread pool is being destroyed, exit the thread. */
        if (pool->destroying) {
            pthread_mutex_unlock(&pool->task_mutex);
            break;
        }

        if (pool->kill_flag[index]) {
            pthread_cond_signal(&pool->queue_not_empty);
            pthread_mutex_unlock(&pool->task_mutex);
            continue;
        }

        /* Retrieve the task and execute it. */
        Task task = pool->task_queue[pool->front];
        pool->front = (pool->front + 1) % TASK_QUEUE_SIZE;
        pool->task_cnt--;
        pthread_cond_broadcast(&pool->queue_not_full);
        pthread_mutex_unlock(&pool->task_mutex);

        pthread_mutex_lock(&pool->busy_mutex);
        pool->busy_cnt++;
        tlogv("start work, thread cnt: %d, task cnt: %d\n", pool->busy_cnt, pool->task_cnt);
        if (pool->task_args[index])
            free(pool->task_args[index]);
        pool->task_args[index] = task.arg;
        pthread_mutex_unlock(&pool->busy_mutex);

        task.task_func(task.arg);

        pthread_mutex_lock(&pool->busy_mutex);
        pool->busy_cnt--;
        pool->task_args[index] = NULL;
        tlogv("end work, thread cnt: %d, task cnt: %d\n", pool->busy_cnt, pool->task_cnt);
        pthread_mutex_unlock(&pool->busy_mutex);
    }

    return NULL;
}

void *admin_thread(void *arg)
{
    int i;
    ThreadPool *pool = (ThreadPool *)arg;
    struct timeval cur_time;
    long time_sec = 0;

    CPU_SET_AFFINITY();
    while (!pool->destroying) {
        sleep(DEFAULT_TIME_SEC);
        gettimeofday(&cur_time, NULL);
        time_sec = cur_time.tv_sec;
        pthread_mutex_lock(&pool->time_mutex);
        for (i = 0; i < THREAD_POOL_SIZE; i++) {
            if (g_time_out[i].flag != 0 && (time_sec - g_time_out[i].start_time) > DEFAULT_TIME_SEC) {
                kill_open_session_thd(&g_time_out[i]);
                g_time_out[i].flag = 0;
            }
        }
        pthread_mutex_unlock(&pool->time_mutex);
    }
    return NULL;
}

static void *deal_packet_thread(void *arg)
{
    int ret;
    int offset = 0;
    int buf_len;
    struct serial_port_file *serial_port = (struct serial_port_file *)arg;

    CPU_SET_AFFINITY();
    while (!g_pool.destroying) {
        if (!serial_port || !serial_port->rd_buf || serial_port->sock <= 0) {
            tloge("serial_port ptr or rd_buf or fd is invalid\n");
            goto end;
        }

        ret = read(serial_port->sock, serial_port->rd_buf + serial_port->offset, BUF_LEN_MAX_RD - serial_port->offset);
        if (ret < 0) {
            if (errno == ECONNRESET || errno == EBADF) {
                goto end;
            }
            tloge("read domain socket failed, err: %s\n", strerror(errno));
            continue;
        }
        // when vm destroy, has many zero read
        if (ret == 0) {
            continue;
        }
        buf_len = ret + serial_port->offset;
        /*
         * while loop will deal all complete packets, left the incomplete one in the
         * starting position of rd_buf, so the offset should be 0 echo read times
         */
        offset = 0;
        while (1) {
            void *packet = NULL;
            packet = get_packet_item(serial_port->rd_buf, buf_len, &offset);
            if (packet == NULL) {
                break;
            }

            vm_trace_data *data = (vm_trace_data *)packet;
            data->serial_port_ptr = (uint64_t)serial_port;
            data->vmid = serial_port->index;
            thread_pool_submit(&g_pool, thread_entry, (void *)((uint64_t)packet));
        }
        serial_port->offset = offset;
    }

end:
    if (serial_port) {
        serial_port->opened = false;
        tlogi("reader thread %d exited\n", serial_port->index);
    } else {
        tloge("serial_port is null, and reader thread exit\n");
    }
    return NULL;
}

int create_reader_thread(struct serial_port_file *serial_port, int i)
{
    int ret;
    char name[THREAD_NAME_LEN] = {0};
    if ((ret = pthread_create(&g_pool.reader_threads[i], NULL, deal_packet_thread, serial_port))) {
        tloge("create reader thread failed\n");
        return ret;
    }
    sprintf(name, "reader_%d", i);
    if ((ret = pthread_setname_np(g_pool.reader_threads[i], name))) {
        tloge("set thread name failed\n");
        return ret;
    }
    if ((ret = pthread_detach(g_pool.reader_threads[i]))) {
        tloge("thread detach failed\n");
    }
    return ret;
}

/* Submit the task to the thread pool. */
void thread_pool_submit(ThreadPool *pool, void *(*task_func)(void *), void *arg)
{
    pthread_mutex_lock(&pool->task_mutex);

    /* Wait for the task queue to become non-full. */
    while (pool->task_cnt == TASK_QUEUE_SIZE && !pool->destroying) {
        pthread_cond_wait(&pool->queue_not_full, &pool->task_mutex);
    }

    /* If the thread pool is being destroyed, no longer accept new tasks. */
    if (pool->destroying) {
        pthread_mutex_unlock(&pool->task_mutex);
        return;
    }

    /* Add the task to the queue. */
    pool->task_queue[pool->rear].task_func = task_func;
    pool->task_queue[pool->rear].arg = arg;
    pool->rear = (pool->rear + 1) % TASK_QUEUE_SIZE;
    pool->task_cnt++;
    tlogv("add task to task queue cnt: %d\n", pool->task_cnt);
    /* Notify waiting threads of a new task. */
    pthread_cond_signal(&pool->queue_not_empty);

    pthread_mutex_unlock(&pool->task_mutex);
}

/* Destroy the thread pool. */
void thread_pool_destroy(ThreadPool *pool)
{
    /* Stop accepting new tasks. */
    pthread_mutex_lock(&pool->task_mutex);
    pool->destroying = 1;
    pthread_mutex_unlock(&pool->task_mutex);

    pthread_cond_broadcast(&pool->queue_not_empty);
    pthread_join(pool->admin_tid, NULL);

    pthread_mutex_destroy(&pool->task_mutex);
    pthread_cond_destroy(&pool->queue_not_empty);
}

void set_thread_session_id(ThreadPool *pool, pthread_t thd, unsigned int id)
{
    pthread_mutex_lock(&pool->session_mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            pool->session_ids[i] = id;
            break;
        }
    }
    pthread_mutex_unlock(&pool->session_mutex);
}

unsigned int get_thread_session_id(ThreadPool *pool, pthread_t thd, unsigned int session_id)
{
    unsigned int id = 0;
    pthread_mutex_lock(&pool->session_mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            if (pool->session_ids[i] == session_id) {
                id = pool->session_ids[i];
                pool->kill_flag[i] = true;
                pool->session_ids[i] = 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&pool->session_mutex);
    return id;
}