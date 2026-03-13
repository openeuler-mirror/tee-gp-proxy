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
#include <sys/socket.h>
#include <errno.h>
#include "thread_pool.h"
#include "serial_port.h"
#include "process_data.h"
#include "vtzb_proxy.h"
#include "debug.h"
#include "vm.h"
#include "libvirt_api_wrap.h"
#include "config.h"

extern ThreadPool g_pool;
ThreadFuncArgs g_thd_args[THREAD_POOL_SIZE];
TimeOut g_time_out[THREAD_POOL_SIZE];
static cpu_set_t g_cpuset = {{0}};

/* Custom signal handler for killing zombie threads. */
void signal_handler(int signum) {
    (void)signum;
    pthread_exit(NULL);
}

static void init_cpu_set()
{
    int cpu_num = get_nprocs();
    CPU_ZERO(&g_cpuset);
    for (int i = 1; i <= CPU_SET_NUM && i < cpu_num; i++) {
        CPU_SET(cpu_num - i, &g_cpuset);
    }
    print_cpuset(&g_cpuset);
}

#define CPU_SET_AFFINITY() \
do { \
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &g_cpuset)) { \
        tloge("set cpu affinity failed\n"); \
    } \
} while(0)

static void set_cpuset(cpu_set_t *cpuset)
{
    if (cpuset == NULL || CPU_COUNT(cpuset) == 0) {
        tlogi("Use initial cpu binding set\n");
        init_cpu_set();
        return;
    } else {
        errno_t ret = memcpy_s(&g_cpuset, sizeof(g_cpuset), cpuset, sizeof(cpu_set_t));
        if (ret != 0) {
            tloge("Failed to copy cpuset: error code %d\n", ret);
            tlogi("Use initial cpu binding set\n");
            init_cpu_set();
            return;
        }
        tlogi("Use configured cpu binding set\n");
        print_cpuset(&g_cpuset);
        return;
    }
}

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
    VtzbConfig *cfg = get_global_config();
    set_cpuset(&cfg->cpuset);
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
    if (tid == 0)
        return;
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
        if (pool->destroying && pool->task_cnt == 0) {
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
                tlogw("check tid is %lu, seq_num is %d, it has been doing for %ld seconds.\n", \
                    g_time_out[i].tid, g_time_out[i].seq_num, time_sec - g_time_out[i].start_time);
            }
        }
        pthread_mutex_unlock(&pool->time_mutex);
    }
    return NULL;
}

static __thread int reboot_flag = 0;
static int domain_reboot_callback(virConnectPtr conn, virDomainPtr dom, void *opaque)
{
    (void)conn;
    const char *name = virDomainGetName(dom);
    struct serial_port_file *file = (struct serial_port_file *)opaque;
    shutdown(file->sock, SHUT_RDWR);
    reboot_flag = 1;
    tlogi("release_vm_file1, domain name is %s ,index is %d \n", name, file->index);
    return 0;
}

static void timeout_callback(int timer, void *opaque)
{
    (void)timer;
    (void)opaque;
    return;
}

static int life_cycle_callback(virConnectPtr conn,
                  virDomainPtr dom,
                  int event,
                  int detail,
                  void *opaque)
{
    (void)conn;
    (void)opaque;
    const char *name = virDomainGetName(dom);
    if (name == NULL)
        return -1;

    switch (event) {
        case VIR_DOMAIN_EVENT_STOPPED:
            switch (detail) {
                case VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN:
                case VIR_DOMAIN_EVENT_STOPPED_DESTROYED:
                case VIR_DOMAIN_EVENT_STOPPED_CRASHED:
                    reboot_flag = 1;
                    tlogi("Shutdown & Destroyed & Crashed happend\n");
                    break;
                default:
                    tlogw("Reason: Other (%d)\n", detail);
            }
            break;
    }
    return 0;
}

static void *deal_rebootmonitor_thread(void *arg)
{
    struct serial_port_file *serial_port = (struct serial_port_file *)arg;

    virConnectPtr conn = init_virt_conn();
    if(conn == NULL){
        tloge("conn init failed \n");
        return NULL;
    }
    // domain ptr
    virDomainPtr domain_ptr = init_domain_by_socket_path(conn, serial_port->path);
    if(domain_ptr == NULL){
        tloge("domain ptr failed, path is %s\n", serial_port->path);
        deinit_virt_conn(conn);
        return NULL;
    }
    
    int lifecycleCallbackID = virConnectDomainEventRegisterAny(
        conn,
        domain_ptr,
        VIR_DOMAIN_EVENT_ID_LIFECYCLE,
        VIR_DOMAIN_EVENT_CALLBACK(life_cycle_callback),
        NULL, NULL
    );

    int callbackID = virConnectDomainEventRegisterAny(
        conn,
        domain_ptr,
        VIR_DOMAIN_EVENT_ID_REBOOT,
        VIR_DOMAIN_EVENT_CALLBACK(domain_reboot_callback),
        (void *)serial_port,
        NULL
    );
    tlogv("callback_id %d \n", callbackID);
    if(callbackID < 0){
        tloge("callbackID error, path is %s\n", serial_port->path);
        deinit_domain(domain_ptr);
        deinit_virt_conn(conn);
        return NULL;
    }

    int timeout_id = virEventAddTimeout(10, timeout_callback, NULL, NULL);
    tlogv("timeout_id %d \n", timeout_id);
    if (timeout_id < 0) {
        tloge("[Thread] Failed to add timeout, path is %s\n", serial_port->path);
        virConnectDomainEventDeregisterAny(conn, callbackID);
        deinit_domain(domain_ptr);
        deinit_virt_conn(conn);
        return NULL;
    }

    while (1) {
        if(reboot_flag == 1 || g_pool.destroying) {
            if (virEventRemoveTimeout(timeout_id) == 0) {
                tlogi("Timer %d removed successfully.\n", timeout_id);
            }
            if(virConnectDomainEventDeregisterAny(conn, callbackID) == 0) {
                tlogi("Deregister reboot successfully %d \n", callbackID);
            }
            if(virConnectDomainEventDeregisterAny(conn, lifecycleCallbackID) == 0) {
                tlogi("Deregister lifecycle successfully %d \n", lifecycleCallbackID);
            }
            if(virEventRunDefaultImpl() < 0){
                tloge("[Thread] Event loop error\n");
            }
            tlogi("unregister libvirt event success\n");
            break;
        }
        if(virEventRunDefaultImpl() < 0) {
            tloge("[Thread] Event loop error\n");
            break;
        }
    }

    reboot_flag = 0;
    deinit_domain(domain_ptr);
    deinit_virt_conn(conn);
    tlogi("deinit thread \n");
    return NULL;
}

int create_rebootmonitor_thread(struct serial_port_file *serial_port, int i)
{
    int ret;
    char name[THREAD_NAME_LEN] = {0};
    if ((ret = pthread_create(&g_pool.rebootmonitor_threads[i], NULL, deal_rebootmonitor_thread, serial_port))) {
        tloge("create reboot monitor thread failed, ret is %d\n", ret);
        return ret;
    }
    sprintf(name, "reboot_%d", i);
    if ((ret = pthread_setname_np(g_pool.rebootmonitor_threads[i], name))) {
        tloge("set thread name failed, ret is %d\n", ret);
        return ret;
    }
    if ((ret = pthread_detach(g_pool.rebootmonitor_threads[i]))) {
        tloge("thread detach failed\n");
        return ret;
    }
    return ret;
}
typedef struct   {
    uint32_t total_fragment_block_num;
    uint32_t fragment_block_num;
    uint32_t cmd_size;
    uint32_t seq_num;
}struct_fragment;

static inline uint32_t get_cmd(void *rd_buf) 
{
    return *(uint32_t *)(rd_buf + sizeof(uint32_t));
}

static int get_struct_fragment(void *packet, struct_fragment *p_frag)
{
    char *rd_buf = (char *)(packet) + sizeof(vm_trace_data);
    uint32_t cmd = get_cmd(rd_buf);
    struct_packet_cmd_session *p_session;
    struct_packet_cmd_send_cmd *p_cmd;
    if (cmd == VTZ_OPEN_SESSION) {
        p_session = (struct_packet_cmd_session *)rd_buf;
        p_frag->total_fragment_block_num = p_session->total_fragment_block_num;
        p_frag->fragment_block_num = p_session->fragment_block_num;
        p_frag->cmd_size = sizeof(struct_packet_cmd_session);
        p_frag->seq_num = p_session->seq_num;
        tlogd("VTZ_OPEN_SESSION packet_size %u", p_session->packet_size);
    }
    else if (cmd == VTZ_SEND_CMD) {
        p_cmd = (struct_packet_cmd_send_cmd*)rd_buf;
        p_frag->total_fragment_block_num = p_cmd->total_fragment_block_num;
        p_frag->fragment_block_num = p_cmd->fragment_block_num;
        p_frag->cmd_size = sizeof(struct_packet_cmd_send_cmd);
        p_frag->seq_num = p_cmd->seq_num;
        tlogd("VTZ_SEND_CMD packet_size %u", p_cmd->packet_size);
    }
    else {
        return -1;
    };
    tlogd("total_fragment_block_num %u, fragment_block_num %u, cmd_size %u, seq_num %u", \
        p_frag->total_fragment_block_num, p_frag->fragment_block_num, p_frag->cmd_size, p_frag->seq_num);
    if (p_frag->total_fragment_block_num <= p_frag->fragment_block_num) 
        return -1;
    return 0;

}

void* get_merged_packet(void* packet, struct_fragment *p_frag) 
{
    static _Thread_local uint32_t seq_num = 0;
    static uint32_t fragment_offset = 0;
    static void *merged_packet = NULL;
    static uint32_t packet_header_size = 0;
    static uint32_t merged_packet_size = 0;

    uint32_t page_blocks_size = p_frag->fragment_block_num * sizeof(struct_page_block);
    tlogd("packet_header_size is %u, page_blocks_size %u merged_packet_size is %u", packet_header_size, page_blocks_size, merged_packet_size);
    tlogd("seq_num is %u, fragment_offset %u merged_packet is %p", seq_num, fragment_offset, merged_packet);
    tlogd("frag cmd_size is %u, fragment_block_num is %u, total_fragment_block_num is %u", p_frag->cmd_size, p_frag->fragment_block_num, p_frag->total_fragment_block_num);

    if (seq_num != p_frag->seq_num) {
        tlogd("seq_num is %u", p_frag->seq_num);
        fragment_offset = 0;
        seq_num = p_frag->seq_num;
        packet_header_size = p_frag->cmd_size + sizeof(vm_trace_data);
        merged_packet_size = p_frag->total_fragment_block_num * sizeof(struct_page_block) + packet_header_size;
        merged_packet = malloc(merged_packet_size);

        if (!merged_packet)
            return NULL;
        memcpy_s(merged_packet, packet_header_size + page_blocks_size, packet, packet_header_size + page_blocks_size);
        fragment_offset += (packet_header_size + page_blocks_size);
        free(packet);
    } else {
        memcpy_s(merged_packet + fragment_offset, page_blocks_size, packet + packet_header_size, page_blocks_size);
        fragment_offset += page_blocks_size;
        free(packet);
        if (fragment_offset == merged_packet_size) { 
            seq_num = 0;
            return merged_packet;
        } 
    } 
    return NULL;
}
static void *deal_packet_thread(void *arg)
{
    int ret;
    int offset = 0;
    int buf_len;
    struct serial_port_file *serial_port = (struct serial_port_file *)arg;
    struct_fragment *p_frag = (struct_fragment *)malloc(sizeof(struct_fragment));
    if (p_frag == NULL) 
        goto end;

    CPU_SET_AFFINITY();
    while (!g_pool.destroying) {
        if (!serial_port || !serial_port->rd_buf || serial_port->sock <= 0) {
            tloge("serial_port ptr or rd_buf or fd is invalid\n");
            goto end;
        }

        ret = read(serial_port->sock, serial_port->rd_buf + serial_port->offset, BUF_LEN_MAX_RD - serial_port->offset);
        if (ret < 0) {
            tloge("read failed , serial_sock %d , ret %d \n", serial_port->sock, ret);
            if (errno == ECONNRESET || errno == EBADF) {
                goto end;
            }
            tloge("read domain socket failed, err: %s\n", strerror(errno));
            continue;
        } else if (ret == 0) {
            tlogw("read domain socket return zero value \n" );
            goto end;
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
            if (get_struct_fragment(packet, p_frag) == 0) {
                packet = get_merged_packet(packet, p_frag);
                if (packet == NULL) {
                    continue;
                }
            }
            thread_pool_submit(&g_pool, thread_entry, (void *)((uint64_t)packet));
        }
        serial_port->offset = offset;
    }

end:
    if (serial_port) {
        tlogi("reader thread %d exited\n", serial_port->index);
    } else {
        tloge("serial_port is null, and reader thread exit\n");
    }
    if (p_frag)
        free(p_frag);
    return NULL;
}

int create_reader_thread(struct serial_port_file *serial_port, int i)
{
    int ret;
    char name[THREAD_NAME_LEN] = {0};
    if ((ret = pthread_create(&g_pool.reader_threads[i], NULL, deal_packet_thread, serial_port))) {
        tloge("create reader thread failed, ret is %d\n", ret);
        return ret;
    }
    sprintf(name, "reader_%d", i);
    if ((ret = pthread_setname_np(g_pool.reader_threads[i], name))) {
        tloge("set thread name failed, ret is %d\n", ret);
        return ret;
    }
    if ((ret = pthread_detach(g_pool.reader_threads[i]))) {
        tloge("thread detach failed\n");
        return ret;
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
