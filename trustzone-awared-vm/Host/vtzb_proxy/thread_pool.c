#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include "thread_pool.h"
#include "debug.h"
#include "vm.h"

ThreadFuncArgs g_thd_args[THREAD_POOL_SIZE];
TimeOut g_time_out[THREAD_POOL_SIZE];

/* Custom signal handler for killing zombie threads. */
void signal_handler(int signum) {
    (void)signum;
    debug("Received user-defined signal (%d)\n", signum);
    pthread_exit(NULL);
}

/* Initialize the thread pool. */
int thread_pool_init(ThreadPool* pool)
{
    pool->task_count = 0;
    pool->front = pool->rear = 0;
    pool->destroying = 0;
    pthread_create(&pool->admin_tid, NULL, admin_thread, pool);
    pthread_mutex_init(&pool->task_mutex, NULL);
    pthread_mutex_init(&pool->session_mutex, NULL);
    pthread_mutex_init(&pool->time_mutex, NULL);
    pthread_cond_init(&pool->queue_not_empty, NULL);
    pthread_cond_init(&pool->queue_not_full, NULL);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        g_thd_args[i].index = i;
        g_thd_args[i].pool = pool;
        pthread_create(&pool->threads[i], NULL, thread_func, &g_thd_args[i]);
    }
    return 0;
}

/* Recreate a new thread to fill the gap in the thread pool after killing a thread. */
void replenish_thread_pool(ThreadPool* pool, pthread_t thd)
{
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            g_thd_args[i].index = i;
            g_thd_args[i].pool = pool;
            pthread_create(&pool->threads[i], NULL, thread_func, &g_thd_args[i]);
            pool->kill_flag[i] = false;
            debug("creat new thread\n");
            break;
        }
    }  
}

/* Thread function */
void *thread_func(void *arg)
{
    ThreadFuncArgs *thd_args = (ThreadFuncArgs *)arg;
    ThreadPool* pool = thd_args->pool;
    int index = thd_args->index;
    if (signal(SIGUSR1, signal_handler) == SIG_ERR) {
        debug("Error registering signal handler");
        return NULL;
    }

    while (1) {
        pthread_mutex_lock(&pool->task_mutex);

        /* Wait for the task queue to become non-empty. */
        while (pool->task_count == 0 && !pool->destroying) {
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
        pool->task_count--;
        pthread_cond_broadcast(&pool->queue_not_full);
        pthread_mutex_unlock(&pool->task_mutex);
        task.task_func(task.arg);
    }

    return NULL;
}

void *admin_thread(void *arg)
{
    int i;
    ThreadPool *pool = (ThreadPool *)arg;
    struct timeval cur_time;
    long time_sec = 0;
    while (!pool->destroying)
    {
        sleep(DEFAULT_TIME_SEC);
        gettimeofday(&cur_time, NULL);
        time_sec = cur_time.tv_sec;
        pthread_mutex_lock(&pool->time_mutex);
        for (i = 0; i < THREAD_POOL_SIZE; i++) {
            if (g_time_out[i].flag != 0 && (time_sec - g_time_out[i].start_time) > DEFAULT_TIME_SEC) {
                debug("before kill open session thread\n");
                kill_open_session_thd(g_time_out[i]);
                debug("after kill open session thread\n");
                g_time_out[i].flag = 0;
            }
        }
        pthread_mutex_unlock(&pool->time_mutex);
    }
    return NULL;
}

/* Submit the task to the thread pool. */
void thread_pool_submit(ThreadPool* pool, void* (*task_func)(void*), void* arg)
{
    debug(" main try task_mutex\n");
    pthread_mutex_lock(&pool->task_mutex);

    /* Wait for the task queue to become non-full. */
    while (pool->task_count == TASK_QUEUE_SIZE && !pool->destroying) {
        debug(" cond_wait\n");
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
    pool->task_count++;
    /* Notify waiting threads of a new task. */
    pthread_cond_signal(&pool->queue_not_empty);

    pthread_mutex_unlock(&pool->task_mutex);
    debug("submit success\n");
}

/* Destroy the thread pool. */
void thread_pool_destroy(ThreadPool* pool)
{
    /* Stop accepting new tasks. */
    pthread_mutex_lock(&pool->task_mutex);
    pool->destroying = 1;
    pthread_mutex_unlock(&pool->task_mutex);

    pthread_cond_broadcast(&pool->queue_not_empty);
    pthread_join(pool->admin_tid, NULL);

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    pthread_mutex_destroy(&pool->task_mutex);
    pthread_cond_destroy(&pool->queue_not_empty);
}

bool check_if_thd_exist(pthread_t thd)
{
    int kill_rc = pthread_kill(thd, 0);
    if(kill_rc != 0)
        return false;
    return true;
}

void set_thread_session_id(ThreadPool* pool, pthread_t thd, unsigned int id)
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

unsigned int get_thread_session_id(ThreadPool* pool, pthread_t thd, unsigned int session_id)
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

