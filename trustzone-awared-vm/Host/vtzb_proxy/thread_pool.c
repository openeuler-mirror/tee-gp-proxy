#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include "thread_pool.h"

/* Custom signal handler for killing zombie threads. */
void signal_handler(int signum) {
    printf("Received user-defined signal (%d)\n", signum);

    pthread_exit(NULL);
}

/* Initialize the thread pool. */
void thread_pool_init(ThreadPool* pool)
{
    pool->task_count = 0;
    pool->front = pool->rear = 0;
    pool->destroying = 0;
    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->cond, NULL);

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&pool->threads[i], NULL, thread_func, pool);
    }
}

/* Recreate a new thread to fill the gap in the thread pool after killing a zombie thread. */
void replenish_thread_pool(ThreadPool* pool, pthread_t thd)
{
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            pthread_create(&pool->threads[i], NULL, thread_func, pool);
            printf("creat new thread\n");
            break;
        }
    }
    pthread_mutex_unlock(&pool->mutex);   
}

/* Thread function */
void *thread_func(void* arg)
{
    ThreadPool* pool = (ThreadPool*)arg;
    if (signal(SIGUSR1, signal_handler) == SIG_ERR) {
        printf("Error registering signal handler");
        return NULL;
    }

    while (1) {
        pthread_mutex_lock(&pool->mutex);

        /* Wait for the task queue to become non-empty. */
        while (pool->task_count == 0 && !pool->destroying) {
            pthread_cond_wait(&pool->cond, &pool->mutex);
        }

        /* If the thread pool is being destroyed, exit the thread. */
        if (pool->destroying) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }

        /* Retrieve the task and execute it. */
        Task task = pool->task_queue[pool->front];
        pool->front = (pool->front + 1) % TASK_QUEUE_SIZE;
        pool->task_count--;
        pthread_mutex_unlock(&pool->mutex);
        task.task_func(task.arg);
    }

    return NULL;
}

/* Submit the task to the thread pool. */
void thread_pool_submit(ThreadPool* pool, void* (*task_func)(void*), void* arg)
{
    pthread_mutex_lock(&pool->mutex);

    /* Wait for the task queue to become non-full. */
    while (pool->task_count == TASK_QUEUE_SIZE && !pool->destroying) {
        pthread_cond_wait(&pool->cond, &pool->mutex);
    }

    /* If the thread pool is being destroyed, no longer accept new tasks. */
    if (pool->destroying) {
        pthread_mutex_unlock(&pool->mutex);
        return;
    }

    /* Add the task to the queue. */
    pool->task_queue[pool->rear].task_func = task_func;
    pool->task_queue[pool->rear].arg = arg;
    pool->rear = (pool->rear + 1) % TASK_QUEUE_SIZE;
    pool->task_count++;
    /* Notify waiting threads of a new task. */
    pthread_cond_signal(&pool->cond);

    pthread_mutex_unlock(&pool->mutex);
}

/* Destroy the thread pool. */
void thread_pool_destroy(ThreadPool* pool)
{
    /* Stop accepting new tasks. */
    pthread_mutex_lock(&pool->mutex);
    pool->destroying = 1;
    pthread_mutex_unlock(&pool->mutex);

    pthread_cond_broadcast(&pool->cond);

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->cond);
}

bool check_if_thd_exist(pthread_t thd)
{
    int kill_rc = pthread_kill(thd, 0);
    if(kill_rc != 0)
        return false;
    return true;
}

void set_kill_flag(ThreadPool* pool, pthread_t thd)
{
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            pool->kill_flag[i] = true;
            break;
        }
    }
    pthread_mutex_unlock(&pool->mutex);    
}

void set_thread_session_id(ThreadPool* pool, pthread_t thd, unsigned int id)
{
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            pool->session_ids[i] = id;
            break;
        }
    }
    pthread_mutex_unlock(&pool->mutex);
}

void set_thread_kill_session_id(ThreadPool* pool, pthread_t thd, unsigned int id)
{
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            pool->kill_session_ids[i] = id;
            break;
        }
    }
    pthread_mutex_unlock(&pool->mutex);
}

unsigned int get_thread_session_id(ThreadPool* pool, pthread_t thd)
{
    unsigned int id = 0;
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            id = pool->session_ids[i];
            break;
        }
    }
    pthread_mutex_unlock(&pool->mutex);
    return id;
}

void set_thread_seq_num(ThreadPool* pool, pthread_t thd, unsigned int seq_num)
{
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            pool->seqs[i] = seq_num;
            break;
        }
    }
    pthread_mutex_unlock(&pool->mutex);
}

void remove_thread_seq_num(ThreadPool* pool, pthread_t thd, unsigned int seq_num)
{
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            if (pool->seqs[i] == seq_num)
                pool->seqs[i] = 0;
            break;
        }
    }
    pthread_mutex_unlock(&pool->mutex);
}

unsigned int get_thread_seq_num(ThreadPool* pool, pthread_t thd)
{
    unsigned int id = 0;
    pthread_mutex_lock(&pool->mutex);
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_equal(pool->threads[i], thd)) {
            id = pool->seqs[i];
            break;
        }
    }
    pthread_mutex_unlock(&pool->mutex);
    return id;
}


