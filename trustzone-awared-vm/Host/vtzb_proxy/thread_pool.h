#ifndef __THREAD_POLL_H__
#define __THREAD_POLL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#define THREAD_POOL_SIZE 196
#define TASK_QUEUE_SIZE 32
#define DEFAULT_TIME_SEC  30

/* task structure */
typedef struct {
    void* (*task_func)(void*); // Task function pointer
    void* arg;                 // Task argument
} Task;

/* the thread pool structure */
typedef struct {
    pthread_t admin_tid;
    pthread_t threads[THREAD_POOL_SIZE]; // Thread array
    unsigned int session_ids[THREAD_POOL_SIZE]; // Session ID of the ongoing command
    bool kill_flag[THREAD_POOL_SIZE];
    void *task_args[THREAD_POOL_SIZE];
    Task task_queue[TASK_QUEUE_SIZE];    // Task queue
    int task_count;                      // Number of tasks in the task queue
    int front;                           // Queue head index
    int rear;                            // Queue tail index
    int destroying;                      // Destruction flag
    pthread_mutex_t task_mutex;               // Mutex
    pthread_mutex_t session_mutex;       // Mutex
    pthread_mutex_t time_mutex;          // Mutex
    pthread_cond_t queue_not_empty;      // Condition variable
    pthread_cond_t queue_not_full;       // Condition variable
} ThreadPool;

typedef struct {
    ThreadPool *pool;
    int index;
} ThreadFuncArgs;

int thread_pool_init(ThreadPool* pool);
void thread_pool_destroy(ThreadPool* pool);
void *thread_func(void* arg);
void *admin_thread(void *arg);
void thread_pool_submit(ThreadPool* pool, void* (*task_func)(void*), void* arg);
void replenish_thread_pool(ThreadPool* pool, pthread_t thd);
void set_thread_session_id(ThreadPool* pool, pthread_t thd, unsigned int id);
unsigned int get_thread_session_id(ThreadPool* pool, pthread_t thd, unsigned int session_id);
#endif
