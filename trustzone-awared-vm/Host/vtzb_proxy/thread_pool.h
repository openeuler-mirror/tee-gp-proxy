#ifndef __THREAD_POLL_H__
#define __THREAD_POLL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#define THREAD_POOL_SIZE 128
#define TASK_QUEUE_SIZE 128

/* task structure */
typedef struct {
    void* (*task_func)(void*); // Task function pointer
    void* arg;                 // Task argument
} Task;

/* the thread pool structure */
typedef struct {
    pthread_t threads[THREAD_POOL_SIZE]; // Thread array
    unsigned int session_ids[THREAD_POOL_SIZE]; // Session ID of the ongoing command
    unsigned int kill_session_ids[THREAD_POOL_SIZE];
    bool kill_flag[THREAD_POOL_SIZE];
    unsigned int seqs[THREAD_POOL_SIZE];
    Task task_queue[TASK_QUEUE_SIZE];    // Task queue
    int task_count;                      // Number of tasks in the task queue
    int front;                           // Queue head index
    int rear;                            // Queue tail index
    int destroying;                      // Destruction flag
    pthread_mutex_t mutex;               // Mutex
    pthread_cond_t cond;                 // Condition variable
} ThreadPool;

void thread_pool_init(ThreadPool* pool);
void thread_pool_destroy(ThreadPool* pool);
void *thread_func(void* arg);
void thread_pool_submit(ThreadPool* pool, void* (*task_func)(void*), void* arg);
void replenish_thread_pool(ThreadPool* pool, pthread_t thd);
void set_kill_flag(ThreadPool* pool, pthread_t thd);
void set_thread_session_id(ThreadPool* pool, pthread_t thd, unsigned int id);
unsigned int get_thread_session_id(ThreadPool* pool, pthread_t thd);
void set_thread_seq_num(ThreadPool* pool, pthread_t thd, unsigned int seq_num);
void remove_thread_seq_num(ThreadPool* pool, pthread_t thd, unsigned int seq_num);
unsigned int get_thread_seq_num(ThreadPool* pool, pthread_t thd);
#endif


