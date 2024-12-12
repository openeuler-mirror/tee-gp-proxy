/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2023. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __THREAD_POLL_H__
#define __THREAD_POLL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include "serial_port.h"

#define THREAD_POOL_SIZE 196
#define TASK_QUEUE_SIZE 32
#define DEFAULT_TIME_SEC  30
#define CPU_SET_NUM 8

/* task structure */
typedef struct {
    void *(*task_func)(void *);// Task function pointer
    void *arg;                 // Task argument
} Task;

/* the thread pool structure */
typedef struct {
    pthread_t admin_tid;
    pthread_t threads[THREAD_POOL_SIZE]; // Thread array
    pthread_t reader_threads[SERIAL_PORT_NUM];
    unsigned int session_ids[THREAD_POOL_SIZE]; // Session ID of the ongoing command
    bool kill_flag[THREAD_POOL_SIZE];
    void *task_args[THREAD_POOL_SIZE];
    Task task_queue[TASK_QUEUE_SIZE];    // Task queue
    int task_cnt;                        // Number of tasks in the task queue
    int busy_cnt;
    int front;                           // Queue head index
    int rear;                            // Queue tail index
    int destroying;                      // Destruction flag
    pthread_mutex_t task_mutex;               // Mutex
    pthread_mutex_t session_mutex;       // Mutex
    pthread_mutex_t time_mutex;          // Mutex
    pthread_mutex_t busy_mutex;          // Mutex
    pthread_cond_t queue_not_empty;      // Condition variable
    pthread_cond_t queue_not_full;       // Condition variable
} ThreadPool;

typedef struct {
    ThreadPool *pool;
    int index;
} ThreadFuncArgs;

int thread_pool_init(ThreadPool *pool);
void thread_pool_destroy(ThreadPool *pool);
void *thread_func(void *arg);
void *admin_thread(void *arg);
int create_reader_thread(struct serial_port_file *serial_port, int i);
void thread_pool_submit(ThreadPool *pool, void *(*task_func)(void *), void *arg);
void replenish_thread_pool(ThreadPool *pool, pthread_t thd);
void set_thread_session_id(ThreadPool *pool, pthread_t thd, unsigned int id);
unsigned int get_thread_session_id(ThreadPool *pool, pthread_t thd, unsigned int session_id);
#endif
