#ifndef _THREAD_POOL_H_
#define _THREAD_POOL_H_

#include "condition.h"

#define  GP_WORKER  3

#ifdef GP_WORKER

#include "tee_client_api.h"
#include "tee_client_list.h"

#endif



#ifdef GP_PROXY
typedef struct sessionid_node 
{
  uint32_t session_id;   
  struct timeval session_createtime;
  struct sessionid_node * next;
  struct sessionid_node * prev;
} sin_t;

typedef struct worker_rec 
{
   uint8_t  busy;	
   int32_t  context_fd;
   uint64_t context_addr;
   struct   timeval context_createtime;
   int      sessionid_count;
   sin_t    * first;   
   sin_t    * last;   
} wr_t;
#endif

#ifdef GP_WORKER
typedef struct teec_session_node
{
    TEEC_Session *self;
    struct timeval createtime;
    struct teec_session_node *next;
    struct teec_session_node *prev;
} tsn_t;

typedef struct teec_session_list
{
    int count;         // 线程池中当前线程数
    tsn_t *first;
    tsn_t *last;
} tsl_t;

typedef struct teec_context_node
{
    TEEC_Context *self;
    struct timeval createtime;
    struct teec_context_node *next;
    struct teec_context_node *prev;
} tcn_t;

typedef struct teec_context_list
{
    int count;         // 线程池中当前线程数
    tcn_t *first;
    tcn_t *last;
} tcl_t;
#endif


// 任务结构体,将任务放入队列由线程池中的线程来执行
typedef struct task
{
    void *(*run)(void *arg);   // 任务回调函数
    void *arg;         // 回调函数参数
    struct task *next;
} task_t;

// 线程池结构体
typedef struct threadpool
{
    condition_t ready;      // mutex and condition var, 任务准备就绪或者线程池销毁通知
    task_t *first;         // 任务队列头指针
    task_t *last;         // 任务队列尾指针
    int counter;         // 线程池中当前线程数
    int idle;         // 线程池中当前正在等待任务的线程数
    int max_threads;      // 线程池中最大允许的线程数
    int quit;         // 销毁线程池的时候置1
} threadpool_t;

// 初始化线程池
void threadpool_init(
      threadpool_t *pool,
      int threads
#ifdef GP_WORKER
      ,
      tcl_t *tcl,
      tsl_t *tsl
#endif
);

// 往线程池中添加任务
void threadpool_add_task(threadpool_t *pool, void *(*run)(void *arg), void *arg);

// 销毁线程池
void threadpool_destroy(threadpool_t *pool);

#endif /* _THREAD_POOL_H_ */
