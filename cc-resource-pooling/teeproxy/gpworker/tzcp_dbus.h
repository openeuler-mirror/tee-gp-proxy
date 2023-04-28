#ifndef _TZCP_DBUS_H_
#define _TZCP_DBUS_H_

#include <stdint.h>
#include <dbus/dbus.h>

#define  GP_PROXY_WORKER  1
// #define  GP_PROXY         2
#define  GP_WORKER        3

#ifdef GP_PROXY_WORKER

#include "threadpool.h"

#define  MAX_NUM_THREAD 128
#define  MAX_NUM_WORKER 128
#define  TIMEDOUT_SESSION 60 //seconds
#define  TIMEDOUT_CONTEXT 90 //seconds

#define    TEEC_ERROR_CONTEXT_NULL         0xAAAA0001  /* null context */
#define    TEEC_ERROR_CONTEXT_TAPATH_NULL  0xAAAA0002  /* null context ta path */
#define    TEEC_ERROR_PARAM0_TEMPMEM_NULL  0xAAAA0003  /* null param0 tempmem buf */
#define    TEEC_ERROR_PARAM0_TEMPMEM_LESS  0xAAAA0004  /* param0 tempmem buf is less */
#define    TEEC_ERROR_PARAM1_TEMPMEM_NULL  0xAAAA0005  /* null param1 tempmem buf */
#define    TEEC_ERROR_PARAM1_TEMPMEM_LESS  0xAAAA0006  /* param1 tempmem buf is less */
#define    TEEC_ERROR_PARAM2_TEMPMEM_NULL  0xAAAA0007  /* null param2 tempmem buf */
#define    TEEC_ERROR_PARAM2_TEMPMEM_LESS  0xAAAA0008  /* param2 tempmem buf is less */
#define    TEEC_ERROR_PARAM3_TEMPMEM_NULL  0xAAAA0009  /* null param3 tempmem buf */
#define    TEEC_ERROR_PARAM3_TEMPMEM_LESS  0xAAAA000A  /* param3 tempmem buf is less */
#define    TEEC_ERROR_CONTEXT_LIST_NULL    0xAAAA000B  /* null context list in woker */
#define    TEEC_ERROR_NO_CONTEXT_MATCH     0xAAAA000C  /* no context match in woker */
#define    TEEC_ERROR_SESSION_LIST_NULL    0xAAAA000D  /* null session list in woker */
#define    TEEC_ERROR_NO_SESSION_MATCH     0xAAAA000E  /* no session match in woker */
#define    TEEC_ERROR_PARAM0_MEMREF_NULL   0xAAAA000F  /* null param0 memref buf */
#define    TEEC_ERROR_PARAM0_MEMREF_LESS   0xAAAA0010  /* param0 memref buf is less */
#define    TEEC_ERROR_PARAM1_MEMREF_NULL   0xAAAA0011  /* null param1 memref buf */
#define    TEEC_ERROR_PARAM1_MEMREF_LESS   0xAAAA0012  /* param1 memref buf is less */
#define    TEEC_ERROR_PARAM2_MEMREF_NULL   0xAAAA0013  /* null param2 memref buf */
#define    TEEC_ERROR_PARAM2_MEMREF_LESS   0xAAAA0014  /* param2 memref buf is less */
#define    TEEC_ERROR_PARAM3_MEMREF_NULL   0xAAAA0015  /* null param3 memref buf */
#define    TEEC_ERROR_PARAM3_MEMREF_LESS   0xAAAA0016  /* param3 memref buf is less */
#define    TEEC_ERROR_NO_WORKER_MATCHED    0xAAAA0017  /* No woker mateched with the context or/and session */
#define    TEEC_ERROR_SESSION_NULL         0xAAAA0018  /* null session */
#define    TEEC_ERROR_NO_SHAREMEMFLAG      0xAAAA0019  /* no share memmory flag */

#endif


#ifdef GP_PROXY_WORKER
typedef struct
{
    DBusMessage *msg;
    DBusConnection *conn;
#ifdef GP_PROXY
    pthread_mutex_t * mutex_workerrec;
    pthread_cond_t  * cond_notbusy;
    wr_t * workerrec;
#endif
#ifdef GP_WORKER
    int64_t workernum;
    pthread_mutex_t *mutex_tcl;
    pthread_mutex_t *mutex_tsl;
    tcl_t *tcl;
    tsl_t *tsl;
#endif
} DBusMsgConn;
#endif

void
receive_signal(void);

void
send_signal(
      char *sigvalue
);

#ifdef GP_PROXY_WORKER

void
receive_methodcall(
      threadpool_t *pool,
#ifdef GP_WORKER
      pthread_mutex_t *mutex_tcl,
      pthread_mutex_t *mutex_tsl,
      tcl_t *tcl,
      tsl_t *tsl,
#endif
      char *workername

#ifdef GP_PROXY
      ,
           pthread_mutex_t * mutex_workerrec,
                pthread_cond_t  * cond_notbusy,
      wr_t * workerrec
#endif
);

#endif

int32_t
method_call_teec_inicont(
      const char *workername,

      const uint8_t *name, size_t name_size,
      int32_t in_context_fd,
      const uint8_t *in_context_tapath, size_t in_context_tapath_size,
      uint64_t in_context_sessionlist_next,
      uint64_t in_context_sessionlist_prev,
      uint64_t in_context_shrdmemlist_next,
      uint64_t in_context_shrdmemlist_prev,
      uint64_t in_context_sharebuffer_buffer,
      int64_t in_context_sharebuffer_bufferbarrier,

      uint32_t *teecresult,
      int32_t *context_fd,
      uint8_t *context_tapath, size_t context_tapath_insize,
      uint64_t *context_sessionlist_next,
      uint64_t *context_sessionlist_prev,
      uint64_t *context_shrdmemlist_next,
      uint64_t *context_shrdmemlist_prev,
      uint64_t *context_sharebuffer_buffer,
      int64_t *context_sharebuffer_bufferbarrier,
      uint64_t *context_addr,
      uint32_t *context_tapath_outsize
);

int32_t
method_call_teec_fincont(
      const char *workername,

      int32_t in_context_fd,
      const uint8_t *in_context_tapath, size_t in_context_tapath_size,
      uint64_t in_context_sessionlist_next,
      uint64_t in_context_sessionlist_prev,
      uint64_t in_context_shrdmemlist_next,
      uint64_t in_context_shrdmemlist_prev,
      uint64_t in_context_sharebuffer_buffer,
      int64_t in_context_sharebuffer_bufferbarrier,
      uint64_t in_context_addr,

      int32_t *context_fd,
      uint8_t *context_tapath, size_t context_tapath_insize,
      uint64_t *context_sessionlist_next,
      uint64_t *context_sessionlist_prev,
      uint64_t *context_shrdmemlist_next,
      uint64_t *context_shrdmemlist_prev,
      uint64_t *context_sharebuffer_buffer,
      int64_t *context_sharebuffer_bufferbarrier,
      uint32_t *context_tapath_outsize
);

int32_t
method_call_teec_opensession(
      const char *workername,

      int32_t in_context_fd,
      const uint8_t *in_context_tapath,
      size_t in_context_tapath_size,
      uint64_t in_context_sessionlist_next,
      uint64_t in_context_sessionlist_prev,
      uint64_t in_context_shrdmemlist_next,
      uint64_t in_context_shrdmemlist_prev,
      uint64_t in_context_sharebuffer_buffer,
      int64_t in_context_sharebuffer_bufferbarrier,

      uint32_t in_destination_timelow,
      uint32_t in_destination_timemid,
      uint32_t in_destination_timehiandver,
      uint32_t *in_destination_clockseqandnode,
      int32_t in_destination_clockseqandnode_size,
      uint32_t in_connectionmethod,
      uint64_t in_connectiondata,
      uint32_t in_operation_started,
      uint32_t in_operation_paramtypes,

      uint64_t in_operation_param1_tmpref_buffer,
      uint32_t in_operation_param1_tmpref_size,
      uint64_t in_operation_param1_memref_parent,
      uint32_t in_operation_param1_memref_size,
      uint32_t in_operation_param1_memref_offset,
      uint32_t in_operation_param1_value_a,
      uint32_t in_operation_param1_value_b,
      int32_t in_operation_param1_ionref_ionsharefd,
      uint32_t in_operation_param1_ionref_ionsize,

      uint64_t in_operation_param2_tmpref_buffer,
      uint32_t in_operation_param2_tmpref_size,
      uint64_t in_operation_param2_memref_parent,
      uint32_t in_operation_param2_memref_size,
      uint32_t in_operation_param2_memref_offset,
      uint32_t in_operation_param2_value_a,
      uint32_t in_operation_param2_value_b,
      int32_t in_operation_param2_ionref_ionsharefd,
      uint32_t in_operation_param2_ionref_ionsize,

      uint64_t in_operation_param3_tmpref_buffer,
      uint32_t in_operation_param3_tmpref_size,
      uint64_t in_operation_param3_memref_parent,
      uint32_t in_operation_param3_memref_size,
      uint32_t in_operation_param3_memref_offset,
      uint32_t in_operation_param3_value_a,
      uint32_t in_operation_param3_value_b,
      int32_t in_operation_param3_ionref_ionsharefd,
      uint32_t in_operation_param3_ionref_ionsize,

      uint64_t in_operation_param4_tmpref_buffer,
      uint32_t in_operation_param4_tmpref_size,
      uint64_t in_operation_param4_memref_parent,
      uint32_t in_operation_param4_memref_size,
      uint32_t in_operation_param4_memref_offset,
      uint32_t in_operation_param4_value_a,
      uint32_t in_operation_param4_value_b,
      int32_t in_operation_param4_ionref_ionsharefd,
      uint32_t in_operation_param4_ionref_ionsize,

      uint64_t in_operation_session,
      int32_t in_operation_cancelflag,

      uint32_t in_returnorigin,

      uint64_t in_context_addr,


      uint32_t *teecresult,

      int32_t *context_fd,
      uint8_t *context_tapath,
      size_t context_tapath_size,
      uint32_t *context_tapath_outsize,
      uint64_t *context_sessionlist_next,
      uint64_t *context_sessionlist_prev,
      uint64_t *context_shrdmemlist_next,
      uint64_t *context_shrdmemlist_prev,
      uint64_t *context_sharebuffer_buffer,
      int64_t *context_sharebuffer_bufferbarrier,

      uint32_t *session_seesionid,
      uint32_t *session_serviceid_timelow,
      uint32_t *session_serviceid_timemid,
      uint32_t *session_serviceid_timehiandver,
      uint32_t *session_serviceid_clockseqandnode,
      int32_t session_serviceid_clockseqandnode_size,
      uint32_t *session_serviceid_clockseqandnode_outsize,
      uint32_t *session_opscnt,
      uint64_t *session_head_next,
      uint64_t *session_head_prev,
      uint64_t *session_context,

      uint32_t *operation_started,
      uint32_t *operation_paramtypes,

      uint64_t *operation_param1_tmpref_buffer,
      uint32_t *operation_param1_tmpref_size,
      uint64_t *operation_param1_memref_parent,
      uint32_t *operation_param1_memref_size,
      uint32_t *operation_param1_memref_offset,
      uint32_t *operation_param1_value_a,
      uint32_t *operation_param1_value_b,
      int32_t *operation_param1_ionref_ionsharefd,
      uint32_t *operation_param1_ionref_ionsize,

      uint64_t *operation_param2_tmpref_buffer,
      uint32_t *operation_param2_tmpref_size,
      uint64_t *operation_param2_memref_parent,
      uint32_t *operation_param2_memref_size,
      uint32_t *operation_param2_memref_offset,
      uint32_t *operation_param2_value_a,
      uint32_t *operation_param2_value_b,
      int32_t *operation_param2_ionref_ionsharefd,
      uint32_t *operation_param2_ionref_ionsize,

      uint64_t *operation_param3_tmpref_buffer,
      uint32_t *operation_param3_tmpref_size,
      uint64_t *operation_param3_memref_parent,
      uint32_t *operation_param3_memref_size,
      uint32_t *operation_param3_memref_offset,
      uint32_t *operation_param3_value_a,
      uint32_t *operation_param3_value_b,
      int32_t *operation_param3_ionref_ionsharefd,
      uint32_t *operation_param3_ionref_ionsize,

      uint64_t *operation_param4_tmpref_buffer,
      uint32_t *operation_param4_tmpref_size,
      uint64_t *operation_param4_memref_parent,
      uint32_t *operation_param4_memref_size,
      uint32_t *operation_param4_memref_offset,
      uint32_t *operation_param4_value_a,
      uint32_t *operation_param4_value_b,
      int32_t *operation_param4_ionref_ionsharefd,
      uint32_t *operation_param4_ionref_ionsize,

      uint64_t *operation_session,
      int32_t *operation_cancelflag,

      uint32_t *returnorigin
);

int32_t
method_call_teec_closesession(
      const char *workername,

      uint32_t in_session_seesionid,
      uint32_t in_session_serviceid_timelow,
      uint32_t in_session_serviceid_timemid,
      uint32_t in_session_serviceid_timehiandver,
      uint32_t *in_session_serviceid_clockseqandnode,
      int32_t in_session_serviceid_clockseqandnode_size,
      uint32_t in_session_opscnt,
      uint64_t in_session_head_next,
      uint64_t in_session_head_prev,
      uint64_t in_session_context,

      uint32_t *session_seesionid,
      uint32_t *session_serviceid_timelow,
      uint32_t *session_serviceid_timemid,
      uint32_t *session_serviceid_timehiandver,
      uint32_t *session_serviceid_clockseqandnode,
      int32_t session_serviceid_clockseqandnode_size,
      uint32_t *session_serviceid_clockseqandnode_outsize,
      uint32_t *session_opscnt,
      uint64_t *session_head_next,
      uint64_t *session_head_prev,
      uint64_t *session_context
);

int32_t
method_call_teec_invokecommand(
      const char *workername,

      uint32_t in_session_seesionid,
      uint32_t in_session_serviceid_timelow,
      uint32_t in_session_serviceid_timemid,
      uint32_t in_session_serviceid_timehiandver,
      uint32_t *in_session_serviceid_clockseqandnode,
      uint32_t in_session_serviceid_clockseqandnode_size,
      uint32_t in_session_opscnt,
      uint64_t in_session_head_next,
      uint64_t in_session_head_prev,
      uint64_t in_session_context,

      uint32_t commandid,

      uint32_t in_operation_started,
      uint32_t in_operation_paramtypes,

      uint64_t in_operation_param1_tmpref_buffer,
      uint32_t in_operation_param1_tmpref_size,
      uint64_t in_operation_param1_memref_parent,
      uint32_t in_operation_param1_memref_parent_flag,
      uint32_t in_operation_param1_memref_size,
      uint32_t in_operation_param1_memref_offset,
      uint32_t in_operation_param1_value_a,
      uint32_t in_operation_param1_value_b,
      int32_t in_operation_param1_ionref_ionsharefd,
      uint32_t in_operation_param1_ionref_ionsize,

      uint64_t in_operation_param2_tmpref_buffer,
      uint32_t in_operation_param2_tmpref_size,
      uint64_t in_operation_param2_memref_parent,
      uint32_t in_operation_param2_memref_parent_flag,
      uint32_t in_operation_param2_memref_size,
      uint32_t in_operation_param2_memref_offset,
      uint32_t in_operation_param2_value_a,
      uint32_t in_operation_param2_value_b,
      int32_t in_operation_param2_ionref_ionsharefd,
      uint32_t in_operation_param2_ionref_ionsize,

      uint64_t in_operation_param3_tmpref_buffer,
      uint32_t in_operation_param3_tmpref_size,
      uint64_t in_operation_param3_memref_parent,
      uint32_t in_operation_param3_memref_parent_flag,
      uint32_t in_operation_param3_memref_size,
      uint32_t in_operation_param3_memref_offset,
      uint32_t in_operation_param3_value_a,
      uint32_t in_operation_param3_value_b,
      int32_t in_operation_param3_ionref_ionsharefd,
      uint32_t in_operation_param3_ionref_ionsize,

      uint64_t in_operation_param4_tmpref_buffer,
      uint32_t in_operation_param4_tmpref_size,
      uint64_t in_operation_param4_memref_parent,
      uint32_t in_operation_param4_memref_parent_flag,
      uint32_t in_operation_param4_memref_size,
      uint32_t in_operation_param4_memref_offset,
      uint32_t in_operation_param4_value_a,
      uint32_t in_operation_param4_value_b,
      int32_t in_operation_param4_ionref_ionsharefd,
      uint32_t in_operation_param4_ionref_ionsize,

      uint64_t in_operation_session,
      int32_t in_operation_cancelflag,

      uint32_t in_returnorigin,

      uint32_t *in_buffer1,
      uint32_t in_buffer1_size,
      uint32_t *in_buffer2,
      uint32_t in_buffer2_size,
      uint32_t *in_buffer3,
      uint32_t in_buffer3_size,
      uint32_t *in_buffer4,
      uint32_t in_buffer4_size,


      uint32_t *teecresult,

      uint32_t *session_seesionid,
      uint32_t *session_serviceid_timelow,
      uint32_t *session_serviceid_timemid,
      uint32_t *session_serviceid_timehiandver,
      uint32_t *session_serviceid_clockseqandnode,
      int32_t session_serviceid_clockseqandnode_size,
      uint32_t *session_serviceid_clockseqandnode_outsize,
      uint32_t *session_opscnt,
      uint64_t *session_head_next,
      uint64_t *session_head_prev,
      uint64_t *session_context,

      uint32_t *operation_started,
      uint32_t *operation_paramtypes,

      uint64_t *operation_param1_tmpref_buffer,
      uint32_t *operation_param1_tmpref_size,
      uint64_t *operation_param1_memref_parent,
      uint32_t *operation_param1_memref_parent_flag,
      uint32_t *operation_param1_memref_size,
      uint32_t *operation_param1_memref_offset,
      uint32_t *operation_param1_value_a,
      uint32_t *operation_param1_value_b,
      int32_t *operation_param1_ionref_ionsharefd,
      uint32_t *operation_param1_ionref_ionsize,

      uint64_t *operation_param2_tmpref_buffer,
      uint32_t *operation_param2_tmpref_size,
      uint64_t *operation_param2_memref_parent,
      uint32_t *operation_param2_memref_parent_flag,
      uint32_t *operation_param2_memref_size,
      uint32_t *operation_param2_memref_offset,
      uint32_t *operation_param2_value_a,
      uint32_t *operation_param2_value_b,
      int32_t *operation_param2_ionref_ionsharefd,
      uint32_t *operation_param2_ionref_ionsize,

      uint64_t *operation_param3_tmpref_buffer,
      uint32_t *operation_param3_tmpref_size,
      uint64_t *operation_param3_memref_parent,
      uint32_t *operation_param3_memref_parent_flag,
      uint32_t *operation_param3_memref_size,
      uint32_t *operation_param3_memref_offset,
      uint32_t *operation_param3_value_a,
      uint32_t *operation_param3_value_b,
      int32_t *operation_param3_ionref_ionsharefd,
      uint32_t *operation_param3_ionref_ionsize,

      uint64_t *operation_param4_tmpref_buffer,
      uint32_t *operation_param4_tmpref_size,
      uint64_t *operation_param4_memref_parent,
      uint32_t *operation_param4_memref_parent_flag,
      uint32_t *operation_param4_memref_size,
      uint32_t *operation_param4_memref_offset,
      uint32_t *operation_param4_value_a,
      uint32_t *operation_param4_value_b,
      int32_t *operation_param4_ionref_ionsharefd,
      uint32_t *operation_param4_ionref_ionsize,

      uint64_t *operation_session,
      int32_t *operation_cancelflag,

      uint32_t *returnorigin,

      uint32_t *buffer1,
      uint32_t buffer1_size,
      uint32_t *buffer1_outsize,
      uint32_t *buffer2,
      uint32_t buffer2_size,
      uint32_t *buffer2_outsize,
      uint32_t *buffer3,
      uint32_t buffer3_size,
      uint32_t *buffer3_outsize,
      uint32_t *buffer4,
      uint32_t buffer4_size,
      uint32_t *buffer4_outsize
);

void
method_call_destroy_threadpool(
      const char *workername
);


#ifdef GP_PROXY_WORKER

void *
reply_to_method_call_teec_inicont(
      void *thdfargs
);

void *
reply_to_method_call_teec_fincont(
      void *thdfargs
);

void *
reply_to_method_call_teec_opensession(
      void *thdfargs
);

void *
reply_to_method_call_teec_closesession(
      void *thdfargs
);

void *
reply_to_method_call_teec_invokecommand(
      void *thdfargs
);

#ifdef GP_PROXY
void*
session_timeout_process ( 
   void* thdfargs
);

void*
context_timeout_process ( 
   void* thdfargs
);
#endif

void *
reply_to_method_call_destroy_threadpool(
      DBusMessage *msg,
      DBusConnection *conn,
      threadpool_t *pool
#ifdef GP_WORKER
      ,
      pthread_mutex_t *mutex_tcl,
      pthread_mutex_t *mutex_tsl
#endif
#ifdef GP_PROXY
      ,
           pthread_mutex_t * mutex_workerbusy,
                pthread_cond_t  * cond_notbusy
#endif
);

#endif


#endif /* _TZCP_DBUS_H_ */
