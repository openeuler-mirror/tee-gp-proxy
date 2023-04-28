#ifndef _DBUSC_GPW_H_
#define _DBUSC_GPW_H_

#include <stdint.h>
#include <dbus/dbus.h>


void
receive_signal(void);

void
send_signal(
      char *sigvalue
);

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

#endif /* _DBUSC_GPW_H_ */
