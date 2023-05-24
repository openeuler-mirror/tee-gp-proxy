#ifndef _TEECC_H
#define _TEECC_H

#include <stdint.h>

struct retstru_teec_inicont {
  uint32_t teecresult;
  int32_t context_fd;
  uint8_t *context_tapath;
  uintptr_t context_tapath_outsize;
  uint64_t context_sessionlist_next;
  uint64_t context_sessionlist_prev;
  uint64_t context_shrdmemlist_next;
  uint64_t context_shrdmemlist_prev;
  uint64_t context_sharebuffer_buffer;
  int64_t context_sharebuffer_bufferbarrier;
  uint64_t context_addr;
  int32_t flag;
};

struct retstru_teec_fincont {
  int32_t context_fd;
  uint8_t *context_tapath;
  uintptr_t context_tapath_outsize;
  uint64_t context_sessionlist_next;
  uint64_t context_sessionlist_prev;
  uint64_t context_shrdmemlist_next;
  uint64_t context_shrdmemlist_prev;
  uint64_t context_sharebuffer_buffer;
  int64_t context_sharebuffer_bufferbarrier;
  int32_t flag;
};

struct retstru_teec_opensession {
  uint32_t teecresult;
  int32_t context_fd;
  uint8_t *context_tapath;
  uintptr_t context_tapath_outsize;
  uint64_t context_sessionlist_next;
  uint64_t context_sessionlist_prev;
  uint64_t context_shrdmemlist_next;
  uint64_t context_shrdmemlist_prev;
  uint64_t context_sharebuffer_buffer;
  int64_t  context_sharebuffer_bufferbarrier;
  uint32_t session_sessionid;
  uint32_t session_serviceid_timelow;
  uint32_t session_serviceid_timemid;
  uint32_t session_serviceid_timehiandver;
  uint8_t *session_serviceid_clockseqandnode;
  uintptr_t session_serviceid_clockseqandnode_outsize;
  uint32_t session_opscnt;
  uint64_t session_head_next;
  uint64_t session_head_prev;
  uint64_t session_context;
  uint32_t operation_started;
  uint32_t operation_paramtypes;
  uint64_t operation_param1_tmpref_buffer;
  uint32_t operation_param1_tmpref_size;
  uint64_t operation_param1_memref_parent;
  uint32_t operation_param1_memref_size;
  uint32_t operation_param1_memref_offset;
  uint32_t operation_param1_value_a;
  uint32_t operation_param1_value_b;
  int32_t operation_param1_ionref_ionsharefd;
  uint32_t operation_param1_ionref_ionsize;
  uint64_t operation_param2_tmpref_buffer;
  uint32_t operation_param2_tmpref_size;
  uint64_t operation_param2_memref_parent;
  uint32_t operation_param2_memref_size;
  uint32_t operation_param2_memref_offset;
  uint32_t operation_param2_value_a;
  uint32_t operation_param2_value_b;
  int32_t operation_param2_ionref_ionsharefd;
  uint32_t operation_param2_ionref_ionsize;
  uint64_t operation_param3_tmpref_buffer;
  uint32_t operation_param3_tmpref_size;
  uint64_t operation_param3_memref_parent;
  uint32_t operation_param3_memref_size;
  uint32_t operation_param3_memref_offset;
  uint32_t operation_param3_value_a;
  uint32_t operation_param3_value_b;
  int32_t operation_param3_ionref_ionsharefd;
  uint32_t operation_param3_ionref_ionsize;
  uint64_t operation_param4_tmpref_buffer;
  uint32_t operation_param4_tmpref_size;
  uint64_t operation_param4_memref_parent;
  uint32_t operation_param4_memref_size;
  uint32_t operation_param4_memref_offset;
  uint32_t operation_param4_value_a;
  uint32_t operation_param4_value_b;
  int32_t operation_param4_ionref_ionsharefd;
  uint32_t operation_param4_ionref_ionsize;
  uint64_t operation_session;
  int32_t operation_cancelflag;
  uint32_t returnorigin;
  int32_t flag;

};

struct retstru_teec_closesession {
  uint32_t session_sessionid;
  uint32_t session_serviceid_timelow;
  uint32_t session_serviceid_timemid;
  uint32_t session_serviceid_timehiandver;
  uint8_t *session_serviceid_clockseqandnode;
  uintptr_t session_serviceid_clockseqandnode_outsize;
  uint32_t session_opscnt;
  uint64_t session_head_next;
  uint64_t session_head_prev;
  uint64_t session_context;
  int32_t flag;

};

struct retstru_teec_invokecommand {
  uint32_t teecresult;
  uint32_t session_sessionid;
  uint32_t session_serviceid_timelow;
  uint32_t session_serviceid_timemid;
  uint32_t session_serviceid_timehiandver;
  uint8_t *session_serviceid_clockseqandnode;
  uintptr_t session_serviceid_clockseqandnode_outsize;
  uint32_t session_opscnt;
  uint64_t session_head_next;
  uint64_t session_head_prev;
  uint64_t session_context;
  uint32_t operation_started;
  uint32_t operation_paramtypes;
  uint64_t operation_param1_tmpref_buffer;
  uint32_t operation_param1_tmpref_size;
  uint64_t operation_param1_memref_parent;
  uint32_t operation_param1_memref_parent_flag;
  uint32_t operation_param1_memref_size;
  uint32_t operation_param1_memref_offset;
  uint32_t operation_param1_value_a;
  uint32_t operation_param1_value_b;
  int32_t operation_param1_ionref_ionsharefd;
  uint32_t operation_param1_ionref_ionsize;
  uint64_t operation_param2_tmpref_buffer;
  uint32_t operation_param2_tmpref_size;
  uint64_t operation_param2_memref_parent;
  uint32_t operation_param2_memref_parent_flag;
  uint32_t operation_param2_memref_size;
  uint32_t operation_param2_memref_offset;
  uint32_t operation_param2_value_a;
  uint32_t operation_param2_value_b;
  int32_t operation_param2_ionref_ionsharefd;
  uint32_t operation_param2_ionref_ionsize;
  uint64_t operation_param3_tmpref_buffer;
  uint32_t operation_param3_tmpref_size;
  uint64_t operation_param3_memref_parent;
  uint32_t operation_param3_memref_parent_flag;
  uint32_t operation_param3_memref_size;
  uint32_t operation_param3_memref_offset;
  uint32_t operation_param3_value_a;
  uint32_t operation_param3_value_b;
  int32_t operation_param3_ionref_ionsharefd;
  uint32_t operation_param3_ionref_ionsize;
  uint64_t operation_param4_tmpref_buffer;
  uint32_t operation_param4_tmpref_size;
  uint64_t operation_param4_memref_parent;
  uint32_t operation_param4_memref_parent_flag;
  uint32_t operation_param4_memref_size;
  uint32_t operation_param4_memref_offset;
  uint32_t operation_param4_value_a;
  uint32_t operation_param4_value_b;
  int32_t operation_param4_ionref_ionsharefd;
  uint32_t operation_param4_ionref_ionsize;
  uint64_t operation_session;
  int32_t operation_cancelflag;
  uint32_t returnorigin;
  uint8_t *buffer1;
  uintptr_t buffer1_outsize;
  uint8_t *buffer2;
  uintptr_t buffer2_outsize;
  uint8_t *buffer3;
  uintptr_t buffer3_outsize;
  uint8_t *buffer4;
  uintptr_t buffer4_outsize;
  int32_t flag;
};


struct retstru_teec_inicont externc_teec_initializecontext(uint8_t *name,
                                                    uint32_t name_size,
                                                    int32_t in_context_fd,
                                                    uint8_t *in_context_tapath,
                                                    int32_t in_context_tapath_size,
                                                    uint64_t in_context_sessionlist_next,
                                                    uint64_t in_context_sessionlist_prev,
                                                    uint64_t in_context_shrdmemlist_next,
                                                    uint64_t in_context_shrdmemlist_prev,
                                                    uint64_t in_context_sharebuffer_buffer,
                                                    int64_t in_context_sharebuffer_bufferbarrier);

void externc_retstru_teec_inicont_free(struct retstru_teec_inicont rs_ins);

struct retstru_teec_fincont externc_teec_finalizecontext(int32_t in_context_fd,
                                                  uint8_t *in_context_tapath,
                                                  int32_t in_context_tapath_size,
                                                  uint64_t in_context_sessionlist_next,
                                                  uint64_t in_context_sessionlist_prev,
                                                  uint64_t in_context_shrdmemlist_next,
                                                  uint64_t in_context_shrdmemlist_prev,
                                                  uint64_t in_context_sharebuffer_buffer,
                                                  int64_t in_context_sharebuffer_bufferbarrier, 
                                                  uint64_t in_context_addr);

void externc_retstru_teec_fincont_free(struct retstru_teec_fincont rs_ins);

struct retstru_teec_opensession externc_teec_opensession(int32_t in_context_fd,
                                                  uint8_t *in_context_tapath,
                                                  int32_t in_context_tapath_size,
                                                  uint64_t in_context_sessionlist_next,
                                                  uint64_t in_context_sessionlist_prev,
                                                  uint64_t in_context_shrdmemlist_next,
                                                  uint64_t in_context_shrdmemlist_prev,
                                                  uint64_t in_context_sharebuffer_buffer,
                                                  int64_t in_context_sharebuffer_bufferbarrier,
                                                  uint32_t in_destination_timelow,
                                                  uint32_t in_destination_timemid,
                                                  uint32_t in_destination_timehiandver,
                                                  uint8_t *in_destination_clockseqandnode,
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
                                                  uint64_t in_context_addr);

void externc_retstru_teec_opensession_free(struct retstru_teec_opensession rs_ins);

struct retstru_teec_closesession externc_teec_closesession(uint32_t in_session_sessionid,
                                                    uint32_t in_session_serviceid_timelow,
                                                    uint32_t in_session_serviceid_timemid,
                                                    uint32_t in_session_serviceid_timehiandver,
                                                    uint8_t *in_session_serviceid_clockseqandnode,
                                                    uintptr_t in_session_serviceid_clockseqandnode_size,
                                                    uint32_t in_session_opscnt,
                                                    uint64_t in_session_head_next,
                                                    uint64_t in_session_head_prev,
                                                    uint64_t in_session_context);

void externc_retstru_teec_closesession_free(struct retstru_teec_closesession rs_ins);

struct retstru_teec_invokecommand externc_teec_invokecommand(uint32_t in_session_sessionid,
                                                      uint32_t in_session_serviceid_timelow,
                                                      uint32_t in_session_serviceid_timemid,
                                                      uint32_t in_session_serviceid_timehiandver,
                                                      uint8_t *in_session_serviceid_clockseqandnode,
                                                      uintptr_t in_session_serviceid_clockseqandnode_size,
                                                      uint32_t in_session_opscnt,
                                                      uint64_t in_session_head_next,
                                                      uint64_t in_session_head_prev,
                                                      uint64_t in_session_context,
                                                      uint32_t in_commandid,
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
                                                      uint8_t *in_buffer1,
                                                      uintptr_t in_buffer1_size,
                                                      uint8_t *in_buffer2,
                                                      uintptr_t in_buffer2_size,
                                                      uint8_t *in_buffer3,
                                                      uintptr_t in_buffer3_size,
                                                      uint8_t *in_buffer4,
                                                      uintptr_t in_buffer4_size);


void externc_retstru_teec_invokecommand_free(struct retstru_teec_invokecommand rs_ins);
#endif // _TEECC_H