#ifndef __VTZB_PROXY_H__
#define __VTZB_PROXY_H__

#include <sys/ioctl.h>
#include <sys/types.h>
#include "tc_ns_client.h"
#include "tee_sys_log.h"
#include "tee_client_list.h"

#define TC_LOGGER_DEV_NAME       "/dev/teelog"

//#define VM_NUM_MAX 2

#define H_OFFSET                 32

#define VTZB_RSP_UNKOWN          0xfffffffe

#define TEEC_PARAM_TYPE_GET(paramTypes, index) \
    (((paramTypes) >> (4 * (index))) & 0x0F)

#define IS_TEMP_MEM(paramType)                                                              \
    (((paramType) == TEEC_MEMREF_TEMP_INPUT) || ((paramType) == TEEC_MEMREF_TEMP_OUTPUT) || \
     ((paramType) == TEEC_MEMREF_TEMP_INOUT))

#define IS_PARTIAL_MEM(paramType)                                                        \
    (((paramType) == TEEC_MEMREF_WHOLE) || ((paramType) == TEEC_MEMREF_PARTIAL_INPUT) || \
     ((paramType) == TEEC_MEMREF_PARTIAL_OUTPUT) || ((paramType) == TEEC_MEMREF_PARTIAL_INOUT))

#define IS_VALUE_MEM(paramType) \
    (((paramType) == TEEC_VALUE_INPUT) || ((paramType) == TEEC_VALUE_OUTPUT) || ((paramType) == TEEC_VALUE_INOUT))

#define IS_SHARED_MEM(paramType) \
    ((paramType) == TEEC_MEMREF_SHARED_INOUT)

#define PAGE_SIZE getpagesize()

typedef union {
    struct {
        uint32_t buf_size;
    } memref;
    struct {
        uint32_t val_a;
        uint32_t val_b;
    } value;
    struct {
        void *buf;
        uint32_t buf_size;
    } share;
} ClientParam;

typedef struct {
    void* vm_buffer;
    void* buffer;
    uint32_t buffer_size;
    int32_t dev_fd;
    struct ListNode node;
} struct_shrd_mem;

typedef union {
    struct{
        uint64_t user_addr;
        uint64_t page_num;
    }block;
    struct{
        uint64_t vm_page_size;
        uint64_t shared_mem_size;        
    }share;
}struct_page_block;

int connect_domsock_chardev(char* dev_path, int* sock);
void *kill_Zombie(void *args);

#endif /* __VTZB_PROXY_H__ */


