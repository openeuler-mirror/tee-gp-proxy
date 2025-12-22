#include <linux/kernel.h>
#include <linux/hashtable.h>
#include "teek_ns_client.h"
#define HT_BITS 10
struct reg_mem {
    uint32_t session_id;
    uint64_t block_addrs[TEE_PARAM_NUM];
    uint64_t block_size[TEE_PARAM_NUM];
    uintptr_t addrs[TEE_PARAM_NUM][3];
    uint32_t page_size;
    struct hlist_node node;
};
int add_reg_mem(struct reg_mem * p_reg);
struct reg_mem * find_reg_mem(uint32_t session_id);
struct reg_mem * del_reg_mem(uint32_t session_id);
