#ifndef RESERVED_SHM_H
#define RESERVED_SHM_H

#include <linux/mutex.h>
#include <linux/list.h>
#include "comm_structs.h"

#define MAILBOX_POOL_SIZE 	SZ_4M
#define INPUT  0
#define OUTPUT 1
#define INOUT  2

#define ADDRS_NUM 3

struct reserved_shm_list
{
	struct mutex lock;
	struct list_head head;
};

struct vtzf_shared_mem {
	void *kernel_addr;
	void *user_addr;
	void *phy_addr;
	void *user_addr_host;
	unsigned int len;
	struct list_head head;
	atomic_t offset;
};

struct reserved_shm
{
	void *kernel_addr;
	size_t buf_len;
	struct list_head head;
	int using;
};

struct session_param_mem_info {
	uint32_t seq_num;
	struct_packet_cmd_session packet_cmd;
	uintptr_t addrs[4][3];
	char *buffer;
	struct list_head node;
	unsigned long live_time;
};

void init_res_shm_list(void);
void destroy_res_shm_list(void);
void *alloc_res_shm(size_t len);
void dealloc_res_shm(void *kernel_buffer);
bool teec_value_type(unsigned int type, int dir);
bool teec_tmpmem_type(unsigned int type, int dir);
bool teec_memref_type(unsigned int type, int dir);
void free_for_params(struct tc_ns_client_context *clicontext,
	uintptr_t addrs[][ADDRS_NUM]);
void find_and_free_session(uint32_t seq_num);
#endif