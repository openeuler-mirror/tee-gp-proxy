#ifndef RESERVED_SHM_H
#define RESERVED_SHM_H

#include <linux/mutex.h>
#include <linux/list.h>

#define MAILBOX_POOL_SIZE 	SZ_4M

struct reserved_shm_list
{
	struct mutex lock;
	struct list_head head;
};

struct vtzf_shared_mem {
	void *kernel_virt_addr;
	void *user_virt_addr;
	void *phy_addr;
	// void *user_addr_ca; /* for ca alloc share mem */
	unsigned int len;
	struct list_head head;
	// atomic_t usage;
	atomic_t offset;
};

struct vtz_shared_mem {
	void *kernel_addr;
	void *user_addr;
	void *user_addr_host;
	unsigned int len;
	int mem_type;
	struct list_head head;
	atomic_t usage;
	atomic_t offset;
};

struct reserved_shm
{
	void *kernel_addr;
	size_t buf_len;
	struct list_head head;
	int using;
};

void init_res_shm_list(void);
void destroy_res_shm_list(void);
void *alloc_res_shm(size_t len);
void dealloc_res_shm(void *kernel_buffer);
#endif

