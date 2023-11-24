#ifndef BLOCK_PAGES__H
#define BLOCK_PAGES__H
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <asm/memory.h>
#include <securec.h>
#include "tc_ns_client.h"
#include "tc_ns_log.h"
#include "teek_client_constants.h"

struct test {
    void * user_buf;
    int buf_size;
    uint32_t offset;
};

struct pagelist_info {
	uint64_t page_num;
	uint64_t page_size;
	uint64_t sharedmem_offset;
	uint64_t sharedmem_size;
};

struct page_block
{
	uint64_t phy_addr;
	uint32_t page_num;
	uint32_t frag_flag;
};

void dump_page_blocks(int block_num, uint64_t block_addr);
void release_shared_mem_page(uint64_t buf, uint32_t buf_size);
int get_page_block(void *user_buffer, uint32_t buf_size,
	void **block_bufp, uint32_t *block_buf_sizep, int *block_countp,
	void **pages_bufp, uint32_t *pages_buf_sizep);
int test_fuc(const struct file *file, unsigned int cmd,
	unsigned long arg);

#endif

