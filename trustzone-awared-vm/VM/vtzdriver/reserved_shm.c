#include "reserved_shm.h"
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "tc_ns_log.h"

struct reserved_shm_list g_res_shm_list;
struct mutex g_lock;
size_t g_alloc_size;
size_t g_relese_size;

void put_alloc(size_t size)
{
	mutex_lock(&g_lock);
	g_alloc_size += size;
	mutex_unlock(&g_lock);
}

void put_relese(size_t size)
{
	mutex_lock(&g_lock);
	g_relese_size += size;
	mutex_unlock(&g_lock);
}

void init_res_shm_list(void)
{
	INIT_LIST_HEAD(&g_res_shm_list.head);
	mutex_init(&g_res_shm_list.lock);
	mutex_init(&g_lock);
	g_alloc_size = 0;
	g_relese_size = 0;
}

void destroy_res_shm_list(void)
{
	struct reserved_shm *shm = NULL;
	struct reserved_shm *temp = NULL;
	mutex_lock(&g_res_shm_list.lock);
	list_for_each_entry_safe(shm, temp, &g_res_shm_list.head, head) {
		if (shm->kernel_addr)
			kfree(shm->kernel_addr);
		list_del(&shm->head);
		kfree(shm);
	}
	mutex_unlock(&g_res_shm_list.lock);
	mutex_destroy(&g_res_shm_list.lock);
}

void *alloc_res_shm(size_t len)
{
	size_t size = 0;
	struct reserved_shm *shm = NULL;
	struct reserved_shm *temp = NULL;
	struct reserved_shm *result = NULL;

	mutex_lock(&g_res_shm_list.lock);
	list_for_each_entry_safe(shm, temp, &g_res_shm_list.head, head) {
		if (!shm->using && shm->buf_len >= len) {
			shm->using = 1;
			result = shm;
			break;
		}
	}
	mutex_unlock(&g_res_shm_list.lock);

	if (result) {
		return result->kernel_addr;
	}
	size = ALIGN(len, PAGE_SIZE);
	if (size > MAILBOX_POOL_SIZE) {
		tloge("vtzf alloc sharemem buffer size %zu is too large \n", len);
		return NULL;
	}
	result = kzalloc(sizeof(struct reserved_shm), GFP_KERNEL);
	if (!result) {
		tloge("failed to alloc mem for struct reserved_shm\n");
		return NULL;
	}
	result->kernel_addr = kzalloc(size, GFP_KERNEL);
	if (!result->kernel_addr) {
		tloge("failed to alloc mem for struct reserved_shm buffer\n");
		kfree(result);
		return NULL;		
	}
	result->using = 1;
	result->buf_len = size;
	INIT_LIST_HEAD(&result->head);
	mutex_lock(&g_res_shm_list.lock);
	list_add_tail(&result->head, &g_res_shm_list.head);
	mutex_unlock(&g_res_shm_list.lock);
	return result->kernel_addr;
}

void dealloc_res_shm(void *kernel_buffer)
{
	int bfind= 0;
	struct reserved_shm *shm = NULL;
	struct reserved_shm *temp = NULL;
	mutex_lock(&g_res_shm_list.lock);
	list_for_each_entry_safe(shm, temp, &g_res_shm_list.head, head) {
		if (shm->kernel_addr == kernel_buffer) {
			shm->using = 0;
			memset(shm->kernel_addr, 0, shm->buf_len);
			bfind = 1;
			list_del(&shm->head);
			list_add_tail(&shm->head, &g_res_shm_list.head);
			tlogd("dealloc res shm \n");
			break;
		}
	}
	mutex_unlock(&g_res_shm_list.lock);
	if (!bfind)
		tloge("can't find res mem\n");
}