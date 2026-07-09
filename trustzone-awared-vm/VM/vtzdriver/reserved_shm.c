#include "reserved_shm.h"
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <securec.h>
#include "block_pages.h"
#include "tc_ns_client.h"
#include "tc_ns_log.h"

struct reserved_shm_list g_res_shm_list;
struct mutex g_lock;
size_t g_alloc_size;
size_t g_relese_size;

LIST_HEAD(delayed_free_mem_list);
DEFINE_SPINLOCK(delayed_free_lock);

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
			memset_s(shm->kernel_addr, shm->buf_len, 0, shm->buf_len);
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

static inline bool is_input_type(int dir)
{
	if (dir == INPUT || dir == INOUT)
		return true;

	return false;
}

static inline bool is_output_type(int dir)
{
	if (dir == OUTPUT || dir == INOUT)
		return true;

	return false;
}

bool teec_value_type(unsigned int type, int dir)
{
	return ((is_input_type(dir) && type == TEEC_VALUE_INPUT) ||
		(is_output_type(dir) && type == TEEC_VALUE_OUTPUT) ||
		type == TEEC_VALUE_INOUT) ? true : false;
}

bool teec_tmpmem_type(unsigned int type, int dir)
{
	return ((is_input_type(dir) && type == TEEC_MEMREF_TEMP_INPUT) ||
		(is_output_type(dir) && type == TEEC_MEMREF_TEMP_OUTPUT) ||
		type == TEEC_MEMREF_TEMP_INOUT) ? true : false;
}

bool teec_memref_type(unsigned int type, int dir)
{
	return ((is_input_type(dir) && type == TEEC_MEMREF_PARTIAL_INPUT) ||
		(is_output_type(dir) && type == TEEC_MEMREF_PARTIAL_OUTPUT) ||
		type == TEEC_MEMREF_PARTIAL_INOUT) ? true : false;
}


void free_for_params(struct tc_ns_client_context *clicontext,
	uintptr_t addrs[][ADDRS_NUM])
{
	int index;
	uint32_t param_type;
	uintptr_t buf;

	void *pages_buf = NULL;
	uint32_t pages_buf_size = 0;
	for (index = 0; index < TEE_PARAM_NUM; index++) {
		param_type = teec_param_type_get(clicontext->param_types, index);
		if (teec_tmpmem_type(param_type, INOUT) && addrs[index][1]) {
			buf = addrs[index][1];
			dealloc_res_shm((void *)buf);
		}else if (param_type == TEEC_MEMREF_SHARED_INOUT ||
					param_type == TEEC_MEMREF_REGISTER_INOUT){
			pages_buf = (void *)addrs[index][1];
			pages_buf_size = (uint32_t)addrs[index][0];
			release_shared_mem_page((uint64_t)pages_buf, pages_buf_size);
		} else {
			/* nothing */
		}
	}	
}

void find_and_free_session(uint32_t seq_num)
{
	struct session_param_mem_info *session_param, *session_param_tmp;

	spin_lock(&delayed_free_lock);

	list_for_each_entry_safe(session_param, session_param_tmp, &delayed_free_mem_list, node) {
		if (session_param->seq_num == seq_num) {
			list_del(&session_param->node);

			free_for_params(&session_param->packet_cmd.cliContext, session_param->addrs);
			if (session_param->buffer) {
				dealloc_res_shm(session_param->buffer);
				session_param->buffer = NULL;
			}

			kfree(session_param);
			spin_unlock(&delayed_free_lock);

			tlogd("Found and freed session with seq_num = %u\n", seq_num);
			return;
		}
	}

	spin_unlock(&delayed_free_lock);
}