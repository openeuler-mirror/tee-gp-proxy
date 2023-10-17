#include "test.h"
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

static int get_block_count(uint64_t *phys_addr, uint32_t pages_no)
{
	uint32_t i=0;
	int block_count = 1;
	uint64_t addr1;
	uint64_t addr2;
	if (pages_no == 0)
		return 0;
	addr1 = phys_addr[0];
	for (i = 1; i < pages_no; i++) {
		addr2 = phys_addr[i];
		if (addr2 != addr1 + PAGE_SIZE) {
			block_count++;
		}
		addr1 = phys_addr[i];
	}
	return block_count;
}

static int do_convert_page_blocks(uint64_t *phys_addr,
	uint32_t pages_no, uint64_t block_addr)
{
	struct page_block *block_buf = NULL;
	uint32_t i=0;
	uint32_t last_pos=0;
	int block_count = 1;
	uint64_t addr1;
	uint64_t addr2;
	if (pages_no == 0)
		return 0;
	block_buf = (struct page_block *)(uintptr_t)block_addr;
	if (pages_no == 1) {
		block_buf[0].page_num = 1;
		block_buf[0].phy_addr = phys_addr[0];
		return 1;
	}

	addr1 = phys_addr[0];
	for (i = 1; i < pages_no; i++) {
		addr2 = phys_addr[i];
		if (addr2 != addr1 + PAGE_SIZE) {
			block_buf[block_count-1].page_num = i - last_pos;
			block_buf[block_count-1].phy_addr = phys_addr[last_pos];
			block_count++;
			last_pos = i;
		}
		addr1 = addr2;
	}

	block_buf[block_count-1].page_num = i - last_pos;	
	block_buf[block_count-1].phy_addr = phys_addr[last_pos];

	return block_count;
}

void dump_page_blocks(int block_num, uint64_t block_addr)
{
	struct page_block *block_buf = (struct page_block *)(uintptr_t)block_addr;
	int i = 0;
	for (i=0;i<block_num;i++){
		tlogi("block_buf[%d].phy_addr = %llx\n", i, block_buf[i].phy_addr);
		tlogi("block_buf[%d].page_num = %lu\n", i, block_buf[i].page_num);
	}
}

static int convert_page_blocks(uint64_t *phys_addr, uint32_t pages_no,
	void **block_bufp, uint32_t *block_buf_size)
{
	int blocks_count = 0;
	int convert_count = 0;
	void *block_buf = NULL;
	uint32_t buff_len;

	blocks_count = get_block_count(phys_addr, pages_no);
	buff_len = sizeof(struct page_block) * blocks_count;
	block_buf = kzalloc(buff_len, GFP_KERNEL);
	if (block_buf == NULL) {
		tloge("kzalloc failed \n");
		return -EFAULT;
	}

	convert_count = do_convert_page_blocks(phys_addr, pages_no, (uint64_t)block_buf);
	if (convert_count != blocks_count) {
		tloge("convert page to blocks failed\n");
		kfree(block_buf);
		return -EFAULT;
	}
	*block_buf_size = buff_len;
	*block_bufp = block_buf; 

	//dump_page_blocks(convert_count, (uint64_t)block_buf);
	//kfree(block_buf);
	return 0;
}

void release_shared_mem_page(uint64_t buf, uint32_t buf_size)
{
	uint32_t i;
	uint64_t *phys_addr = NULL;
	struct pagelist_info *page_info = NULL;
	struct page *page = NULL;

	page_info = (struct pagelist_info *)(uintptr_t)buf;
	phys_addr = (uint64_t *)(uintptr_t)buf + (sizeof(*page_info) / sizeof(uint64_t));

	if (buf_size != sizeof(*page_info) + sizeof(uint64_t) * page_info->page_num) {
		tloge("bad size, cannot release page\n");
		return;
	}

	for (i = 0; i < page_info->page_num; i++) {
		page = (struct page *)(uintptr_t)phys_to_page(phys_addr[i]);
		if (page == NULL)
			continue;
		set_bit(PG_dirty, &page->flags);
		put_page(page);
	}
	kfree(buf);
}

int fill_shared_mem_info(uint64_t start_vaddr, uint32_t pages_no,
	uint32_t offset, uint32_t buffer_size, uint64_t info_addr,
	void **block_bufp, uint32_t *block_buf_sizep, int *block_countp)
{
	struct pagelist_info *page_info = NULL;
	struct page **pages = NULL;
	uint64_t *phys_addr = NULL;
	uint32_t page_num;
	uint32_t i;
	int block_count = 0;
	void *block_buf = NULL;
	uint32_t block_buf_size = 0;
	if (pages_no == 0)
		return -EFAULT;

	pages = (struct page **)vmalloc(pages_no * sizeof(uint64_t));
	if (pages == NULL)
		return -EFAULT;

	down_read(&mm_sem_lock(current->mm));
	page_num = get_user_pages((uintptr_t)start_vaddr, pages_no, FOLL_WRITE, pages, NULL);
	up_read(&mm_sem_lock(current->mm));
	if (page_num != pages_no) {
		tloge("get page phy addr failed\n");
		if (page_num > 0)
			release_pages(pages, page_num);
		vfree(pages);
		return -EFAULT;
	}

	page_info = (struct pagelist_info *)(uintptr_t)info_addr;
	page_info->page_num = pages_no;
	page_info->page_size = PAGE_SIZE;
	page_info->sharedmem_offset = offset;
	page_info->sharedmem_size = buffer_size;

	phys_addr = (uint64_t *)(uintptr_t)info_addr + (sizeof(*page_info) / sizeof(uint64_t));
	for (i = 0; i < pages_no; i++) {
		struct page *page = pages[i];
		if (page == NULL) {
			release_pages(pages, page_num);
			vfree(pages);
			return -EFAULT;
		}
		phys_addr[i] = (uintptr_t)page_to_phys(page);
		//tlogi("phys_addr[%d] = %lx\n", i, phys_addr[i]);
	}
	block_count = get_block_count(phys_addr, pages_no);
	tlogi("page_block count =%d\n",block_count);

	if (convert_page_blocks(phys_addr, pages_no, &block_buf, &block_buf_size) != 0) {
		tloge("convert_page_blocks failed\n");
		release_pages(pages, page_num);
		vfree(pages);
		return -EFAULT;
	}
	*block_bufp = block_buf;
	*block_buf_sizep = block_buf_size;
	*block_countp = block_count;

	vfree(pages);
	return 0;
}

int get_page_block(void *user_buffer, uint32_t buf_size,
	void **block_bufp, uint32_t *block_buf_sizep, int *block_countp,
	void **pages_bufp, uint32_t *pages_buf_sizep)
{
	void *buff = NULL;
	void *start_vaddr = NULL;
	uint32_t buffer_size;
	uint32_t pages_no;
	uint32_t offset;
	uint32_t buff_len;
	uint64_t buffer_addr;
	void *block_buf = NULL;
	uint32_t block_buf_size = 0;
	int block_count = 0;
	tlogi("enter test func\n");

	buffer_addr = (uint64_t)user_buffer;
	buff = (void *)(uint64_t)(buffer_addr);
	buffer_size = buf_size;
	start_vaddr = (void *)(((uint64_t)buff) & PAGE_MASK);
	offset = ((uint32_t)(uintptr_t)buff) & (~PAGE_MASK);
	pages_no = PAGE_ALIGN(offset + buffer_size) / PAGE_SIZE;
	buff_len = sizeof(struct pagelist_info) + (sizeof(uint64_t) * pages_no);

	tlogi("buffer_addr = %llx\n", buffer_addr);
	tlogi("start_vaddr = %llx\n", (uint64_t)start_vaddr);
	tlogi("offset      = %x\n", offset);
	tlogi("pages_no    = %u\n", pages_no);

	buff = kzalloc(buff_len, GFP_KERNEL);
	if (buff == NULL) {
		tloge("kzalloc failed \n");
		return -EFAULT;
	}

	if (fill_shared_mem_info((uint64_t)start_vaddr, pages_no, offset, buffer_size,
		(uint64_t)buff, &block_buf, &block_buf_size, &block_count)) {
		kfree(buff);
		return -EFAULT;
	}
	*block_bufp = block_buf;
	*block_buf_sizep = block_buf_size;
	*block_countp = block_count;
	*pages_bufp = buff;
	*pages_buf_sizep = buff_len;
	/*记录一下，后面好释放PAGE*/
	//dump_page_blocks(block_count, (uint64_t)block_buf);
	//release_shared_mem_page((uint64_t)buff, buff_len);
	return 0;
}

int test_fuc(const struct file *file, unsigned int cmd,
	unsigned long arg)
{
	void *buff = NULL;
	void *start_vaddr = NULL;
	struct test test;
	void *argp = (void __user *)(uintptr_t)arg;
	uint32_t buffer_size = 0;
	uint32_t pages_no = 0;
	uint32_t offset = 0;
	uint32_t buff_len = 0;
	uint64_t buffer_addr = 0;
	void *block_buf = NULL;
	uint32_t block_buf_size = 0;
	int block_count = 0;
	tlogi("enter test func\n");
	if (!argp) {
		tloge("invalid params\n");
		return -EINVAL;
	}
	if (copy_from_user(&test, argp, sizeof(test)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	buffer_addr = (uint64_t)test.user_buf;
	buff = (void *)(uint64_t)(buffer_addr + test.offset);
	buffer_size = test.buf_size;
	start_vaddr = (void *)(((uint64_t)buff) & PAGE_MASK);
	offset = ((uint32_t)(uintptr_t)buff) & (~PAGE_MASK);
	pages_no = PAGE_ALIGN(offset + buffer_size) / PAGE_SIZE;
	buff_len = sizeof(struct pagelist_info) + (sizeof(uint64_t) * pages_no);

	tlogi("buffer_addr = %llx\n", buffer_addr);
	tlogi("start_vaddr = %p\n", start_vaddr);
	tlogi("offset      = %x\n", offset);
	tlogi("pages_no    = %u\n", pages_no);

	buff = kzalloc(buff_len, GFP_KERNEL);
	if (buff == NULL) {
		tloge("kzalloc failed \n");
		return -EFAULT;
	}

	if (fill_shared_mem_info((uint64_t)start_vaddr, pages_no, offset, buffer_size,
		(uint64_t)buff, &block_buf, &block_buf_size, &block_count)) {
		kfree(buff);
		return -EFAULT;
	}
	dump_page_blocks(block_count, (uint64_t)block_buf);
	release_shared_mem_page((uint64_t)buff, buff_len);
	return 0;
}


