#ifndef VTZF_H
#define VTZF_H

#include <linux/mutex.h>
#include <linux/list.h>
#include "tc_ns_client.h"
#include "teek_ns_client.h"
#include "comm_structs.h"
#include "reserved_shm.h"

#define VTZF_DEV        	"vtzf"
#define CONFIG_CONFIDENTIAL_CONTAINER
#ifndef SECURITY_AUTH_ENHANCE 
#define SECURITY_AUTH_ENHANCE
#endif

#ifndef ZERO_SIZE_PTR
#define ZERO_SIZE_PTR 		((void *)16)
#define ZERO_OR_NULL_PTR(x) 	((unsigned long)(x) <= (unsigned long)ZERO_SIZE_PTR)
#endif

#define INVALID_MAP_ADDR 	((void *)-1)
#define MAILBOX_POOL_SIZE 	SZ_4M

#define IS_TEMP_MEM(paramType)                                                              \
    (((paramType) == TEEC_MEMREF_TEMP_INPUT) || ((paramType) == TEEC_MEMREF_TEMP_OUTPUT) || \
     ((paramType) == TEEC_MEMREF_TEMP_INOUT))

#define IS_PARTIAL_MEM(paramType)                                                        \
    (((paramType) == TEEC_MEMREF_WHOLE) || ((paramType) == TEEC_MEMREF_PARTIAL_INPUT) || \
     ((paramType) == TEEC_MEMREF_PARTIAL_OUTPUT) || ((paramType) == TEEC_MEMREF_PARTIAL_INOUT))

#define IS_VALUE_MEM(paramType) \
    (((paramType) == TEEC_VALUE_INPUT) || ((paramType) == TEEC_VALUE_OUTPUT) || ((paramType) == TEEC_VALUE_INOUT))

/* Use during device initialization */
struct dev_node {
	struct class *driver_class;
	struct cdev char_dev;
	dev_t devt;
	struct device *class_dev;
	const struct file_operations *fops;
	char *node_name;
};

/* List of devices that have already been opened*/
struct vtzf_dev_list {
	struct mutex dev_lock; /* for dev_file_list */
	struct list_head dev_file_list;
};

struct vtzf_dev_file {
	unsigned int dev_file_id;
	int32_t ptzfd;
	struct list_head head;
	struct mutex shared_mem_lock; /* for shared_mem_list */
	struct list_head shared_mem_list;
	void *buf;
};

struct agent_buf
{
	uint32_t id;
	uint32_t buf_size;
	void *buf;
};

int tc_ns_client_open(struct vtzf_dev_file **dev_file, uint32_t flag);
static int vtzf_client_open(struct inode *inode, struct file *file);
static int vtzf_private_open(struct inode *inode, struct file *file);
static int vtzf_cvm_open(struct inode *inode, struct file *file);
int vtzf_close(struct inode *inode, struct file *file);
void shared_vma_open(struct vm_area_struct *vma);
void shared_vma_close(struct vm_area_struct *vma);
static int vtzf_mmap(struct file *filp, struct vm_area_struct *vma);
static long tc_client_ioctl(struct file *file,
	unsigned int cmd, unsigned long arg);
static long tc_private_ioctl(struct file *file,
	unsigned int cmd, unsigned long arg);
static long tc_cvm_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg);
static int public_ioctl(const struct file *file, unsigned int cmd,
	unsigned long arg, bool is_from_client_node);
static int open_tzdriver(struct vtzf_dev_file *dev_file, uint32_t flag);
static int close_tzdriver(struct vtzf_dev_file *dev_file);
#ifdef CONFIG_COMPAT
long tc_compat_client_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
long tc_compat_private_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
long tc_compat_cvm_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg);
#endif

static int proxy_mmap(struct vtzf_dev_file *dev_file, void * user_buffer,
	uint32_t buffer_size, uint32_t pgoff, uint8_t unmap);

static int tc_ns_open_session(struct vtzf_dev_file *dev_file,
	struct tc_ns_client_context *clicontext);
int tc_client_session_ioctl(struct vtzf_dev_file *dev_file,
	unsigned int cmd, unsigned long arg);
static int tc_ns_send_cancel_cmd(struct vtzf_dev_file *dev_file, void *argp);
static int tc_ns_client_login_func(struct vtzf_dev_file *dev_file,
	const void __user *buffer);
static int tc_ns_get_tee_version(struct vtzf_dev_file *dev_file,
	void __user *argp);
static int tc_ns_late_init(unsigned long arg);
static int sync_system_time_from_user(struct vtzf_dev_file *dev_file, 
	const struct tc_ns_client_time *user_time);
#endif // VTZF_H