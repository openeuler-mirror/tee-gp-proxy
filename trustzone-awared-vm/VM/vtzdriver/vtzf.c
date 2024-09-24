#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h> 
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/mman.h>
#include "vtzf.h"
#include "tlogger.h"
#include "serialport.h"
#include "tee_info.h"
#include "comm_structs.h"
#include "reserved_shm.h"
#include "securec.h"
#include "tc_ns_client.h"
#include "tc_ns_log.h"
#include "teek_client_constants.h"
#include "block_pages.h"

#define CONFIG_CONFIDENTIAL_CONTAINER

#define PRINTF_SIZE 16
void dump_buff(const char *buffer, size_t bufLen) {
	size_t i;
	if (buffer == NULL || bufLen == 0) {
		return;
	}
	tlogd("--------------------------------------------------\n");
	tlogd("bufLen = %d\n", (int)bufLen);
	for (i = 0; i < bufLen; i++) {
		if (i % PRINTF_SIZE == 0 && i != 0) {
			tlogd("\n");
		}
		tlogd("%02x ", *(buffer + i));
	}
	tlogd("\n--------------------------------------------------\n");
	return;
}

static struct class *g_driver_class;
static struct device_node *g_dev_node;

struct dev_node g_tc_client;
struct dev_node g_tc_private;
#if defined(CONFIG_CONFIDENTIAL_CONTAINER) || defined(CONFIG_TEE_TELEPORT_SUPPORT)
struct dev_node g_tc_cvm;
#endif
/* dev node list and itself has mutex to avoid race */
struct vtzf_dev_list g_tc_ns_dev_list;

static unsigned int g_device_file_cnt = 1;
static DEFINE_MUTEX(g_device_file_cnt_lock);

#define MAX_AGENTS_NUM	10
struct agent_buf g_agents_buf[MAX_AGENTS_NUM] = {0};

static struct vm_operations_struct g_shared_remap_vm_ops = {
	.open = shared_vma_open,
	.close = shared_vma_close,
};

static const struct file_operations g_tc_ns_client_fops = {
	.owner = THIS_MODULE,
	.open = vtzf_client_open,
	.release = vtzf_close,
	.unlocked_ioctl = tc_client_ioctl,
	.mmap = vtzf_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tc_compat_client_ioctl,
#endif
};

static const struct file_operations g_teecd_fops = {
	.owner = THIS_MODULE,
	.open = vtzf_private_open,
	.release = vtzf_close,
	.unlocked_ioctl = tc_private_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tc_compat_private_ioctl,
#endif
};

static const struct file_operations g_cvm_fops = {
	.owner = THIS_MODULE,
	.open = vtzf_cvm_open,
	.release = vtzf_close,
	.unlocked_ioctl = tc_cvm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tc_compat_cvm_ioctl,
#endif
};

const struct file_operations *get_cvm_fops(void)
{
	return &g_cvm_fops;
}

struct vtzf_dev_list *get_dev_list(void)
{
	return &g_tc_ns_dev_list;
}

static int create_dev_node(struct dev_node *node)
{
	int ret;
	if (!node || !(node->node_name)) {
		tloge("node or member is null\n");
		return -EFAULT;
	}
	if (alloc_chrdev_region(&(node->devt), 0, 1,
		node->node_name) != 0) {
		tloge("alloc chrdev region failed");
		ret = -EFAULT;
		return ret;
	}
	node->class_dev = device_create(node->driver_class, NULL, node->devt,
		NULL, node->node_name);
	if (IS_ERR_OR_NULL(node->class_dev)) {
		tloge("class device create failed");
		ret = -ENOMEM;
		goto chrdev_region_unregister;
	}
	node->class_dev->of_node = g_dev_node;

	cdev_init(&(node->char_dev), node->fops);
	(node->char_dev).owner = THIS_MODULE;

	return 0;

chrdev_region_unregister:
	unregister_chrdev_region(node->devt, 1);
	return ret;
}

static int init_dev_node(struct dev_node *node, char *node_name,
	struct class *driver_class, const struct file_operations *fops)
{
	int ret = -1;
	if (!node) {
		tloge("node is NULL\n");
		return ret;
	}
	node->node_name = node_name;
	node->driver_class = driver_class;
	node->fops = fops;

	ret = create_dev_node(node);
	return ret;
}

static void destory_dev_node(struct dev_node *node, struct class *driver_class)
{
	device_destroy(driver_class, node->devt);
	unregister_chrdev_region(node->devt, 1);
	return;
}

static int tc_ns_client_init(void)
{
	int ret;

	g_driver_class = class_create(THIS_MODULE, TC_NS_CLIENT_DEV);
	if (IS_ERR_OR_NULL(g_driver_class)) {
		tloge("class create failed");
		ret = -ENOMEM;
		return ret;
	}

	ret = init_dev_node(&g_tc_client, TC_NS_CLIENT_DEV, g_driver_class, &g_tc_ns_client_fops);
	if (ret != 0) {
		class_destroy(g_driver_class);
		return ret;
	}
	ret = init_dev_node(&g_tc_private, TC_PRIV_DEV, g_driver_class, &g_teecd_fops);
	if (ret != 0) {
		destory_dev_node(&g_tc_client, g_driver_class);
		class_destroy(g_driver_class);
		return ret;
	}
#if defined(CONFIG_CONFIDENTIAL_CONTAINER) || defined(CONFIG_TEE_TELEPORT_SUPPORT)
	ret = init_dev_node(&g_tc_cvm, TC_NS_CVM_DEV, g_driver_class, get_cvm_fops());
	if (ret != 0) {
		destory_dev_node(&g_tc_private, g_driver_class);
		destory_dev_node(&g_tc_client, g_driver_class);
		class_destroy(g_driver_class);
		return ret;
	}
#endif
	INIT_LIST_HEAD(&g_tc_ns_dev_list.dev_file_list);
	mutex_init(&g_tc_ns_dev_list.dev_lock);
	return ret;
}

static int enable_dev_nodes(void)
{
	int ret;

	ret = cdev_add(&(g_tc_private.char_dev),
		MKDEV(MAJOR(g_tc_private.devt), 0), 1);
	if (ret < 0) {
		tloge("cdev add failed %d", ret);
		return ret;
	}

	ret = cdev_add(&(g_tc_client.char_dev),
		MKDEV(MAJOR(g_tc_client.devt), 0), 1);
	if (ret < 0) {
		tloge("cdev add failed %d", ret);
		cdev_del(&(g_tc_private.char_dev));
		return ret;
	}

#if defined(CONFIG_CONFIDENTIAL_CONTAINER) || defined(CONFIG_TEE_TELEPORT_SUPPORT)
	ret = cdev_add(&(g_tc_cvm.char_dev),
				MKDEV(MAJOR(g_tc_cvm.devt), 0), 1);
	if (ret < 0) {
		tloge("cdev add failed %d", ret);
		cdev_del(&(g_tc_client.char_dev));
		cdev_del(&(g_tc_private.char_dev));
		return ret;
	}
#endif
	return 0;
}

static int __init vtzf_init(void)
{
	int ret;
	ret = tc_ns_client_init();
	if (ret != 0)
		return ret;
	init_res_shm_list();
	ret = tlogger_init();
	if (ret != 0) {
		tloge("tlogger init failed\n");
		goto exit_tlogger;
	}
	ret = enable_dev_nodes();
	if (ret != 0) {
		tloge("enable dev nodes failed\n");
		goto class_device_destroy;
	}
	ret = serial_port_init();
	if (ret != 0) {
		goto class_device_destroy;
	}
	seq_num_init();
	return 0;

class_device_destroy:
#if defined(CONFIG_CONFIDENTIAL_CONTAINER) || defined(CONFIG_TEE_TELEPORT_SUPPORT)
	destory_dev_node(&g_tc_cvm, g_driver_class);
#endif
	destory_dev_node(&g_tc_client, g_driver_class);
	destory_dev_node(&g_tc_private, g_driver_class);
	class_destroy(g_driver_class);
exit_tlogger:
	tlogger_exit();
	return ret;
}	

static void free_dev_list(void)
{
	struct vtzf_dev_file *dev_file = NULL, *temp = NULL;

	mutex_lock(&g_tc_ns_dev_list.dev_lock);
	list_for_each_entry_safe(dev_file, temp, &g_tc_ns_dev_list.dev_file_list, head) {
		list_del(&dev_file->head);
		kfree(dev_file);
	}
	mutex_unlock(&g_tc_ns_dev_list.dev_lock);
}

static void __exit vtzf_exit(void)
{
#if defined(CONFIG_CONFIDENTIAL_CONTAINER) || defined(CONFIG_TEE_TELEPORT_SUPPORT)
	cdev_del(&(g_tc_cvm.char_dev));
#endif
	cdev_del(&(g_tc_private.char_dev));
	cdev_del(&(g_tc_client.char_dev));
#if defined(CONFIG_CONFIDENTIAL_CONTAINER) || defined(CONFIG_TEE_TELEPORT_SUPPORT)
	destory_dev_node(&g_tc_cvm, g_driver_class);
#endif

	destory_dev_node(&g_tc_client, g_driver_class);
	destory_dev_node(&g_tc_private, g_driver_class);
	class_destroy(g_driver_class);
	tlogi("class_destroy success\n");
	tlogger_exit();
	tlogi("tlogger_exit success\n");
	free_dev_list();
	tlogi("free_dev_list success\n");
	free_serial_port_list();
	tlogi("free_serial_port_list success\n");
	destroy_res_shm_list();
	tlogi("destroy_res_shm_list success\n");
}	

int tc_ns_client_open(struct vtzf_dev_file **dev_file, uint32_t flag)
{
	struct vtzf_dev_file *dev = NULL;
	tlogd("vtzf open \n");
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)dev)) {
		tloge("vtzf_dev_file malloc failed\n");
		return -ENOMEM;
	}

	mutex_lock(&g_tc_ns_dev_list.dev_lock);
	list_add_tail(&dev->head, &g_tc_ns_dev_list.dev_file_list);
	mutex_unlock(&g_tc_ns_dev_list.dev_lock);

	mutex_lock(&g_device_file_cnt_lock);
	dev->dev_file_id = g_device_file_cnt;
	g_device_file_cnt++;
	mutex_unlock(&g_device_file_cnt_lock);

	INIT_LIST_HEAD(&dev->shared_mem_list);
	mutex_init(&dev->shared_mem_lock);

	(void)open_tzdriver(dev, flag);

	*dev_file = dev;
	return 0;
}

static int vtzf_client_open(struct inode *inode, struct file *file)
{
	int ret;
	struct vtzf_dev_file *dev_file = NULL;
	(void)inode;
	file->private_data = NULL;
	ret = tc_ns_client_open(&dev_file, TC_NS_CLIENT_DEV_FLAG);
	if (!ret)
		file->private_data = dev_file;
	
	return 0;
}

static int vtzf_private_open(struct inode *inode, struct file *file)
{
	struct vtzf_dev_file *dev_file = NULL;

	dev_file = kzalloc(sizeof(*dev_file), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)dev_file)) {
		tloge("vtzf_dev_file malloc failed\n");
		return -ENOMEM;
	}

	mutex_lock(&g_tc_ns_dev_list.dev_lock);
	list_add_tail(&dev_file->head, &g_tc_ns_dev_list.dev_file_list);
	mutex_unlock(&g_tc_ns_dev_list.dev_lock);

	mutex_lock(&g_device_file_cnt_lock);
	dev_file->dev_file_id = g_device_file_cnt;
	g_device_file_cnt++;
	mutex_unlock(&g_device_file_cnt_lock);

	INIT_LIST_HEAD(&dev_file->shared_mem_list);
	mutex_init(&dev_file->shared_mem_lock);

	file->private_data = dev_file;

	(void)open_tzdriver(dev_file, TC_PRIVATE_DEV_FLAG);
	return 0;
}

static int vtzf_cvm_open(struct inode *inode, struct file *file)
{
	int ret = -1;
	struct vtzf_dev_file *dev = NULL;
	(void)inode;

	file->private_data = NULL;
	ret = tc_ns_client_open(&dev, TC_CVM_DEV_FLAG);
	if (ret == 0)
		file->private_data = dev;
	return ret;
}

static int open_tzdriver(struct vtzf_dev_file *dev_file, uint32_t flag)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_open_tzd packet_cmd = {0};
	struct_packet_rsp_open_tzd packet_rsp = {0};
	packet_cmd.packet_size = sizeof(packet_cmd);
	if (!dev_file) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	dev_file->ptzfd = -1;
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_OPEN_TZD;
	packet_cmd.vmid = 0;
	/* if flag==0, open tc_ns_client; if flag==1, open tc_private */
	packet_cmd.flag = flag;

	ret = send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num);
	if (!ret) {
		ret = packet_rsp.ret;
		if (ret) {
			tloge("open TZdriver failed ret is %d\n", ret);
			goto END;
		}
		dev_file->ptzfd = packet_rsp.ptzfd;
	} else {
		tloge("send to proxy failed ret is %d\n", ret);
	}
END:
	return ret;
}

int vtzf_close(struct inode *inode, struct file *file)
{
	int ret = 0;
	struct vtzf_dev_file *dev_file = file->private_data;

	mutex_destroy(&dev_file->shared_mem_lock);

	mutex_lock(&g_tc_ns_dev_list.dev_lock);
	list_del(&dev_file->head);
	mutex_unlock(&g_tc_ns_dev_list.dev_lock);

	(void)close_tzdriver(dev_file);

	kfree(dev_file);
	mutex_lock(&g_device_file_cnt_lock);
	g_device_file_cnt--;
	mutex_unlock(&g_device_file_cnt_lock);

	file->private_data = NULL;
	return ret;
}	

static int close_tzdriver(struct vtzf_dev_file *dev_file)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_close_tzd packet_cmd = {0};
	struct_packet_rsp_close_tzd packet_rsp = {0};
	packet_cmd.packet_size = sizeof(packet_cmd);

	if (!dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_CLOSE_TZD;
	packet_cmd.ptzfd = dev_file->ptzfd;
	tlogd("close ptzfd = %d\n", dev_file->ptzfd);

	ret = send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num);
	if (!ret) {
		ret = packet_rsp.ret;
		if (ret) {
			tloge("close TZdriver failed ret is %d\n", ret);
			goto END;
		}
	} else {
		tloge("send to proxy failed ret is %d\n", ret);
	}
END:
	return ret;
}

void shared_vma_open(struct vm_area_struct *vma)
{
	(void)vma;
}

void shared_vma_close(struct vm_area_struct *vma)
{
	struct vtzf_dev_file *dev_file = NULL;
	struct vtzf_shared_mem *shared_mem = NULL;
	struct vtzf_shared_mem *shared_mem_temp = NULL;
	bool find = false;

	if (!vma) {
		tloge("virtual memory area is null \n");
		return;
	}
	dev_file = vma->vm_private_data;
	if (!dev_file) {
		tloge("virtual memory area private data is null \n");
		return;
	}

	mutex_lock(&dev_file->shared_mem_lock);
	list_for_each_entry_safe(shared_mem, shared_mem_temp,
			&dev_file->shared_mem_list, head) {
		if (shared_mem) {
			if (shared_mem->user_addr ==
				(void *)(uintptr_t)vma->vm_start) {
				shared_mem->user_addr = NULL;
				list_del(&shared_mem->head);
				if (shared_mem->kernel_addr) {
					dealloc_res_shm(shared_mem->kernel_addr);
					shared_mem->kernel_addr = NULL;
				}
				kfree(shared_mem);
				find = true;
				break;
			} 
		}
	}
	mutex_unlock(&dev_file->shared_mem_lock);
	if (find) {
		(void)proxy_mmap(dev_file, (void *)(uintptr_t)vma->vm_start, 0 ,0, true);
	}
}

static int proxy_mmap(struct vtzf_dev_file *dev_file,
	void * user_buffer, uint32_t buffer_size,
	uint32_t pgoff, uint8_t unmap)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_mmap packet_cmd = {0};
	struct_packet_rsp_mmap packet_rsp = {0};

	if (!dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = unmap ? VTZF_MUNMAP : VTZF_MMAP;
	packet_cmd.seq_num = seq_num;
	packet_cmd.ptzfd = dev_file->ptzfd;
	packet_cmd.buffer = (uint64_t)user_buffer;
	packet_cmd.size = buffer_size;
	packet_cmd.offset = pgoff;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
		goto END;
	} else {
		ret = packet_rsp.ret;
	}
END:
	return ret;
}

static int vtzf_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct vtzf_dev_file *dev_file = NULL;
	struct vtzf_shared_mem *shared_mem = NULL;
	void *addr = NULL;
	size_t len;

	if (!filp || !vma || !filp->private_data) {
		tloge("vtzf invalid args for mmap \n");
		return -EINVAL;
	}
	dev_file = filp->private_data;

	shared_mem = kmalloc(sizeof(*shared_mem), GFP_KERNEL | __GFP_ZERO);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)shared_mem)) {
		tloge("vtzf shared_mem kmalloc failed \n");
		return -ENOMEM;
	}

	len = vma->vm_end - vma->vm_start;
	len = ALIGN(len, 1 << PAGE_SHIFT);
	if (len > MAILBOX_POOL_SIZE) {
		tloge("vtzf alloc sharemem buffer size %zu is too large \n", len);
		kfree(shared_mem);
		return -EINVAL;
	}

	addr = alloc_res_shm(len);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)addr)) {
		tloge("kmalloc shared_mem buffer failed \n");
		return -ENOMEM;
	}

	shared_mem->kernel_addr = addr;
	shared_mem->len = len;
	shared_mem->user_addr =(void *)vma->vm_start;
	shared_mem->phy_addr = (void *)virt_to_phys(addr);

	tlogv("shared_mem user   virtual address = 0x%016llx \n", (uint64_t)shared_mem->user_addr);
	tlogv("shared_mem kernel virtual address = 0x%016llx \n", (uint64_t)shared_mem->kernel_addr);
	tlogv("shared_mem physical       address = 0x%016llx \n", (uint64_t)shared_mem->phy_addr);
	tlogv("shared_mem allocated buffer len   = 0x%08x, %d \n", (int)len, (int)len);

	vma->vm_flags |= VM_USERMAP;
 
	if (remap_pfn_range(vma, vma->vm_start,
		virt_to_phys(addr)>>PAGE_SHIFT, len, vma->vm_page_prot)) {	
		tloge("shared_mem buffer remap failed \n");
		return -EAGAIN;
	}

	vma->vm_flags |= VM_DONTCOPY;
	vma->vm_ops = &g_shared_remap_vm_ops;
	shared_vma_open(vma);
	vma->vm_private_data = (void *)dev_file;

	shared_mem->user_addr = (void *)(uintptr_t)vma->vm_start;
	atomic_set(&shared_mem->offset, vma->vm_pgoff);
	mutex_lock(&dev_file->shared_mem_lock);
	list_add_tail(&shared_mem->head, &dev_file->shared_mem_list);
	mutex_unlock(&dev_file->shared_mem_lock);

	(void)proxy_mmap(filp->private_data, shared_mem->user_addr,
		shared_mem->len, (uint32_t)atomic_read(&shared_mem->offset), false);
	return 0;
}

#define INPUT  0
#define OUTPUT 1
#define INOUT  2

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

static inline bool teec_value_type(unsigned int type, int dir)
{
	return ((is_input_type(dir) && type == TEEC_VALUE_INPUT) ||
		(is_output_type(dir) && type == TEEC_VALUE_OUTPUT) ||
		type == TEEC_VALUE_INOUT) ? true : false;
}

static inline bool teec_tmpmem_type(unsigned int type, int dir)
{
	return ((is_input_type(dir) && type == TEEC_MEMREF_TEMP_INPUT) ||
		(is_output_type(dir) && type == TEEC_MEMREF_TEMP_OUTPUT) ||
		type == TEEC_MEMREF_TEMP_INOUT) ? true : false;
}

static inline bool teec_memref_type(unsigned int type, int dir)
{
	return ((is_input_type(dir) && type == TEEC_MEMREF_PARTIAL_INPUT) ||
		(is_output_type(dir) && type == TEEC_MEMREF_PARTIAL_OUTPUT) ||
		type == TEEC_MEMREF_PARTIAL_INOUT) ? true : false;
}

static long tc_client_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -EFAULT;
	void *argp = (void __user *)(uintptr_t)arg;

	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_SES_OPEN_REQ:
	case TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ:
	case TC_NS_CLIENT_IOCTL_SEND_CMD_REQ:
		ret = tc_client_session_ioctl(file->private_data, cmd, arg);
		break;
	case TC_NS_CLIENT_IOCTL_CANCEL_CMD_REQ:
		/* TZdriver don't support send cancel cmd now */
		ret = tc_ns_send_cancel_cmd(file->private_data, argp);
		break;
	case TC_NS_CLIENT_IOCTL_LOGIN:
		ret = tc_ns_client_login_func(file->private_data, argp);
		break;
	case TC_NS_CLIENT_IOCTL_LOAD_APP_REQ:
		ret = public_ioctl(file, cmd, arg, true);
		break;
	default:
		tlogd(" default\n");
		break;
	}

	tlogd("tc client ioctl ret = 0x%x\n", ret);
	return (long)ret;
}
static int alloc_for_params_sess(struct vtzf_dev_file *dev_file,
	struct_packet_cmd_session *packet_cmd, uintptr_t addrs[][3]);
static void update_free_params_sess(struct tc_ns_client_context *clicontext, 
	struct tc_ns_client_context *context, uintptr_t addrs[4][3]);
static void free_for_params(struct tc_ns_client_context *clicontext,
	uintptr_t addrs[4][3]);
	
static int tc_ns_open_session(struct vtzf_dev_file *dev_file,
	struct tc_ns_client_context *clicontext)
{
	int ret = -EINVAL;
	int i = 0;
	uint32_t offset = 0;
	uint32_t total_buf_size = 0;
	void *cmd_buf = NULL;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_session packet_cmd = {0};
	struct_packet_rsp_session packet_rsp = {0};
	size_t file_size = 0;
	char *buffer = NULL;
	char *tmp_buffer = NULL;
	uintptr_t addrs[4][3];
	if (!clicontext || !dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_OPEN_SESSION;
	packet_cmd.ptzfd = dev_file->ptzfd;
	packet_cmd.cliContext = *clicontext;

	file_size = (size_t)packet_cmd.cliContext.file_size;
	tlogd("file_size = %lu \n", file_size);
	buffer = (char *)alloc_res_shm(file_size);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)buffer)) {
		tloge("vtzf_dev_file malloc failed\n");
		return -ENOMEM;
	}

	tmp_buffer = packet_cmd.cliContext.file_buffer;
	tlogd("buffer addr = %016llx ,tmp_buffer =%016llx \n",
		(unsigned long long)clicontext->file_buffer, (unsigned long long)tmp_buffer);
	packet_cmd.cliContext.file_buffer = (char *)virt_to_phys(buffer);

	if (copy_from_user(buffer, (const void __user *)tmp_buffer, file_size)) {
		tloge("file buf get failed \n");
		ret = -EFAULT;
		goto END;
	}

	ret = alloc_for_params_sess(dev_file, &packet_cmd, addrs);
	if (ret) {
		tloge("alloc for params failed \n");
		return ret;
	}
	for (i = 0;i < TEE_PARAM_NUM; i++) {
		total_buf_size += packet_cmd.block_size[i];
	}
	packet_cmd.fragment_block_num = total_buf_size / sizeof(struct page_block);
	total_buf_size += sizeof(packet_cmd);
	packet_cmd.packet_size = total_buf_size;
	cmd_buf = kzalloc(total_buf_size, GFP_KERNEL);
	if (!cmd_buf) {
		tloge("cmd_buf malloc failed\n");
		ret = -ENOMEM;
		goto err2;
	}

	if (memcpy_s(cmd_buf, sizeof(packet_cmd), &packet_cmd, sizeof(packet_cmd)) != 0) {
		ret = -EFAULT;
		goto err1;
	}	
	offset = sizeof(packet_cmd);

	for (i = 0; i < TEE_PARAM_NUM; i++) {
		if (packet_cmd.block_size[i] != 0 && 
			memcpy_s(cmd_buf + offset, packet_cmd.block_size[i],
				(void *)packet_cmd.block_addrs[i], packet_cmd.block_size[i]) != 0) {
			ret = -EFAULT;
			goto err1;
		}
		offset += packet_cmd.block_size[i];
	}

	ret = send_to_proxy(cmd_buf, total_buf_size, &packet_rsp, sizeof(packet_rsp), seq_num);
	if (!ret) {
		ret = packet_rsp.ret;
		tlogd(" opensession ret =%d \n", ret);
		if (!ret) {
			packet_rsp.cliContext.file_buffer = tmp_buffer;
			update_free_params_sess(&packet_rsp.cliContext, clicontext, addrs);
			*clicontext = packet_rsp.cliContext;
		} else {
			tloge("open session failed ret is %d\n", ret);
			clicontext->returns = packet_rsp.cliContext.returns;
			free_for_params(&packet_cmd.cliContext, addrs);
		}
	} else {
		tloge("send to proxy failed ret is %d\n", ret);
		free_for_params(&packet_cmd.cliContext, addrs);
	}
	kfree(cmd_buf);
	for (i = 0; i < TEE_PARAM_NUM; i++) {
		if (packet_cmd.block_size[i] != 0 && packet_cmd.block_addrs[i]) {
			kfree((void *)packet_cmd.block_addrs[i]);
		}
	}
	dealloc_res_shm(buffer);
	return ret;
err1:
	kfree(cmd_buf);
	for (i = 0; i < TEE_PARAM_NUM; i++) {
		if (packet_cmd.block_size[i] != 0 && packet_cmd.block_addrs[i]) {
			kfree((void *)packet_cmd.block_addrs[i]);
		}
	}	
err2:
	free_for_params(&packet_cmd.cliContext, addrs);
END:
	dealloc_res_shm(buffer);
	return ret;
}

static int tc_ns_close_session(struct vtzf_dev_file *dev_file, void __user *argp)
{
	int ret;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_session packet_cmd = {0};
	struct_packet_rsp_general packet_rsp = {0};
	
	if (!argp || !dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	if (copy_from_user(&packet_cmd.cliContext, argp, sizeof(packet_cmd.cliContext)) != 0) {
		tloge("copy from user failed\n");
		return -ENOMEM;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_CLOSE_SESSION;
	packet_cmd.ptzfd = dev_file->ptzfd;

	ret = send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num);
	if (!ret) {
		ret = packet_rsp.ret;
		if (ret) {
			tloge("close session failed ret is %d\n", ret);
		}
	} else if(ret != -EINTR) {
		tloge("send to proxy failed ret is %d\n", ret);
	}

	return ret;
}

static int alloc_for_tmp_mem(struct tc_ns_client_context *clicontext,
	int index, uintptr_t addrs[][3])
{
	uint32_t buf_size;
	uintptr_t buffer;
	uintptr_t user_buf_size, user_buf;

	user_buf = (uintptr_t)(clicontext->params[index].memref.buffer
			| (uint64_t)clicontext->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);
	user_buf_size = (uintptr_t)(clicontext->params[index].memref.size_addr
			| (uint64_t)clicontext->params[index].memref.size_h_addr << ADDR_TRANS_NUM);

	tlogv("buf_addr %lx, size_addr %lx\n", user_buf, user_buf_size);
	if (copy_from_user(&buf_size, (void *)user_buf_size, sizeof(uint32_t)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	tlogd(" buffer size = %u\n", buf_size);
	buffer = (uintptr_t)alloc_res_shm(buf_size);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)buffer)) {
		tloge("buffer malloc failed\n");
		return -ENOMEM;
	}
	if (copy_from_user((void *)buffer, (void *)user_buf, buf_size) != 0) {
		tloge("copy from user failed\n");
		dealloc_res_shm((void *)buffer);
		return -EFAULT;
	}

	addrs[index][1] = buffer;
	buffer = (uintptr_t)virt_to_phys((void *)buffer);
	clicontext->params[index].memref.buffer = (unsigned int)(uintptr_t)buffer;
	clicontext->params[index].memref.buffer_h_addr = ((unsigned long long)(uintptr_t)buffer) >> ADDR_TRANS_NUM;
	clicontext->params[index].memref.size_addr = buf_size;
	return 0;
}

static int alloc_for_val_mem(struct tc_ns_client_context *clicontext,
	int index, uintptr_t addrs[][3])
{
	uint32_t val_a, val_b;
	uintptr_t user_val_a, user_val_b;

	user_val_a = (uintptr_t)(clicontext->params[index].value.a_addr 
			| (uint64_t)clicontext->params[index].value.a_h_addr << ADDR_TRANS_NUM);
	user_val_b = (uintptr_t)(clicontext->params[index].value.b_addr 
			| (uint64_t)clicontext->params[index].value.b_h_addr << ADDR_TRANS_NUM);
	tlogv("a_val_addr %lx, b_val_addr %lx\n", user_val_a, user_val_b);
	if (copy_from_user(&val_a, (void *)user_val_a, sizeof(uint32_t)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}
	if (copy_from_user(&val_b, (void *)user_val_b, sizeof(uint32_t)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	clicontext->params[index].value.a_addr = val_a;
	clicontext->params[index].value.b_addr = val_b;
	return 0;
}

static int alloc_for_ref_mem(struct vtzf_dev_file *dev_file,
	struct_packet_cmd_send_cmd *packet_cmd, int index, uintptr_t addrs[][3])
{
	uintptr_t user_size_addr;
	struct tc_ns_client_context *clicontext = &packet_cmd->cliContext;
	bool b_found = false;
	struct vtzf_shared_mem *shared_mem = NULL;
	struct vtzf_shared_mem *shared_mem_temp = NULL;
	void *user_buffer = NULL;
	uintptr_t phy_buffer;
	uint32_t buf_size;

	user_size_addr = (uintptr_t)(clicontext->params[index].memref.size_addr 
			| (uint64_t)clicontext->params[index].memref.size_h_addr << ADDR_TRANS_NUM);
	user_buffer = (void *)(clicontext->params[index].memref.buffer
				| (uint64_t)clicontext->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);
	
	tlogv("buf_addr %p, size_addr %lx\n", user_buffer, user_size_addr);
	if (copy_from_user(&buf_size, (void *)user_size_addr, sizeof(uint32_t)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	mutex_lock(&dev_file->shared_mem_lock);
	list_for_each_entry_safe(shared_mem, shared_mem_temp, &dev_file->shared_mem_list, head) {
		if (shared_mem) {
			if (shared_mem->user_addr == user_buffer) {
				tlogv("found the mapped shared_mem for cliContext.params[index].memref.buffer\n");
				phy_buffer = (uintptr_t)shared_mem->phy_addr;
				clicontext->params[index].memref.buffer = 
					(unsigned int)(uintptr_t)phy_buffer;
				clicontext->params[index].memref.buffer_h_addr = 
					((unsigned long long)(uintptr_t)phy_buffer) >> ADDR_TRANS_NUM;

				packet_cmd->addrs[index] = (unsigned long long)user_buffer;
				b_found = true;
				break;
			}
		}
	}
	mutex_unlock(&dev_file->shared_mem_lock);
	if (!b_found) {
		tloge("can't found the mapped shared_mem for cliContext.params[index].memref.buffer \n");
		return -EFAULT;
	}
	clicontext->params[index].memref.size_addr = buf_size;
	return 0;
}

static int alloc_for_ref_mem_sess(struct vtzf_dev_file *dev_file,
	struct_packet_cmd_session *packet_cmd, int index, uintptr_t addrs[][3])
{
	uintptr_t user_size_addr;
	struct tc_ns_client_context *clicontext = &packet_cmd->cliContext;
	bool b_found = false;
	struct vtzf_shared_mem *shared_mem = NULL;
	struct vtzf_shared_mem *shared_mem_temp = NULL;
	void *user_buffer = NULL;
	uintptr_t phy_buffer;
	uint32_t buf_size;

	user_size_addr = (uintptr_t)(clicontext->params[index].memref.size_addr 
			| (uint64_t)clicontext->params[index].memref.size_h_addr << ADDR_TRANS_NUM);
	user_buffer = (void *)(clicontext->params[index].memref.buffer
				| (uint64_t)clicontext->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);

	if (copy_from_user(&buf_size, (void *)user_size_addr, sizeof(uint32_t)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	mutex_lock(&dev_file->shared_mem_lock);
	list_for_each_entry_safe(shared_mem, shared_mem_temp, &dev_file->shared_mem_list, head) {
		if (shared_mem) {
			if (shared_mem->user_addr == user_buffer) {
				tlogv("found the mapped shared_mem for cliContext.params[index].memref.buffer\n");
				phy_buffer = (uintptr_t)shared_mem->phy_addr;
				clicontext->params[index].memref.buffer = 
					(unsigned int)(uintptr_t)phy_buffer;
				clicontext->params[index].memref.buffer_h_addr = 
					((unsigned long long)(uintptr_t)phy_buffer) >> ADDR_TRANS_NUM;

				packet_cmd->addrs[index] = (unsigned long long)user_buffer;
				b_found = true;
				break;
			}
		}
	}
	mutex_unlock(&dev_file->shared_mem_lock);
	if (!b_found) {
		tloge("can't found the mapped shared_mem for cliContext.params[index].memref.buffer \n");
		return -EFAULT;
	}
	clicontext->params[index].memref.size_addr = buf_size;
	return 0;
}

static int check_buffer_for_sharedmem(uint32_t *buffer_size,
	struct_packet_cmd_send_cmd *packet_cmd, int index)
{
	uintptr_t user_size_addr;
	void *user_buffer = NULL;
	struct tc_ns_client_context *clicontext = &packet_cmd->cliContext;
	user_size_addr = (uintptr_t)(clicontext->params[index].memref.size_addr 
			| (uint64_t)clicontext->params[index].memref.size_h_addr << ADDR_TRANS_NUM);
	user_buffer = (void *)(clicontext->params[index].memref.buffer
				| (uint64_t)clicontext->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);

	if (copy_from_user(buffer_size, (void *)user_size_addr, sizeof(uint32_t)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	if (*buffer_size == 0 || *buffer_size > SZ_256M) {
		tloge("invalid buffer size\n");
		return -ENOMEM;
	}

	if ((packet_cmd->cliContext.params[index].memref.offset >= SZ_256M) ||
		(UINT64_MAX - (uint64_t)user_buffer <= packet_cmd->cliContext.params[index].memref.offset)) {
		tloge("invalid buff or offset\n");
		return -EFAULT;
	}
	return 0;
}

static int check_buffer_for_sharedmem_sess(uint32_t *buffer_size,
	struct_packet_cmd_session *packet_cmd, int index)
{
	uintptr_t user_size_addr;
	void *user_buffer = NULL;
	struct tc_ns_client_context *clicontext = &packet_cmd->cliContext;
	user_size_addr = (uintptr_t)(clicontext->params[index].memref.size_addr 
			| (uint64_t)clicontext->params[index].memref.size_h_addr << ADDR_TRANS_NUM);
	user_buffer = (void *)(clicontext->params[index].memref.buffer
				| (uint64_t)clicontext->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);

	if (copy_from_user(buffer_size, (void *)user_size_addr, sizeof(uint32_t)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	if (*buffer_size == 0 || *buffer_size > SZ_256M) {
		tloge("invalid buffer size\n");
		return -ENOMEM;
	}

	if ((packet_cmd->cliContext.params[index].memref.offset >= SZ_256M) ||
		(UINT64_MAX - (uint64_t)user_buffer <= packet_cmd->cliContext.params[index].memref.offset)) {
		tloge("invalid buff or offset\n");
		return -EFAULT;
	}
	return 0;
}

static int alloc_for_share_mem(struct vtzf_dev_file *dev_file,
	struct_packet_cmd_send_cmd *packet_cmd, int index, uintptr_t addrs[][3])
{
	struct tc_ns_client_context *clicontext = &packet_cmd->cliContext;
	void *user_buffer = NULL;
	uint32_t user_buf_size = 0;
	void *block_buf = NULL;
	uint32_t block_buf_size = 0;
	void *pages_buf = NULL;
	uint32_t pages_buf_size = 0;
	int block_count;
	uint32_t offset;

	user_buffer = (void *)(clicontext->params[index].memref.buffer
				| (uint64_t)clicontext->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);
	tlogd(" user_buffer = %p \n", user_buffer);
	if (check_buffer_for_sharedmem(&user_buf_size, packet_cmd, index))
		return -EINVAL;

	tlogd("share mem buf size = %u\n", user_buf_size);
	if (get_page_block(user_buffer, user_buf_size, &block_buf, &block_buf_size, &block_count, &pages_buf, &pages_buf_size) != 0) {
		tloge("get_page_block failed \n");
		return -EFAULT;
	}
	tlogd("alloc for share mem \n");
	tlogd("block_buf = %llx \n", (uint64_t)block_buf);
	tlogd("block_buf_size = %u \n", block_buf_size);
	//dump_page_blocks(block_count, (uint64_t)block_buf);
	addrs[index][1] = (uintptr_t)pages_buf;
	addrs[index][0] = (uintptr_t)pages_buf_size;
	packet_cmd->block_addrs[index] = (uint64_t)block_buf;
	packet_cmd->block_size[index] = block_buf_size;
	packet_cmd->vm_page_size = PAGE_SIZE;
	clicontext->params[index].memref.size_addr = user_buf_size;
	offset = ((uint32_t)(uintptr_t)user_buffer) & (~PAGE_MASK);
	/*memref.h_offset 保存首个PAGE内部的偏移， memref.offset用户buffer的偏移*/
	clicontext->params[index].memref.h_offset = offset;
	tlogd("clicontext->params[index].memref.h_offset = %u, 0x%x\n",
		clicontext->params[index].memref.h_offset, clicontext->params[index].memref.h_offset);
	return 0;
}

static int alloc_for_share_mem_sess(struct vtzf_dev_file *dev_file,
	struct_packet_cmd_session *packet_cmd, int index, uintptr_t addrs[][3])
{
	struct tc_ns_client_context *clicontext = &packet_cmd->cliContext;
	void *user_buffer = NULL;
	uint32_t user_buf_size = 0;
	void *block_buf = NULL;
	uint32_t block_buf_size = 0;
	void *pages_buf = NULL;
	uint32_t pages_buf_size = 0;
	int block_count;
	uint32_t offset;

	user_buffer = (void *)(clicontext->params[index].memref.buffer
				| (uint64_t)clicontext->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);
	tlogd(" user_buffer = %p \n", user_buffer);
	if (check_buffer_for_sharedmem_sess(&user_buf_size, packet_cmd, index))
		return -EINVAL;

	tlogd("share mem buf size = %u\n", user_buf_size);
	if (get_page_block(user_buffer, user_buf_size, &block_buf, &block_buf_size, &block_count, &pages_buf, &pages_buf_size) != 0) {
		tloge("get_page_block failed \n");
		return -EFAULT;
	}
	tlogd("alloc for share mem \n");
	tlogd("block_buf = %llx \n", (uint64_t)block_buf);
	tlogd("block_buf_size = %u \n", block_buf_size);
	//dump_page_blocks(block_count, (uint64_t)block_buf);
	addrs[index][1] = (uintptr_t)pages_buf;
	addrs[index][0] = (uintptr_t)pages_buf_size;
	packet_cmd->block_addrs[index] = (uint64_t)block_buf;
	packet_cmd->block_size[index] = block_buf_size;
	packet_cmd->vm_page_size = PAGE_SIZE;
	clicontext->params[index].memref.size_addr = user_buf_size;
	offset = ((uint32_t)(uintptr_t)user_buffer) & (~PAGE_MASK);
	/*memref.h_offset 保存首个PAGE内部的偏移， memref.offset用户buffer的偏移*/
	clicontext->params[index].memref.h_offset = offset;
	tlogd("clicontext->params[index].memref.h_offset = %u, 0x%x\n",
		clicontext->params[index].memref.h_offset, clicontext->params[index].memref.h_offset);
	return 0;
}

static int alloc_for_params(struct vtzf_dev_file *dev_file,
	struct_packet_cmd_send_cmd *packet_cmd, uintptr_t addrs[][3])
{
	int ret;
	int index;
	uint32_t param_type;
	bool checkValue;
	for (index = 0; index < TEE_PARAM_NUM; index++) {
		param_type = teec_param_type_get(packet_cmd->cliContext.param_types, index);
		checkValue = (param_type == TEEC_ION_INPUT || param_type == TEEC_ION_SGLIST_INPUT);
		tlogd("param %u type is %x\n", index, param_type);
		if (teec_tmpmem_type(param_type, INOUT))
			ret = alloc_for_tmp_mem(&packet_cmd->cliContext, index, addrs);
		else if (teec_memref_type(param_type, INOUT))
			ret = alloc_for_ref_mem(dev_file , packet_cmd, index, addrs);
		else if (teec_value_type(param_type, INOUT) || checkValue)
			ret = alloc_for_val_mem(&packet_cmd->cliContext, index, addrs);
		else if (param_type == TEEC_MEMREF_SHARED_INOUT || 
					param_type == TEEC_MEMREF_REGISTER_INOUT)
			ret = alloc_for_share_mem(dev_file , packet_cmd, index, addrs);
		else
			tlogd("param type = TEEC_NONE\n");
		if (ret != 0) {
			goto ERR;
		}
	}

	return 0;
ERR:
	return ret;

}

static int alloc_for_params_sess(struct vtzf_dev_file *dev_file,
	struct_packet_cmd_session *packet_cmd, uintptr_t addrs[][3])
{
	int ret;
	int index;
	uint32_t param_type;
	bool checkValue;
	for (index = 0; index < TEE_PARAM_NUM; index++) {
		param_type = teec_param_type_get(packet_cmd->cliContext.param_types, index);
		checkValue = (param_type == TEEC_ION_INPUT || param_type == TEEC_ION_SGLIST_INPUT);
		tlogd("param %u type is %x\n", index, param_type);
		if (teec_tmpmem_type(param_type, INOUT))
			ret = alloc_for_tmp_mem(&packet_cmd->cliContext, index, addrs);
		else if (teec_memref_type(param_type, INOUT))
			ret = alloc_for_ref_mem_sess(dev_file , packet_cmd, index, addrs);
		else if (teec_value_type(param_type, INOUT) || checkValue)
			ret = alloc_for_val_mem(&packet_cmd->cliContext, index, addrs);
		else if (param_type == TEEC_MEMREF_SHARED_INOUT || 
					param_type == TEEC_MEMREF_REGISTER_INOUT)
			ret = alloc_for_share_mem_sess(dev_file , packet_cmd, index, addrs);
		else
			tlogd("param type = TEEC_NONE\n");
		if (ret != 0) {
			goto ERR;
		}
	}

	return 0;
ERR:
	return ret;

}

static void update_free_params(struct tc_ns_client_context *clicontext, 
	struct tc_ns_client_context *context, uintptr_t addrs[4][3])
{
	int ret = 0;
	int index;
	uint32_t param_type;
	bool checkValue;
	uintptr_t buf;
	uintptr_t user_addr_size, user_addr_buf;
	uintptr_t user_addr_val_a, user_addr_val_b;
	uint32_t buf_size;
	uint32_t val_a, val_b;
	void *pages_buf = NULL;
	uint32_t pages_buf_size = 0;
	for (index = 0; index < TEE_PARAM_NUM; index++) {
		param_type = teec_param_type_get(clicontext->param_types, index);
		checkValue = (param_type == TEEC_ION_INPUT || param_type == TEEC_ION_SGLIST_INPUT);
		if (teec_tmpmem_type(param_type, INOUT)) {
			buf_size = clicontext->params[index].memref.size_addr;
			buf = addrs[index][1];

			user_addr_size = (uintptr_t)(context->params[index].memref.size_addr 
				| (uint64_t)context->params[index].memref.size_h_addr << ADDR_TRANS_NUM);
			user_addr_buf = (uintptr_t)(context->params[index].memref.buffer 
				| (uint64_t)context->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);

			if (copy_to_user((void *)user_addr_size, &buf_size, sizeof(uint32_t)) != 0)
				ret = -EFAULT;
			if (copy_to_user((void *)user_addr_buf, (void *)buf, buf_size) != 0)
				ret = -EFAULT;
			dealloc_res_shm((void *)buf);

		} else if(teec_memref_type(param_type, INOUT)) {
			buf_size = clicontext->params[index].memref.size_addr;

			user_addr_size = (uintptr_t)(context->params[index].memref.size_addr 
				| (uint64_t)context->params[index].memref.size_h_addr << ADDR_TRANS_NUM);
			if (copy_to_user((void *)user_addr_size, &buf_size, sizeof(uint32_t)) != 0)
				ret = -EFAULT;
		} else if(teec_value_type(param_type, INOUT) || checkValue) {
			val_a = clicontext->params[index].value.a_addr;
			val_b = clicontext->params[index].value.b_addr;

			user_addr_val_a = (uintptr_t)(context->params[index].value.a_addr 
				| (uint64_t)context->params[index].value.a_h_addr << ADDR_TRANS_NUM);
			user_addr_val_b = (uintptr_t)(context->params[index].value.b_addr 
				| (uint64_t)context->params[index].value.b_h_addr << ADDR_TRANS_NUM);

			if (copy_to_user((void *)user_addr_val_a, &val_a, sizeof(uint32_t)) != 0)
				ret = -EFAULT;
			if (copy_to_user((void *)user_addr_val_b, &val_b, sizeof(uint32_t)) != 0)
				ret = -EFAULT;
		} else if (param_type == TEEC_MEMREF_SHARED_INOUT || 
					param_type == TEEC_MEMREF_REGISTER_INOUT){
			pages_buf = (void *)addrs[index][1];
			pages_buf_size = (uint32_t)addrs[index][0];
			release_shared_mem_page((uint64_t)pages_buf, pages_buf_size);
		} else {
			/* nothing */
		}

		if (ret) {
			tloge(" ret =%d \n", ret);
		}
	}	
}

static void update_free_params_sess(struct tc_ns_client_context *clicontext, 
	struct tc_ns_client_context *context, uintptr_t addrs[4][3])
{
	int ret = 0;
	int index;
	uint32_t param_type;
	bool checkValue;
	uintptr_t buf;
	uintptr_t user_addr_size, user_addr_buf;
	uintptr_t user_addr_val_a, user_addr_val_b;
	uint32_t buf_size;
	uint32_t val_a, val_b;
	void *pages_buf = NULL;
	uint32_t pages_buf_size = 0;
	for (index = 0; index < 2; index++) {
		param_type = teec_param_type_get(clicontext->param_types, index);
		checkValue = (param_type == TEEC_ION_INPUT || param_type == TEEC_ION_SGLIST_INPUT);
		if (teec_tmpmem_type(param_type, INOUT)) {
			buf_size = clicontext->params[index].memref.size_addr;
			buf = addrs[index][1];

			user_addr_size = (uintptr_t)(context->params[index].memref.size_addr 
				| (uint64_t)context->params[index].memref.size_h_addr << ADDR_TRANS_NUM);
			user_addr_buf = (uintptr_t)(context->params[index].memref.buffer 
				| (uint64_t)context->params[index].memref.buffer_h_addr << ADDR_TRANS_NUM);

			if (copy_to_user((void *)user_addr_size, &buf_size, sizeof(uint32_t)) != 0)
				ret = -EFAULT;
			if (copy_to_user((void *)user_addr_buf, (void *)buf, buf_size) != 0)
				ret = -EFAULT;
			dealloc_res_shm((void *)buf);

		} else if(teec_memref_type(param_type, INOUT)) {
			buf_size = clicontext->params[index].memref.size_addr;

			user_addr_size = (uintptr_t)(context->params[index].memref.size_addr 
				| (uint64_t)context->params[index].memref.size_h_addr << ADDR_TRANS_NUM);
			if (copy_to_user((void *)user_addr_size, &buf_size, sizeof(uint32_t)) != 0)
				ret = -EFAULT;
		} else if(teec_value_type(param_type, INOUT) || checkValue) {
			val_a = clicontext->params[index].value.a_addr;
			val_b = clicontext->params[index].value.b_addr;

			user_addr_val_a = (uintptr_t)(context->params[index].value.a_addr 
				| (uint64_t)context->params[index].value.a_h_addr << ADDR_TRANS_NUM);
			user_addr_val_b = (uintptr_t)(context->params[index].value.b_addr 
				| (uint64_t)context->params[index].value.b_h_addr << ADDR_TRANS_NUM);

			if (copy_to_user((void *)user_addr_val_a, &val_a, sizeof(uint32_t)) != 0)
				ret = -EFAULT;
			if (copy_to_user((void *)user_addr_val_b, &val_b, sizeof(uint32_t)) != 0)
				ret = -EFAULT;
		} else if (param_type == TEEC_MEMREF_SHARED_INOUT || 
					param_type == TEEC_MEMREF_REGISTER_INOUT){
			pages_buf = (void *)addrs[index][1];
			pages_buf_size = (uint32_t)addrs[index][0];
			release_shared_mem_page((uint64_t)pages_buf, pages_buf_size);
		} else {
			/* nothing */
		}

		if (ret) {
			tloge(" ret =%d \n", ret);
		}
	}	
}

static void free_for_params(struct tc_ns_client_context *clicontext,
	uintptr_t addrs[4][3])
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

static int tc_ns_send_cmd(struct vtzf_dev_file *dev_file,
	struct tc_ns_client_context *context)
{
	int ret = -EINVAL;
	int i = 0;
	uint32_t offset = 0;
	uint32_t total_buf_size = 0;
	void *cmd_buf = NULL;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_send_cmd packet_cmd = {0};
	struct_packet_rsp_send_cmd packet_rsp = {0};
	uintptr_t addrs[4][3];
	if (!dev_file || !context || dev_file->ptzfd <= 0) {
		tloge("invalid dev_file or context\n");
		return -EINVAL;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_SEND_CMD;
	packet_cmd.ptzfd = dev_file->ptzfd;
	packet_cmd.cliContext = *context;

	ret = alloc_for_params(dev_file, &packet_cmd, addrs);
	if (ret) {
		tloge("alloc for params failed \n");
		return ret;
	}
	for (i = 0;i < TEE_PARAM_NUM; i++) {
		total_buf_size += packet_cmd.block_size[i];
	}
	packet_cmd.fragment_block_num = total_buf_size / sizeof(struct page_block);
	total_buf_size += sizeof(packet_cmd);
	packet_cmd.packet_size = total_buf_size;
	cmd_buf = kzalloc(total_buf_size, GFP_KERNEL);
	if (!cmd_buf) {
		tloge("cmd_buf malloc failed\n");
		ret = -ENOMEM;
		goto err2;
	}

	if (memcpy_s(cmd_buf, sizeof(packet_cmd), &packet_cmd, sizeof(packet_cmd)) != 0) {
		ret = -EFAULT;
		goto err1;
	}	
	offset = sizeof(packet_cmd);

	for (i = 0; i < TEE_PARAM_NUM; i++) {
		if (packet_cmd.block_size[i] != 0 && 
			memcpy_s(cmd_buf + offset, packet_cmd.block_size[i],
				(void *)packet_cmd.block_addrs[i], packet_cmd.block_size[i]) != 0) {
			ret = -EFAULT;
			goto err1;
		}
		offset += packet_cmd.block_size[i];
	}

	ret = send_to_proxy(cmd_buf, total_buf_size, &packet_rsp, sizeof(packet_rsp), seq_num);
	if (!ret) {
		ret = packet_rsp.ret;
		if (ret) {
			tloge("invoke cmd failed ret is %d\n", ret);
			context->returns = packet_rsp.cliContext.returns;
			free_for_params(&packet_cmd.cliContext, addrs);
		} else {
			context->returns = packet_rsp.cliContext.returns;
			update_free_params(&packet_rsp.cliContext, context, addrs);
		}
	} else {
		tloge("send to proxy failed ret is %d\n", ret);
		free_for_params(&packet_cmd.cliContext, addrs);
	}

	kfree(cmd_buf);
	for (i = 0; i < TEE_PARAM_NUM; i++) {
		if (packet_cmd.block_size[i] != 0 && packet_cmd.block_addrs[i]) {
			kfree((void *)packet_cmd.block_addrs[i]);
		}
	}
	return ret;
err1:
	kfree(cmd_buf);
	for (i = 0; i < TEE_PARAM_NUM; i++) {
		if (packet_cmd.block_size[i] != 0 && packet_cmd.block_addrs[i]) {
			kfree((void *)packet_cmd.block_addrs[i]);
		}
	}	
err2:
	free_for_params(&packet_cmd.cliContext, addrs);
	return ret;
}

static int ioctl_session_send_cmd(struct vtzf_dev_file *dev_file,
	struct tc_ns_client_context *context, void *argp)
{
	int ret;
	ret = tc_ns_send_cmd(dev_file, context);
	if (ret != 0)
		tloge("send cmd failed ret is %d\n", ret);
	if (copy_to_user(argp, context, sizeof(*context)) != 0) {
		if (ret == 0)
			ret = -EFAULT;
	}
	return ret;
}

int tc_client_session_ioctl(struct vtzf_dev_file *dev_file, unsigned int cmd,
	unsigned long arg)
{
	int ret = -EINVAL;
	void *argp = (void __user *)(uintptr_t)arg;
	struct tc_ns_client_context context;

	if (!argp || !dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}
	if (copy_from_user(&context, argp, sizeof(context)) != 0) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_SES_OPEN_REQ:
		ret = tc_ns_open_session(dev_file, &context);
		if (copy_to_user(argp, &context, sizeof(context)) != 0 && ret == 0)
			ret = -EFAULT;
		break;
	case TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ:
		ret = tc_ns_close_session(dev_file, argp);
		break;
	case TC_NS_CLIENT_IOCTL_SEND_CMD_REQ:
		ret = ioctl_session_send_cmd(dev_file, &context, argp);
		break;
	default:
		tloge("invalid cmd:0x%x!\n", cmd);
		return ret;
	}

	return ret;
}

static int tc_ns_send_cancel_cmd(struct vtzf_dev_file *dev_file, void *argp)
{
	int ret;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_cancel_cmd packet_cmd = {0};
	struct_packet_rsp_cancel_cmd packet_rsp = {0};

	if (!argp || !dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_CANCEL_CMD;
	packet_cmd.ptzfd = dev_file->ptzfd;

	if (copy_from_user(&packet_cmd.cliContext, argp, sizeof(packet_cmd.cliContext)) != 0) {
		tloge("copy from user failed\n");
		return -ENOMEM;
	}
	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
		goto END;
	} else {
		ret = packet_rsp.ret;
		if (!ret && copy_to_user(argp, &packet_rsp.cliContext, sizeof(packet_rsp.cliContext)) != 0)
			ret = -EFAULT;
	}

END:
	return ret;
}

static int tc_ns_client_login_func(struct vtzf_dev_file *dev_file,
	const void __user *buffer)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	uint32_t total_size = 0;
	struct_packet_cmd_login_non packet_cmd_non = {0};
	struct_packet_rsp_login packet_rsp = {0};
	struct_packet_cmd_login *packet_cmd = NULL;

	if (!dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	if (!buffer) {
		packet_cmd_non.packet_size = sizeof(packet_cmd_non);
		packet_cmd_non.seq_num = seq_num;
		packet_cmd_non.cmd = VTZF_LOG_IN_NHIDL;
		packet_cmd_non.ptzfd = dev_file->ptzfd;
		if (send_to_proxy(&packet_cmd_non, sizeof(packet_cmd_non), &packet_rsp, sizeof(packet_rsp), seq_num)) {
			ret = -EFAULT;
			goto END;
		}
		ret = packet_rsp.ret;
		goto END;
	}
	total_size = sizeof(*packet_cmd) + CERT_BUF_MAX_SIZE;
	packet_cmd = kzalloc(total_size, GFP_KERNEL);
	if (!packet_cmd)
		goto END;

	packet_cmd->packet_size = total_size;
	packet_cmd->seq_num = seq_num;
	packet_cmd->cmd = VTZF_LOG_IN;
	packet_cmd->ptzfd = dev_file->ptzfd;

	if (copy_from_user(packet_cmd->cert_buffer, buffer, CERT_BUF_MAX_SIZE) != 0) {
		tloge("copy from user failed\n");
		ret = -EFAULT;
		goto END;
	}
	if (send_to_proxy(packet_cmd, total_size, &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
		goto END;
	} else {
		ret = packet_rsp.ret;
	}

END:
	if (packet_cmd)
		kfree(packet_cmd);
	return ret;
}

static int tc_ns_get_tee_version(struct vtzf_dev_file *dev_file, void __user *argp)
{
	int ret;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_getteever packet_cmd = {0};
	struct_packet_rsp_getteever packet_rsp = {0};

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = VTZF_GET_TEE_VERSION;
	packet_cmd.seq_num = seq_num;
	packet_cmd.ptzfd = dev_file->ptzfd;

	/* There is no ptzfd, the TZdriver is opened and close immediately after use. */
	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
		goto END;
	} else {
		ret = packet_rsp.ret;
		if (!ret && copy_to_user(argp, &packet_rsp.tee_ver, sizeof(uint32_t)) != 0)
			ret = -EFAULT;
	}
END:
	return ret;
}

static int tc_ns_late_init(unsigned long arg)
{
	int ret;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_lateinit packet_cmd = {0};
	struct_packet_rsp_lateinit packet_rsp = {0};

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = VTZF_LATE_INIT;
	packet_cmd.seq_num = seq_num;
	packet_cmd.index = (uint32_t)arg;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
		goto END;
	} else {
		ret = packet_rsp.ret;
	}

END:
	return ret;
}

static int sync_system_time_from_user(struct vtzf_dev_file *dev_file, 
	const struct tc_ns_client_time *user_time)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_synctime packet_cmd = {0};
	struct_packet_rsp_synctime packet_rsp ={0};
	struct tc_ns_client_time time = {0};

	if (!user_time) {
		tloge("user time is NULL input buffer\n");
		return -EINVAL;
	}

	if (copy_from_user(&packet_cmd.tcNsTime, user_time, sizeof(time))) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = VTZF_SYNC_TIME;
	packet_cmd.seq_num = seq_num;
	packet_cmd.ptzfd = dev_file->ptzfd;

	/* There is no ptzfd, the TZdriver is opened and close immediately after use */
	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
		goto END;
	} else {
		ret = packet_rsp.ret;
	}
END:
	return ret;
}

static bool is_valid_agent(unsigned int buffer_size)
{
	if (buffer_size > SZ_512K) {
		tloge("size: %u of user agent's shared mem is invalid\n", buffer_size);
		return false;
	}
	return true;
}

static unsigned long agent_buffer_map(unsigned long phy_buffer, uint32_t size)
{
	struct vm_area_struct *vma = NULL;
	unsigned long user_addr;
	int ret;

	user_addr = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, 0);
	if (IS_ERR_VALUE((uintptr_t)user_addr)) {
		tloge("vm mmap failed\n");
		return user_addr;
	}

	down_read(&mm_sem_lock(current->mm));
	vma = find_vma(current->mm, user_addr);
	if (!vma) {
		tloge("user_addr is not valid in vma");
		goto err_out;
	}

	ret = remap_pfn_range(vma, user_addr, phy_buffer >> PAGE_SHIFT, size,
		vma->vm_page_prot);
	if (ret != 0) {
		tloge("remap agent buffer failed, err=%d", ret);
		goto err_out;
	}

	up_read(&mm_sem_lock(current->mm));
	return user_addr;
err_out:
	up_read(&mm_sem_lock(current->mm));
	if (vm_munmap(user_addr, size))
		tloge("munmap failed\n");
	return 0;
}

static int get_agent_buf(struct vtzf_dev_file *dev_file, struct vtzf_shared_mem *shared_mem,
	struct_packet_cmd_regagent *packet_cmd, void **bufferp, void **user_addrp, uint32_t agentid)
{
	size_t size = 0;
	void *buffer = NULL;
	void *user_addr = NULL;

	if (!dev_file || !packet_cmd)
		return -EINVAL;

	size = (size_t)packet_cmd->args.buffer_size;
	size = ALIGN(size, 1 << PAGE_SHIFT);
	buffer = kzalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	user_addr = (void *)agent_buffer_map(virt_to_phys(buffer), size);
	if (!user_addr) {
		return -ENOMEM;
	}
	shared_mem->kernel_addr = buffer;
	shared_mem->user_addr = user_addr;
	shared_mem->len = size;
	mutex_lock(&dev_file->shared_mem_lock);

	list_add_tail(&shared_mem->head, &dev_file->shared_mem_list);
	mutex_unlock(&dev_file->shared_mem_lock);
	*bufferp = buffer;
	*user_addrp = user_addr;
	return 0;
}

static int ioctl_register_agent(struct vtzf_dev_file *dev_file, void __user *argp)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_regagent packet_cmd = {0};
	struct_packet_rsp_regagent packet_rsp = {0};
	struct vtzf_shared_mem *shared_mem = NULL;
	void *buffer = NULL;
	void *user_addr = NULL;

	if (!argp || !dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}
	if (copy_from_user(&packet_cmd.args, (void *)(uintptr_t)argp, sizeof(packet_cmd.args)) != 0) {
		tloge("copy agent args failed\n");
		return -EFAULT;
	}
	if (!is_valid_agent(packet_cmd.args.buffer_size)) {
		return -EINVAL;
	}

	shared_mem = kzalloc(sizeof(*shared_mem), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)shared_mem)) {
		tloge("shared_mem malloc failed\n");
		return -ENOMEM;
	}

	if (get_agent_buf(dev_file, shared_mem, &packet_cmd, &buffer, &user_addr, packet_cmd.args.id)) {
		kfree(shared_mem);
		return -1;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = VTZ_REGISTER_AGENT;
	packet_cmd.seq_num = seq_num;
	packet_cmd.ptzfd = dev_file->ptzfd;
	packet_cmd.phyaddr = (void *)virt_to_phys(buffer);

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
		goto END;
	} else {
		ret = packet_rsp.ret;
		if (!ret) {
			shared_mem->user_addr_host = packet_rsp.args.buffer;
			packet_rsp.args.buffer = user_addr;
			if (copy_to_user(argp, &packet_rsp.args, sizeof(packet_rsp.args)) != 0) {
				tloge("copy to user failed\n");
				ret = -EFAULT;
			}
			dev_file->buf = (void *)shared_mem;
		} else{
			mutex_lock(&dev_file->shared_mem_lock);
			list_del(&shared_mem->head);
			mutex_unlock(&dev_file->shared_mem_lock);
			if (shared_mem->kernel_addr)
				kfree(shared_mem->kernel_addr);
			kfree(shared_mem);
			dev_file->buf = NULL;
		}
		tlogd("packet_rsp.ret = %d \n", packet_rsp.ret);
	}

END:
	return ret;
}

static int tc_ns_unregister_agent(struct vtzf_dev_file * dev_file, unsigned int agent_id)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct vtzf_shared_mem *shared_mem = NULL;
	struct_packet_cmd_unregagent packet_cmd = {0};
	struct_packet_rsp_unregagent packet_rsp = {0};

	if (!agent_id || !dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = VTZ_UNREGISTER_AGENT;
	packet_cmd.seq_num = seq_num;
	packet_cmd.ptzfd = dev_file->ptzfd;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
	}

	if (dev_file->buf) {
		shared_mem = (struct vtzf_shared_mem *)dev_file->buf;
		mutex_lock(&dev_file->shared_mem_lock);
		list_del(&shared_mem->head);
		mutex_unlock(&dev_file->shared_mem_lock);
		if (shared_mem->kernel_addr)
			kfree(shared_mem->kernel_addr);
		kfree(shared_mem);
		dev_file->buf = NULL;
	}

	return ret;
}

static int send_wait_event(struct vtzf_dev_file *dev_file, unsigned int agent_id)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(agent_id);
	struct_packet_cmd_event packet_cmd = {0};
	struct_packet_rsp_general packet_rsp = {0};
	if (!dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = VTZF_WAIT_EVENT;
	packet_cmd.seq_num = seq_num;
	packet_cmd.ptzfd = dev_file->ptzfd;
	packet_cmd.agent_id = agent_id;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		tloge("sen to proxy failed\n");
		return -EFAULT;
	} else {
		ret = packet_rsp.ret;
	}
	return ret;
}

static int send_event_response(struct vtzf_dev_file *dev_file, unsigned int agent_id)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_event packet_cmd = {0};
	struct_packet_rsp_general packet_rsp = {0};
	if (!dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = VTZF_SEND_EVENT_RESPONSE;
	packet_cmd.seq_num = seq_num;
	packet_cmd.ptzfd = dev_file->ptzfd;
	packet_cmd.agent_id = agent_id;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		tloge("sen to proxy failed\n");
		return -EFAULT;
	} else {
		ret = packet_rsp.ret;
	}
	return ret;
}

static int tc_ns_load_secfile(struct vtzf_dev_file *dev_file,
	struct load_secfile_ioctl_struct *ioctlArg)
{
	int ret;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_load_sec packet_cmd = {0};
	struct_packet_rsp_load_sec packet_rsp = {0};
	size_t file_size = 0;
	char *buffer = NULL;
	char *tmp_buffer = NULL;

	if (!ioctlArg || !dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.ioctlArg = *ioctlArg;
	file_size = (size_t)packet_cmd.ioctlArg.sec_file_info.file_size;
	tlogd("file_size = %lu \n", file_size);

	buffer = (char *)alloc_res_shm(file_size);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)buffer)) {
		tloge("vtzf_dev_file malloc failed\n");
		return -ENOMEM;
	}
	tmp_buffer = packet_cmd.ioctlArg.file_buffer;

	if (copy_from_user(buffer, (const void __user *)tmp_buffer, file_size)) {
		tloge("file buf get failed \n");
		ret = -EFAULT;
		goto END;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_LOAD_SEC;
	packet_cmd.ptzfd = dev_file->ptzfd;
	packet_cmd.ioctlArg.file_buffer = (char *)virt_to_phys(buffer);

	ret = send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num);
	if (!ret) {
		ret = packet_rsp.ret;
		if (!ret) {
			packet_rsp.ioctlArg.file_buffer = tmp_buffer;
			*ioctlArg = packet_rsp.ioctlArg;
		} else {
			tloge("load_secfile failed ret is %d\n", ret);
		}
	} else {
		tloge("send to proxy failed ret is %d\n", ret);
	}
END:
	dealloc_res_shm((void *)buffer);
	return ret;
}

static int ioctl_check_is_ccos(void __user *argp)
{
	int ret = 0;
	unsigned int check_ccos = 1;
	if (!argp) {
		tloge("error input parameter\n");
		return -EINVAL;
	}
	if (copy_to_user(argp, &check_ccos, sizeof(unsigned int)) != 0)
		ret = -EFAULT;
	return ret;
}

int public_ioctl(const struct file *file, unsigned int cmd,
	unsigned long arg, bool is_from_client_node)
{
	int ret = -EINVAL;
	void *argp = (void __user *)(uintptr_t)arg;
	struct vtzf_dev_file *dev_file = NULL;
	struct load_secfile_ioctl_struct ioctlArg;
	dev_file = file->private_data;
	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_WAIT_EVENT:
		ret = send_wait_event(dev_file, (unsigned int)arg);
		break;
	case TC_NS_CLIENT_IOCTL_SEND_EVENT_RESPONSE:
		ret = send_event_response(dev_file, (unsigned int)arg);
		break;
	case TC_NS_CLIENT_IOCTL_REGISTER_AGENT:
		ret = ioctl_register_agent(dev_file, (void *)arg);
		break;
	case TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT:
		ret = tc_ns_unregister_agent(dev_file, (unsigned int)arg);
		break;
	case TC_NS_CLIENT_IOCTL_LOAD_APP_REQ:
		if (copy_from_user(&ioctlArg, argp, sizeof(ioctlArg)) != 0) {
			tloge("copy from user failed\n");
			return -EFAULT;
		}
		ret = tc_ns_load_secfile(file->private_data, &ioctlArg);
		if (copy_to_user(argp, &ioctlArg, sizeof(ioctlArg)) != 0 && ret == 0)
			ret = -EFAULT;
		break;
	case TC_NS_CLIENT_IOCTL_CHECK_CCOS:
		ret = ioctl_check_is_ccos(argp);
		break;
	default:
		tloge("invalid cmd!");
		return ret;
	}
	return ret;
}

static long tc_private_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	int ret = -EFAULT;
	void *argp = (void __user *)(uintptr_t)arg;
	struct vtzf_dev_file *dev_file = file->private_data;
	if (!dev_file) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_GET_TEE_VERSION:
		ret = tc_ns_get_tee_version(file->private_data, argp);
		break;
	case TC_NS_CLIENT_IOCTL_GET_TEE_INFO:
		ret = tc_ns_get_tee_info(dev_file->ptzfd, argp, false);
		break;
	case TC_NS_CLIENT_IOCTL_SET_NATIVECA_IDENTITY:
		break;
	case TC_NS_CLIENT_IOCTL_LATEINIT:
		ret = tc_ns_late_init(arg);
		break;
	case TC_NS_CLIENT_IOCTL_SYC_SYS_TIME:
		ret = sync_system_time_from_user(file->private_data, (struct tc_ns_client_time *)(uintptr_t)arg);
		break;
	default:
		ret = public_ioctl(file, cmd, arg, false);
		break;
	}

	return ret;
}

static long tc_cvm_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	int ret = -EFAULT;
	void *argp = (void __user *)(uintptr_t)arg;
	struct vtzf_dev_file *dev_file = file->private_data;
	if (!dev_file) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_GET_TEE_INFO:
		ret = tc_ns_get_tee_info(dev_file->ptzfd, argp, false);
		break;

#ifdef CONFIG_TEE_TELEPORT_SUPPORT
	case TC_NS_CLIENT_IOCTL_PORTAL_REGISTER:
		if (check_tee_teleport_auth() == 0)
			ret = tee_portal_register(file->private_data, argp);
		else
			tloge("check tee_teleport path failed\n");
		break;
	case TC_NS_CLIENT_IOCTL_PORTAL_WORK:
		if (check_tee_teleport_auth() == 0)
			ret = tee_portal_work(file->private_data);
		else
			tloge("check tee_teleport path failed\n");
		break;
#endif
	default:
		ret = public_ioctl(file, cmd, arg, false);
		break;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
long tc_compat_client_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	long ret;

	if (!file)
		return -EINVAL;

	ret = tc_client_ioctl(file, cmd, (unsigned long)(uintptr_t)compat_ptr(arg));
	return ret;
}

long tc_compat_private_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	long ret;

	if (!file)
		return -EINVAL;

	ret = tc_private_ioctl(file, cmd, (unsigned long)(uintptr_t)compat_ptr(arg));
	return ret;
}

long tc_compat_cvm_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	long ret;

	if (!file)
		return -EINVAL;

	ret = tc_cvm_ioctl(file, cmd, (unsigned long)(uintptr_t)compat_ptr(arg));
	return ret;
}

#endif

MODULE_DESCRIPTION("virtual trustzone frontend driver");
MODULE_VERSION("1.00");
MODULE_AUTHOR("TrustCute");

module_init(vtzf_init);
module_exit(vtzf_exit);

MODULE_LICENSE("GPL");