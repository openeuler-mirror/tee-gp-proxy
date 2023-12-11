#include <linux/version.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <securec.h>
#include "serialport.h"
#include "comm_structs.h"
#include "process_data.h"
#include "block_pages.h"
#include "tc_ns_log.h"
#include "tlogger.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0)   
#include <linux/timekeeping.h>
struct timespec64 start, end;
#else
#include <linux/time.h>
struct timeval start, end;
#endif

#define SEQ_NUM_AGENT_MAX 65536u
extern int g_log_ret_flag;
extern wait_queue_head_t g_log_wait_event_wq;
uint32_t g_seq_num_normal;
uint32_t g_seq_num_fs_agent;
uint32_t g_seq_num_sec_agent;
uint32_t g_seq_num_misc_agent;
struct mutex g_seq_lock;
struct vtzf_serial_port_list g_serial_port_list;
struct vtzf_event_data_list g_event_data_list;
struct vtzf_wr_data_list g_wr_data_list;
int g_destroy_rd_thread = 0;
int g_destroy_wr_thread = 0;
struct vtzf_serial_port_file *g_serial_port_file;

void dump_time(void)
{
	uint32_t cost = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0)
	cost = (1000000 * end.tv_sec + end.tv_nsec/1000) - (1000000 * start.tv_sec + start.tv_nsec/1000);
#else
	cost = (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);
#endif
	tlogi("time cost = %u us\n", cost);
}

uint32_t get_seq_num(int agent_id)
{
	uint32_t ret;
	if (agent_id == AGENT_FS_ID) {
		return 10;
	} else if (agent_id == SECFILE_LOAD_AGENT_ID) {
		return 20;
	} else if (agent_id ==AGENT_MISC_ID) {
		return 30;
	}
	mutex_lock(&g_seq_lock);
	g_seq_num_normal = (g_seq_num_normal + 2u) % 0xfffffff0;
	if (g_seq_num_normal < SEQ_NUM_AGENT_MAX)
		g_seq_num_normal = SEQ_NUM_AGENT_MAX;
	ret = g_seq_num_normal;
	mutex_unlock(&g_seq_lock);
	return ret;
}

void seq_num_init(void)
{
	mutex_init(&g_seq_lock);
	g_seq_num_normal = SEQ_NUM_AGENT_MAX;
	g_seq_num_fs_agent = 10;
	g_seq_num_sec_agent = 20;
	g_seq_num_misc_agent = 30;
}

struct vtzf_serial_port_list *get_serial_port_list(void)
{
	return &g_serial_port_list;
}

static inline void rd_increment(struct vtzf_serial_port_file *file) {
	if (!file)
		return;
	mutex_lock(&file->rd_flag_lock);
	file->rd_flag += 1;
	tlogd("increment rd wait flag = %d \n", file->rd_flag);
	mutex_unlock(&file->rd_flag_lock);
}

static inline void rd_decrement(struct vtzf_serial_port_file *file) {
	if (!file)
		return;
	mutex_lock(&file->rd_flag_lock);
	file->rd_flag -= 1 ;
	if (file->rd_flag < 0)
		file->rd_flag = 0;
	tlogd("decrement rd wait flag = %d \n", file->rd_flag);
	mutex_unlock(&file->rd_flag_lock);
}

static inline void wr_increment(struct vtzf_serial_port_file *file) {
	if (!file)
		return;
	mutex_lock(&file->wr_flag_lock);
	file->wr_flag += 1;
	tlogd("increment wr wait flag = %d \n", file->wr_flag);
	mutex_unlock(&file->wr_flag_lock);
}

static inline void wr_decrement(struct vtzf_serial_port_file *file) {
	if (!file)
		return;
	mutex_lock(&file->wr_flag_lock);
	file->wr_flag -= 1 ;
	if (file->wr_flag < 0)
		file->wr_flag = 0;
	tlogd("decrement wr wait flag = %d \n", file->wr_flag);
	mutex_unlock(&file->wr_flag_lock);
}

static void wake_tlog_thrd(void)
{
	struct vhc_event_data *event_data;
	struct vhc_event_data *tmp;
	spin_lock(&g_event_data_list.spinlock);
	list_for_each_entry_safe(event_data, tmp, &g_event_data_list.head, head) {
		if (event_data->seq_num == 41) {
			event_data->rd_ret = -EAGAIN;
			event_data->ret_flag = 1;
			tlogi("wake event\n");
			wake_up(&event_data->wait_event_wq);
			break;
		}
	}
	spin_unlock(&g_event_data_list.spinlock);
}

static inline void wake_up_log_thread(void)
{
	struct vtzf_serial_port_file *file = g_serial_port_file;
	file->log_flag = 1;
	wake_up(&file->log_wait_event_wq);
	wake_tlog_thrd();
}

static inline void wake_up_rd_thread(void)
{
	struct vtzf_serial_port_file *file = g_serial_port_file;
	rd_increment(file);
	wake_up(&file->rd_wait_event_wq);
}

static inline void wake_up_wr_thread(void)
{
	struct vtzf_serial_port_file *file = g_serial_port_file;
	wr_increment(file);
	wake_up(&file->wr_wait_event_wq);
}

static void destroy_data_list(void)
{
	struct vhc_event_data * event_data;
	struct vhc_event_data * temp;
	struct wr_data * write_data;
	struct wr_data * n;
	spin_lock(&g_event_data_list.spinlock);
	list_for_each_entry_safe(event_data, temp, &g_event_data_list.head, head) {
		if (event_data) {
			list_del(&event_data->head);
			kfree(event_data);
		}
	}
	spin_unlock(&g_event_data_list.spinlock);

	spin_lock(&g_wr_data_list.spinlock);
	list_for_each_entry_safe(write_data, n, &g_wr_data_list.head, head) {
		if (write_data) {
			list_del(&write_data->head);
			if (write_data->wr_buf) {
				kfree(write_data->wr_buf);
			}
			kfree(write_data);
		}
	}
	spin_unlock(&g_wr_data_list.spinlock);
}

void free_serial_port_list(void)
{
	struct vtzf_serial_port_file *dev_file = NULL;
	struct vtzf_serial_port_file *tmp = NULL;
	struct_packet_cmd_nothing packet_cmd = {0};
	struct_packet_rsp_nothing packet_rsp = {0};
	uint32_t seq_num = get_seq_num(0);
	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZ_NOTHING;
	g_destroy_rd_thread = 1;

	mutex_lock(&g_serial_port_list.lock);
	/*In fact, there is only one serial port.*/
	list_for_each_entry_safe(dev_file, tmp, &g_serial_port_list.head, head) {
		list_del(&dev_file->head);
		if (dev_file->log_thread){
			tlogd("before kthread_stop log\n");
			wake_up_log_thread();
			tlogd("after kthread_stop log\n");
		}
		if (dev_file->rd_thread){
			tlogd("before kthread_stop rd\n");
			(void)send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num);
			tlogd("after kthread_stop rd\n");
		}
		if (dev_file->wr_thread){
			tlogd("before kthread_stop wr\n");
			g_destroy_wr_thread = 1;
			wake_up_wr_thread();
			tlogd("after kthread_stop wr\n");
		}
		if (dev_file->rd_thread_name)
			kfree(dev_file->rd_thread_name);
		if (dev_file->wr_thread_name)
			kfree(dev_file->wr_thread_name);
		if (dev_file->filep)
			filp_close(dev_file->filep, NULL);
		if (dev_file->buffer)
			kfree(dev_file->buffer);
		mutex_destroy(&dev_file->lock);
		mutex_destroy(&dev_file->wr_flag_lock);
		mutex_destroy(&dev_file->wr_flag_lock);
		kfree(dev_file);
	}
	mutex_unlock(&g_serial_port_list.lock);
	mutex_destroy(&g_serial_port_list.lock);
	destroy_data_list();
}

void put_event_data(void *packet, int packet_size, uint32_t seq_num)
{
	struct vhc_event_data *event_data;
	struct vhc_event_data *tmp;
	if (!packet)
		return;
	spin_lock(&g_event_data_list.spinlock);
	list_for_each_entry_safe(event_data, tmp, &g_event_data_list.head, head) {
		if (event_data->seq_num == seq_num) {
			if (memcpy_s(event_data->rd_buf, event_data->size_rd_buf, packet, packet_size) != 0) {
				tloge("memcpy_s failed\n");
			}
			event_data->rd_ret = 0;
			event_data->ret_flag = 1;
			wake_up(&event_data->wait_event_wq);
			break;
		}
	}
	spin_unlock(&g_event_data_list.spinlock);
	return;
}

int rd_thread_func(void *arg)
{
	struct vtzf_serial_port_file *file = (struct vtzf_serial_port_file *)arg;
	loff_t off = 0;
	int ssize_ret = 0;
	int ret = 0;
	uint32_t seq_num;
	int buf_len = 0;
	int offset = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0)
	struct vtz_buf_struct vtz_buf = {0};
#endif
	struct file *fp_serialport = NULL;
	fp_serialport = file->filep;
	while (!kthread_should_stop()) {
		ret = wait_event_interruptible(file->rd_wait_event_wq, file->rd_flag);
		if (ret != 0) {
			tloge("rd thread wait event interruptible failed!\n");
			ret = -EINTR;
		}
		if (g_destroy_rd_thread)
			break;
		off = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0)
		vtz_buf.buf = file->buffer + file->offset;
		vtz_buf.buf_size = SERIAL_PORT_BUF_LEN - file->offset;
		ssize_ret = fp_serialport->f_op->unlocked_ioctl(fp_serialport,
			TC_NS_CLIENT_IOCTL_READ_REQ, (unsigned long)(&vtz_buf));
#else
		ssize_ret = kernel_read(file->filep, file->buffer + file->offset,
			SERIAL_PORT_BUF_LEN - file->offset, &off);
#endif
		tlogd("kernel_read, ret value = %d, offset = %ld \n", (int)ssize_ret, (long)off);
		if (ssize_ret <= 0) {
			tloge("kernel_read failed, ret = %d \n", (int)ssize_ret);
			wake_tlog_thrd();
			rd_decrement(file);
			continue;
		}
		if (file->log_flag == 2) {
			wake_tlog_thrd();
			file->log_flag = 0;
		}

		buf_len = ssize_ret + file->offset;
		tlogd("buf_len = %d\n", buf_len);
		/*
		* The data may span across multiple packets, and the last packet may even be incomplete. 
		* Each time, complete packets are extracted from the buffer, and the last incomplete 
		* packet is moved to the starting position of the buffer. The offset is recorded simultaneously, 
		* and the next data is filled into the buffer starting from that offset. Each round of 
		* processing begins from the starting position of the buffer, so the offset is set to 0.
		*/
		offset = 0;
		while(1) {
			void *packet = NULL;
			int packet_size = 0;
			packet = get_packet_item(file->buffer, buf_len, &offset, &packet_size);
			if (packet == NULL) {
				break;
			}
			rd_decrement(file);
			seq_num = *(int *)(packet + 4);
			put_event_data(packet, packet_size, seq_num);
		}
		file->offset = offset;
		tlogd("offset = %d\n", offset);
		schedule();
	}
	return 0;
}

struct wr_data *get_wr_data(void)
{
	struct wr_data *write_data = NULL;
	struct wr_data *tmp = NULL;
	spin_lock(&g_wr_data_list.spinlock);
	if (!list_empty(&g_wr_data_list.head)){
		list_for_each_entry_safe(write_data, tmp, &g_wr_data_list.head, head) {
			if (write_data->wr_buf){
				list_del(&write_data->head);
				break;
			}
		}
	}
	spin_unlock(&g_wr_data_list.spinlock);
	if (write_data && !write_data->wr_buf) {
		tloge("write_data->wr_buf NULL\n");
		return NULL;
	}
	return write_data;
}

void destroy_wr_data(struct wr_data *write_data)
{
	if (!write_data)
		return;
	if (write_data->wr_buf)
		kfree(write_data->wr_buf);
	kfree(write_data);
}

static int do_write(struct file *fp_serialport, void *buf, uint32_t buf_size)
{
	int ret = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0)
	struct vtz_buf_struct vtz_buf = {0};
#else
	loff_t off =0;
#endif

	if (!fp_serialport || !buf || buf_size > 32 * 1024)
		return -EINVAL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0)
	if (!fp_serialport->f_op->unlocked_ioctl) {
		tloge("kernel version > 5.0.0, f_op->unlocked_ioctl is NULL, check virtio-console\n");
		return -EINVAL;
	}
	vtz_buf.buf = buf;
	vtz_buf.buf_size = buf_size;
	ret = fp_serialport->f_op->unlocked_ioctl(fp_serialport,
		TC_NS_CLIENT_IOCTL_WRITE_REQ, (unsigned long)(&vtz_buf));
#else
	ret = kernel_write(fp_serialport, buf, buf_size, &off);
#endif
	return ret < 0 ? ret : 0;
}

#define BLOCK_MTU 1024
#define MASK (BLOCK_MTU - 1)
#define FIRST_FRAG_LEN (sizeof(struct_packet_cmd_send_cmd) + BLOCK_MTU * sizeof(struct page_block))
#define MID_FRAG_LEN (BLOCK_MTU * sizeof(struct page_block))

int alloc_packet_space(void **fragments, uint32_t nums, uint32_t last_size)
{
	int i = 0;
	uint32_t buf_size = 0;
	for (i = 0; i < nums; i++) {
		if (i == 0 )
			buf_size = FIRST_FRAG_LEN;
		else if (i == nums - 1)
			buf_size = last_size;
		else 
			buf_size = MID_FRAG_LEN;
		fragments[i] = kzalloc(buf_size, GFP_KERNEL);
		if (!fragments[i]) {
			goto err;
		}
	}
	return 0;
err:
	for (i = 0; i< nums; i++) {
		if (fragments[i])
			kfree(fragments[i]);
	}
	return -ENOMEM;
}

#define FRAG_FLAG 0xAEAE

int memcpy_packet(void **fragments, uint32_t nums, void *wr_buf, uint32_t last_size)
{
	int i = 0;
	int offset = 0;
	if (memcpy_s(fragments[0], FIRST_FRAG_LEN, wr_buf, FIRST_FRAG_LEN))
		return -EFAULT;
	offset += FIRST_FRAG_LEN;
	((struct_packet_cmd_send_cmd *)fragments[0])->fragment_block_num = BLOCK_MTU;
	for (i = 1; i < nums - 1; i++) {
		if (memcpy_s(fragments[i], MID_FRAG_LEN, wr_buf + offset, MID_FRAG_LEN))
			return -EFAULT;
		offset += MID_FRAG_LEN;
		((struct page_block *)fragments[i])->frag_flag = FRAG_FLAG;
	}
	if (memcpy_s(fragments[nums - 1], last_size, wr_buf + offset, last_size))
		return -EFAULT;
	((struct page_block *)fragments[nums - 1])->frag_flag = FRAG_FLAG;
	return 0;
}

static int write_split(struct file *fp_serialport, void *wr_buf)
{
	int ret = 0;
	int i = 0;
	void **fragments;
	int blocks_num = 0;
	int fragms_num = 0;
	int last_num = 0;
	uint32_t last_size = 0;
	blocks_num = ((struct_packet_cmd_send_cmd *)wr_buf)->fragment_block_num;
	fragms_num = blocks_num / BLOCK_MTU;
	last_num = blocks_num & MASK;
	if (last_num)
		fragms_num++;
	else
		last_num = BLOCK_MTU;
	fragments = (void **)kzalloc(sizeof(void *) * fragms_num, GFP_KERNEL);
	if (!fragments) {
		return -ENOMEM;
	}
	last_size = last_num * sizeof(struct page_block);
	if (alloc_packet_space(fragments, fragms_num, last_size)) {
		kfree(fragments);
		return -EFAULT;
	}

	if (memcpy_packet(fragments, fragms_num, wr_buf, last_size)) {
		ret = -EFAULT;
		goto free;
	}

	for (i = 0; i < fragms_num; i++) {
		int buf_size = 0;
		if (i == 0)
			buf_size = FIRST_FRAG_LEN;
		else if (i == fragms_num -1)
			buf_size = last_size;
		else
			buf_size = MID_FRAG_LEN;
		do_write(fp_serialport, fragments[i], buf_size);
	}

free:
	for (i = 0; i < fragms_num; i++) {
		if (fragments[i])
			kfree(fragments[i]);
	}
	if (fragments)
		kfree(fragments);

	return ret < 0 ? ret : 0;
}

static inline bool require_split(void *buf)
{
	struct_packet_cmd_general *packet_cmd = (struct_packet_cmd_general *)buf;
	if (packet_cmd->cmd == VTZF_SEND_CMD &&
		packet_cmd->packet_size - sizeof(struct_packet_cmd_send_cmd) > BLOCK_MTU * sizeof(struct page_block)) {
		return true;
	}
	return false;
}

static int safe_write(struct wr_data *write_data, struct file *fp_serialport)
{
	int ret = 0;
	if (!write_data || !write_data->wr_buf ||
		write_data->size_wr_buf < 3 * sizeof(uint32_t))
		return -EINVAL;
	if (require_split(write_data->wr_buf)) {
		if (write_split(fp_serialport, write_data->wr_buf))
			return -EFAULT;
	} else {
		ret = do_write(fp_serialport, write_data->wr_buf, write_data->size_wr_buf);
	}
	return ret;
} 

int wr_thread_func(void *arg)
{
	struct vtzf_serial_port_file *file = (struct vtzf_serial_port_file *)arg;
	struct file *fp_serialport = NULL;
	int ret = 0;
	struct wr_data *write_data = NULL;
	if (!file || !file->filep)
		return -EFAULT;
	fp_serialport = file->filep;

	while (!kthread_should_stop()) {
		ret = wait_event_interruptible(file->wr_wait_event_wq, file->wr_flag);
		if (ret != 0) {
			tloge("wr thread wait event interruptible failed!\n");
			ret = -EINTR;
		}
		if (g_destroy_wr_thread)
			break;
		write_data = get_wr_data();
		wr_decrement(file);
		if(!write_data)
			continue;
		ret = safe_write(write_data, fp_serialport);
		if (ret < 0)
			tloge("write failed ret = %d\n", ret);
		wake_up_rd_thread();
		destroy_wr_data(write_data);
		schedule();
	}
	return 0;
}

int create_thread(int pos, struct vtzf_serial_port_file *file)
{
	struct task_struct *tmp_thread;
	char *thread_name = kzalloc(32, GFP_KERNEL);
	if (!thread_name) {
		tloge("Failed to allocate memory for thread name\n");
		return -ENOMEM;
	}

	(void)snprintf(thread_name, 32, "vtz_rd_thread_%d", pos);
	file->rd_thread_name = thread_name;

	thread_name = kzalloc(32, GFP_KERNEL);
	if (!thread_name) {
		tloge("Failed to allocate memory for thread name\n");
		kfree(file->rd_thread_name);
		file->rd_thread_name = NULL;
		return -ENOMEM;
	}
	(void)snprintf(thread_name, 32, "vtz_wr_thread_%d", pos);
	file->wr_thread_name = thread_name;

	thread_name = kzalloc(32, GFP_KERNEL);
	if (!thread_name) {
		tloge("Failed to allocate memory for thread name\n");
		kfree(file->rd_thread_name);
		file->rd_thread_name = NULL;
		return -ENOMEM;
	}
	(void)snprintf(thread_name, 32, "vtz_log_thread_%d", pos);
	file->log_thread_name = thread_name;

	tmp_thread = kthread_run(rd_thread_func, file, file->rd_thread_name);
	if (tmp_thread) {
		file->rd_thread = tmp_thread;
		tlogi("Kernel thread created successfully\n");
	} else {
		tloge("Failed to create kernel thread\n");
		return -EFAULT;
	}

	tmp_thread = kthread_run(wr_thread_func, file, file->wr_thread_name);
	if (tmp_thread) {
		file->wr_thread = tmp_thread;
		tlogi("Kernel thread created successfully\n");
	} else {
		tloge("Failed to create kernel thread\n");
		return -EFAULT;
	}

	tmp_thread = kthread_run(log_thread_func, file, file->log_thread_name);
	if (tmp_thread) {
		file->log_thread = tmp_thread;
		tlogi("Kernel thread created successfully\n");
	} else {
		tloge("Failed to create kernel thread\n");
		return -EFAULT;
	}

	return 0;
}

int serial_port_init(void)
{
	int ret = 0;
	int i;
	int size_written;
	struct file *file;
	struct vtzf_serial_port_file *serial_port_file = NULL;
	void *buffer = NULL;
	char device_path[256];

	void *threads = kzalloc(sizeof(struct task_struct) * SERIAL_PORT_NUM, GFP_KERNEL);
	if (!threads) {
		tloge("Failed to allocate memory for threads\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&g_serial_port_list.head);
	mutex_init(&g_serial_port_list.lock);
	INIT_LIST_HEAD(&g_event_data_list.head);
	spin_lock_init(&g_event_data_list.spinlock);

	INIT_LIST_HEAD(&g_wr_data_list.head);
	spin_lock_init(&g_wr_data_list.spinlock);

	for (i = 0; i < SERIAL_PORT_NUM; i++) {
		size_written = snprintf(device_path, sizeof(device_path), "%s%d", VTZF_SERIALPORT, i);
		serial_port_file = kzalloc(sizeof(*serial_port_file), GFP_KERNEL);
		if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)serial_port_file)) {
			tloge("alloc serial_port_file failed\n");
			ret = -ENOMEM;
			goto err;
		}
		buffer = kzalloc(SERIAL_PORT_BUF_LEN, GFP_KERNEL);
		if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)buffer)) {
			tloge("alloc serial_port_file failed\n");
			ret = -ENOMEM;
			kfree(serial_port_file);
			goto err;
		}
		file = filp_open(device_path, O_RDWR, 0);
		if (IS_ERR(file)) {
			tloge("open serial_pore failed \n");
			ret = -EFAULT;
			kfree(serial_port_file);
			kfree(buffer);
			goto err;
		}
		serial_port_file->filep = file;
		serial_port_file->buffer = buffer;
		serial_port_file->rd_flag = 0;
		serial_port_file->wr_flag = 0;
		serial_port_file->log_flag = 0;
		mutex_init(&serial_port_file->lock);
		mutex_init(&serial_port_file->rd_flag_lock);
		mutex_init(&serial_port_file->wr_flag_lock);
		init_waitqueue_head(&(serial_port_file->rd_wait_event_wq));
		init_waitqueue_head(&(serial_port_file->wr_wait_event_wq));
		init_waitqueue_head(&(serial_port_file->log_wait_event_wq));
		list_add_tail(&serial_port_file->head, &g_serial_port_list.head);
		g_serial_port_file = serial_port_file;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0) 
		if (!file->f_op->unlocked_ioctl) {
			tloge("waring! file->f_op->unlocked_ioctl undefine!\n");
			ret = -EFAULT;
			goto err;
		}
#endif
		if (create_thread(i, serial_port_file))
			goto err;
	}
	tlogi(" open serial port success\n");
	return 0;
err:
	free_serial_port_list();
	return ret;
}

int creat_wr_data(void *wr_buf, size_t buf_size)
{
	struct wr_data * write_data;
	if (!wr_buf)
		return -EINVAL;
	write_data = kzalloc(sizeof(struct wr_data), GFP_KERNEL);
	if (!write_data) {
		tloge("alloc wr write_data failed\n");
		return -ENOMEM;
	}
	write_data->size_wr_buf = buf_size;
	write_data->wr_buf = kzalloc(buf_size, GFP_KERNEL);
	if (!write_data->wr_buf) {
		tloge("alloc failed\n");
		kfree(write_data);
		return -ENOMEM;
	}
	if (memcpy_s(write_data->wr_buf, buf_size, wr_buf, buf_size) != 0) {
		tloge("memcpy_s write_data->wr_buf failed\n");
		kfree(write_data->wr_buf);
		kfree(write_data);
		return -EFAULT;
	}
	INIT_LIST_HEAD(&(write_data->head));
	spin_lock(&g_wr_data_list.spinlock);
	list_add_tail(&write_data->head, &g_wr_data_list.head);
	spin_unlock(&g_wr_data_list.spinlock);
	return 0;
}

struct vhc_event_data *creat_event_data(void *rd_buf, size_t size_rd_buf, int seq_num)
{
	struct vhc_event_data * event_data = kzalloc(sizeof(struct vhc_event_data), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)event_data)) {
		tloge("alloc event_data failed\n");
		return NULL;
	}
	event_data->seq_num = seq_num + 1;
	event_data->rd_buf = rd_buf;
	event_data->size_rd_buf = size_rd_buf;
	event_data->ret_flag = 0;
	event_data->rd_ret = 0;
	INIT_LIST_HEAD(&(event_data->head));
	init_waitqueue_head(&(event_data->wait_event_wq));

	spin_lock(&g_event_data_list.spinlock);
	list_add_tail(&event_data->head, &g_event_data_list.head);
	spin_unlock(&g_event_data_list.spinlock);
	return event_data;
}

void destroy_event_data(struct vhc_event_data *event_data)
{
	if (event_data == NULL)
		return ;

	spin_lock(&g_event_data_list.spinlock);
	list_del(&event_data->head);
	spin_unlock(&g_event_data_list.spinlock);

	kfree(event_data);
	return ;
}

int send_to_proxy(void * wrt_buf, size_t size_wrt_buf, void * rd_buf, size_t size_rd_buf, uint32_t seq_num)
{
	int ret = -1;
	struct vhc_event_data *event_data;

	ret = creat_wr_data(wrt_buf, size_wrt_buf);
	if (ret != 0) {
		tloge("creat_wr_data failed\n");
		return ret;
	}

	event_data = creat_event_data(rd_buf, size_rd_buf, seq_num);
	if (event_data == NULL)
		goto err;
	wake_up_wr_thread();

	ret = wait_event_interruptible(event_data->wait_event_wq,
		event_data->ret_flag);
	if (ret != 0) {
		tloge("wait event interruptible failed!, ret = %d\n", ret);
		ret = -EINTR;
	} else {
		ret = event_data->rd_ret;
	}
	destroy_event_data(event_data);
	return ret;

err:
	return ret;
}