#include "tlogger.h"
#include <linux/cdev.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>
#include <linux/delay.h>
#include <asm/ioctls.h>
#include <linux/syscalls.h>
#include <linux/kthread.h>
#include <securec.h>
#include "comm_structs.h"
#include "serialport.h"
#include "tee_info.h"
#include "teek_client_constants.h"
#include "tc_ns_client.h"
#include "teek_ns_client.h"
#include <linux/printk.h>

#ifndef CONFIG_TEE_LOG_ACHIVE_PATH
#define CONFIG_TEE_LOG_ACHIVE_PATH "/var/log/tee/last_teemsg"
#endif
#define MAX_LOG__FILE_SIZE	1024*1024*32
static struct log_buffer *g_log_buffer = NULL;
static struct tlogger_reader *g_thread_reader = NULL;
static int g_buff_len = 0;
static LIST_HEAD(m_log_list);
static uint32_t g_log_mem_len = 0;
static uint32_t g_tlogcat_count = 0;
static struct tlogger_log *g_log;
static struct mutex g_reader_group_mutex;
static LIST_HEAD(g_reader_group_list);

static int g_vmid = 0;

static struct tlogger_log *get_reader_log(const struct file *file)
{
	struct tlogger_reader *reader = NULL;

	reader = file->private_data;
	if (!reader)
		return NULL;

	return reader->log;
}

static struct tlogger_group *get_tlogger_group(void)
{
	struct tlogger_group *group = NULL;
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	uint32_t nsid = task_active_pid_ns(current)->ns.inum;
#else
	uint32_t nsid = PROC_PID_INIT_INO;
#endif

	list_for_each_entry(group, &g_reader_group_list, node) {
		if (group->nsid == nsid)
			return group;
	}

	return NULL;
}

static struct tlogger_log *get_tlogger_log_by_minor(int minor)
{
	struct tlogger_log *log = NULL;

	list_for_each_entry(log, &m_log_list, logs) {
		if (log->misc_device.minor == minor)
			return log;
	}

	return NULL;
}

static void init_tlogger_reader(struct tlogger_reader *reader, struct tlogger_log *log, struct tlogger_group *group)
{
	reader->log = log;
	reader->group = group;

	get_task_struct(current);
	reader->pid = get_task_pid(current, PIDTYPE_PID);
	put_task_struct(current);

	reader->r_all = true;
	reader->r_off = 0;
	reader->r_loops = 0;
	reader->r_sn = 0;
	reader->r_failtimes = 0;
	reader->r_is_tlogf = 0;
	reader->r_from_cur = 0;

	INIT_LIST_HEAD(&reader->list);
	init_waitqueue_head(&reader->wait_queue_head);
}

static void init_tlogger_group(struct tlogger_group *group)
{
	group->reader_cnt = 1;
#ifdef CONFIG_CONFIDENTIAL_CONTAINER
	group->nsid = task_active_pid_ns(current)->ns.inum;
#else
	group->nsid = PROC_PID_INIT_INO;
#endif
	group->tlogf_stat = 0;
}

#ifndef NSID_FILE_PATH
#define NSID_FILE_PATH   "/tmp/qca_nsid"
#endif

static int store_nsid_file(int vmid)
{
	struct file *filep = NULL;
	char str[32]={0};
	loff_t pos = 0;
	filep = filp_open(NSID_FILE_PATH, O_CREAT | O_RDWR | O_TRUNC, OPEN_FILE_MODE);
	if (!filep || IS_ERR(filep)) {
		tloge("open last teemsg file err %ld\n", PTR_ERR(filep));
		return -1;
	}
	(void)snprintf(str, 32, "%d", vmid);
	(void)kernel_write(filep, str, strlen(str), &pos);
	filp_close(filep, NULL);
	return 0;
}

static int open_tzdriver_tlogger(struct tlogger_reader *dev_file, uint32_t flag, bool isthd)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_open_tzd packet_cmd = {0};
	struct_packet_rsp_open_tzd packet_rsp = {0};

	if (!dev_file) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	dev_file->ptzfd = -1;
	if (isthd)
		seq_num = 40;
	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_OPEN_TZD;
	packet_cmd.vmid = 0;
	/* if flag==0, open tc_ns_client; if flag==1, open tc_private */
	packet_cmd.flag = flag;
	tlogi("start open tlogger\n");
	ret = send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num);
	if (!ret) {
		ret = packet_rsp.ret;
		if (ret) {
			tloge("open TZdriver failed ret is %d\n", ret);
			goto END;
		}
		dev_file->ptzfd = packet_rsp.ptzfd;
		if (!g_vmid) {
			store_nsid_file(packet_rsp.vmid);
		}
	} else {
		tloge("send to proxy failed ret is %d\n", ret);
	}
	tlogi("try open tlogger, ret = %d\n", ret);
END:
	return ret;	
}

static int process_tlogger_open(struct inode *inode,
	struct file *file)
{
	struct tlogger_log *log = NULL;
	int ret;
	struct tlogger_reader *reader = NULL;
	struct tlogger_group *group = NULL;

	tlogd("open logger open ++\n");
	/* not support seek */
	ret = nonseekable_open(inode, file);
	if (ret != 0)
		return ret;

	tlogd("Before get log from minor\n");
	log = get_tlogger_log_by_minor(MINOR(inode->i_rdev));
	if (!log)
		return -ENODEV;

	mutex_lock(&g_reader_group_mutex);
	group = get_tlogger_group();
	if (group == NULL) {
		group = kzalloc(sizeof(*group), GFP_KERNEL);
		if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)group)) {
			mutex_unlock(&g_reader_group_mutex);
			return -ENOMEM;
		}
		init_tlogger_group(group);
		list_add_tail(&group->node, &g_reader_group_list);
	} else {
		group->reader_cnt++;
	}
	mutex_unlock(&g_reader_group_mutex);

	reader = kmalloc(sizeof(*reader), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)reader)) {
		mutex_lock(&g_reader_group_mutex);
		if (--group->reader_cnt == 0) {
			list_del(&group->node);
			kfree(group);
		}
		mutex_unlock(&g_reader_group_mutex);
		return -ENOMEM;
	}
	init_tlogger_reader(reader, log, group);

	mutex_lock(&log->mutex_log_chnl);
	list_add_tail(&reader->list, &log->readers);
	g_tlogcat_count++;
	mutex_unlock(&log->mutex_log_chnl);

	file->private_data = reader;
	(void)open_tzdriver_tlogger(reader, TLOG_DEV_FLAG, false);
	tlogd("tlogcat count %u\n", g_tlogcat_count);
	return 0;
}

static int close_tzdriver_tlogger(struct tlogger_reader *dev_file)
{
	int ret = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_close_tzd packet_cmd = {0};
	struct_packet_rsp_close_tzd packet_rsp = {0};

	if (!dev_file || dev_file->ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}
	packet_cmd.packet_size = sizeof(packet_cmd);
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

static int process_tlogger_release(struct inode *ignored,
	struct file *file)
{
	struct tlogger_reader *reader = NULL;
	struct tlogger_log *log = NULL;
	struct tlogger_group *group = NULL;

	(void)ignored;

	tlogd("logger_release ++\n");

	if (!file)
		return -1;

	reader = file->private_data;
	if (!reader) {
		tloge("reader is null\n");
		return -1;
	}

	log = reader->log;
	if (!log) {
		tloge("log is null\n");
		return -1;
	}

	mutex_lock(&log->mutex_log_chnl);
	list_del(&reader->list);
	if (g_tlogcat_count >= 1)
		g_tlogcat_count--;
	mutex_unlock(&log->mutex_log_chnl);

	group = reader->group;
	if (group != NULL) {
		mutex_lock(&g_reader_group_mutex);
		if (reader->r_is_tlogf != 0)
			group->tlogf_stat = 0;
		if (--group->reader_cnt == 0) {
			list_del(&group->node);
			kfree(group);
		}
		mutex_unlock(&g_reader_group_mutex);
	}
	(void)close_tzdriver_tlogger(reader);
	kfree(reader);
	tlogd("tlogcat count %u\n", g_tlogcat_count);
	return 0;
}

void dump_buff_log(const char* buffer, size_t bufLen)
{
    size_t i;
    if (buffer == NULL || bufLen == 0) {
        return;
    }
    pr_info("--------------------------------------------------\n");
    pr_info("bufLen = %d\n", (int)bufLen);
    for (i = 0; i < bufLen; i++) {
        if (i % 16 == 0 && i != 0) {
            pr_info("\n");
        }
        pr_info("%02x ", *(buffer + i));
    }
    pr_info("\n--------------------------------------------------\n");
    return;
}

static int get_log_from_host(struct tlogger_reader *dev_file)
{
	int ret;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_get_log packet_cmd = {0};
	struct_packet_rsp_get_log* packet_rsp = {0};
	packet_rsp= kzalloc(sizeof(*packet_rsp) + LOG_BUFFER_LEN, GFP_KERNEL);
	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_GET_LOG;
	packet_cmd.ptzfd = dev_file->ptzfd;
	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), packet_rsp,
		sizeof(*packet_rsp) + LOG_BUFFER_LEN, seq_num)) {
		tloge("send to proxy failed\n");
		return  -EFAULT;
	} else {
		ret = packet_rsp->ret;
		g_buff_len = packet_rsp->length;
		memcpy_s(g_log_buffer, packet_rsp->length, packet_rsp->buffer, packet_rsp->length);
	}
	tlogd("-----------get_log_from_host-------\n");
	kfree((void *)(packet_rsp));
	return ret;
}

static ssize_t process_tlogger_read(struct file *file,
	char __user *buf, size_t count, loff_t *pos)
{
	int ret = g_buff_len;
	(void)buf;
	(void)count;
	(void)pos;
	tlogd("--------------log-------------\n");
	if (copy_to_user(buf, (void *)g_log_buffer, g_buff_len) != 0)
		tloge("copy failed, item len %u\n", g_buff_len);
	g_buff_len = 0;
	return ret;
}

static unsigned int process_tlogger_poll(struct file *file,
	poll_table *wait)
{
	struct tlogger_reader *reader = NULL;
	struct tlogger_log *log = NULL;
	struct log_buffer *buffer = NULL;
	uint32_t ret = POLLOUT | POLLWRNORM;

	tlogd("logger_poll ++\n");
	if (!file) {
		tloge("file is null\n");
		return ret;
	}

	reader = file->private_data;
	if (!reader) {
		tloge("the private data is null\n");
		return ret;
	}

	log = reader->log;
	if (!log) {
		tloge("log is null\n");
		return ret;
	}

	buffer = (struct log_buffer*)log->buffer_info;
	if (!buffer) {
		tloge("buffer is null\n");
		return ret;
	}

	(void)get_log_from_host(reader);
	ret |= POLLIN | POLLRDNORM;
	tlogd("before return \n");
	return ret;
}

static int check_user_arg(unsigned long arg, size_t arg_len)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 18) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(4, 19, 71))
	return (int)access_ok(VERIFY_READ,
		(void __user *)(uintptr_t)arg, arg_len);
#else
	return (int)access_ok((void __user *)(uintptr_t)arg, arg_len);
#endif
}

static int get_teeos_version(struct tlogger_reader *dev_file,
	uint32_t cmd, unsigned long arg)
{
	int ret;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_get_ver packet_cmd = {0};
	struct_packet_rsp_get_ver packet_rsp = {0};

	if ((_IOC_DIR(cmd) & _IOC_READ) == 0) {
		tloge("check get version cmd failed\n");
		return -1;
	}

	ret = check_user_arg(arg,
		sizeof(g_log_buffer->flag.version_info));
	if (ret == 0) {
		tloge("check version info arg failed\n");
		return -1;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_GET_TEEOS_VER;
	packet_cmd.ptzfd = dev_file->ptzfd;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		tloge("sen to proxy failed\n");
		return  -EFAULT;
	} else {
		ret = packet_rsp.ret;
		if (copy_to_user((void __user *)(uintptr_t)arg,
			(void *)packet_rsp.version_info,
			sizeof(packet_rsp.version_info)) != 0) {
			tloge("version info copy failed\n");
			return -1;
		}
	}
	return ret;
}

#define SET_READ_POS   1U
static int set_reader_cur_pos(const struct file *file)
{
	int ret = 0;
	struct tlogger_reader *dev_file = NULL;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_set_reader_cur packet_cmd = {0};
	struct_packet_rsp_set_reader_cur packet_rsp = {0};

	if (!file || !file->private_data)
		return -EINVAL;
	dev_file = file->private_data;
	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_SET_READER_CUR;
	packet_cmd.ptzfd = dev_file->ptzfd;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		tloge("sen to proxy failed\n");
		return  -EFAULT;
	} else {
		ret = packet_rsp.ret;
	}
	return ret;
}

static int set_tlogcat_f_stat(const struct file *file)
{
	int ret = 0;
	struct tlogger_reader *dev_file = NULL;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_set_tlogcat_stat packet_cmd = {0};
	struct_packet_rsp_set_tlogcat_stat packet_rsp = {0};

	if (!file || !file->private_data)
		return -EINVAL;

	dev_file = file->private_data;

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_SET_TLOGCAT_STAT;
	packet_cmd.ptzfd = dev_file->ptzfd;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		tloge("sen to proxy failed\n");
		return  -EFAULT;
	} else {
		ret = packet_rsp.ret;
	}
	return ret;
}

static int get_tlogcat_f_stat(const struct file *file)
{
	struct tlogger_reader *dev_file = NULL;
	int tlogf_stat = 0;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_get_tlogcat_stat packet_cmd = {0};
	struct_packet_rsp_get_tlogcat_stat packet_rsp = {0};

	if (!file || !file->private_data)
		return tlogf_stat;

	dev_file = file->private_data;

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.seq_num = seq_num;
	packet_cmd.cmd = VTZF_GET_TLOGCAT_STAT;
	packet_cmd.ptzfd = dev_file->ptzfd;
	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		tloge("sen to proxy failed\n");
		return  -EFAULT;
	} else {
		tlogf_stat = packet_rsp.ret;
	}
	return tlogf_stat;
}

static long process_tlogger_ioctl(struct file *file,
	unsigned int cmd, unsigned long arg)
{
	struct tlogger_log *log = NULL;
	long ret = -EINVAL;
	struct tlogger_reader *dev_file = NULL;
	if (!file)
		return -1;

	log = get_reader_log(file);
	if (!log) {
		tloge("log is null\n");
		return -1;
	}
	dev_file = file->private_data;
	if (dev_file == NULL) {
		return -1;
	}

	tlogd("logger_ioctl start ++\n");
	mutex_lock(&log->mutex_info);

	switch (cmd) {
	case TEELOGGER_GET_VERSION:
		if (get_teeos_version(dev_file, cmd, arg) == 0)
			ret = 0;
		break;
	case TEELOGGER_SET_READERPOS_CUR:
		(void)set_reader_cur_pos(file);
		ret = 0;
		break;
	case TEELOGGER_SET_TLOGCAT_STAT:
		(void)set_tlogcat_f_stat(file);
		ret = 0;
		break;
	case TEELOGGER_GET_TLOGCAT_STAT:
		ret = get_tlogcat_f_stat(file);
		break;
	case TEELOGGER_GET_TEE_INFO:
		ret = tc_ns_get_tee_info(dev_file->ptzfd, (void *)(uintptr_t)arg, true);
		break;
	default:
		tloge("ioctl error default\n");
		break;
	}

	mutex_unlock(&log->mutex_info);
	return ret;
}

#ifdef CONFIG_COMPAT
static long process_tlogger_compat_ioctl(struct file *file,
	unsigned int cmd, unsigned long arg)
{
	tlogd("logger_compat_ioctl ++\n");
	arg = (unsigned long)(uintptr_t)compat_ptr(arg);
	return process_tlogger_ioctl(file, cmd, arg);
}
#endif

static const struct file_operations g_logger_fops = {
	.owner = THIS_MODULE,
	.read = process_tlogger_read,
	.poll = process_tlogger_poll,
	.unlocked_ioctl = process_tlogger_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = process_tlogger_compat_ioctl,
#endif
	.open = process_tlogger_open,
	.release = process_tlogger_release,
};

static int open_msg_file(struct file **file,
	const char *file_path, uint32_t file_path_len)
{
	struct file *filep = NULL;
    loff_t file_size;
	(void)file_path_len;

	filep = filp_open(file_path, O_CREAT | O_RDWR | O_APPEND, OPEN_FILE_MODE);
	if (!filep || IS_ERR(filep)) {
		tloge("open last teemsg file err %ld\n", PTR_ERR(filep));
		return -1;
	}

    file_size = i_size_read(file_inode(filep));

    if (file_size > MAX_LOG__FILE_SIZE) {
        vfs_truncate(&filep->f_path, 0);
        pr_info("Log file %s truncated.\n", file_path);
    }

	*file = filep;
	return 0;
}

#ifdef WRITE_VERSION
static int write_version_to_msg(struct file *filep,
	loff_t *pos)
{
	ssize_t write_len;
	/* first write tee versino info */
	write_len = kernel_write(filep, g_log_buffer->flag.version_info,
		strlen(g_log_buffer->flag.version_info), pos);
	if (write_len < 0) {
		tloge("Failed to write to last teemsg version\n");
		return -1;
	}

	tlogd("Succeed to Write to last teemsg version, len=%zd\n", write_len);
	return 0;
}
#endif

static bool check_log_item_validite(const struct log_item *item,
	uint32_t item_max_size)
{
	bool con = (item && (item->magic == LOG_ITEM_MAGIC) &&
		(item->buffer_len > 0) &&
		(item->real_len > 0) &&
		(item->buffer_len % LOG_ITEM_LEN_ALIGN == 0) &&
		(item->real_len <= item->buffer_len) &&
		((item->buffer_len - item->real_len) < LOG_ITEM_LEN_ALIGN) &&
		(item->buffer_len + sizeof(*item) <= item_max_size));

	return con;
}

static struct log_item *msg_get_next(unsigned char *buffer_start,
	uint32_t read_pos, uint32_t scope_len, uint32_t max_len)
{
	uint32_t i = 0;
	struct log_item *item = NULL;
	uint32_t item_max_size;
	uint32_t len;

	while (i <= scope_len &&
		((read_pos + i + sizeof(*item)) < max_len)) {
		len = (uint32_t)(scope_len - i);
		item_max_size =
			((len > LOG_ITEM_MAX_LEN) ? LOG_ITEM_MAX_LEN : len);
		item = (struct log_item *)(buffer_start + read_pos + i);

		if (check_log_item_validite(item, item_max_size)) {
			if ((read_pos + i + sizeof(*item) +
				item->buffer_len) > max_len) {
				tloge("check item len error\n");
				return NULL;
			}

			return item;
		}

		i += LOG_ITEM_LEN_ALIGN;
		item = NULL;
	}

	return NULL;
}

static int write_part_log_to_msg( unsigned char *buffer,
	uint32_t buffer_max_len, loff_t *pos,
	uint32_t read_off, uint32_t read_off_end)
{
	struct file *filep = NULL;
	struct log_item *next_item = NULL;
	uint32_t item_len;
	uint32_t total_len = 0;
	ssize_t write_len;
	int ret = 0;
	ret = open_msg_file(&filep, CONFIG_TEE_LOG_ACHIVE_PATH, sizeof(CONFIG_TEE_LOG_ACHIVE_PATH));
	if (ret != 0)
		return 0;

	next_item = msg_get_next(buffer, read_off,
		LOG_ITEM_MAX_LEN, buffer_max_len);

	while (next_item && read_off <= read_off_end) {
		item_len = next_item->buffer_len + sizeof(*next_item);
		write_len = kernel_write(filep, next_item->log_buffer,
			next_item->real_len, pos);
		if (write_len < 0) {
			tloge("Failed to write last teemsg %zd\n", write_len);
			ret = -1;
			goto END;
		}

		tlogd("Succeed to Write last teemsg, len=%zd\n", write_len);
		total_len += item_len;
		read_off = (unsigned char *)next_item - buffer + item_len;
		if (total_len >= buffer_max_len)
			break;

		next_item = msg_get_next(buffer, read_off,
			LOG_ITEM_MAX_LEN, buffer_max_len);
	}
END:
	filp_close(filep, NULL);
	return ret;
}

int log_thread_func(void *arg)
{
	struct vtzf_serial_port_file *dev_file = (struct vtzf_serial_port_file *)arg;
	int ret = 0;
	uint32_t seq_num = 40;
	loff_t pos = 0;
	struct_packet_cmd_get_log packet_cmd;
	struct_packet_rsp_get_log* packet_rsp;
	if (!dev_file)
		return -EINVAL;
	g_thread_reader = kmalloc(sizeof(*g_thread_reader), GFP_KERNEL);
	if (!g_thread_reader) {
		return -ENOMEM;
	}
	packet_rsp= kzalloc(sizeof(*packet_rsp) + LOG_BUFFER_LEN, GFP_KERNEL);
	if (!packet_rsp) {
		kfree(g_thread_reader);
		return -ENOMEM;
	}

	ret = -EAGAIN;
	while(!kthread_should_stop() && !dev_file->log_flag){
		if (ret == -EAGAIN) {
			dev_file->log_flag = 2;
			while(!kthread_should_stop() && open_tzdriver_tlogger(g_thread_reader, TLOG_DEV_THD_FLAG, true)){
				tlogd("will sleep 10s\n");
				(void)wait_event_interruptible_timeout(dev_file->log_wait_event_wq, dev_file->log_flag, 10 * HZ);
				tlogd("after sleep 10s\n");
			}
		} else if (!ret) {
			write_part_log_to_msg(packet_rsp->buffer, packet_rsp->length, &pos, 0, packet_rsp->length);
			tlogd("write tlog \n");
		}
		if (kthread_should_stop() || dev_file->log_flag)
			break;
		tlogd("g_thread_reader->ptzfd = %d\n", g_thread_reader->ptzfd);
		packet_cmd.packet_size = sizeof(packet_cmd);
		packet_cmd.seq_num = seq_num;
		packet_cmd.cmd = VTZF_GET_LOG;
		packet_cmd.ptzfd = g_thread_reader->ptzfd;
		ret = send_to_proxy(&packet_cmd, sizeof(packet_cmd), packet_rsp,
			sizeof(*packet_rsp) + LOG_BUFFER_LEN, seq_num);
		schedule();
	}
	kfree((void *)(packet_rsp));
	kfree(g_thread_reader);
	return 0;
}

static int register_device(const char *log_name,
	uintptr_t addr, int size)
{
	int ret;
	struct tlogger_log *log = NULL;
	unsigned char *buffer = (unsigned char *)addr;
	(void)size;

	log = kzalloc(sizeof(*log), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)log)) {
		tloge("kzalloc is failed\n");
		return -ENOMEM;
	}
	log->buffer_info = buffer;
	log->misc_device.minor = MISC_DYNAMIC_MINOR;
	log->misc_device.name = kstrdup(log_name, GFP_KERNEL);
	if (!log->misc_device.name) {
		ret = -ENOMEM;
		tloge("kstrdup is failed\n");
		goto out_free_log;
	}
	log->misc_device.fops = &g_logger_fops;
	log->misc_device.parent = NULL;

	INIT_LIST_HEAD(&log->readers);
	mutex_init(&log->mutex_info);
	mutex_init(&log->mutex_log_chnl);
	INIT_LIST_HEAD(&log->logs);
	list_add_tail(&log->logs, &m_log_list);

	/* register misc device for this log */
	ret = misc_register(&log->misc_device);
	if (unlikely(ret)) {
		tloge("failed to register misc device:%s\n",
			log->misc_device.name);
		goto out_free_log;
	}
	g_log = log;
	return 0;

out_free_log:
	if (log->misc_device.name)
		kfree(log->misc_device.name);

	kfree(log);
	return ret;
}

static int alloc_log_mem(void)
{
	int ret = 0;
	void *tmp = kzalloc(TEMP_LOG_MEM_SIZE, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)tmp)) {
		tloge("alloc serial_port_file failed\n");
			ret = -ENOMEM;
			goto END;
	}
	g_log_buffer = (struct log_buffer *)tmp;
	g_log_mem_len = TEMP_LOG_MEM_SIZE;
	g_log_buffer->flag.max_len = g_log_mem_len - sizeof(*g_log_buffer);
END:
	return ret;
}

int register_tloger_device(void)
{
	int ret;
	ret = alloc_log_mem();
	if (ret)
		return ret;
	ret = register_device(LOGGER_LOG_TEEOS, (uintptr_t)g_log_buffer,
		g_log_mem_len);
	if (ret != 0) {
		kfree((void *)g_log_buffer);
		g_log_buffer = NULL;
		g_log_mem_len = 0;
	}
	return ret;
}

static void unregister_tlogger(void)
{
	struct tlogger_log *current_log = NULL;
	struct tlogger_log *next_log = NULL;

	list_for_each_entry_safe(current_log, next_log, &m_log_list, logs) {
		/* we have to delete all the entry inside m_log_list */
		misc_deregister(&current_log->misc_device);
		kfree(current_log->misc_device.name);
		list_del(&current_log->logs);
		kfree(current_log);
	}

	kfree((void *)g_log_buffer);
	g_log_buffer = NULL;
	g_log_mem_len = 0;
}

void tlogger_exit(void)
{
	unregister_tlogger();
}

int tlogger_init(void)
{
	return register_tloger_device();
}
