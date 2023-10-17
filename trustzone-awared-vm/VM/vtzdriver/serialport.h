#ifndef SERIAL_H
#define SERIAL_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#define SERIAL_PORT_BUF_LEN		1024*128
#define VTZF_SERIALPORT         "/dev/virtio-ports/vtzf_serialport"
#define SERIAL_PORT_NUM			 1

#define AGENT_FS_ID 0x46536673
#define SECFILE_LOAD_AGENT_ID 0x4c4f4144
#define AGENT_MISC_ID 0x4d495343

#define VTZ_IOC_MAGIC  'v'
#define TC_NS_CLIENT_IOCTL_READ_REQ \
	 _IOWR(VTZ_IOC_MAGIC, 1, struct vtz_buf_struct)
#define TC_NS_CLIENT_IOCTL_WRITE_REQ \
	_IOWR(VTZ_IOC_MAGIC, 2, struct vtz_buf_struct)

struct vtz_buf_struct{
    uint32_t buf_size;
    void * buf;
};

struct vtzf_serial_port_list {
	struct mutex lock;
	struct list_head head;
};

struct vtzf_event_data_list {
	spinlock_t spinlock;
	struct list_head head;
};

struct vtzf_wr_data_list {
	spinlock_t  spinlock;
	struct list_head head;
};

struct vtzf_serial_port_file
{
	struct file *filep;
	struct list_head head;
	struct mutex lock;
	wait_queue_head_t rd_wait_event_wq;
	wait_queue_head_t wr_wait_event_wq;
	int rd_flag;
	int wr_flag;
	struct mutex rd_flag_lock;
	struct mutex wr_flag_lock;
	struct task_struct * rd_thread;
	struct task_struct * wr_thread;
	char *rd_thread_name;
	char *wr_thread_name;
	bool using;
	void *buffer;
    int buf_size;
    int offset;
};

struct wr_data
{
	struct list_head head;
	void *wr_buf;
	size_t size_wr_buf;
};

struct vhc_event_data {
	struct list_head head;
	wait_queue_head_t wait_event_wq;
	int ret_flag;
	uint32_t seq_num;
	void *rd_buf;
	size_t size_rd_buf;
	int rd_ret;
};

int serial_port_init(void);
void free_serial_port_list(void);
void seq_num_init(void);
uint32_t get_seq_num(int agent_id);
struct vtzf_serial_port_list *get_serial_port_list(void);
int send_to_proxy(void * wrt_buf, size_t size_wrt_buf, void * rd_buf, size_t size_rd_buf, uint32_t seq_num);

#endif






