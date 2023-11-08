#ifndef __VM_H__
#define __VM_H__
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pthread.h>
#include "tc_ns_client.h"
#include "tee_sys_log.h"
#include "tee_client_list.h"
#include "debug.h"

struct vm_file {
    uint32_t vmpid;
    int log_fd;
    struct ListNode head;
    pthread_mutex_t fd_lock;
    struct ListNode fds_head;
    pthread_mutex_t agents_lock;
    struct ListNode agents_head;
    pthread_mutex_t shrd_mem_lock;
    struct ListNode shrd_mem_head;
};

struct fd_file {
    int32_t ptzfd;
    struct ListNode head;
    pthread_mutex_t session_lock;
    struct ListNode session_head;
};

struct session {
    struct ListNode head;
    unsigned int  session_id;
    TC_NS_ClientContext cliContext;	
    pthread_t thread_id;
};

struct fd_file *find_fd_file(int ptzfd, struct vm_file *vm_fp);
int remove_fd(int ptzfd, struct vm_file *vm_fp);
void add_fd_list(int fd, struct vm_file *vm_fp);
void remove_session(int ptzfd, int session_id, struct vm_file *vm_fp);
void add_session_list(int ptzfd, struct vm_file *vm_fp, TC_NS_ClientContext *clicontext);
int destroy_vm_file(struct vm_file *vm_file);
struct vm_file *get_vm_file(uint32_t vmid);

void add_mem(void *addr, int buf_size);
void del_mem(void *addr);
#endif

