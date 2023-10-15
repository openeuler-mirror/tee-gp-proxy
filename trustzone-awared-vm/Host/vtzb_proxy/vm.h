#ifndef __VM_H__
#define __VM_H__
#include <sys/ioctl.h>
#include <sys/types.h>
#include "tc_ns_client.h"
#include "tee_sys_log.h"
#include "tee_client_list.h"

struct vm_file {
    uint32_t vmpid;
    struct ListNode head;
    pthread_mutex_t fd_lock;
    struct ListNode fds_head;
    pthread_mutex_t agents_lock;
    struct ListNode agents_head;
};

#endif