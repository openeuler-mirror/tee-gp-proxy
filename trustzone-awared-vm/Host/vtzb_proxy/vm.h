/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2023. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

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
    pthread_t thread_id;
};

typedef struct {
    int flag;
    int start_time;
    pthread_t tid;
    int seq_num;
    struct serial_port_file *serial_port;
} TimeOut;

struct fd_file *find_fd_file(int ptzfd, struct vm_file *vm_fp);
int remove_fd(int ptzfd, struct vm_file *vm_fp);
void add_fd_list(int fd, struct vm_file *vm_fp);
void remove_session(int ptzfd, int session_id, struct vm_file *vm_fp);
void add_session_list(int ptzfd, struct vm_file *vm_fp, TC_NS_ClientContext *clicontext);
int destroy_vm_file(struct vm_file *vm_file);
struct vm_file *create_vm_file(uint32_t vmid);
void *Kill_useless_thread(void *args);
int set_start_time(pthread_t tid, int seq_num, struct serial_port_file *serial_port);
void remove_start_time(int i);
void kill_open_session_thd(TimeOut t_out);
#endif