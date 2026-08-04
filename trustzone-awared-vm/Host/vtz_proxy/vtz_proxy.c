#define _GNU_SOURCE
#include "vtz_proxy.h"
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include "securec.h"
#include "tc_ns_client.h"
#include "tee_client_list.h"
#include "comm_structs.h"
#include "virt.h"
#include "thread_pool.h"
#include "debug.h"
#include "agent.h"
#include "serial_port.h"
#include "process_data.h"
#include "tlogcat.h"
#include "enhance_stability.h"
#include "config.h"
#include <sys/utsname.h>

ThreadPool g_pool = {0};
pthread_mutex_t g_private_fd_lock;
int g_private_dev_fd;
extern struct pollfd g_pollfd[SERIAL_PORT_NUM_MAX];
extern struct serial_port_file *g_serial_array[SERIAL_PORT_NUM_MAX];

static void open_tzdriver(struct_packet_cmd_open_tzd *packet_cmd,
    struct serial_port_file *serial_port)
{
    int fd = -1;
    int ret;
    struct_packet_rsp_open_tzd packet_rsp;
    struct vm_file *vm_fp = NULL;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.vmid = serial_port->vm_file->vmpid;
    struct_vm_group_info vm_info;
    vm_info.vmid = serial_port->vm_file->vmpid;
    vm_info.nsid = packet_cmd->nsid;

    if (packet_cmd->flag == TLOG_DEV_THD_FLAG) {
        if (!serial_port->vm_file || !serial_port->vm_file->log_fd) {
            fd = open(TC_LOGGER_DEV_NAME, O_RDONLY);
            ret = ioctl(fd, TEELOGGER_SET_VM_FLAG, &vm_info);
        } else {
            fd = serial_port->vm_file->log_fd;
        }
    } else if(packet_cmd->flag == TLOG_DEV_FLAG) {
            fd = open(TC_LOGGER_DEV_NAME, O_RDONLY);
            ret = ioctl(fd, TEELOGGER_SET_VM_FLAG, &vm_info);
    } else{
        switch (packet_cmd->flag)
        {
        case TC_NS_CLIENT_DEV_FLAG:
            fd = open(TC_NS_CLIENT_DEV_NAME, O_RDWR);   
            break;
        case TC_PRIVATE_DEV_FLAG:
            fd = open(TC_TEECD_PRIVATE_DEV_NAME, O_RDWR);
            break;
        case TC_CVM_DEV_FLAG:
            fd = open(TC_NS_CVM_DEV_NAME, O_RDWR);
            break;
        default:
            break;
        }
        if (fd != -1)
            ret = ioctl(fd, TC_NS_CLIENT_IOCTL_SET_VM_FLAG, &vm_info);
    }

    tlogd("vmid %d, proxy-vmid %u flag %d open tzdriver, fd %d, nsid is %u\n", packet_cmd->vmid, serial_port->vm_file->vmpid, packet_cmd->flag, fd, packet_cmd->nsid);
    packet_rsp.ptzfd = fd;
    if (fd < 0) {
        tloge("open tee client dev failed, fd is %d\n", fd);
        packet_rsp.ret = fd;
        goto END;
    }
    packet_rsp.ret = 0;

END:
    if (fd > 0) {
        vm_fp = serial_port->vm_file;
        add_fd_list(fd, packet_cmd->flag, vm_fp);
        if (packet_cmd->flag == TLOG_DEV_THD_FLAG) {
            vm_fp->log_fd = fd;
        }
    }
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp) && fd > 0) {
        remove_fd(fd, vm_fp);
    }
}

static void close_tzdriver(struct_packet_cmd_close_tzd *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = -1;
    struct_packet_rsp_close_tzd packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = 0;
    (void)ret;
    if (!serial_port->vm_file) {
        tloge("serial_port->vm_file is null\n");
        return;
    }
    if (packet_cmd->ptzfd <= 2) {
        tloge("invalid ptzfd %d\n", packet_cmd->ptzfd);
        return;
    }

    ret = remove_fd(packet_cmd->ptzfd, serial_port->vm_file);
    packet_rsp.ret = ret;

    if (send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp)) != sizeof(packet_rsp))
        tloge("close_tzdriver send to VM failed \n");
}

static void log_in_NonHidl(struct_packet_cmd_login_non *packet_cmd, 
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_login packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_LOGIN, NULL);
    packet_rsp.ret = ret;

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp))
        tloge("log_in_NonHidl send to VM failed \n");
}

static void log_in(struct_packet_cmd_login *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_login packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_LOGIN, packet_cmd->cert_buffer);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("log_in send to VM failed \n");
    }
}

static void get_tee_ver(struct_packet_cmd_getteever *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_getteever packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_GET_TEE_VERSION, &packet_rsp.tee_ver);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp))
        tloge("get_tee_ver send to VM failed \n");
}

static void get_tee_info(struct_packet_cmd_getteeinfo *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_getteeinfo packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    if (packet_cmd->istlog) {
        ret = ioctl(packet_cmd->ptzfd, TEELOGGER_GET_TEE_INFO, &packet_rsp.info);
    } else{
        ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_GET_TEE_INFO, &packet_rsp.info);
    }
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp))
        tloge("get_tee_info send to VM failed \n");
}

static void sync_sys_time(struct_packet_cmd_synctime *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_synctime packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SYC_SYS_TIME, &packet_cmd->tcNsTime);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp))
        tloge("sync_sys_time send to VM failed \n");
}

static int process_address_sess(struct_packet_cmd_session *packet_cmd,
    ClientParam params[], struct vm_file *vm_fp);
static void process_address_end_sess(struct_packet_cmd_session *packet_cmd, ClientParam params[]);
static void set_thread_id(int ptzfd, unsigned int session_id, int flag, struct vm_file *vm_fp);

static void open_session(struct_packet_cmd_session *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = -1;
    int index;
    struct_packet_rsp_session packet_rsp;
    ClientParam params[TEEC_PARAM_NUM];
    struct_vm_group_info vm_info;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    vm_info.vmid = serial_port->vm_file->vmpid;
    vm_info.nsid = packet_cmd->nsid;
    tlogd("proxy-vmid %u nsid is %u\n", serial_port->vm_file->vmpid, packet_cmd->nsid);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SET_VM_FLAG, &vm_info);
    if (ret != 0) {
        tloge("set vmid %u, nsid %u failed, ret is %d",serial_port->vm_file->vmpid, packet_cmd->nsid, ret);
        goto END;
    }
    index = set_start_time(pthread_self(), packet_cmd->seq_num, serial_port);
    if (!process_address_sess(packet_cmd, params, serial_port->vm_file)) {
        set_thread_id(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, 1, serial_port->vm_file);
        ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SES_OPEN_REQ, &packet_cmd->cliContext);
        
        set_thread_id(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, 0, serial_port->vm_file);
        process_address_end_sess(packet_cmd, params);
    }
    remove_start_time(index);
END:
    packet_rsp.ret = ret;
    packet_rsp.cliContext = packet_cmd->cliContext;
    if (ret == 0)
        add_session_list(packet_cmd->ptzfd, serial_port->vm_file, &packet_rsp.cliContext);

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp))
        tloge("open_session send to VM failed \n");
}

static void close_session(struct_packet_cmd_session *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_general packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    if (!serial_port->vm_file)
        return;
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ, &packet_cmd->cliContext);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp))
        tloge("close_session send to VM failed \n");
    remove_session(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, serial_port->vm_file);
}

static int process_address(struct_packet_cmd_send_cmd *packet_cmd,
    ClientParam params[], struct vm_file *vm_fp)
{
    int index;
    int icount = 0;
    int ret = 0;
    uint32_t paramTypes[TEEC_PARAM_NUM];
    uint64_t *vm_hvas = (uint64_t *)packet_cmd->cliContext.file_buffer;
    uint32_t offset = sizeof(struct_packet_cmd_send_cmd);
    for (index = 0; index < TEEC_PARAM_NUM; index++) {
        paramTypes[index] =
            TEEC_PARAM_TYPE_GET(packet_cmd->cliContext.paramTypes, index);
        if (IS_PARTIAL_MEM(paramTypes[index])) {
            void *vm_buffer = (void *)packet_cmd->addrs[index];
            bool b_found = false;
            struct ListNode *ptr = NULL;

            params[index].memref.buf_size = packet_cmd->cliContext.params[index].memref.size_addr;
            packet_cmd->cliContext.params[index].memref.size_addr = 
                (unsigned int)((uintptr_t)&params[index].memref.buf_size);
            packet_cmd->cliContext.params[index].memref.size_h_addr = 
                (unsigned int)((uint64_t)&params[index].memref.buf_size >> H_OFFSET);

            pthread_mutex_lock(&vm_fp->shrd_mem_lock);
            if (!LIST_EMPTY(&vm_fp->shrd_mem_head)) {
                LIST_FOR_EACH(ptr, &vm_fp->shrd_mem_head) {
                    struct_shrd_mem *shrd_mem =
                        CONTAINER_OF(ptr, struct_shrd_mem, node);
                    if (shrd_mem->vm_buffer == vm_buffer) {
                        vm_hvas[index] = packet_cmd->cliContext.params[index].memref.buffer
                            | (uint64_t)packet_cmd->cliContext.params[index].memref.buffer_h_addr << H_OFFSET;
                        /* Switch to the user address corresponding to the mmap space on the host. */
                        packet_cmd->cliContext.params[index].memref.buffer =
                            (unsigned int)(uintptr_t)shrd_mem->buffer;
                        packet_cmd->cliContext.params[index].memref.buffer_h_addr =
                            ((unsigned long long)(uintptr_t)shrd_mem->buffer) >> H_OFFSET;
                        icount++;
                        b_found = true;
                        break;
                    }
                }
            }
            pthread_mutex_unlock(&vm_fp->shrd_mem_lock);
            if (b_found == false) {
                tloge("can't find mmap buffer %p \n", vm_buffer);
                ret = -1;
                return ret;
            }
        } else if (IS_TEMP_MEM(paramTypes[index])) {
            params[index].memref.buf_size = packet_cmd->cliContext.params[index].memref.size_addr;
            packet_cmd->cliContext.params[index].memref.size_addr = 
                (unsigned int)((uintptr_t)&params[index].memref.buf_size);
            packet_cmd->cliContext.params[index].memref.size_h_addr = 
                (unsigned int)((uint64_t)&params[index].memref.buf_size >> H_OFFSET);
        } else if (IS_VALUE_MEM(paramTypes[index])) {
            params[index].value.val_a = packet_cmd->cliContext.params[index].value.a_addr;
            params[index].value.val_b = packet_cmd->cliContext.params[index].value.b_addr;

            packet_cmd->cliContext.params[index].value.a_addr = 
                (unsigned int)(uintptr_t)&params[index].value.val_a;
            packet_cmd->cliContext.params[index].value.a_h_addr = 
                (unsigned int)((uint64_t)&params[index].value.val_a >> H_OFFSET);
            packet_cmd->cliContext.params[index].value.b_addr = 
                (unsigned int)(uintptr_t)&params[index].value.val_b;
            packet_cmd->cliContext.params[index].value.b_h_addr = 
                (unsigned int)((uint64_t)&params[index].value.val_b >> H_OFFSET);
        } else if(IS_SHARED_MEM(paramTypes[index])) {
            uint32_t share_mem_size = packet_cmd->cliContext.params[index].memref.size_addr;
            struct_page_block *page_block = (struct_page_block *)((char *)packet_cmd + offset);
            uint32_t block_buf_size = packet_cmd->block_size[index];
            uint32_t tmp_buf_size = sizeof(struct_page_block) + packet_cmd->block_size[index];
            params[index].share.buf_size = tmp_buf_size;
            offset += packet_cmd->block_size[index];
            void *tmp_buf = malloc(tmp_buf_size);
            if (!tmp_buf) {
                tloge("malloc failed \n");
                return -ENOMEM;
            }
            ((struct_page_block *)tmp_buf)->share.shared_mem_size = share_mem_size;
            ((struct_page_block *)tmp_buf)->share.vm_page_size = packet_cmd->vm_page_size;
            struct_page_block *block_buf = (struct_page_block *)((char *)tmp_buf + sizeof(struct_page_block));
            if (memcpy_s((void *)block_buf, block_buf_size, (void *)page_block, block_buf_size) != 0) {
                tloge("memcpy_s failed \n");
                return -EFAULT;
            }
            params[index].share.buf = tmp_buf;
            packet_cmd->cliContext.params[index].memref.buffer = (unsigned int)(uintptr_t)tmp_buf;
            packet_cmd->cliContext.params[index].memref.buffer_h_addr = (unsigned int)((uint64_t)tmp_buf >> H_OFFSET);
            packet_cmd->cliContext.params[index].memref.size_addr = (unsigned int)(uintptr_t)&(params[index].share.buf_size);
            packet_cmd->cliContext.params[index].memref.size_h_addr = (unsigned int)((uint64_t)&(params[index].share.buf_size) >> H_OFFSET);
        }
    }// end for
    if (icount ==0) {
        packet_cmd->cliContext.file_buffer = NULL;
    }
    return ret;
}

static int process_address_sess(struct_packet_cmd_session *packet_cmd,
    ClientParam params[], struct vm_file *vm_fp)
{
    int index;
    int icount = 0;
    int ret = 0;
    uint32_t paramTypes[TEEC_PARAM_NUM];
    uint64_t *vm_hvas = (uint64_t *)packet_cmd->cliContext.file_buffer;
    uint32_t offset = sizeof(struct_packet_cmd_session);
    for (index = 0; index < TEEC_PARAM_NUM; index++) {
        paramTypes[index] =
            TEEC_PARAM_TYPE_GET(packet_cmd->cliContext.paramTypes, index);
        if (IS_PARTIAL_MEM(paramTypes[index])) {
            void *vm_buffer = (void *)packet_cmd->addrs[index];
            bool b_found = false;
            struct ListNode *ptr = NULL;

            params[index].memref.buf_size = packet_cmd->cliContext.params[index].memref.size_addr;
            packet_cmd->cliContext.params[index].memref.size_addr = 
                (unsigned int)((uintptr_t)&params[index].memref.buf_size);
            packet_cmd->cliContext.params[index].memref.size_h_addr = 
                (unsigned int)((uint64_t)&params[index].memref.buf_size >> H_OFFSET);

            pthread_mutex_lock(&vm_fp->shrd_mem_lock);
            if (!LIST_EMPTY(&vm_fp->shrd_mem_head)) {
                LIST_FOR_EACH(ptr, &vm_fp->shrd_mem_head) {
                    struct_shrd_mem *shrd_mem =
                        CONTAINER_OF(ptr, struct_shrd_mem, node);
                    if (shrd_mem->vm_buffer == vm_buffer) {
                        vm_hvas[index] = packet_cmd->cliContext.params[index].memref.buffer
                            | (uint64_t)packet_cmd->cliContext.params[index].memref.buffer_h_addr << H_OFFSET;
                        /* Switch to the user address corresponding to the mmap space on the host. */
                        packet_cmd->cliContext.params[index].memref.buffer =
                            (unsigned int)(uintptr_t)shrd_mem->buffer;
                        packet_cmd->cliContext.params[index].memref.buffer_h_addr =
                            ((unsigned long long)(uintptr_t)shrd_mem->buffer) >> H_OFFSET;
                        icount++;
                        b_found = true;
                        break;
                    }
                }
            }
            pthread_mutex_unlock(&vm_fp->shrd_mem_lock);
            if (b_found == false) {
                tloge("can't find mmap buffer %p \n", vm_buffer);
                ret = -1;
                return ret;
            }
        } else if (IS_TEMP_MEM(paramTypes[index])) {
            params[index].memref.buf_size = packet_cmd->cliContext.params[index].memref.size_addr;
            packet_cmd->cliContext.params[index].memref.size_addr = 
                (unsigned int)((uintptr_t)&params[index].memref.buf_size);
            packet_cmd->cliContext.params[index].memref.size_h_addr = 
                (unsigned int)((uint64_t)&params[index].memref.buf_size >> H_OFFSET);
        } else if (IS_VALUE_MEM(paramTypes[index])) {
            params[index].value.val_a = packet_cmd->cliContext.params[index].value.a_addr;
            params[index].value.val_b = packet_cmd->cliContext.params[index].value.b_addr;

            packet_cmd->cliContext.params[index].value.a_addr = 
                (unsigned int)(uintptr_t)&params[index].value.val_a;
            packet_cmd->cliContext.params[index].value.a_h_addr = 
                (unsigned int)((uint64_t)&params[index].value.val_a >> H_OFFSET);
            packet_cmd->cliContext.params[index].value.b_addr = 
                (unsigned int)(uintptr_t)&params[index].value.val_b;
            packet_cmd->cliContext.params[index].value.b_h_addr = 
                (unsigned int)((uint64_t)&params[index].value.val_b >> H_OFFSET);
        } else if(IS_SHARED_MEM(paramTypes[index])) {
            uint32_t share_mem_size = packet_cmd->cliContext.params[index].memref.size_addr;
            struct_page_block *page_block = (struct_page_block *)((char *)packet_cmd + offset);
            uint32_t block_buf_size = packet_cmd->block_size[index];
            uint32_t tmp_buf_size = sizeof(struct_page_block) + packet_cmd->block_size[index];
            params[index].share.buf_size = tmp_buf_size;
            offset += packet_cmd->block_size[index];
            void *tmp_buf = malloc(tmp_buf_size);
            if (!tmp_buf) {
                tloge("malloc failed \n");
                return -ENOMEM;
            }
            ((struct_page_block *)tmp_buf)->share.shared_mem_size = share_mem_size;
            ((struct_page_block *)tmp_buf)->share.vm_page_size = packet_cmd->vm_page_size;
            struct_page_block *block_buf = (struct_page_block *)((char *)tmp_buf + sizeof(struct_page_block));
            if (memcpy_s((void *)block_buf, block_buf_size, (void *)page_block, block_buf_size) != 0) {
                tloge("memcpy_s failed \n");
                return -EFAULT;
            }
            params[index].share.buf = tmp_buf;
            packet_cmd->cliContext.params[index].memref.buffer = (unsigned int)(uintptr_t)tmp_buf;
            packet_cmd->cliContext.params[index].memref.buffer_h_addr = (unsigned int)((uint64_t)tmp_buf >> H_OFFSET);
            packet_cmd->cliContext.params[index].memref.size_addr = (unsigned int)(uintptr_t)&(params[index].share.buf_size);
            packet_cmd->cliContext.params[index].memref.size_h_addr = (unsigned int)((uint64_t)&(params[index].share.buf_size) >> H_OFFSET);
        }
    }// end for
    if (icount ==0) {
        // packet_cmd->cliContext.file_buffer = NULL;
    }
    return ret;
}

static void process_address_end(struct_packet_cmd_send_cmd *packet_cmd, ClientParam params[])
{
    int index;
    uint32_t paramTypes[TEEC_PARAM_NUM];

    for (index = 0; index < TEEC_PARAM_NUM; index++) {
        paramTypes[index] =
            TEEC_PARAM_TYPE_GET(packet_cmd->cliContext.paramTypes, index);
        if (IS_PARTIAL_MEM(paramTypes[index])) {
            packet_cmd->cliContext.params[index].memref.size_addr = params[index].memref.buf_size;
        } else if (IS_TEMP_MEM(paramTypes[index])) {
            packet_cmd->cliContext.params[index].memref.size_addr = params[index].memref.buf_size;
        } else if (IS_VALUE_MEM(paramTypes[index])) {
            packet_cmd->cliContext.params[index].value.a_addr = params[index].value.val_a;
            packet_cmd->cliContext.params[index].value.b_addr = params[index].value.val_b;
        } else if(IS_SHARED_MEM(paramTypes[index])) {
            if (params[index].share.buf) {
                free(params[index].share.buf);
            }
        }
    }
}

static void process_address_end_sess(struct_packet_cmd_session *packet_cmd, ClientParam params[])
{
    int index;
    uint32_t paramTypes[TEEC_PARAM_NUM];

    for (index = 0; index < TEEC_PARAM_NUM; index++) {
        paramTypes[index] =
            TEEC_PARAM_TYPE_GET(packet_cmd->cliContext.paramTypes, index);
        if (IS_PARTIAL_MEM(paramTypes[index])) {
            packet_cmd->cliContext.params[index].memref.size_addr = params[index].memref.buf_size;
        } else if (IS_TEMP_MEM(paramTypes[index])) {
            packet_cmd->cliContext.params[index].memref.size_addr = params[index].memref.buf_size;
        } else if (IS_VALUE_MEM(paramTypes[index])) {
            packet_cmd->cliContext.params[index].value.a_addr = params[index].value.val_a;
            packet_cmd->cliContext.params[index].value.b_addr = params[index].value.val_b;
        } else if(IS_SHARED_MEM(paramTypes[index])) {
            if (params[index].share.buf) {
                free(params[index].share.buf);
            }
        }
    }
}

static void do_set_thread_id(struct fd_file *fd_p, unsigned int session_id, int flag)
{
    struct ListNode *ptr = NULL;
    if (!fd_p)
        return ;
    pthread_t current_thread;
    current_thread = flag > 0 ? pthread_self() : 0;
    pthread_mutex_lock(&fd_p->session_lock);
    if (!LIST_EMPTY(&fd_p->session_head)) {
        LIST_FOR_EACH(ptr, &fd_p->session_head) {
            struct session *sp = CONTAINER_OF(ptr, struct session, head);
            if (sp->session_id == session_id) {
                sp->thread_id = current_thread;
                break;
            }
        }
    }
    pthread_mutex_unlock(&fd_p->session_lock);
    if (flag)
        set_thread_session_id(&g_pool, pthread_self(), session_id);
    else
        set_thread_session_id(&g_pool, pthread_self(), 0);
}

static void set_thread_id(int ptzfd, unsigned int session_id, int flag, struct vm_file *vm_fp)
{
    struct fd_file *fd_p;
    if (!vm_fp) {
        tloge("vm_file is null\n");
        return;
    }
    fd_p  = find_fd_file(ptzfd, vm_fp);
    if (!fd_p) {
        tloge("found the fd %d 's fd_file failed\n", ptzfd);
        return;
    }
    do_set_thread_id(fd_p, session_id, flag);
}

static void send_cmd(struct_packet_cmd_send_cmd *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = -1;
    struct_packet_rsp_send_cmd packet_rsp;
    ClientParam params[TEEC_PARAM_NUM];
    void *vm_hvas[TEEC_PARAM_NUM] = {0};
    if (!serial_port->vm_file)
        return;
    packet_cmd->cliContext.file_buffer = (char *)vm_hvas;
    packet_cmd->cliContext.file_size = sizeof(void *) * TEEC_PARAM_NUM;

    if (!process_address(packet_cmd, params, serial_port->vm_file)) {
        set_thread_id(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, 1, serial_port->vm_file);
        ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SEND_CMD_REQ, &packet_cmd->cliContext);

        set_thread_id(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, 0, serial_port->vm_file);
        process_address_end(packet_cmd, params);
    }

    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = ret;
    packet_rsp.cliContext = packet_cmd->cliContext;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send_cmd send to VM failed \n");
    }
}

static void load_sec_file(struct_packet_cmd_load_sec *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_load_sec packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_LOAD_APP_REQ, &packet_cmd->ioctlArg);
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = ret;
    packet_rsp.ioctlArg = packet_cmd->ioctlArg;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp))
        tloge("load_sec_file send to VM failed \n");
}

static void vtz_dommap(struct_packet_cmd_mmap *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_mmap packet_rsp;
    struct_shrd_mem *tmp = NULL;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    void *buffer = mmap(0, (unsigned long)packet_cmd->size, (PROT_READ | PROT_WRITE), MAP_SHARED,
                            packet_cmd->ptzfd, (long)(packet_cmd->offset * (uint32_t)PAGE_SIZE));
    if (buffer == MAP_FAILED) {
        tloge("mmap failed\n");
        packet_rsp.ret = -ENOMEM;
        goto END;
    }
    packet_rsp.ret = ret;

    tmp = (struct_shrd_mem *)malloc(sizeof(struct_shrd_mem));
    ListInit(&tmp->node);
    tmp->buffer = buffer;
    tmp->vm_buffer = (void *)packet_cmd->buffer;
    tmp->buffer_size = (size_t)packet_cmd->size;
    tmp->dev_fd = packet_cmd->ptzfd;

    pthread_mutex_lock(&serial_port->vm_file->shrd_mem_lock);
    ListInsertTail(&(serial_port->vm_file->shrd_mem_head), &tmp->node);
    pthread_mutex_unlock(&serial_port->vm_file->shrd_mem_lock);
END:
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("vtz_dommap send to VM failed \n");
        pthread_mutex_lock(&serial_port->vm_file->shrd_mem_lock);
        ListRemoveEntry(&(tmp->node));
        pthread_mutex_unlock(&serial_port->vm_file->shrd_mem_lock);
        (void)munmap(tmp->buffer, tmp->buffer_size);
        free(tmp);
    }
}

static void vtz_dounmmap(struct_packet_cmd_mmap *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_mmap packet_rsp;
    void *buffer = NULL;
    uint32_t buffer_size;
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    pthread_mutex_lock(&(serial_port->vm_file->shrd_mem_lock));
    if (!LIST_EMPTY(&(serial_port->vm_file->shrd_mem_head))) {
        LIST_FOR_EACH_SAFE(ptr, n, &(serial_port->vm_file->shrd_mem_head)) {
            struct_shrd_mem *shrd_mem =
                CONTAINER_OF(ptr, struct_shrd_mem, node);
            if (shrd_mem->vm_buffer == (void *)packet_cmd->buffer) {
                ListRemoveEntry(&(shrd_mem->node));
                buffer = shrd_mem->buffer;
                buffer_size = shrd_mem->buffer_size;
                free(shrd_mem);
            }
        }
    }
    pthread_mutex_unlock(&(serial_port->vm_file->shrd_mem_lock));
    if (buffer != NULL) {
        ret = munmap(buffer, (size_t)buffer_size);
        if (ret) {
            tloge("Release SharedMemory failed, munmap error\n");
        }
    }
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("vtz_dounmmap send to VM failed \n");
    }
}

static void vtz_mmap(struct_packet_cmd_mmap *packet_cmd,
    struct serial_port_file *serial_port)
{
    if (packet_cmd->cmd == VTZ_MMAP) {
        vtz_dommap(packet_cmd, serial_port);
    } else {
        vtz_dounmmap(packet_cmd, serial_port);
    }
}

static void vtz_nothing(struct_packet_cmd_nothing *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_nothing packet_rsp = {0};
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = 0;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("vtz_nothing send to VM failed \n");
    }
}

static int register_teleport(uint32_t vm_id)
{
    pid_t pid = fork();
    if (pid == -1) {
        tloge("fork failed");
        return -1;
    } else if (pid == 0) {
        struct sigaction sa;
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = SIG_DFL;
        sa.sa_flags = 0;
        int signals[] = {SIGCHLD, SIGINT, SIGTERM, SIGSEGV, SIGABRT, SIGILL, SIGFPE, SIGPIPE, SIGUSR1};
        int sig_num = sizeof(signals) / sizeof(signals[0]);
        
        for (int i = 0; i < sig_num; i++) {
            int sig = signals[i];
            if (sigaction(sig, &sa, NULL) < 0) {
                tloge("vtz_proxy child: reset signal %d failed, errno=%d", sig, errno);
            }
        }
        sigset_t mask;
        sigemptyset(&mask);
        sigprocmask(SIG_SETMASK, &mask, NULL);

        char cmd_buf[1024];
        snprintf_s(cmd_buf, 1024, 1024, "tee_teleport --nsid=%u --containerid=$(cat /proc/%u/cmdline | tr '\\0' ' ' | egrep -o -- '-uuid [0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}' | sed 's/-uuid //' | tr -d '-' | awk '{print $0$0}') --config-container", vm_id, vm_id);
        char *args[] = {"sh", "-c", cmd_buf, NULL};
        execvp(args[0], args);
        exit(EXIT_FAILURE);
    } else {
        int status = -1;
        pid_t wait_ret;
        wait_ret = waitpid(pid, &status, 0);
        if (wait_ret == -1) {
            if (errno == ECHILD) {
                return 0;
            } else {
                tloge("waitpid failed! errno=%d, msg=%s, status is %d", errno, strerror(errno), status);
                return -1;
            }
        }
       if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            tlogi("tee_teleport exited normally, pid=%d, exit code=%d", pid, exit_code);
            return exit_code;
        } else if (WIFSIGNALED(status)) {
	          int sig = WTERMSIG(status);
            int coredump = WCOREDUMP(status);
            tloge("tee_teleport killed by signal! pid=%d, signal=%d, coredump: %d, status: 0x%x\n",pid, 
           sig, coredump, status);
            return -1;
        } else {
            tloge("tee_teleport exited for unknown reason, pid=%d", pid);
            return -1;
        }
    }
}

uint64_t vtz_translate_gpa(uint32_t cid, uint64_t gpa)
{
    struct vm_gpa_info vm_gpa;

    vm_gpa.cid = cid;
    vm_gpa.gpa = gpa;

    int ret = ioctl(g_private_dev_fd, TC_NS_CLIENT_IOCTL_TRANSLATE_GPA, &vm_gpa);
    if (ret != 0) {
        return 0;
    }

    return vm_gpa.gpa;
}

static unsigned int hash(pid_t pid)
{
    return (unsigned int)(pid % HASH_TABLE_SIZE);
}

static void insert_pid_hash(hash_table* ht, pid_t pid, int cid)
{
    unsigned int index = hash(pid);

    hash_node* new_node = (hash_node*)malloc(sizeof(hash_node));
    if (!new_node) {
        perror("malloc failed");
        return;
    }
    new_node->pid = pid;
    new_node->cid = cid;
    new_node->next = NULL;

    if (ht->buckets[index] == NULL) {
        ht->buckets[index] = new_node;
    } else {
        new_node->next = ht->buckets[index];
        ht->buckets[index] = new_node;
    }
}

static hash_node* query_hash_table(hash_table* ht, pid_t pid)
{
    unsigned int index = hash(pid);

    hash_node* current = ht->buckets[index];
    if (current != NULL) {
        while (current != NULL) {
            if (current->pid == pid)
                return current;
            current = current->next;
        }
    }
    return NULL;
}

void free_hash_table(hash_table* ht)
{
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        hash_node* current = ht->buckets[i];
        while (current != NULL) {
            hash_node* temp = current;
            current = current->next;
            free(temp);
        }
    }
}

static char cmdline_buffer[CMD_BUFFER_LEN];
static hash_table pid_hash_table = {0};
static bool is_euler = false;
#define PID_OF_QEMU_CMD1  "pidof qemu-system-aarch64"
#define PID_OF_QEMU_CMD2  "pidof qemu-kvm"

static void test_system_release(void)
{
    struct utsname system_info;
    char *euler = "euleros";

    if (uname(&system_info) == -1) {
        tloge("Error calling uname\n");
        return;
    }

    tlogi("system_info:%s\n", system_info.release);
    if (strstr(system_info.release, euler)) {
        is_euler = true;
    }
}

static int get_guest_cid(pid_t pid)
{
    int fd;
    char path[PROC_PATH_LEN] = {0};
    size_t bytes_read, scan_byte = 0;
    int cid = -1;
    char *pos, *search_key = "guest-cid";
    int offset = 1;

    if (is_euler)
        offset = 2;

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    bytes_read = read(fd, cmdline_buffer, sizeof(cmdline_buffer));
    close(fd);
    if (bytes_read <= 0)
        return -1;

    while (scan_byte < bytes_read) {
        pos = strstr(cmdline_buffer + scan_byte, search_key);
        if (pos != NULL) {
            char *endptr;
            long value;
            pos += strlen(search_key) + offset;
            value = strtol(pos, &endptr, 10);
            if (value < INT_MAX)
                cid = (int)value;
            if (endptr == pos)
                cid = -1;
        }
        scan_byte += strlen(cmdline_buffer + scan_byte) + 1;
    }

    return cid;
}

static int translate_cid_to_pid(uint32_t cid)
{
    int tmp_cid;
    char buffer[PID_BUFFER_LEN];
    FILE* fp;
    const char* command = PID_OF_QEMU_CMD1;

    if (is_euler)
        command = PID_OF_QEMU_CMD2;

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run command");
        return 1;
    }

    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        char* token = strtok(buffer, " \t\n");
        while (token != NULL) {
            pid_t pid = atoi(token);
            if (pid > 0) {
                hash_node* node = query_hash_table(&pid_hash_table, pid);
                if (!node) {
                    tmp_cid = get_guest_cid(pid);
                    if (tmp_cid > 0)
                        insert_pid_hash(&pid_hash_table, pid, tmp_cid);
                    if ((uint32_t)tmp_cid == cid) {
                        pclose(fp);
                        return pid;
                    }
                } else {
                    if ((uint32_t)node->cid == cid) {
                        pclose(fp);
                        return node->pid;
                    }
                }
            }
            token = strtok(NULL, " \t\n");
        }
    }
    pclose(fp);
    return -1;
}

static void vtz_register_nsid_vmid(struct_packet_cmd_open_tzd *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_open_tzd packet_rsp;
    struct_vm_group_info vm_info;
    uint32_t cid_to_vmid = serial_port->vm_file->cid;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.vmid = serial_port->vm_file->vmpid;
    serial_port->vm_file->nsid = packet_cmd->nsid;

    pthread_mutex_lock(&g_private_fd_lock);
    if (!g_private_dev_fd) {
        int fd = open(TC_TEECD_PRIVATE_DEV_NAME, O_RDWR);
        if (fd < 0) {
            tloge("open %s failed\n", TC_TEECD_PRIVATE_DEV_NAME);
            ret = -1;
            pthread_mutex_unlock(&g_private_fd_lock);
            goto END;
        }
        g_private_dev_fd = fd;
    }

    ret = translate_cid_to_pid(cid_to_vmid);
    pthread_mutex_unlock(&g_private_fd_lock);
    if (ret < 0) {
        tloge("vtz translate cid failed, cid = %u\n", cid_to_vmid);
        goto END;
    }
    cid_to_vmid = ret;
    tlogd("vtz translate cid succ, cid is %u, pid is %u.\n", serial_port->vm_file->cid, cid_to_vmid);
    serial_port->vm_file->vmpid = cid_to_vmid;

    vm_info.vmid = serial_port->vm_file->vmpid;
    vm_info.nsid = packet_cmd->nsid;
    ret = ioctl(g_private_dev_fd, TC_NS_CLIENT_IOCTL_REGISTER_VM_VMID_NSID, &vm_info);
    if (ret != 0) {
        tloge("vtz register nsid vmid failed, vmid = %u, nsid = %u, ret = %d, serial_port %p\n",\
            serial_port->vm_file->vmpid, packet_cmd->nsid, ret, serial_port);
        goto END;
    }

    ret = register_teleport(serial_port->vm_file->vmpid);
    if (ret != 0) {
	    tloge("register teleport failed, vmpid is %u, ret is %d, serial_port %p", \
        serial_port->vm_file->vmpid, ret, serial_port);
        goto END;
    }

END:
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("vtz register nsid vmid send to vm failed\n");
    }
    return;
}

static int do_vcpu_mapping(uint64_t worker_attr_hva, struct vm_file *vm_file)
{
    struct map_vcpu_info args;
    args.cpu_set_addr = worker_attr_hva + CPU_SET_OFFSET;
    args.cpu_set_size = sizeof(cpu_set_t);
    args.vmpid = vm_file->vmpid;
    int ret = 0;

    ret = ioctl(g_private_dev_fd, TC_NS_CLIENT_IOCTL_MAP_VCPU, &args);
    if (ret != 0) {
        tloge("ioctl map vcpu failed, ret=%d\n", ret);
        return ret;
    }
    tlogi("map vcpu success, ret is %d\n", ret);
    return ret;
}

static void translate_vm_addr(char *rd_buf, struct vm_file *vm_file)
{
    uint32_t ui32_cmd = *(uint32_t *)(rd_buf + sizeof(uint32_t));
    struct_page_block *page_block;
    uint32_t param_type, i, fragment_block_num;
    uint64_t gpa, hva;
    struct_packet_cmd_regagent *packet_cmd1;
    struct_packet_cmd_session * packet_cmd2;
    struct_packet_cmd_send_cmd * packet_cmd3;
    struct_packet_cmd_load_sec *packet_cmd;

    switch (ui32_cmd) {
    case VTZ_LOAD_SEC:
        packet_cmd = (struct_packet_cmd_load_sec *)rd_buf;
        packet_cmd->ioctlArg.fileBuffer = (char *)vtz_translate_gpa(vm_file->cid, (uint64_t)packet_cmd->ioctlArg.fileBuffer);
        break;
    case VTZ_FS_REGISTER_AGENT:
        packet_cmd1 = (struct_packet_cmd_regagent *)rd_buf;
        packet_cmd1->vmaddr = (void *)vtz_translate_gpa(vm_file->cid, (uint64_t)packet_cmd1->vmaddr);
        break;
    case VTZ_OPEN_SESSION:
        packet_cmd2 = (struct_packet_cmd_session *)rd_buf;
        gpa = (uint64_t)packet_cmd2->cliContext.file_buffer;
        packet_cmd2->cliContext.file_buffer = (char *)vtz_translate_gpa(vm_file->cid, gpa);
        for (i = 0; i < TEEC_PARAM_NUM; i++) {
            param_type = TEEC_PARAM_TYPE_GET(packet_cmd2->cliContext.paramTypes, i);
            if (IS_TEMP_MEM(param_type) || IS_PARTIAL_MEM(param_type)) {
                gpa = (uint64_t)packet_cmd2->cliContext.params[i].memref.buffer |
                    (uint64_t)packet_cmd2->cliContext.params[i].memref.buffer_h_addr << H_OFFSET;
                hva = vtz_translate_gpa(vm_file->cid, gpa);
                packet_cmd2->cliContext.params[i].memref.buffer = (unsigned int)hva;
                packet_cmd2->cliContext.params[i].memref.buffer_h_addr = (unsigned int)(hva >> H_OFFSET);
            }
        }
        uint32_t param_type_0 = TEEC_PARAM_TYPE_GET(packet_cmd2->cliContext.paramTypes, 0);
        uint32_t param_type_1 = TEEC_PARAM_TYPE_GET(packet_cmd2->cliContext.paramTypes, 1);
        if (param_type_0 == TEEC_MEMREF_REGISTER_INOUT &&
            param_type_1 == TEEC_MEMREF_TEMP_INPUT &&
            get_global_config()->use_vcpuset) {
            uint64_t worker_attr_hva = (uint64_t)packet_cmd2->cliContext.params[1].memref.buffer |
                (uint64_t)packet_cmd2->cliContext.params[1].memref.buffer_h_addr << H_OFFSET;
            if (worker_attr_hva != 0) {
                do_vcpu_mapping(worker_attr_hva, vm_file);
            }
        }
        fragment_block_num = packet_cmd2->total_fragment_block_num;
        if (fragment_block_num) {
            page_block = (struct_page_block *)((char *)packet_cmd2 + sizeof(struct_packet_cmd_session));
            for(uint32_t j = 0; j < fragment_block_num; j++) {
                gpa= page_block[j].block.user_addr;
                page_block[j].block.user_addr = vtz_translate_gpa(vm_file->cid, gpa);
                if (!page_block[j].block.user_addr)
                   tloge("VTZ_OPEN_SESSION translate addr fail\n");
            }
        }
        break;
    case VTZ_SEND_CMD:
        packet_cmd3 = (struct_packet_cmd_send_cmd *)rd_buf;
        for (i = 0; i < TEEC_PARAM_NUM; i++) {
            param_type = TEEC_PARAM_TYPE_GET(packet_cmd3->cliContext.paramTypes, i);
            if (IS_TEMP_MEM(param_type) || IS_PARTIAL_MEM(param_type)) {
                gpa = (uint64_t)packet_cmd3->cliContext.params[i].memref.buffer |
                    (uint64_t)packet_cmd3->cliContext.params[i].memref.buffer_h_addr << H_OFFSET;
                hva = vtz_translate_gpa(vm_file->cid, gpa);
                packet_cmd3->cliContext.params[i].memref.buffer = (unsigned int)hva;
                packet_cmd3->cliContext.params[i].memref.buffer_h_addr = (unsigned int)(hva >> H_OFFSET);
            }
        }
        fragment_block_num = packet_cmd3->total_fragment_block_num;
        if (fragment_block_num) {
            page_block = (struct_page_block *)((char *)packet_cmd3 + sizeof(struct_packet_cmd_send_cmd));
            for(uint32_t j = 0; j < fragment_block_num; j++) {
                gpa= page_block[j].block.user_addr;
                page_block[j].block.user_addr = vtz_translate_gpa(vm_file->cid, gpa);
                if (!page_block[j].block.user_addr)
                   tloge("VTZ_SEND_CMD translate addr fail\n");
            }
        }
        break;
    default:
        break;
    }
}

void *thread_entry(void *args)
{
    struct_packet_cmd_general *packet_general = NULL;
    uint32_t ui32_cmd = 0;
    vm_trace_data *data = (vm_trace_data *)args;
    struct serial_port_file *serial_port = (struct serial_port_file *)data->serial_port_ptr;
    char *rd_buf = (char *)(args) + sizeof(vm_trace_data);
    ui32_cmd = *(uint32_t *)(rd_buf + sizeof(uint32_t));

    struct vm_file *vm_fp = serial_port->vm_file;
    struct worker *worker_p = (struct worker *)malloc(sizeof(struct worker));
    ListInit(&worker_p->head);
    pthread_mutex_lock(&vm_fp->workers_lock);
    worker_p->tid = pthread_self();
    ListInsertTail(&vm_fp->workers_head, &worker_p->head);
    pthread_mutex_unlock(&vm_fp->workers_lock);

    struct_packet_cmd_nothing *p = (struct_packet_cmd_nothing *)rd_buf;
    tlogd("worker_p tid %lu, vm %u cmd %u, size %u, seq %u\n", worker_p->tid, data->vmid, p->cmd, p->packet_size, p->seq_num);

    if (ui32_cmd == VTZ_REGISTER_VM_VMID_NSID) {
        (void)vtz_register_nsid_vmid((struct_packet_cmd_open_tzd *)rd_buf, serial_port);
        goto END;
    }

    if (ui32_cmd == VTZ_OPEN_TZD) {
        (void)open_tzdriver((struct_packet_cmd_open_tzd *)rd_buf, serial_port);
        goto END;
    }

    if (ui32_cmd == VTZ_NOTHING) {
        (void)vtz_nothing((struct_packet_cmd_nothing *)rd_buf, serial_port);
        goto END;
    }

    packet_general = (struct_packet_cmd_general *)rd_buf;
    if (!serial_port || !packet_general ||
        !find_fd_file(packet_general->ptzfd, serial_port->vm_file)) {
        tloge("invalid params\n");
        goto END;
    }

    translate_vm_addr(rd_buf, serial_port->vm_file);
    switch (ui32_cmd) {
    case VTZ_CLOSE_TZD:
        (void)close_tzdriver((struct_packet_cmd_close_tzd *)rd_buf, serial_port);
        break;
    case VTZ_LOG_IN_NHIDL:
        (void)log_in_NonHidl((struct_packet_cmd_login_non *)rd_buf, serial_port);
        break;
    case VTZ_GET_TEE_VERSION:
        (void)get_tee_ver((struct_packet_cmd_getteever *)rd_buf, serial_port);
        break;
    case VTZ_GET_TEE_INFO:
        (void)get_tee_info((struct_packet_cmd_getteeinfo *)rd_buf, serial_port);
        break;
    case VTZ_LATE_INIT:
        break;
    case VTZ_SYNC_TIME:
        (void)sync_sys_time((struct_packet_cmd_synctime *)rd_buf, serial_port);
        break;
    case VTZ_LOG_IN:
        (void)log_in((struct_packet_cmd_login *)rd_buf, serial_port);
        break;
    case VTZ_LOAD_SEC:
        (void)load_sec_file((struct_packet_cmd_load_sec *)rd_buf, serial_port);
        break;
    case VTZ_OPEN_SESSION:
        (void)open_session((struct_packet_cmd_session *)rd_buf, serial_port);
        break;
    case VTZ_CLOSE_SESSION:
        (void)close_session((struct_packet_cmd_session *)rd_buf, serial_port);
        break;
    case VTZ_SEND_CMD:
        (void)send_cmd((struct_packet_cmd_send_cmd *)rd_buf, serial_port);
        break;
    case VTZ_FS_REGISTER_AGENT:
        (void)register_agent((struct_packet_cmd_regagent *)rd_buf, serial_port);
        break;
    case VTZ_WAIT_EVENT:
        (void)wait_event((struct_packet_cmd_event *)rd_buf, serial_port);
        break;
    case VTZ_SEND_EVENT_RESPONSE:
        (void)sent_event_response((struct_packet_cmd_event *)rd_buf, serial_port);
        break;
    case VTZ_MMAP:
    case VTZ_MUNMAP:
        (void)vtz_mmap((struct_packet_cmd_mmap *)rd_buf, serial_port);
        break;
    case VTZ_GET_TEEOS_VER:
    case VTZ_SET_READER_CUR:
    case VTZ_SET_TLOGCAT_STAT:
    case VTZ_GET_TLOGCAT_STAT:
    case VTZ_GET_LOG:
        (void)tlog(ui32_cmd, (void *)rd_buf, serial_port);
        break;
    default:
        tloge("invalid cmd %d\n", ui32_cmd);
        break;
    }

END:
    if (args)
        free(args);

    pthread_mutex_lock(&vm_fp->workers_lock);
    ListRemoveEntry(&(worker_p->head));
    pthread_mutex_unlock(&vm_fp->workers_lock);
    free(worker_p);
    return NULL;
}

int main() {
    int ret = 0;
    if (acquire_singleton_lock() != 0) { 
        tloge("acquire_singleton_lock failed"); 
        return -1; 
    }

    if (register_signal_handlers() != 0) {
        tloge("register signal handlers failed, exit");
        return -1;
    }

    test_system_release();
    /* Initialize configuration (must be before thread_pool_init) */
    config_init();
    VtzConfig *cfg = get_global_config();
    int serial_port_num = cfg->max_vm_count;

    serial_port_list_init();
    pthread_mutex_init(&g_private_fd_lock, NULL);
    if (thread_pool_init(&g_pool))
        goto END2;
    if (check_stat_serial_port_first())
        goto END1;

    while (1) {
        do_check_stat_serial_port();
        ret = safepoll(g_pollfd, serial_port_num, 2*1000);
        if (ret <= 0) {
            continue;
        }
        for (int i = 0; i < serial_port_num; i++) {
            // when vm restart quickly, use poll can capture this event
            if (g_pollfd[i].revents & (POLLERR|POLLHUP|POLLRDHUP)) {
                tlogi("vm %d got POLLHUP event, release vm\n", i);
		        g_pollfd[i].revents = 0;
            }
        }

    }

END1:
    if (g_private_dev_fd > 0)
        close(g_private_dev_fd);
    thread_pool_destroy(&g_pool);
END2:
    serial_port_list_destroy();
    return 0;
}
