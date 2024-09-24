#include "vtzb_proxy.h"
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

ThreadPool g_pool = {0};
extern struct pollfd g_pollfd[SERIAL_PORT_NUM];
extern struct serial_port_file *g_serial_array[SERIAL_PORT_NUM];

static void open_tzdriver(struct_packet_cmd_open_tzd *packet_cmd,
    struct serial_port_file *serial_port)
{
    int fd = -1;
    int ret;
    struct_packet_rsp_open_tzd packet_rsp;
    struct vm_file *vm_fp = NULL;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.vmid = packet_cmd->vmid;

    if (packet_cmd->flag == TLOG_DEV_THD_FLAG) {
        if (!serial_port->vm_file || !serial_port->vm_file->log_fd) {
            fd = open(TC_LOGGER_DEV_NAME, O_RDONLY);
            ret = ioctl(fd, TEELOGGER_SET_VM_FLAG, packet_cmd->vmid);
        } else {
            fd = serial_port->vm_file->log_fd;
        }
    } else if(packet_cmd->flag == TLOG_DEV_FLAG) {
            fd = open(TC_LOGGER_DEV_NAME, O_RDONLY);
            ret = ioctl(fd, TEELOGGER_SET_VM_FLAG, packet_cmd->vmid);
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
            ret = ioctl(fd, TC_NS_CLIENT_IOCTL_SET_VM_FLAG, packet_cmd->vmid);
    }

    tlogv("vmid %d flag %d open tzdriver, fd %d\n", packet_cmd->vmid, packet_cmd->flag, fd);
    packet_rsp.ptzfd = fd;
    if (fd < 0) {
        tloge("open tee client dev failed, fd is %d\n", fd);
        packet_rsp.ret = fd;
        goto END;
    }
    packet_rsp.ret = 0;

END:
    if (fd > 0) {
        if (!serial_port->vm_file) {
            vm_fp = create_vm_file(packet_cmd->vmid);
            serial_port->vm_file = vm_fp;
        } else {
            vm_fp = serial_port->vm_file;
        }
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

    free_agent_buf(packet_cmd->ptzfd, serial_port->vm_file);
    ret = remove_fd(packet_cmd->ptzfd, serial_port->vm_file);

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
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    index = set_start_time(pthread_self(), packet_cmd->seq_num, serial_port);
    if (!process_address_sess(packet_cmd, params, serial_port->vm_file)) {
        set_thread_id(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, 1, serial_port->vm_file);
        ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SES_OPEN_REQ, &packet_cmd->cliContext);
        
        set_thread_id(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, 0, serial_port->vm_file);
        process_address_end_sess(packet_cmd, params);
    }
    remove_start_time(index);
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


void *thread_entry(void *args)
{
    struct_packet_cmd_general *packet_general = NULL;
    uint32_t ui32_cmd = 0;
    vm_trace_data *data = (vm_trace_data *)args;
    struct serial_port_file *serial_port = (struct serial_port_file *)data->serial_port_ptr;
    char *rd_buf = (char *)(args) + sizeof(vm_trace_data);
    ui32_cmd = *(uint32_t *)(rd_buf + sizeof(uint32_t));

    struct_packet_cmd_nothing *p = (struct_packet_cmd_nothing *)rd_buf;
    tlogd("vm %u cmd %u, size %u, seq %u\n", data->vmid, p->cmd, p->packet_size, p->seq_num);

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
    return NULL;
}

void proc_event(struct serial_port_file *serial_port)
{
    int ret;
    int offset = 0;
    int buf_len;
    int fd;

    if (!serial_port || !serial_port->rd_buf || serial_port->sock <= 0) {
        tloge("serial_port ptr or rd_buf is NULL!\n");
        return;
    }
    fd = serial_port->sock;
    ret = read(fd, serial_port->rd_buf + serial_port->offset, BUF_LEN_MAX_RD - serial_port->offset);
    if (ret < 0) {
        tloge("read domain socket failed \n");
        return;
    }
    if (ret == 0)
        return;
    buf_len = ret + serial_port->offset;
    while (1) {
        void *packet = NULL;
        packet = get_packet_item(serial_port->rd_buf, buf_len, &offset);
        if (packet == NULL)
            break;
        
        vm_trace_data *data = (vm_trace_data *)packet;
        data->serial_port_ptr = (uint64_t)serial_port;
        data->vmid = serial_port->index;
        thread_pool_submit(&g_pool, thread_entry, (void *)((uint64_t)packet));
    }
    serial_port->offset = offset;
}

int main() {
    int ret = 0;
    int i;
    serial_port_list_init();
    if (thread_pool_init(&g_pool))
        goto END2;
    if (check_stat_serial_port_first())
        goto END1;

    while (1) {
        check_stat_serial_port();
        ret = safepoll(g_pollfd, SERIAL_PORT_NUM, 20*1000);
        if (ret <= 0) {
            tlogv("pollfd no event or failed, ret = %d\n", ret);
            continue;
        }
        
        tlogv("poll receive event %d\n", ret);
        for (i = 0; i < SERIAL_PORT_NUM; i++) {
            if (g_pollfd[i].revents == 0) {
                continue;
            }

            tlogv("vm %d, event %x, fd %d\n", i, g_pollfd[i].revents, g_pollfd[i].fd);
            if (g_pollfd[i].revents & POLLIN) {
                proc_event(g_serial_array[i]);
            }

            if (g_pollfd[i].revents & POLLERR ||
                g_pollfd[i].revents & POLLNVAL) {
                tloge("vm %d got error event\n", i);
                continue;
            }

            if (g_pollfd[i].revents & POLLHUP) {
                tloge("vm %d got POLLHUP event\n", i);
                release_vm_file(g_serial_array[i], i);
            }
        }
    }

END1:
    thread_pool_destroy(&g_pool);
END2:
    serial_port_list_destroy();
    return 0;
}
