/*
 */

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

ThreadPool g_pool;
LIST_DECLARE(g_shrd_mem_list);

LIST_DECLARE(g_vm_list);
pthread_mutex_t g_mutex_shrd_mem = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_mutex_vm = PTHREAD_MUTEX_INITIALIZER;


pthread_mutex_t g_mutex_log_ver = PTHREAD_MUTEX_INITIALIZER;
int g_count = 0;

extern int g_pollfd_len;
extern struct pollfd g_pollfd[SERIAL_PORT_NUM];

typedef union {
    struct{
        uint64_t phy_addr;
        uint64_t page_num;
    }block;
    struct{
        uint64_t first_page_offset;
        uint64_t shared_mem_size;        
    }share;
}struct_page_block;

static struct vm_file *get_vm_file(uint32_t vmid)
{
    bool isfind = false;
    struct ListNode *ptr = NULL;
    struct vm_file *tmp = NULL;
    pthread_mutex_lock(&g_mutex_vm);
    if (!LIST_EMPTY(&g_vm_list)) {
        LIST_FOR_EACH(ptr, &g_vm_list) {
            tmp = CONTAINER_OF(ptr, struct vm_file, head);
            if (tmp->vmpid == vmid) {
                isfind = true;
                break;
            }
        }
    }

    if (!isfind) {
        tmp = (struct vm_file *)malloc(sizeof(struct vm_file));
        if (!tmp) {
            tloge("Failed to allocate memory for vm_file\n");
            goto END;
        }
        pthread_mutex_init(&tmp->fd_lock, NULL);
        pthread_mutex_init(&tmp->agents_lock, NULL);
        ListInit(&tmp->head);
        ListInit(&tmp->fds_head);
        ListInit(&tmp->agents_head);
        tmp->vmpid = vmid;
        ListInsertTail(&g_vm_list, &tmp->head);
    }
END:
    pthread_mutex_unlock(&g_mutex_vm);
    return tmp;
}

static void add_fd_list(int fd, struct vm_file *vm_fp)
{
    struct fd_file *tmp = (struct fd_file *)malloc(sizeof(struct fd_file));
    if (!tmp || !vm_fp)
        return ;
    tmp->ptzfd = fd;
    pthread_mutex_init(&tmp->session_lock, NULL);
    ListInit(&tmp->session_head);
    ListInit(&tmp->head);

    pthread_mutex_lock(&vm_fp->fd_lock);
    ListInsertTail(&vm_fp->fds_head, &tmp->head);
    pthread_mutex_unlock(&vm_fp->fd_lock);
}

static struct fd_file *find_fd_file(int ptzfd, struct vm_file *vm_fp)
{
    struct ListNode *ptr = NULL;
    struct fd_file *fd_p = NULL;
    struct fd_file *result = NULL;
    if (!vm_fp)
        return NULL;
    pthread_mutex_lock(&vm_fp->fd_lock);
    if (!LIST_EMPTY(&vm_fp->fds_head)) {
        LIST_FOR_EACH(ptr, &vm_fp->fds_head) {
            fd_p = CONTAINER_OF(ptr, struct fd_file, head);
            if (fd_p->ptzfd == ptzfd) {
                result = fd_p;
                break;
            }
        }
    }
    pthread_mutex_unlock(&vm_fp->fd_lock);
    return result;
}

void *kill_Zombie(void *args)
{
    pthread_t tid = (pthread_t)args;
    debug("before handle kill|cncel thread \n");
    pthread_detach(tid);
    int result = pthread_kill(tid, SIGUSR1);
    debug("result = %d \n", result);
    if (result == 0) {
        pthread_join(tid, NULL);
        replenish_thread_pool(&g_pool, tid);
    } else {
        debug("pthread_kill fail \n");
    }  
    debug("after handle kill|cncel thread \n");
    return NULL;
}

static void close_remove_session(struct fd_file *fd_p)
{
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    unsigned int session_id;
    if (!fd_p)
        return ;
    debug(" will close_remove_session\n ");
    pthread_mutex_lock(&fd_p->session_lock);
    if (!LIST_EMPTY(&fd_p->session_head)) {
        LIST_FOR_EACH_SAFE(ptr, n, &fd_p->session_head) {
            struct session *sp = CONTAINER_OF(ptr, struct session, head);
            ListRemoveEntry(&(sp->head));

            if (sp->thread_id != 0) {
                session_id = get_thread_session_id(&g_pool, sp->thread_id);
                debug("close_remove_session session_id = %u , th_session_id = %u \n", sp->session_id, session_id);
                if (session_id == sp->session_id)
                    thread_pool_submit(&g_pool, kill_Zombie, (void *)(sp->thread_id));
            }
            free(sp);
        }
    }
    pthread_mutex_unlock(&fd_p->session_lock);

}

static void remove_fd_list(int ptzfd, struct vm_file *vm_fp)
{
    if (!vm_fp)
        return;
    struct fd_file *fd_p = find_fd_file(ptzfd, vm_fp);
    if (fd_p) {
        close_remove_session(fd_p);		
    }
}

static void open_tzdriver(struct_packet_cmd_open_tzd *packet_cmd,
    struct serial_port_file *serial_port)
{
    debug("*****cmd is open_tzdriver*****\n");
    int fd = -1;
    int ret;
    struct_packet_rsp_open_tzd packet_rsp;
    struct vm_file* vm_fp = NULL;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    debug("packet_cmd->flag =%d \n",packet_cmd->flag);
    if (packet_cmd->flag == TLOG_DEV_FLAG) {
        fd = open(TC_LOGGER_DEV_NAME, O_RDONLY);
        ret = ioctl(fd, TEELOGGER_SET_VM_FLAG, packet_cmd->vmid);
    } else {
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

    packet_rsp.ptzfd = fd;
    if (fd < 0) {
        tloge("open tee client dev failed, fd is %d\n", fd);
        packet_rsp.ret = fd;
        goto END;
    }
    packet_rsp.ret = 0;
    debug("    ptzfd           = %d \n", packet_rsp.ptzfd);
    debug("    qemu_pid|vmid   = %d \n", packet_cmd->vmid);

END:
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
        if (fd > 0)
            (void)close(fd);
    }
    if (fd > 0 && ret == sizeof(packet_rsp)) {
        if (!serial_port->vm_file) {
            vm_fp = get_vm_file(packet_cmd->vmid);
            serial_port->vm_file = vm_fp;
        } else {
            vm_fp = serial_port->vm_file;
        }
        add_fd_list(fd, vm_fp);
    }
}


static void close_tzdriver(struct_packet_cmd_close_tzd *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = -1;
    debug("*****cmd is close TZdriver***** \n");
    struct_packet_rsp_close_tzd packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = 0;
    (void)ret;
    if (!serial_port->vm_file)
        return;
    if (packet_cmd->ptzfd > 2){
        debug("    ptzfd           = %d \n", packet_cmd->ptzfd);

        free_agent_buf(packet_cmd->ptzfd, serial_port->vm_file);
        debug("    after free_agent_buf\n");

        ret = close(packet_cmd->ptzfd);		
        debug("close ret = %d \n", ret);

        remove_fd_list(packet_cmd->ptzfd, serial_port->vm_file);
    }
    
    if (send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp)) != sizeof(packet_rsp)) {
        tloge("close ptzfd send to VM failed \n");
    }
}

static void log_in_NonHidl(struct_packet_cmd_login_non *packet_cmd, 
    struct serial_port_file *serial_port)
{
    debug("*****cmd is log_in_nonhidl \n");
    int ret;
    struct_packet_rsp_login packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_LOGIN, NULL);
    packet_rsp.ret = ret;

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }	
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
    debug("***** cmd is login ***** \n");
    debug("    ptzfd           = %d \n", packet_cmd->ptzfd);
    debug("    ret             = %d \n", ret);
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
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
    debug("***** cmd is get ver ***** \n");
    debug("    ptzfd           = %d \n", packet_cmd->ptzfd);
    debug("    ret             = %d \n", ret);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
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
   debug("***** cmd is get tee info ***** \n");
    debug("    ptzfd           = %d \n", packet_cmd->ptzfd);
    debug("    ret             = %d \n", ret);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
}

static void SyncSysTime(struct_packet_cmd_synctime *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_synctime packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SYC_SYS_TIME, &packet_cmd->tcNsTime);
    packet_rsp.ret = ret;
    debug("***** cmd is SyncSysTime *****\n");
    debug("    ptzfd           = %d \n", packet_cmd->ptzfd);
    debug("    ret             = %d \n", ret);
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
}

static void add_session_list(int ptzfd, TC_NS_ClientContext *clicontext)
{
    bool isfind = false;
    struct ListNode *ptr = NULL;
    struct ListNode *ptr1 = NULL;
    struct vm_file *tmp = NULL;
    struct fd_file *fd_p = NULL;

    struct session *sessionp = (struct session *)malloc(sizeof(struct session)); 
    if (!sessionp)
        return ;
    sessionp->session_id = clicontext->session_id;
    sessionp->cliContext = *clicontext;
    debug("uuid = %x \n", sessionp->cliContext.uuid);
    ListInit(&sessionp->head);

    pthread_mutex_lock(&g_mutex_vm);
    if (!LIST_EMPTY(&g_vm_list)) {
        LIST_FOR_EACH(ptr, &g_vm_list) {
            tmp = CONTAINER_OF(ptr, struct vm_file, head);
            pthread_mutex_lock(&tmp->fd_lock);
            if (!LIST_EMPTY(&tmp->fds_head)) {
                LIST_FOR_EACH(ptr1, &tmp->fds_head) {
                    fd_p = CONTAINER_OF(ptr1, struct fd_file, head);
                    if (fd_p->ptzfd == ptzfd) {
                        isfind = true;
                        debug("add session \n");
                        ListInsertTail(&fd_p->session_head, &sessionp->head);
                        break;
                    }
                }
            }
            pthread_mutex_unlock(&tmp->fd_lock);
            if (isfind)
                break;
        }
    }
    pthread_mutex_unlock(&g_mutex_vm); 
}

static void doremove_session(unsigned int session_id, struct fd_file *fd_p)
{
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    if (!fd_p)
        return ;
    pthread_mutex_lock(&fd_p->session_lock);
    if (!LIST_EMPTY(&fd_p->session_head)) {
        LIST_FOR_EACH_SAFE(ptr, n, &fd_p->session_head) {
            struct session *sp = CONTAINER_OF(ptr, struct session, head);
            if (sp->session_id == session_id) {
                debug("remove session \n");
                ListRemoveEntry(&(sp->head));
                free(sp);
            }
        }
    }
    pthread_mutex_unlock(&fd_p->session_lock);	
}

static void remove_session_list(int ptzfd, int session_id, struct vm_file *vm_fp)
{
    struct fd_file *fd_p = NULL;
    if (!vm_fp)
        return;
    fd_p = find_fd_file(ptzfd, vm_fp);
    if (fd_p) {
        doremove_session(session_id, fd_p);		
    }
}

static void open_session(struct_packet_cmd_session *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_session packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    debug("***** cmd is open session *****\n");
    debug("    cliContext.login.method = %d\n",packet_cmd->cliContext.login.method);
    debug("    cliContext.file_size = %d \n ", packet_cmd->cliContext.file_size);
    debug("    cliContext.file_buffer = %p \n ", packet_cmd->cliContext.file_buffer);

    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SES_OPEN_REQ, &packet_cmd->cliContext);
    packet_rsp.ret = ret;
    packet_rsp.cliContext = packet_cmd->cliContext;
    debug("    ptzfd            = %d \n", packet_cmd->ptzfd);
    debug("    ret              = %d \n", ret);
    debug("    session_id       = %d \n",packet_rsp.cliContext.session_id);

    if (ret == 0)
        add_session_list(packet_cmd->ptzfd, &packet_rsp.cliContext);

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
        return ;
    }
}

static void close_session(struct_packet_cmd_session *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_general packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ, &packet_cmd->cliContext);
    packet_rsp.ret = ret;
    debug("***** cmd is close session *****\n");
    debug("    ptzfd            = %d \n", packet_cmd->ptzfd);	
    debug("    ret              = %d \n", ret);
    debug("    uuid = %x \n",packet_cmd->cliContext.uuid);

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
    remove_session_list(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, serial_port->vm_file);
}

static int process_address(struct_packet_cmd_send_cmd *packet_cmd, ClientParam params[])
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
            void* vm_buffer = (void*)packet_cmd->addrs[index];
            bool b_found = false;
            struct ListNode* ptr = NULL;

            params[index].memref.buf_size = packet_cmd->cliContext.params[index].memref.size_addr;
            packet_cmd->cliContext.params[index].memref.size_addr = 
                (unsigned int)((uintptr_t)&params[index].memref.buf_size);
            packet_cmd->cliContext.params[index].memref.size_h_addr = 
                (unsigned int)((uint64_t)&params[index].memref.buf_size >> H_OFFSET);

            pthread_mutex_lock(&g_mutex_shrd_mem);
            if (!LIST_EMPTY(&g_shrd_mem_list)) {
                LIST_FOR_EACH(ptr, &g_shrd_mem_list) {
                    struct_shrd_mem* shrd_mem =
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
            pthread_mutex_unlock(&g_mutex_shrd_mem);
            if (b_found == false) {
                tloge("can't find mmap buffer %p \n", vm_buffer);
                debug("can't find mmap buffer %p \n", vm_buffer);
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
            uint32_t block_nums = packet_cmd->block_size[index] / sizeof(struct_page_block);
            struct_page_block *page_block = (struct_page_block *)((char *)packet_cmd + offset);
            /* 第一个struct_page_block 存放shared mem 的size信息，后面的才是block buf*/
            uint32_t block_buf_size = packet_cmd->block_size[index];
            uint32_t tmp_buf_size = sizeof(struct_page_block) + packet_cmd->block_size[index];
            offset += packet_cmd->block_size[index];
            for(uint32_t j = 0; j < block_nums; j++) {
                debug("page_block[%u].block.phy_addr = 0x%llx\n", j, page_block[j].block.phy_addr);
                debug("page_block[%u].block.page_num = 0x%llx\n", j, page_block[j].block.page_num);
            }
            void *tmp_buf = malloc(tmp_buf_size);
            if (!tmp_buf) {
                debug("malloc failed \n");
                tloge("malloc failed \n");
                return -ENOMEM;
            }
            ((struct_page_block *)tmp_buf)->share.shared_mem_size = share_mem_size;
            debug("share mem size = %u \n", ((struct_page_block *)tmp_buf)->share.shared_mem_size);
            debug("shared mem first page offset = %u\n", packet_cmd->cliContext.params[index].memref.h_offset);
            debug("shared mem offset = %u\n", packet_cmd->cliContext.params[index].memref.offset);
            void * block_buf = (void *)((char *)tmp_buf + sizeof(struct_page_block));
            if (memcpy_s(block_buf, block_buf_size, (void *)page_block, block_buf_size) != 0) {
                tloge("memcpy_s failed \n");
                debug("memcpy_s failed \n");
                return -EFAULT;
            }
            /*保存下来，返回的时候释放*/
            params[index].share.buf = tmp_buf;
            /* 修改替换掉 packet_cmd->cliContext.params[index].memref */
            packet_cmd->cliContext.params[index].memref.buffer = (unsigned int)(uintptr_t)tmp_buf;
            packet_cmd->cliContext.params[index].memref.buffer_h_addr = (unsigned int)((uint64_t)tmp_buf >> H_OFFSET);
            packet_cmd->cliContext.params[index].memref.size_addr = (unsigned int)(uintptr_t)&tmp_buf_size;
            packet_cmd->cliContext.params[index].memref.size_h_addr = (unsigned int)((uint64_t)&tmp_buf_size >> H_OFFSET);
            debug("packet_cmd->cliContext.params[index].memref.buffer = 0x%lx\n", packet_cmd->cliContext.params[index].memref.buffer);
            debug("packet_cmd->cliContext.params[index].memref.buffer_h_addr = 0x%lx\n", packet_cmd->cliContext.params[index].memref.buffer_h_addr);

        }
    }// end for
    if (icount ==0) {
        packet_cmd->cliContext.file_buffer = NULL;
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
            if (params[index].share.buf)
                free(params[index].share.buf);
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
                debug("set thread_id = %u \n", current_thread);
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
    if (!vm_fp)
        return;
    fd_p  = find_fd_file(ptzfd, vm_fp);
    if (fd_p) {
        do_set_thread_id(fd_p, session_id, flag);
    }
}

static void send_cmd(struct_packet_cmd_send_cmd *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = -1;
    struct timeval start, end;
    uint32_t cost = 0;

    struct_packet_rsp_send_cmd packet_rsp;
    ClientParam params[TEEC_PARAM_NUM];
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    void *vm_hvas = (void *)malloc(sizeof(void *)*TEEC_PARAM_NUM);
    if (!vm_hvas) {
        tloge("Failed to allocate memory for serial_port\n");
        ret = -ENOMEM;
        goto END;
    }
    debug("CMD is SEND CMD\n");
    packet_cmd->cliContext.file_buffer = vm_hvas;
    packet_cmd->cliContext.file_size = sizeof(void *)*TEEC_PARAM_NUM;
    
    /*
    dump_buff((char *)packet_cmd, packet_cmd->packet_size);
    uint64_t tmp_addr;
    for (int index =0;index<4;index++){
        tmp_addr = packet_cmd->cliContext.params[index].memref.buffer
                            | (uint64_t)packet_cmd->cliContext.params[index].memref.buffer_h_addr << H_OFFSET;
        debug("params[index].memref.buffer = %llx \n", tmp_addr);
    }*/

    /* mmap */
    gettimeofday(&start, NULL);
    if (!process_address(packet_cmd, params)) {
        debug("    process addrs success \n");
        set_thread_id(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, 1, serial_port->vm_file);
        ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SEND_CMD_REQ, &packet_cmd->cliContext);

        set_thread_id(packet_cmd->ptzfd, packet_cmd->cliContext.session_id, 0, serial_port->vm_file);
        debug("    send cmd ret = %d \n", ret);
        process_address_end(packet_cmd, params);
    }
    gettimeofday(&end, NULL);
    cost = (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);
    (void)cost;
    //printf("invoke cmd cost : %f us\n", cost * 1.0);
    free(vm_hvas);



END:
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = ret;
    packet_rsp.cliContext = packet_cmd->cliContext;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
}

static void load_sec_file(struct_packet_cmd_load_sec *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_load_sec packet_rsp;
    //unsigned long buf[2];
    //buf[0] = (unsigned long)(&packet_cmd->ioctlArg);
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    debug("***** cmd is load_sec_file *****\n");
    debug("    secFileInfo.fileSize = %d \n", packet_cmd->ioctlArg.secFileInfo.fileSize);
    debug("    ioctlArg.fileBuffer = %p \n", packet_cmd->ioctlArg.fileBuffer);
    debug("    ioctlArg.secFileInfo.fileType = %d \n",packet_cmd->ioctlArg.secFileInfo.fileType);
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_LOAD_APP_REQ, &packet_cmd->ioctlArg);
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = ret;
    packet_rsp.ioctlArg = packet_cmd->ioctlArg;
    debug("    ptzfd            = %d \n", packet_cmd->ptzfd);
    debug("    ret              = %d \n", ret);

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
}

static void vtz_dommap(struct_packet_cmd_mmap *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_mmap packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    void *buffer = mmap(0, (unsigned long)packet_cmd->size, (PROT_READ | PROT_WRITE), MAP_SHARED,
                            packet_cmd->ptzfd, (long)(packet_cmd->offset * (uint32_t)PAGE_SIZE));
    if (buffer == MAP_FAILED) {
        tloge("mmap failed\n");
        debug("mmap failed \n");
        ret = -ENOMEM;
    }

    debug("    mmap ret = %d \n", ret);
    packet_rsp.ret = ret;

    debug("    vm_buffer = %p\n", packet_cmd->buffer);
    struct_shrd_mem* tmp = (struct_shrd_mem*)malloc(sizeof(struct_shrd_mem));
    ListInit(&tmp->node);
    tmp->buffer = buffer;
    tmp->vm_buffer = (void*)packet_cmd->buffer;
    tmp->buffer_size = (size_t)packet_cmd->size;
    tmp->dev_fd = packet_cmd->ptzfd;

    pthread_mutex_lock(&g_mutex_shrd_mem);
    ListInsertTail(&g_shrd_mem_list, &tmp->node);
    pthread_mutex_unlock(&g_mutex_shrd_mem);

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
        pthread_mutex_lock(&g_mutex_shrd_mem);
        ListRemoveEntry(&(tmp->node));
        pthread_mutex_unlock(&g_mutex_shrd_mem);
        (void)munmap(tmp->buffer, tmp->buffer_size);
        free(tmp);
    }
}

static void vtz_dounmmap(struct_packet_cmd_mmap *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_mmap packet_rsp;
    void* buffer = NULL;
    uint32_t buffer_size;
    struct ListNode* ptr = NULL;
    struct ListNode* n = NULL;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
    pthread_mutex_lock(&g_mutex_shrd_mem);
    if (!LIST_EMPTY(&g_shrd_mem_list)) {
        LIST_FOR_EACH_SAFE(ptr, n, &g_shrd_mem_list) {
            struct_shrd_mem* shrd_mem =
                CONTAINER_OF(ptr, struct_shrd_mem, node);
            if (shrd_mem->vm_buffer == (void*)packet_cmd->buffer) {
                ListRemoveEntry(&(shrd_mem->node));
                buffer = shrd_mem->buffer;
                buffer_size = shrd_mem->buffer_size;
                free(shrd_mem);
            }
        }
    }
    pthread_mutex_unlock(&g_mutex_shrd_mem);
    if (buffer != NULL) {
        debug("   munmap buffer = %p \n", buffer);
        ret = munmap(buffer, (size_t)buffer_size);
    if (ret) {
        tloge("Release SharedMemory failed, munmap error\n");
        debug("Release SharedMemory failed, munmap error\n");
        }
    }
}

static void vtz_mmap(struct_packet_cmd_mmap *packet_cmd,
    struct serial_port_file *serial_port)
{
    debug("*****cmd is mmap*****\n");
    debug("    ptzfd            = %d \n", packet_cmd->ptzfd);	
    if (packet_cmd->cmd == VTZ_MMAP) {
        vtz_dommap(packet_cmd, serial_port);
    } else {
        vtz_dounmmap(packet_cmd, serial_port);
    }
    
}

static void vtz_nothing(struct_packet_cmd_nothing *packet_cmd, struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_nothing packet_rsp = {0};
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = 0;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }    
}

void *thread_entry(void *args)
{
    uint32_t ui32_cmd = 0;
    uint32_t packet_size = 0;
    //int serial_port_fd = *(uint64_t*)(args);
    //struct serial_port_file *serial_port = get_serial_port_file(serial_port_fd);
    
    uint64_t u64 = *(uint64_t*)(args);
    struct serial_port_file *serial_port = (struct serial_port_file *)u64;
    char* rd_buf = (char*)(args) + sizeof(uint64_t);

    uint32_t seq_num = *(uint32_t*)(rd_buf + sizeof(uint32_t) * 2);
    set_thread_seq_num(&g_pool, pthread_self(), seq_num);
    ui32_cmd = *(uint32_t*)(rd_buf + sizeof(uint32_t));
    packet_size = *(uint32_t*)rd_buf;
    (void)packet_size;

    debug("received message packet from guest: \n");
    debug("cmd = %d, 0x%8.8x \n", ui32_cmd, ui32_cmd);

    switch (ui32_cmd)
    {
    case VTZ_OPEN_TZD:
        debug("before open tz \n");
        (void)open_tzdriver((struct_packet_cmd_open_tzd *)rd_buf, serial_port);
        break;
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
        (void)SyncSysTime((struct_packet_cmd_synctime *)rd_buf, serial_port);
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
    case VTZ_NOTHING:
        (void)vtz_nothing((struct_packet_cmd_nothing *)rd_buf, serial_port);
        break;			
    default:
        break;
    }

    remove_thread_seq_num(&g_pool, pthread_self(), seq_num);
    free(args);
    return NULL;
}

struct test
{
    int cmd;
    int seq;
    char name[256];
    int seq2;
};

struct test2
{
    int cmd;
    int seq;
    char name[256];
    int seq2;
    char tmp[256];
};

struct timeval g_start, g_end;
uint32_t g_cost = 0;
int icount = 0;
void process_event(int fd)
{
    int ret;
    int offset = 0;
    struct serial_port_file *serial_port;

    int buf_len;
    serial_port = get_serial_port_file(fd);
    if (!serial_port || !serial_port->rd_buf){
        tloge(" rd_buf is NULL \n");
        return ;
    }
    pthread_mutex_lock(&serial_port->lock);
    ret = read(fd, serial_port->rd_buf + serial_port->offset, BUF_LEN_MAX_RD - serial_port->offset);
    tlogd("read len = %d\n",ret);

    if (ret < 0) {
        tloge("read domain socket failed \n");
        debug("read domain socket failed \n");
        goto END;
    }
    if (ret == 0) {
        goto END;
    }
    buf_len = ret + serial_port->offset;
    if (g_cost == 0)
        gettimeofday(&g_start, NULL);
    while(1){
        void *packet = NULL;
        packet = get_packet_item(serial_port->rd_buf, buf_len, &offset);
        if (packet == NULL) {
            break;
        }
        *(uint64_t*)(packet) = (uint64_t)serial_port;
        if (*(int*)(packet+sizeof(uint64_t))==999 || *(int*)(packet+sizeof(uint64_t))==911){
            int seq = ((struct test*)(packet+4))->seq;
            int seq2 = ((struct test*)(packet+4))->seq2;
            if (seq %10000 == 0) {
                printf("seq = %d, buf_size = %d serial_port->offset= %ld\n", ((struct test*)(packet+4))->seq, ret, serial_port->offset);
                gettimeofday(&g_end, NULL);
                g_cost = (1000000 * g_end.tv_sec + g_end.tv_usec) - (1000000 * g_start.tv_sec + g_start.tv_usec);
                printf("serial cost : %f us data total size = %ld KB, speed = %ld B/ms\n", g_cost * 1.0, 
                    seq * sizeof(struct test)/1024,
                    seq * sizeof(struct test)/(g_cost/1000));
            }
            if (icount != seq || seq*seq != seq2) {
                printf("err\n");
                dump_buff(packet, 160);
                exit(0);
            }
            icount++;
            if(icount == 500000)
                icount = 0;
            free(packet);
            continue;
        }
        thread_pool_submit(&g_pool, thread_entry, (void *)((uint64_t)packet));
    }
    serial_port->offset = offset;

END:
    pthread_mutex_unlock(&serial_port->lock);
}

int main() {
    int ret = 0;
    int i;
    init_tlog();
    thread_pool_init(&g_pool);
    serial_port_list_init();
    check_stat_serial_port(1);

    while (1) {
        check_stat_serial_port(0);
        ret = safepoll(g_pollfd, g_pollfd_len, -1);
        if (ret == -1) {
            tloge("pollfd failed, ret = %d \n", ret);
            return -1;
        }
        if (ret == 0) {
            tloge("pollfd timeout \n");
            continue;
        }

        for (i = 0; i < g_pollfd_len; i++) {
            if (g_pollfd[i].revents & POLLIN) {
                process_event(g_pollfd[i].fd);
            }
        }
    }

    serial_port_list_destroy();
    return 0;
}


