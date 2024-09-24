#include "agent.h"
#include "comm_structs.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "serial_port.h"

#include "tee_client_log.h"
#include "tee_sys_log.h"
#include "debug.h"
#include "thread_pool.h"
#include "vtzb_proxy.h"
#include "vm.h"

extern ThreadPool g_pool;

void do_free_agent(struct_agent_args *agent_args)
{
    int ret = -1;

    if (agent_args == NULL) {
        tloge("agent args is null\n");
        return;
    }

    tlogv("free agent fd %u\n", agent_args->dev_fd);
    ListRemoveEntry(&(agent_args->node));
    ret = ioctl(agent_args->dev_fd, TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT, agent_args->args.id);
    if (ret) {
        tloge("ioctl failed\n");
    }
    close(agent_args->dev_fd);
    agent_args->dev_fd = -1;

    if (agent_args->thd!= 0) {
        thread_pool_submit(&g_pool, Kill_useless_thread, (void *)(agent_args->thd));
    }
    pthread_spin_destroy(&agent_args->spinlock);
    free(agent_args);
}

void free_agent_buf(int ptzfd, struct vm_file *vm_fp)
{
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    if (!vm_fp) {
        tloge("vm file is NULL\n");
        return;
    }
    pthread_mutex_lock(&vm_fp->agents_lock);
    if (LIST_EMPTY(&vm_fp->agents_head)) {
        // when teecd init, this is possible
        tlogd("agent list is empty\n");
        goto END;
    }

    LIST_FOR_EACH_SAFE(ptr, n, &vm_fp->agents_head) {
        struct_agent_args *tmp =
            CONTAINER_OF(ptr, struct_agent_args, node);
        if (tmp->dev_fd == ptzfd) {
            do_free_agent(tmp);
        }
    }
END:
    pthread_mutex_unlock(&vm_fp->agents_lock);
}

void register_agent(struct_packet_cmd_regagent *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret;
    struct_packet_rsp_regagent packet_rsp;
    unsigned long buf[2];
    buf[0] = (unsigned long)(&packet_cmd->args);
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_REGISTER_AGENT, buf);
    if (!ret) {
        /* Add the agent buffer to the linked list. */
        struct_agent_args *tmp = (struct_agent_args *)calloc(1, sizeof(struct_agent_args));
        if (!tmp) {
            tloge("Failed to allocate memory for agent buffer\n");
            ret = -ENOMEM;
            goto END;
        }
        pthread_spin_init(&tmp->spinlock, PTHREAD_PROCESS_PRIVATE);
        ListInit(&tmp->node);
        tmp->dev_fd = packet_cmd->ptzfd;
        tmp->args = packet_cmd->args;
        tmp->vmaddr = packet_cmd->vmaddr;
        pthread_mutex_lock(&serial_port->vm_file->agents_lock);
        ListInsertTail(&serial_port->vm_file->agents_head, &tmp->node);
        pthread_mutex_unlock(&serial_port->vm_file->agents_lock);
    }
END:
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.ret = ret;
    packet_rsp.args = packet_cmd->args;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("register_agent send to VM failed \n");
    }
}

void wait_event(struct_packet_cmd_event *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = -EFAULT;
    struct_packet_rsp_general packet_rsp;
    unsigned long buf[2];
    struct ListNode *ptr = NULL;
    bool bfind = false;
    struct_agent_args *agent_args;
    buf[0] = packet_cmd->agent_id;

    pthread_mutex_lock(&serial_port->vm_file->agents_lock);
    if (!LIST_EMPTY(&serial_port->vm_file->agents_head)) {
        LIST_FOR_EACH(ptr, &serial_port->vm_file->agents_head) {
            agent_args =
                CONTAINER_OF(ptr, struct_agent_args, node);
            if (agent_args->args.id == packet_cmd->agent_id) {
                buf[1] = (unsigned long)agent_args->vmaddr;
                bfind = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&serial_port->vm_file->agents_lock);
    if (bfind) {
        agent_args->thd  = pthread_self();
        ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_WAIT_EVENT, buf);
        agent_args->thd  = 0;
    }
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.ret = ret;

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("wait_event send to VM failed \n");
    }
}

void sent_event_response(struct_packet_cmd_event *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = -EFAULT;
    struct_packet_rsp_general packet_rsp;
    unsigned long buf[2];
    bool bfind = false;
    struct ListNode *ptr = NULL;
    buf[0] = packet_cmd->agent_id;
    pthread_mutex_lock(&serial_port->vm_file->agents_lock);
    if (!LIST_EMPTY(&serial_port->vm_file->agents_head)) {
        LIST_FOR_EACH(ptr, &serial_port->vm_file->agents_head) {
            struct_agent_args *agent_args =
                CONTAINER_OF(ptr, struct_agent_args, node);
            if (agent_args->args.id == packet_cmd->agent_id) {
                buf[1] = (unsigned long)agent_args->vmaddr;
                bfind = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&serial_port->vm_file->agents_lock);

    if (bfind) {
        ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_SEND_EVENT_RESPONSE, buf);
    }

    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.ret = ret;

    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("sent_event_response send to VM failed \n");
    }
}