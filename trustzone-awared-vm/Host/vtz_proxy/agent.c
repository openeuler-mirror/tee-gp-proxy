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
#include "vtz_proxy.h"
#include "vm.h"

extern ThreadPool g_pool;

void register_agent(struct_packet_cmd_regagent *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = -1;
    struct_packet_rsp_regagent packet_rsp;
    unsigned long buf[2];
    buf[0] = (unsigned long)(&packet_cmd->args);
    packet_rsp.seq_num = packet_cmd->seq_num + 1;

    struct ListNode *ptr = NULL;
    struct fd_file *fd_p = NULL;
    if (!serial_port->vm_file) {
        tloge("vm_file is null\n");
        goto END;
    }
    pthread_mutex_lock(&serial_port->vm_file->fd_lock);
    if (!LIST_EMPTY(&serial_port->vm_file->fds_head)) {
        LIST_FOR_EACH(ptr, &serial_port->vm_file->fds_head) {
            fd_p = CONTAINER_OF(ptr, struct fd_file, head);
            if (fd_p->ptzfd == packet_cmd->ptzfd) {
                if (fd_p->agent.vmaddr != NULL) {
                    tloge("agent has registered %d", fd_p->agent.args.id);
                    pthread_mutex_unlock(&serial_port->vm_file->fd_lock);
                    goto END;
                }
                ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_REGISTER_AGENT, buf);
                if (!ret) {
                    fd_p->agent.args = packet_cmd->args;
                    fd_p->agent.vmaddr = packet_cmd->vmaddr;
                } else {
                    tloge("register agent failed ret is %d, agentis is %u, errno is %d, reason is %s",\
                        ret, packet_cmd->args.id, errno, strerror(errno));
                }
            }
        }
    }
    pthread_mutex_unlock(&serial_port->vm_file->fd_lock);
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
    struct fd_file *fd_p;
    buf[0] = packet_cmd->agent_id;

    pthread_mutex_lock(&serial_port->vm_file->fd_lock);
    if (!LIST_EMPTY(&serial_port->vm_file->fds_head)) {
        LIST_FOR_EACH(ptr, &serial_port->vm_file->fds_head) {
            fd_p = CONTAINER_OF(ptr, struct fd_file, head);
            if (fd_p->agent.vmaddr && fd_p->agent.args.id == packet_cmd->agent_id) {
                buf[1] = (unsigned long)fd_p->agent.vmaddr;
                bfind = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&serial_port->vm_file->fd_lock);
    if (bfind) {
        fd_p->agent.thd  = pthread_self();
        ret = ioctl(packet_cmd->ptzfd, TC_NS_CLIENT_IOCTL_WAIT_EVENT, buf);
        fd_p->agent.thd  = 0;
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
    pthread_mutex_lock(&serial_port->vm_file->fd_lock);
    if (!LIST_EMPTY(&serial_port->vm_file->fds_head)) {
        LIST_FOR_EACH(ptr, &serial_port->vm_file->fds_head) {
            struct fd_file *fd_p = CONTAINER_OF(ptr, struct fd_file, head);
            if (fd_p->agent.vmaddr && fd_p->agent.args.id == packet_cmd->agent_id) {
                buf[1] = (unsigned long)fd_p->agent.vmaddr;
                bfind = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&serial_port->vm_file->fd_lock);

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
