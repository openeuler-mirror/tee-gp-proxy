#ifndef __AGENT_H__
#define __AGENT_H__

#include "tc_ns_client.h"
#include "tee_client_list.h"
#include "comm_structs.h"
#include "serial_port.h"
#include "vm.h"

typedef struct {
    struct AgentIoctlArgs args;
    int32_t dev_fd;
    void *vmaddr;
    struct ListNode node;
    pthread_spinlock_t spinlock;
    pthread_t thd;
} struct_agent_args;

void free_agent_buf(int ptzfd, struct vm_file *vm_fp);
void register_agent(struct_packet_cmd_regagent *packet_cmd, struct serial_port_file *serial_port);
void wait_event(struct_packet_cmd_event *packet_cmd, struct serial_port_file *serial_port);
void sent_event_response(struct_packet_cmd_event *packet_cmd, struct serial_port_file *serial_port);

#endif