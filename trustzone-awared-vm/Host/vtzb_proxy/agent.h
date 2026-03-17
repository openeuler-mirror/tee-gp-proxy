#ifndef __AGENT_H__
#define __AGENT_H__

#include "tc_ns_client.h"
#include "tee_client_list.h"
#include "comm_structs.h"
#include "serial_port.h"

void register_agent(struct_packet_cmd_regagent *packet_cmd, struct serial_port_file *serial_port);
void wait_event(struct_packet_cmd_event *packet_cmd, struct serial_port_file *serial_port);
void sent_event_response(struct_packet_cmd_event *packet_cmd, struct serial_port_file *serial_port);

#endif