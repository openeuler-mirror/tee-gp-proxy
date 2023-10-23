#include "tee_info.h"
#include "tc_ns_log.h"
#include "comm_structs.h"
#include "serialport.h"

int tc_ns_get_tee_info(int ptzfd, void __user *argp, bool flag)
{
	int ret;
	uint32_t seq_num = get_seq_num(0);
	struct_packet_cmd_getteeinfo packet_cmd = {0};
	struct_packet_rsp_getteeinfo packet_rsp = {0};

	if (!argp || ptzfd <= 0) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	packet_cmd.packet_size = sizeof(packet_cmd);
	packet_cmd.cmd = VTZF_GET_TEE_INFO;
	packet_cmd.seq_num = seq_num;
	packet_cmd.ptzfd = ptzfd;
	packet_cmd.istlog = flag;

	if (send_to_proxy(&packet_cmd, sizeof(packet_cmd), &packet_rsp, sizeof(packet_rsp), seq_num)) {
		ret = -EFAULT;
		goto END;
	} else {
		ret = packet_rsp.ret;
		if (copy_to_user(argp, &packet_rsp.info, sizeof(struct tc_ns_tee_info)) != 0)
			ret = -EFAULT;
	}

END:
	return ret;
}

