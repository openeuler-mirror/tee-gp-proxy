#include "tlogcat.h"
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>
#include "securec.h"
#include "debug.h"
#include "serial_port.h"
#include "comm_structs.h"

static void *g_log_buffer = NULL;
static char g_log_teeVersion[MAX_TEE_VERSION_LEN];

static void tlog_get_teever(struct_packet_cmd_get_ver *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_get_ver packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TEELOGGER_GET_VERSION, g_log_teeVersion);
    packet_rsp.ret = ret;
    if (memcpy_s(packet_rsp.version_info, MAX_TEE_VERSION_LEN,
        g_log_teeVersion, MAX_TEE_VERSION_LEN)) {
        tloge("memcpy_s err \n");
    }
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
}

static void tlog_set_reader_cur(
    struct_packet_cmd_set_reader_cur *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_set_reader_cur packet_rsp;

    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TEELOGGER_SET_READERPOS_CUR, 0);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
}

static void tlog_set_stat(struct_packet_cmd_set_tlogcat_stat *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_set_tlogcat_stat packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TEELOGGER_SET_TLOGCAT_STAT, 0);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
}

static void tlog_get_stat(struct_packet_cmd_get_tlogcat_stat *packet_cmd,
    struct serial_port_file *serial_port)
{
    int ret = 0;
    struct_packet_rsp_get_tlogcat_stat packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    ret = ioctl(packet_cmd->ptzfd, TEELOGGER_GET_TLOGCAT_STAT, 0);
    packet_rsp.ret = ret;
    ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
    if (ret != sizeof(packet_rsp)) {
        tloge("send to VM failed \n");
    }
}

static void tlog_get_log(struct_packet_cmd_get_log *packet_cmd,
    struct serial_port_file *serial_port)
{
    int32_t result;
    int32_t ret = 0;
    struct timeval tv;
    fd_set readset;
    struct_packet_rsp_get_log packet_rsp;
    packet_rsp.seq_num = packet_cmd->seq_num + 1;
    packet_rsp.packet_size = sizeof(packet_rsp);
    while(1){
        do {
            tv.tv_sec = 20;
            tv.tv_usec = 0;
            FD_ZERO(&readset);
            FD_SET(packet_cmd->ptzfd, &readset);
            tlogd("while select\n");
            result = select((packet_cmd->ptzfd + 1), &readset, NULL, NULL, &tv);
        } while (result == -1 && errno == EINTR);
        if (result <= 0) {
            goto END;
        }
        ret = read(packet_cmd->ptzfd, packet_rsp.buffer, LOG_BUFFER_LEN);
        if (ret == 0)
            continue;
END:
        packet_rsp.length = ret < 0 ? 0 : ret;
        ret = send_to_vm(serial_port, &packet_rsp, sizeof(packet_rsp));
        if (ret != sizeof(packet_rsp)) {
            tloge("send to VM failed \n");
        }
        break;
    }
}

void tlog(uint32_t cmd, void *packet_cmd,struct serial_port_file *serial_port)
{
    switch (cmd)
    {
    case VTZ_GET_TEEOS_VER:
        (void)tlog_get_teever((struct_packet_cmd_get_ver *)packet_cmd,
            serial_port);
        break;
    case VTZ_SET_READER_CUR:
        (void)tlog_set_reader_cur((struct_packet_cmd_set_reader_cur *)packet_cmd,
            serial_port);
        break;
    case VTZ_SET_TLOGCAT_STAT:
        (void)tlog_set_stat((struct_packet_cmd_set_tlogcat_stat *)packet_cmd,
            serial_port);
        break;
    case VTZ_GET_TLOGCAT_STAT:
        (void)tlog_get_stat((struct_packet_cmd_get_tlogcat_stat *)packet_cmd,
            serial_port);
        break;
    case VTZ_GET_LOG:
        (void)tlog_get_log((struct_packet_cmd_get_log *)packet_cmd,
            serial_port);
    default:
        break;
    }
}

int init_tlog()
{
    g_log_buffer = malloc(LOG_BUFFER_LEN);
    if (!g_log_buffer) {
        tloge("Failed to allocate memory\n");
        return -ENOMEM;       
    }
    return 0;
}