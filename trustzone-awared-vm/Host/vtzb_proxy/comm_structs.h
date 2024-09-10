#ifndef COMM_STRUCTS_H
#define COMM_STRUCTS_H

#include <linux/types.h>
#include "tc_ns_client.h"

#define CERT_BUF_MAX_SIZE        2048

#define TC_NS_CLIENT_DEV_FLAG    3
#define TC_PRIVATE_DEV_FLAG      4
#define TC_CVM_DEV_FLAG          5
#define TLOG_DEV_FLAG            6
#define TLOG_DEV_THD_FLAG        7

#define VTZ_OPEN_TZD            15
#define VTZ_CLOSE_TZD           17
#define VTZ_LOG_IN_NHIDL        19
#define VTZ_GET_TEE_VERSION     21
#define VTZ_GET_TEE_INFO        23
#define VTZ_LATE_INIT           25
#define VTZ_SYNC_TIME           27
#define VTZ_LOG_IN              29
#define VTZ_OPEN_SESSION        31
#define VTZ_SEND_CMD            33
#define VTZ_CANCEL_CMD          35
#define VTZ_MMAP                37
#define VTZ_MUNMAP              39
#define VTZ_CLOSE_SESSION       41
#define VTZ_CLOSE_PTZDEV        43
#define VTZ_FS_REGISTER_AGENT   45
#define VTZ_WAIT_EVENT          49
#define VTZ_SEND_EVENT_RESPONSE 51
#define VTZ_LOAD_SEC            53
#define VTZ_TEST                47

#define VTZ_GET_TEEOS_VER       55
#define VTZ_SET_READER_CUR      57
#define VTZ_SET_TLOGCAT_STAT    59
#define VTZ_GET_TLOGCAT_STAT    61
#define VTZ_GET_LOG             63
#define VTZ_NOTHING             67

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_general;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_general;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    uint32_t vmid;
    uint32_t flag;
} struct_packet_cmd_open_tzd;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    int32_t ptzfd;
    int32_t vmid;
} struct_packet_rsp_open_tzd;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_close_tzd;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_close_tzd;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_getteever;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    uint32_t tee_ver;
} struct_packet_rsp_getteever;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    bool istlog;
} struct_packet_cmd_getteeinfo;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    TC_NS_TEE_Info info;
} struct_packet_rsp_getteeinfo;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    void  *vmaddr;
    struct AgentIoctlArgs args;
} struct_packet_cmd_regagent;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    struct AgentIoctlArgs args;
} struct_packet_rsp_regagent;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    uint32_t agent_id;
} struct_packet_cmd_event;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    uint32_t index;
} struct_packet_cmd_lateinit;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_lateinit;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    TC_NS_Time tcNsTime;
} struct_packet_cmd_synctime;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_synctime;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    uint8_t cert_buffer[CERT_BUF_MAX_SIZE];
} struct_packet_cmd_login;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_login_non;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_login;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    __s32 cpu_index;
    struct SecLoadIoctlStruct ioctlArg;
} struct_packet_cmd_load_sec;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    struct SecLoadIoctlStruct ioctlArg;
} struct_packet_rsp_load_sec;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    __s32 cpu_index;
    int32_t err_flag;
    int32_t is_fragment;
    uint32_t fragment_block_num;
    uint32_t vm_page_size;
    uint64_t block_addrs[4];//qemu and proxy don't use
    uint32_t block_size[4];
    unsigned long long addrs[4]; //used by ref mem mmap
    TC_NS_ClientContext cliContext;
} struct_packet_cmd_session;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    TC_NS_ClientContext cliContext;
} struct_packet_rsp_session;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    int32_t err_flag;
    int32_t is_fragment;
    uint32_t fragment_block_num;
    uint32_t vm_page_size;
    uint64_t block_addrs[4];//qemu and proxy don't use
    uint32_t block_size[4];
    unsigned long long addrs[4]; //used by ref mem mmap
    TC_NS_ClientContext cliContext;
} struct_packet_cmd_send_cmd;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    TC_NS_ClientContext cliContext;
} struct_packet_rsp_send_cmd;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    __s32 cpu_index;
    TC_NS_ClientContext cliContext;
    pid_t pid;
} struct_packet_cmd_cancel_cmd;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    TC_NS_ClientContext cliContext;
} struct_packet_rsp_cancel_cmd;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
    uint64_t buffer;
    uint32_t size;
    uint32_t offset;
} struct_packet_cmd_mmap;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_mmap;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
} struct_packet_cmd_nothing;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_nothing;

#endif