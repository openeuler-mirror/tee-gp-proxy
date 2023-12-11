/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2023. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __TLOGCAT_H__
#define __TLOGCAT_H__
#include <sys/types.h>
#include "tc_ns_client.h"
#include "tee_sys_log.h"
#include "tee_client_list.h"
#include "serial_port.h"

/* for tlog ioctl */
/* LOG_BUFFER_LEN: The maximum transmission size for one serial communication is 2048 bytes.
 * If the data size exceeds this limit, it may need to be sent in multiple segments.
 * The receiving end might find it inconvenient to handle these segments individually.
 */
#define LOG_BUFFER_LEN                2000
#define TEELOGGERIO                   0xBE
#define GET_VERSION_BASE              5
#define SET_READERPOS_CUR_BASE        6
#define SET_TLOGCAT_STAT_BASE         7
#define GET_TLOGCAT_STAT_BASE         8
#define GET_TEE_INFO_BASE             9
#define SET_VM_FLAG                   10
#define MAX_TEE_VERSION_LEN         256U
#define TEELOGGER_GET_VERSION \
    _IOR(TEELOGGERIO, GET_VERSION_BASE, char[MAX_TEE_VERSION_LEN])
/* set the log reader pos to current pos */
#define TEELOGGER_SET_READERPOS_CUR _IO(TEELOGGERIO, SET_READERPOS_CUR_BASE)
#define TEELOGGER_SET_TLOGCAT_STAT  _IO(TEELOGGERIO, SET_TLOGCAT_STAT_BASE)
#define TEELOGGER_GET_TLOGCAT_STAT  _IO(TEELOGGERIO, GET_TLOGCAT_STAT_BASE)
#define TEELOGGER_GET_TEE_INFO      _IOR(TEELOGGERIO, GET_TEE_INFO_BASE, TC_NS_TEE_Info)
#define TEELOGGER_SET_VM_FLAG       _IOR(TEELOGGERIO, SET_VM_FLAG, int)

/*
 * Structure related to log
 */
typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_get_ver;

#define VERSION_INFO_LEN           156U
typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    unsigned char version_info[MAX_TEE_VERSION_LEN];
} struct_packet_rsp_get_ver;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_set_reader_cur;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_set_reader_cur;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_set_tlogcat_stat;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_set_tlogcat_stat;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_get_tlogcat_stat;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
} struct_packet_rsp_get_tlogcat_stat;

typedef struct {
    uint32_t packet_size;
    uint32_t cmd;
    uint32_t seq_num;
    int32_t ptzfd;
} struct_packet_cmd_get_log;

typedef struct {
    uint32_t packet_size;
    uint32_t seq_num;
    uint32_t ret;
    int length;
    char buffer[LOG_BUFFER_LEN];
} struct_packet_rsp_get_log;

void tlog(uint32_t cmd, void *packet_cmd, struct serial_port_file *serial_port);

#endif