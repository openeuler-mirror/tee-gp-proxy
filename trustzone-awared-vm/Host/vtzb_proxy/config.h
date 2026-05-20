/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

// #ifndef _GNU_SOURCE
// #define _GNU_SOURCE
// #endif
#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdbool.h>
#include <sched.h>

#define CONFIG_PATH "/var/vtzb/vtzb_proxy.conf"
#define MAX_LINE_LEN 256
#define MAX_PATH_LEN 108
#define MAX_URI_LEN 128

/* Default values */
#define DEFAULT_SOCKET_PATH "/var/vtzb/vm_vtzb_sock"
#define DEFAULT_MAX_VM_COUNT 64
#define DEFAULT_LIBVIRT_URI "qemu:///system"
#define DEFAULT_USE_VCPUSET true

typedef struct {
    char socket_path[MAX_PATH_LEN];         /* Virtual serial port socket path prefix */
    char libvirt_uri[MAX_URI_LEN];          /* Libvirt connection URI */
    int max_vm_count;                       /* Maximum number of VMs supported */
    cpu_set_t cpuset;
    bool use_vcpuset;                       /* Whether to enable vcpu mapping */
} VtzbConfig;

void print_cpuset(cpu_set_t *cpuset);
/* Initialize configuration from file, returns 0 on success */
void config_init(void);

/* Get global config pointer */
VtzbConfig *get_global_config(void);

#endif /* __CONFIG_H__ */
