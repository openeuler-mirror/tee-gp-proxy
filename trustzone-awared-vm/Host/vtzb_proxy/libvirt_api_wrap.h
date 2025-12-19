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
#ifndef __LIBVIRT_API_WRAP_H__
#define __LIBVIRT_API_WRAP_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/time.h>
#include <stdio.h>
#include "tlogcat.h"

#define QEMU_NS_URI "http://libvirt.org/schemas/domain/qemu/1.0"

virConnectPtr init_virt_conn();
virDomainPtr init_domain_by_socket_path(virConnectPtr conn_ptr, const char *socket_path);

void deinit_virt_conn(virConnectPtr conn_ptr);
void deinit_domain(virDomainPtr dom);

#endif