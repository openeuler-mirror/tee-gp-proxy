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

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <sys/time.h>
#include <stdio.h>
//#define DEBUG 1

double __get_us(struct timeval t);
#ifdef DEBUG
void debug(const char* fmt, ...);
void dump_buff(const char* buffer, size_t bufLen);
#else
#define debug(fmt, ...) \
    do {                \
    } while (0)

#define dump_buff(buffer, bufLen) \
    do {                          \
    } while (0)
#endif

#endif
