/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * iTrustee licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef TEEC_SYS_LOG_H
#define TEEC_SYS_LOG_H

#include <syslog.h>
#include <unistd.h>
#include <sys/syscall.h>
#define TEE_LOG_MASK        TZ_LOG_INFO

#define TZ_LOG_VERBOSE 0
#define TZ_LOG_DEBUG   1
#define TZ_LOG_INFO    2
#define TZ_LOG_WARN    3
#define TZ_LOG_ERROR   4

#define log_format(lev, fmt, ...) syslog(lev, "[%lu][%s] " fmt, (unsigned long)syscall(SYS_gettid), __func__, ##__VA_ARGS__)
#define tlogv(fmt, ...) \
    do { \
        if (TZ_LOG_VERBOSE == TEE_LOG_MASK) \
            log_format(LOG_USER | LOG_NOTICE, fmt, ##__VA_ARGS__); \
    } while (0)

#define tlogd(fmt, ...) \
    do { \
        if (TZ_LOG_DEBUG >= TEE_LOG_MASK) \
            log_format(LOG_USER | LOG_DEBUG, fmt, ##__VA_ARGS__); \
    } while (0)

#define tlogi(fmt, ...) \
    do { \
        if (TZ_LOG_INFO >= TEE_LOG_MASK) \
            log_format(LOG_USER | LOG_INFO, fmt, ##__VA_ARGS__); \
    } while (0)

#define tlogw(fmt, ...) \
    do { \
        if (TZ_LOG_WARN >= TEE_LOG_MASK) \
            log_format(LOG_USER | LOG_WARNING, fmt, ##__VA_ARGS__); \
    } while (0)

#define tloge(fmt, ...) \
    do { \
        if (TZ_LOG_ERROR >= TEE_LOG_MASK) \
            log_format(LOG_USER | LOG_ERR, fmt, ##__VA_ARGS__); \
    } while (0)

#endif

