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
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include "config.h"
#include "tee_sys_log.h"
#include "securec.h"

VtzbConfig g_config = {
    .socket_path = DEFAULT_SOCKET_PATH,
    .libvirt_uri = DEFAULT_LIBVIRT_URI,
    .max_vm_count = DEFAULT_MAX_VM_COUNT,
    .cpuset = {{0}},
    .use_vcpuset = DEFAULT_USE_VCPUSET
};

static char *trim(char *str)
{
    char *end;
    while (isspace((unsigned char)*str)) {
        str++;
    }
    if (*str == 0)
        return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }
    end[1] = '\0';
    return str;
}

static int set_socket_path(const char *value)
{
    if (value[0] != '/') {
        tlogw("set_socket_path: socket path should be absolute path (start with '/')\n");
    }
    errno_t err = memset_s(g_config.socket_path, sizeof(g_config.socket_path), 0, sizeof(g_config.socket_path));
    if (err != 0) {
        tloge("set_socket_path: memset_s failed, error %d\n", err);
        return -1;
    }
    
    err = strcpy_s(g_config.socket_path, sizeof(g_config.socket_path), value);
    if (err != 0) {
        tloge("set_socket_path: strcpy_s failed, error %d\n", err);
        return -1;
    }
    
    tlogi("set_socket_path: successfully set socket path to '%s'\n", value);
    return 0;
}

static int set_libvirt_uri(const char *value)
{
    if (value == NULL) {
        tloge("set_libvirt_uri: value is NULL\n");
        return -1;
    }
    
    errno_t err = memset_s(g_config.libvirt_uri, sizeof(g_config.libvirt_uri), 0, sizeof(g_config.libvirt_uri));
    if (err != 0) {
        tloge("set_libvirt_uri: memset_s failed, error %d\n", err);
        return -1;
    }
    
    err = strcpy_s(g_config.libvirt_uri, sizeof(g_config.libvirt_uri), value);
    if (err != 0) {
        tloge("set_libvirt_uri: strcpy_s failed, error %d\n", err);
        return -1;
    }
    
    tlogi("set_libvirt_uri: successfully set libvirt uri to '%s'\n", value);
    return 0;
}

static int set_max_vm_count(const char *value)
{
    if (value == NULL) {
        tloge("set_max_vm_count: value is NULL\n");
        return -1;
    }

    errno = 0;
    long max_vm_count = strtol(value, NULL, 10);
    if (errno != 0 || max_vm_count < 0 || max_vm_count > DEFAULT_MAX_VM_COUNT) {
        tloge("set_max_vm_count: invalid value %s\n", value);
        return -1;
    }

    g_config.max_vm_count = (int)max_vm_count;
    tlogi("set_max_vm_count: successfully set max vm count to %d\n", g_config.max_vm_count);
    return 0;
}

static int set_use_vcpuset(const char *value)
{
    if (value == NULL) {
        tloge("set_use_vcpuset: value is NULL\n");
        return -1;
    }

    if (strcasecmp(value, "true") == 0) {
        g_config.use_vcpuset = true;
    } else if (strcasecmp(value, "false") == 0) {
        g_config.use_vcpuset = false;
    } else {
        tlogw("set_use_vcpuset: invalid value '%s', using default true\n", value);
        g_config.use_vcpuset = DEFAULT_USE_VCPUSET;
    }

    tlogi("set_use_vcpuset: successfully set use_vcpuset to %s\n",
          g_config.use_vcpuset ? "true" : "false");
    return 0;
}

static int get_available_cpu_count(void)
{
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus <= 0) {
        return -1;
    }
    return (int)num_cpus;
}

static int is_cpu_id_valid(int cpu_id, int max_cpus)
{
    if (cpu_id < 0 || cpu_id >= max_cpus) {
        return 0;
    }
    return 1;
}

static const char *skip_whitespace(const char *str)
{
    if (str == NULL) {
        return NULL;
    }
    return str + strspn(str, " \t\r\n");
}

static char *parse_number(const char *str, int *out_value)
{
    const char *p = NULL;
    long value = 0;
    char *endptr = NULL;
    if (str == NULL || out_value == NULL) {
        return NULL;
    }
    p = skip_whitespace(str);
    if (*p == '\0' || !isdigit((unsigned char)*p)) {
        return NULL;
    }

    errno = 0;
    value = strtol(p, &endptr, 10);
    if (errno != 0 || endptr == p || value < 0 || value > INT_MAX) {
        return NULL;
    }

    *out_value = (int)value;
    return endptr;
}

static void set_single_cpu(int cpu_id, cpu_set_t *tmp_set, int *cpu_count)
{
    CPU_SET(cpu_id, tmp_set);
    (*cpu_count)++;
}

static void set_multi_cpu(int cpu_start, int cpu_end, cpu_set_t *tmp_set, int *cpu_count)
{
    for (int i = cpu_start; i <= cpu_end; i++) {
        set_single_cpu(i, tmp_set, cpu_count);
    }
}

static int pre_parse(const char *value, int *max_cpus)
{
    if (value == NULL || max_cpus == NULL) {
        tloge("pre_parse: invalid parameters\n");
        return -1;
    }
    if (*value == '\0') {
        tloge("pre_parse: empty input string\n");
        return -1;
    }
    *max_cpus = get_available_cpu_count();
    if (*max_cpus <= 0) {
        tloge("pre_parse: failed to get CPU count\n");
        return -1;
    }
    return 0;
}

static int check_cpu_number(const char *p, int cpu_id, int max_cpus)
{
    if (p == NULL) {
        tloge("check_cpu_number: invalid params\n");
        return -1;
    }
    if (!is_cpu_id_valid(cpu_id, max_cpus)) {
        tloge("check_cpu_number: invalid CPU ID %d (max: %d)\n", cpu_id, max_cpus - 1);
        return -1;
    }
    return 0;
}

int set_numa_bindings(const char *value)
{
    cpu_set_t tmp_set;
    const char *p = NULL;
    int max_cpus = 0, cpu_start = 0, cpu_end = 0, cpu_count = 0;

    if (pre_parse(value, &max_cpus) != 0) {
        return -1;
    }
    CPU_ZERO(&tmp_set);
    p = value;
    while (*p != '\0') {
        p = parse_number(p, &cpu_start);
        if (check_cpu_number(p, cpu_start, max_cpus) != 0) {
            return -1;
        }
        p = skip_whitespace(p);
        if (*p == '-') {
            p++;
            p = parse_number(p, &cpu_end);
            if (check_cpu_number(p, cpu_end, max_cpus) != 0) {
                return -1;
            }
            if (cpu_start > cpu_end) {
                tloge("set_numa_bindings: invalid range %d-%d\n", cpu_start, cpu_end);
                return -1;
            }
            set_multi_cpu(cpu_start, cpu_end, &tmp_set, &cpu_count);
            p = skip_whitespace(p);
        } else {
            set_single_cpu(cpu_start, &tmp_set, &cpu_count);
        }
        if (*p == ',') {
            p++;
            p = skip_whitespace(p);
            if (*p == '\0') {
                tloge("set_numa_bindings: unexpected end after comma\n");
                return -1;
            }
        } else if (*p != '\0') {
            tloge("set_numa_bindings: unexpected character '%c'\n", *p);
            return -1;
        }
    }
    if (cpu_count == 0) {
        tloge("set_numa_bindings: no CPU specified\n");
        return -1;
    }
    g_config.cpuset = tmp_set;
    tlogi("set_max_vm_count: successfully set cpuset\n");
    return 0;
}

void print_cpuset(cpu_set_t *cpuset)
{
    int max_cpus = get_available_cpu_count();
    tlogi("cpuset list: \n");
    for (int i = 0; i < max_cpus; i++) {
        if (CPU_ISSET(i, cpuset)) {
            tlogi("%d\n", i);
        }
    }
}

static int set_g_config(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        tloge("set_g_config: key or value is NULL\n");
        return -1;
    }
    if (strcmp(key, "socket_path") == 0) {
        return set_socket_path(value);
    } else if (strcmp(key, "libvirt_uri") == 0) {
        return set_libvirt_uri(value);
    } else if (strcmp(key, "max_vm_count") == 0) {
        return set_max_vm_count(value);
    } else if (strcmp(key, "numa_bindings") == 0) {
        return set_numa_bindings(value);
    } else if (strcmp(key, "use_vcpuset") == 0) {
        return set_use_vcpuset(value);
    } else {
        tloge("set_g_config: undefined configuration: %s\n", key);
        return -1;
    }
}

static int parse_config_line(const char *line)
{
    char buffer[MAX_LINE_LEN];
    char key[MAX_LINE_LEN];
    char value[MAX_LINE_LEN];
    char *eq_pos;
    char *trimmed;

    errno_t err = strncpy_s(buffer, MAX_LINE_LEN, line, MAX_LINE_LEN - 1);
    if (err != 0) {
        tloge("parse_config_line: copy line failed, error is %d\n", err);
        return -1;
    }
    buffer[MAX_LINE_LEN - 1] = '\0';
    trimmed = trim(buffer);
    if (trimmed[0] == '#' || trimmed[0] == '\0') {
        return 0;
    }

    eq_pos = strchr(trimmed, '=');
    if (eq_pos == NULL) {
        return -1;
    }
    *eq_pos = '\0';
    char *trimmed_key = trim(trimmed);
    char *trimmed_value = trim(eq_pos + 1);
    if (strlen(trimmed_key) == 0) {
        tloge("parse_config_line: lack of key\n");
        return -1;
    }
    if (strlen(trimmed_value) == 0) {
        tloge("parse_config_line: lack of value\n");
        return -1;
    }

    err = strncpy_s(key, MAX_LINE_LEN, trimmed_key, MAX_LINE_LEN - 1);
    if (err != 0) {
        tloge("parse_config_line: copy key failed, error is %d\n", err);
        return -1;
    }
    err = strncpy_s(value, MAX_LINE_LEN, trimmed_value, MAX_LINE_LEN - 1);
    if (err != 0) {
        tloge("parse_config_line: copy value failed, error is %d\n", err);
        return -1;
    }
    int ret = set_g_config((const char *)key, (const char *)value);
    return ret;
}

void config_init()
{
    FILE *fp;
    char line[MAX_LINE_LEN];
    fp = fopen(CONFIG_PATH, "r");
    if (fp == NULL) {
        tlogw("Config file %s not found, using defaults\n", CONFIG_PATH);
        goto print_config;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (parse_config_line(line) < 0) {
            tloge("Failed to parse config line: %s\n", line);
        }
    }
    fclose(fp);
    goto print_config;

print_config:
    tlogi("Config: socket_path = %s\n", g_config.socket_path);
    tlogi("Config: max_vm_count = %d\n", g_config.max_vm_count);
    tlogi("Config: libvirt_uri = %s\n", g_config.libvirt_uri);
    tlogi("Config: use_vcpuset = %s\n", g_config.use_vcpuset ? "true" : "false");
}

VtzbConfig *get_global_config(void)
{
    return &g_config;
}
