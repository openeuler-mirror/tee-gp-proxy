#include "process_data.h"
#include <stdlib.h>
#include <stdint.h>
#include "debug.h"
#include "tee_sys_log.h"
#include "securec.h"
#include "vm.h"

static void *malloc_copy(void *buf, int buf_len, int size, int *poffset)
{
    void *res;
    int offset = *poffset;
    // packet date not write complete, just move date to front
    if (buf_len < offset + size || size < (int)sizeof(uint32_t)) {
        if (offset) {
            memmove_s(buf, buf_len, buf + offset, buf_len - offset);
        }
        *poffset = buf_len - offset;
        return NULL;
    }
    res = malloc(size + sizeof(vm_trace_data));
    if (!res) {
        tloge("failed malloc\n");
        return NULL;
    }
    if (memcpy_s(res + sizeof(vm_trace_data), size, buf + offset, size)) {
        tloge("memcpy_s failed, just skip this packet\n");
        free(res);
        res = NULL;
    }
    *poffset = offset + size;
    return res;
}

void *get_packet_item(void *buf, int buf_len, int *poffset)
{
    uint32_t packet_size;
    void *res = NULL;
    // packet data deal over, offset reset zero
    if (buf_len == *poffset) {
        *poffset = 0;
        return NULL;
    }

    if (buf_len < *poffset + (int)sizeof(uint32_t)) {
        return malloc_copy(buf, buf_len, buf_len - *poffset, poffset);
    }
    packet_size = *(uint32_t *)(buf + *poffset);
    res = malloc_copy(buf, buf_len, packet_size, poffset);
    return res; 
}