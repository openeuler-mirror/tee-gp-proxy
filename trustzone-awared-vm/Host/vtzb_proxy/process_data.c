#include "process_data.h"
#include <stdlib.h>
#include <stdint.h>
#include "debug.h"
#include "tee_sys_log.h"
#include "securec.h"
#include "vm.h"

static void *malloc_copy(void *buf, int buf_len , int size, int *poffset)
{
    void *res;
    int offset = *poffset;
    if (buf_len < offset + size || size < 4) {
        memmove_s(buf, buf_len, buf + offset, buf_len - offset);
        *poffset = buf_len - offset;
        return NULL;
    }
    res = malloc(size + sizeof(uint64_t));
    if (!res) {
        tloge("failed malloc\n");
        return NULL;
    }
    if (memcpy_s(res + sizeof(uint64_t), size, buf + offset, size)) {
        tloge("memcpy_s err\n");
        debug("memcpy_s err\n");
    }
    *poffset = offset + size;
    return res;
}

void *get_packet_item(void *buf, int buf_len, int *poffset)
{
    uint32_t packet_size;
    void *res = NULL;
    if (buf_len == *poffset) {
        *poffset = 0;
        return NULL;
    }

    if (buf_len < *poffset + (int)sizeof(int)) {
        return malloc_copy(buf, buf_len, buf_len - *poffset, poffset);
    }
    packet_size = *(uint32_t*)(buf + *poffset);
    res = malloc_copy(buf, buf_len, packet_size, poffset);
    return res; 
}