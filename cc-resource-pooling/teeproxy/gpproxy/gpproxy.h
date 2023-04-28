#ifndef _GPPROXY_H
#define _GPPROXY_H
typedef struct sessionid_node
{
    uint32_t session_id;
    struct timeval session_createtime;
    struct sessionid_node *next;
    struct sessionid_node *prev;
} sin_t;

typedef struct worker_rec
{
    uint8_t busy;
    int32_t context_fd;
    uint64_t context_addr;
    struct timeval context_createtime;
    int sessionid_count;
    sin_t *first;
    sin_t *last;
} wr_t;
#endif // _GPPROXY_H
