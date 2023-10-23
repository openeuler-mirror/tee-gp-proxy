#include "serial_port.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "securec.h"
#include "tc_ns_client.h"
#include "tee_client_list.h"
#include "tee_client_log.h"
#include "tee_sys_log.h"
#include "comm_structs.h"
#include "debug.h"
#include "virt.h"

struct serial_port_list g_serial_list;
struct pollfd g_pollfd[SERIAL_PORT_NUM];
int g_pollfd_len = 0;
struct timeval g_last_time, g_cur_time;

int serial_port_list_init()
{
    int i;
    struct serial_port_file *serial_port;
    gettimeofday(&g_last_time, NULL);
    gettimeofday(&g_cur_time, NULL);
    pthread_mutex_init(&g_serial_list.lock, NULL);
    ListInit(&g_serial_list.head);
    for ( i = 0; i < SERIAL_PORT_NUM; i++)
    {
        serial_port = (struct serial_port_file *)malloc(sizeof(struct serial_port_file));
        if (!serial_port) {
            tloge("Failed to allocate memory for serial_port\n");
            goto ERR;
        }
        memset_s(serial_port, sizeof(struct serial_port_file), 0, sizeof(struct serial_port_file));
        sprintf(serial_port->path, "%s%d", VTZB_CHAR_DEV, i);
        printf("path = %s \n", serial_port->path);
        serial_port->opened = false;
        serial_port->offset = 0;
        serial_port->rd_buf = (char *)malloc(BUF_LEN_MAX_RD);
        serial_port->vm_file = NULL;
        if (!serial_port->rd_buf) {
            tloge("Failed to allocate memory for rd_buf\n");
            free(serial_port);
            goto ERR;
        }
        pthread_mutex_init(&serial_port->lock, NULL);
        ListInsertTail(&g_serial_list.head, &serial_port->head);
    }

    return 0;
ERR:
    serial_port_list_destroy();
    return -ENOMEM;
}

void serial_port_list_destroy()
{
    debug("free serialports\n");
    struct serial_port_file *serial_port = NULL;
    struct serial_port_file *tmp = NULL;
    (void)pthread_mutex_lock(&g_serial_list.lock);
    LIST_FOR_EACH_ENTRY_SAFE(serial_port, tmp, &g_serial_list.head, head) {
        if (serial_port->rd_buf) {
            free(serial_port->rd_buf);
            serial_port->rd_buf = NULL;
        }
        if (serial_port->opened) {
            close(serial_port->sock);
        }
        ListRemoveEntry(&serial_port->head);
        (void)pthread_mutex_destroy(&serial_port->lock);
        free(serial_port);
    }
    (void)pthread_mutex_unlock(&g_serial_list.lock);
    (void)pthread_mutex_destroy(&g_serial_list.lock);
}

int send_to_vm(struct serial_port_file *serial_port, void *packet_rsp, size_t size_rsp)
{
    int ret = 0;
    pthread_mutex_lock(&serial_port->lock);
    ret = write(serial_port->sock, packet_rsp, size_rsp);
    pthread_mutex_unlock(&serial_port->lock);
    return ret;
}

void *get_rd_buf(int serial_port_fd)
{
    struct serial_port_file *serial_port;
    LIST_FOR_EACH_ENTRY(serial_port, &g_serial_list.head, head){
        if (serial_port->sock == serial_port_fd) {
            return serial_port->rd_buf;
        }
    }
    return NULL;
}

void *get_serial_port_file(int serial_port_fd)
{
    struct serial_port_file *serial_port;
    LIST_FOR_EACH_ENTRY(serial_port, &g_serial_list.head, head){
        if (serial_port->sock == serial_port_fd) {
            return serial_port;
        }
    }
    return NULL;
}

static int connect_domsock_chardev(char* dev_path, int* sock)
{
    int ret;
    ret = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ret == -1) {
        tloge("execute socket() failed \n");
        return -1;
    }

    *sock = ret;

    struct sockaddr_un sock_addr;
    sock_addr.sun_family = AF_UNIX;
    if (memcpy_s(&sock_addr.sun_path, sizeof(sock_addr.sun_path), dev_path,
        sizeof(sock_addr.sun_path))) {
        tloge("memcpy_s err\n");
        debug("memcpy_s err\n");
    }
    ret = connect(*sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret < 0) {
        tloge("connect domain socket %s failed \n", dev_path);
    }

    return ret;
}

void do_check_stat_serial_port()
{
    int ret;
    struct timeval start, end;
    struct serial_port_file *serial_port;
    uint32_t cost = 0;
    gettimeofday(&start, NULL);
    (void)pthread_mutex_lock(&g_serial_list.lock);
    LIST_FOR_EACH_ENTRY(serial_port, &g_serial_list.head, head){
        if (serial_port->opened == false) {
            ret = access(serial_port->path, R_OK | W_OK);
            if (ret == 0) {
                ret = connect_domsock_chardev(serial_port->path, &(serial_port->sock));
                if (ret < 0) {
                    debug("connect_domsock_chardev(%s) failed, ret = %d \n", serial_port->path, ret);
                } else {
                    debug("open new socket \n");
                    serial_port->opened = true;
                    serial_port->offset = 0;
                    g_pollfd[g_pollfd_len].fd = serial_port->sock;
                    g_pollfd[g_pollfd_len].events = POLLIN;
                    serial_port->index = g_pollfd_len;
                    g_pollfd_len++;
                }
            } else{
                debug(" can't access \n");
            }
        } else {
            ret = access(serial_port->path, R_OK | W_OK);
            if (ret) {
                debug(" disconnetc socket \n");
                close(serial_port->sock);
                g_pollfd[serial_port->index] = g_pollfd[g_pollfd_len - 1];
                g_pollfd_len--;
                serial_port->opened = false;
                serial_port->vm_file = NULL;
            }
        }
    }
    (void)pthread_mutex_unlock(&g_serial_list.lock);
    gettimeofday(&end, NULL);
    cost = (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);
    (void)cost;
    //printf("check_stat_serial_port cost : %f us\n", cost * 1.0);
}

void check_stat_serial_port()
{
    gettimeofday(&g_cur_time, NULL);
    if (g_cur_time.tv_sec - g_last_time.tv_sec > 20) {
        do_check_stat_serial_port();
        gettimeofday(&g_last_time, NULL);
    }
}

static int clean_dirty_data()
{
    int ret = 0;
    int i = 0;
    struct timeval start, end;
    void *tmp_buf;
    (void)ret;
    if (!g_pollfd_len)
        return 0;
    tmp_buf = malloc(BUF_LEN_MAX_RD);
    if (!tmp_buf)
        return -ENOMEM;
    gettimeofday(&start, NULL);
    gettimeofday(&end, NULL);
    while(end.tv_sec - start.tv_sec < 1) {
        ret = safepoll(g_pollfd, g_pollfd_len, 0);
        for (i = 0; i < g_pollfd_len; i++) {
            if (g_pollfd[i].revents & POLLIN) {
                ret = read(g_pollfd[i].fd, tmp_buf, BUF_LEN_MAX_RD);
            }
        }
        gettimeofday(&end, NULL);
    }
    free(tmp_buf);
    return 0;
}

int check_stat_serial_port_first()
{
    gettimeofday(&g_cur_time, NULL);
    gettimeofday(&g_last_time, NULL);
    do_check_stat_serial_port();
    return clean_dirty_data();
}
