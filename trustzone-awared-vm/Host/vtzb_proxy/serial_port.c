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
#include "vm.h"
#include "debug.h"
#include "thread_pool.h"
#include "virt.h"

struct serial_port_list g_serial_list;
struct pollfd g_pollfd[SERIAL_PORT_NUM];
struct timeval g_last_time, g_cur_time;
struct serial_port_file *g_serial_array[SERIAL_PORT_NUM];

int serial_port_list_init()
{
    int i;
    struct serial_port_file *serial_port;
    gettimeofday(&g_last_time, NULL);
    gettimeofday(&g_cur_time, NULL);
    pthread_mutex_init(&g_serial_list.lock, NULL);
    ListInit(&g_serial_list.head);
    for (i = 0; i < SERIAL_PORT_NUM; i++) {
        serial_port = (struct serial_port_file *)malloc(sizeof(struct serial_port_file));
        if (!serial_port) {
            tloge("Failed to allocate memory for serial_port\n");
            goto ERR;
        }
        memset_s(serial_port, sizeof(struct serial_port_file), 0, sizeof(struct serial_port_file));
        sprintf(serial_port->path, "%s%d", VTZB_CHAR_DEV, i);
        serial_port->opened = false;
        serial_port->offset = 0;
        serial_port->rd_buf = (char *)malloc(BUF_LEN_MAX_RD);
        serial_port->vm_file = NULL;
        serial_port->index = i;
        g_pollfd[i].fd = -1;
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
        release_vm_file(serial_port, serial_port->index);
        free(serial_port);
    }
    (void)pthread_mutex_unlock(&g_serial_list.lock);
    (void)pthread_mutex_destroy(&g_serial_list.lock);
}

int send_to_vm(struct serial_port_file *serial_port, void *packet_rsp, size_t size_rsp)
{
    int ret = 0;
    if (!serial_port || serial_port->sock <= 0 || !packet_rsp)
        return -1;
    pthread_mutex_lock(&serial_port->lock);
    ret = send(serial_port->sock, packet_rsp, size_rsp, MSG_NOSIGNAL);
    if (ret == -1) {
        if (errno == EPIPE) {
            // 处理 EPIPE 错误
            tloge("Send failed with EPIPE: Broken pipe, socket closed\n");
        } else {

            tloge("Send failed, errno: %d\n", errno);
        }
    }
    pthread_mutex_unlock(&serial_port->lock);
    return ret;
}

static int connect_domsock_chardev(char *dev_path, int *sock)
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
        goto CLOSE;
    }
    ret = connect(*sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
    if (ret < 0) {
        tloge("connect domain socket %s failed \n", dev_path);
        goto CLOSE;
    }
    return ret;

CLOSE:
    close(*sock);
    *sock = -1;
    return ret;
}

void release_vm_file(struct serial_port_file *serial_port, int i)
{
    if (!serial_port) {
        tloge("vm %d 's serial_port is null\n", i);
        return;
    }
    close(serial_port->sock);
    serial_port->sock = -1;
    g_pollfd[i].fd = -1;
    g_serial_array[i] = NULL;
    serial_port->opened = false;
    serial_port->offset = 0;
    if (serial_port->vm_file) {
        destroy_vm_file(serial_port->vm_file);
    }
    serial_port->vm_file = NULL;
}

static void do_check_stat_serial_port()
{
    int ret;
    int i = 0;
    struct serial_port_file *serial_port;
    (void)pthread_mutex_lock(&g_serial_list.lock);
    LIST_FOR_EACH_ENTRY(serial_port, &g_serial_list.head, head) {
        if (serial_port->opened == false) {
            ret = access(serial_port->path, R_OK | W_OK);
            if (ret == 0) {
                ret = connect_domsock_chardev(serial_port->path, &(serial_port->sock));
                if (ret < 0) {
                    tloge("connect_domsock_chardev(%s) failed, ret = %d \n", serial_port->path, ret);
                } else {
                    tlogd("vm %d started, connect fd %d, create read thread\n", i, serial_port->sock);
                    serial_port->opened = true;
                    serial_port->offset = 0;
                    g_pollfd[i].fd = serial_port->sock;
                    g_serial_array[i] = serial_port;
                    create_reader_thread(serial_port, i);
                }
            }
        } else {
            ret = access(serial_port->path, R_OK | W_OK);
            if (ret) {
                tlogd("vm %d closed, fd %d is invalid, should close\n", i, serial_port->sock);
                g_pollfd[i].fd = -1;
                serial_port->opened = false;
                g_serial_array[i] = NULL;
                release_vm_file(serial_port, i);
            }
        }
        i++;
    }
    (void)pthread_mutex_unlock(&g_serial_list.lock);
}

void check_stat_serial_port()
{
    gettimeofday(&g_cur_time, NULL);
    if (g_cur_time.tv_sec - g_last_time.tv_sec > CHECK_TIME_SEC) {
        do_check_stat_serial_port();
        gettimeofday(&g_last_time, NULL);
    } else {
        sleep(CHECK_TIME_SEC);
    }
}

static int clean_dirty_data()
{
    int ret = 0;
    int i = 0;
    struct timeval start, end;
    void *tmp_buf;
    (void)ret;
    tmp_buf = malloc(BUF_LEN_MAX_RD);
    if (!tmp_buf)
        return -ENOMEM;
    gettimeofday(&start, NULL);
    gettimeofday(&end, NULL);
    while (end.tv_sec - start.tv_sec < 1) {
        ret = safepoll(g_pollfd, SERIAL_PORT_NUM, 0);
        for (i = 0; i < SERIAL_PORT_NUM; i++) {
            if (g_pollfd[i].revents & POLLIN) {
                ret = read(g_pollfd[i].fd, tmp_buf, BUF_LEN_MAX_RD);
                tlogd("clean vm %d dirty data %d\n", i, ret);
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