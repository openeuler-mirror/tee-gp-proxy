#define _GNU_SOURCE
#include "serial_port.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
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
#include "config.h"

#include <linux/vm_sockets.h>

#define VSOCK_PORT 30000
int g_server_fd = -1;
int g_index = 0;

extern ThreadPool g_pool;
struct serial_port_list g_serial_list;
struct pollfd g_pollfd[SERIAL_PORT_NUM_MAX];
struct timeval g_last_time, g_cur_time;
struct serial_port_file *g_serial_array[SERIAL_PORT_NUM_MAX];

static void pollfd_init()
{
    for (int i = 0; i < SERIAL_PORT_NUM_MAX; ++i) {
        g_pollfd[i].fd = -1;
    }
}

int serial_port_list_init()
{
    VtzConfig *cfg = get_global_config();
    int serial_port_num = cfg->max_vm_count;
    gettimeofday(&g_last_time, NULL);
    gettimeofday(&g_cur_time, NULL);
    pthread_mutex_init(&g_serial_list.lock, NULL);
    ListInit(&g_serial_list.head);
    pollfd_init();

    g_server_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        tloge("vsock server socket creation failed\n");
        return -1;
    }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_HOST;
    addr.svm_port = VSOCK_PORT;

    if (bind(g_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        tloge("bind vsock server failed\n");
        close(g_server_fd);
        return -1;
    }

    if (listen(g_server_fd, serial_port_num) < 0) {
        tloge("listen vsock server failed\n");
        close(g_server_fd);
        return -1;
    }

    tlogi("vsock server start to listen\n");
    return 0;

    serial_port_list_destroy();
    return -ENOMEM;
}

struct serial_port_file* find_port_by_cid(uint32_t cid)
{
    struct serial_port_file *port;

    (void)pthread_mutex_lock(&g_serial_list.lock);

    LIST_FOR_EACH_ENTRY(port, &g_serial_list.head, head) {
        if (port->vm_file->cid == cid) {
            (void)pthread_mutex_unlock(&g_serial_list.lock);
            return port;
        }
    }

    (void)pthread_mutex_unlock(&g_serial_list.lock);
    return NULL;
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

void release_vm_file(struct serial_port_file *serial_port, int i)
{
    if (!serial_port) {
        tloge("vm %d 's serial_port is null\n", i);
        return;
    }
    if (serial_port->sock >= 0) {
        shutdown(serial_port->sock, SHUT_RDWR);
        close(serial_port->sock);
    }
    serial_port->sock = -1;
    g_pollfd[i].fd = -1;
    g_serial_array[i] = NULL;
    serial_port->opened = false;
    serial_port->offset = 0;
    if (serial_port->vm_file) {
        thread_pool_submit(&g_pool, destroy_vm_file, (void *)(serial_port->vm_file));
    }
    serial_port->vm_file = NULL;
}

int set_serial_port_index(struct serial_port_file *serial_port)
{
    for (int i = 0; i < SERIAL_PORT_NUM_MAX; ++i) {
        if (g_pollfd[i].fd == -1) {
            serial_port->index = i;
            g_pollfd[i].fd = serial_port->sock;
            g_pollfd[i].events = (POLLERR|POLLHUP|POLLRDHUP);
            return 0;
        }
    }
    return -1;
}

void do_check_stat_serial_port()
{
    int ret;
    struct serial_port_file *serial_port = NULL;
    struct pollfd pfd = {0};
    int client_fd;

    pfd.fd = g_server_fd;
    pfd.events = POLLIN;

    ret = safepoll(&pfd, 1, 1000);
    if (ret <= 0)
        return;

    if (pfd.revents & POLLIN) {
        struct sockaddr_vm addr;
        socklen_t len = sizeof(addr);

        while(1) {
            client_fd = accept(g_server_fd, (struct sockaddr*)&addr, &len);
            if (client_fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    tloge("accept failed, errno=%d\n", errno);
                return;
            }

            serial_port = (struct serial_port_file *)malloc(sizeof(struct serial_port_file));
            if (!serial_port) {
                tloge("Failed to allocate memory for serial_port\n");
                close(client_fd);
                return;
            }
            memset_s(serial_port, sizeof(struct serial_port_file), 0, sizeof(struct serial_port_file));
            serial_port->sock = client_fd;
            if (set_serial_port_index(serial_port)) {
                tloge("vm num upper limit\n");
                close(client_fd);
                return;
            }
            serial_port->offset = 0;
            serial_port->rd_buf = (char *)malloc(BUF_LEN_MAX_RD);
            memset(serial_port->rd_buf, 0x55, BUF_LEN_MAX_RD);
            serial_port->vm_file = create_vm_file(addr.svm_cid);
            g_serial_array[serial_port->index] = serial_port;

            create_reader_thread(serial_port, serial_port->index);

            (void)pthread_mutex_lock(&g_serial_list.lock);
            ListInsertTail(&g_serial_list.head, &serial_port->head);
            (void)pthread_mutex_unlock(&g_serial_list.lock);
        }
    }
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
    VtzConfig *cfg = get_global_config();
    int serial_port_num = cfg->max_vm_count;
    tmp_buf = malloc(BUF_LEN_MAX_RD);
    if (!tmp_buf)
        return -ENOMEM;
    gettimeofday(&start, NULL);
    gettimeofday(&end, NULL);
    while (end.tv_sec - start.tv_sec < 1) {
        ret = safepoll(g_pollfd, serial_port_num, 0);
        for (i = 0; i < serial_port_num; i++) {
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
