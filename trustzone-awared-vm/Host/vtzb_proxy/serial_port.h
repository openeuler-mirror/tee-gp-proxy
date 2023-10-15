#ifndef __SERIAL_PORT_H__
#define __SERIAL_PORT_H__
#include <sys/types.h>
#include <pthread.h>
#include <stdbool.h>
#include <poll.h>
#include "tee_client_list.h"
#include "vm.h"

#define VTZB_CHAR_DEV            "/tmp/vm_vtzb_sock"

#define SERIAL_PORT_NUM			 12
#define BUF_LEN_MAX_RD           1024 *512
#define UNIX_PATH_MAX            108

struct serial_port_list {
    pthread_mutex_t lock;
    struct ListNode head;
};

struct serial_port_file {
    pthread_mutex_t lock;
    char path[UNIX_PATH_MAX];
    int sock;
    bool opened;
    int index;
    struct ListNode head;
    char *rd_buf;
    int buf_size;
    off_t offset;
    struct vm_file *vm_file;
};

int serial_port_list_init();
void serial_port_list_destroy();
int send_to_vm(struct serial_port_file *serial_port, void *packet_rsp, size_t size_rsp);
void *get_rd_buf(int serial_port_fd);
void *get_serial_port_file(int serial_port_fd);
void check_stat_serial_port(int first);
#endif

