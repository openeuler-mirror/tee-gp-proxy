/*
 * File Name: qca_host_server_demo.c
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <linux/vm_sockets.h>
#include <pthread.h>

#include "ra_client_api.h"
#include "tee_client_api.h"
#include "securec.h"
#include "cJSON.h"

#define DEFAULT_PORT 8000
#define MAXLINE 4096

#define SHAREMEM_LIMIT (0x100000) /* 1 MB */
#define PARAMS_RESERVED_SIZE (0x2000)
#define OUT_DATA_RESERVED_SIZE (0x3000)
#define REMOTE_ATTEST_CMD (0x1001)

#define MAX_VM_NUM  32
struct fd_map
{
    int vm_fd;
    int client_fd;
    int nsid;
    int valid;
};

struct fd_map g_fd_map[MAX_VM_NUM] = {0};

char g_JSON[4096];

static const TEEC_UUID g_tee_qta_uuid = {
    0xe08f7eca, 0xe875, 0x440e, {
        0x9a, 0xb0, 0x5f, 0x38, 0x11, 0x36, 0xc6, 0x00
    }
};

#define CMD_CAN_NOT_CM_VM   0xff001100
#define CMD_OK              0xff000000
#define CMD_REGISTER_VM     0xff110011

typedef struct {
    int packet_size;
    int cmd;
    int nsid;
    char data[];
} struct_packet_cmd;

typedef struct {
    int packet_size;
    int rsp;
    int ret;
} struct_packet_rsp;

TEEC_Context g_context = {0};
TEEC_Session g_session = {0};
TEEC_Operation g_operation = {0};

int init_context()
{
    TEEC_UUID uuid = g_tee_qta_uuid;
    TEEC_Result result = TEEC_InitializeContext(NULL, &g_context);
    if (result != TEEC_SUCCESS)
    {
        printf("init g_context is failed, result is 0x%x\n", result);
        return result;
    }

    g_operation.started = 1;
    g_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    result = TEEC_OpenSession(&g_context, &g_session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &g_operation, NULL);
    if (result != TEEC_SUCCESS)
    {
        printf("open g_session is failed, result is 0x%x\n", result);
        goto cleanup_1;
    }
    printf("InitializeContext success\n");
    return 0;
cleanup_1:
    TEEC_FinalizeContext(&g_context);
    return result;
}

void destroy_contex()
{
    TEEC_CloseSession(&g_session);
    TEEC_FinalizeContext(&g_context);
}

int reg_vm(char *buf)
{
    uint32_t origin;
    struct ra_buffer_data data;
    data.buf = buf;
    data.size = strlen(buf);

    TEEC_Result result = RegisterContainer(&data, &g_context, &g_session, &origin);
    if (result != TEEC_SUCCESS) {
        printf("open g_session is failed, result is 0x%x\n", result);
    }

    printf("reg VM result = %d\n", result);
    return result;
}

void add_vm_fd_map(int vm_fd, int nsid)
{
    int find = 0;
    for (int i = 0; i < MAX_VM_NUM; i++) {
        if (g_fd_map[i].nsid == nsid) {
            g_fd_map[i].vm_fd = vm_fd;
            g_fd_map[i].nsid = nsid;
            g_fd_map[i].valid = 1;
            printf("add vm_fd = %d\n", vm_fd);
            find = 1;
            break;
        }
    }
    if (find)
        return;
    for (int i = 0; i < MAX_VM_NUM; i++) {
        if (!g_fd_map[i].valid) {
            g_fd_map[i].vm_fd = vm_fd;
            g_fd_map[i].nsid = nsid;
            g_fd_map[i].valid = 1;
            printf("add vm_fd = %d\n", vm_fd);
            break;
        }
    }
}

void add_client_fd_map(int client_fd, int nsid)
{
    for (int i = 0; i < MAX_VM_NUM; i++) {
        if (g_fd_map[i].valid == nsid) {
            g_fd_map[i].client_fd = client_fd;
            break;
        }
    }
}

void remove_fd_map(int nsid)
{
     for (int i = 0; i < MAX_VM_NUM; i++) {
        if (g_fd_map[i].nsid == nsid) {
            g_fd_map[i].vm_fd = 0;
            g_fd_map[i].nsid = 0;
            g_fd_map[i].valid = 0;

            break;
        }
    }   
}

void proc_mesg(char *recv_buf, int peer_fd)
{
    int ret = 0;
    struct_packet_cmd *packet_cmd = (struct_packet_cmd *)recv_buf;
    struct_packet_rsp packet_rsp = {0};
    if (!packet_cmd)
        return;
    switch (packet_cmd->cmd)
    {
    case CMD_REGISTER_VM:
        if (packet_cmd->cmd == CMD_REGISTER_VM) {
            printf("data = %s \n", ((struct_packet_cmd*)recv_buf)->data);
        }
        ret = reg_vm(packet_cmd->data);
        packet_rsp.packet_size = sizeof(packet_rsp);
        packet_rsp.ret = ret;
        packet_rsp.rsp = CMD_OK;
        send(peer_fd, &packet_rsp, sizeof(packet_rsp), 0);
        if (ret == 0)
            add_vm_fd_map(peer_fd, packet_cmd->nsid);
        break;
    
    default:
        break;
    }
}

void *th_vsock_fun(void *arg)
{
    int s;
    int peer_fd;
    struct sockaddr_vm peer_addr;
    socklen_t peer_addr_size;
    struct sockaddr_vm addr;
    char recv_buf[4096];
    size_t sizet_buf_recv;
    char cbuf_vmreg[6];
    char cbuf_strhashnsid[65];
    char cbuf_strnsid[10];
    int insid;
    int iresult;
    unsigned char uc_sockbuf[4096];

    s = socket(AF_VSOCK, SOCK_STREAM, 0);

    if (s < 0) {
        perror("socket");
        return NULL;
    }

    memset(&addr, 0, sizeof(struct sockaddr_vm));
    addr.svm_family = AF_VSOCK;
    addr.svm_port = 9999;
    addr.svm_cid = VMADDR_CID_HOST;
    bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_vm));
    listen(s, 0);

    peer_addr_size = sizeof(struct sockaddr_vm);

    while (1) {
        peer_fd = accept(s, (struct sockaddr *)&peer_addr, &peer_addr_size);
        if (peer_fd < 0) {
            perror("accept");
            printf("accept vsocket error: %s(errno: %d)", strerror(errno), errno);
            continue;
        }
        fprintf(stderr, "connection from cid %u port %u \n", peer_addr.svm_cid, peer_addr.svm_port);

        sizet_buf_recv = recv(peer_fd, &recv_buf, 4096, 0);
        if (sizet_buf_recv > 0) {
            printf("   received %lu bytes \n", sizet_buf_recv);
        }

        proc_mesg(recv_buf, peer_fd);

        /*
            if (!fork())
            {
                if (send(connect_fd, "Hello,you are connected!\n", 26, 0) == -1)
                perror("send error");
                close(connect_fd);
                exit(0);
            }
            buff[n] = '\0';
            printf("recv msg from client: %s\n", buff);
         */

        //close(peer_fd);
    }
    close(s);
}


typedef struct {
    int packet_size;
    int cmd;
    int nsid;
    char data[];
} packet_cmd_client;

typedef struct {
    int packet_size;
    int cmd;
    int rsp;
    int ret;
    char data[];
} packet_rsp_client;

void proc_client_cmd(char *buff, int sock_fd)
{
    int bfind = 0;
    int ret = 0;
    int recv_size;
    int buf_size = 0x4000 + sizeof(packet_rsp_client);
    packet_cmd_client *packet_cmd = (packet_cmd_client *)buff;
    packet_rsp_client *packet_rsp;
    packet_rsp = (packet_rsp_client *)malloc(buf_size);
    switch (packet_cmd->cmd)
    {
    case 1:/*验证TA*/
        for (int i = 0; i < MAX_VM_NUM; i++) {
            if (g_fd_map[i].nsid == packet_cmd->nsid) {
                send(g_fd_map[i].vm_fd, packet_cmd, packet_cmd->packet_size, 0);
                printf("recv msg from client: %s\n", packet_cmd->data);
                recv_size = recv(g_fd_map[i].vm_fd, packet_rsp, buf_size, 0);
                printf("ret = %d, cmd = %lx\n", packet_rsp->ret, packet_rsp->cmd);
                //printf("data = %s\n", packet_rsp->data);
                send(sock_fd, packet_rsp, packet_rsp->packet_size, 0);
                close(sock_fd);
                bfind = 1;
                break;
            }
        }
        if (!bfind) {
            packet_rsp->rsp = CMD_CAN_NOT_CM_VM;
            packet_rsp->ret = -1;
            send(sock_fd, packet_rsp, packet_rsp->packet_size, 0);
        }
        break;
    default:
        break;
    }
}

void *th_pro_client(void *args)
{
    int socket_fd;
    struct sockaddr_in servaddr;
    char buff[4096];
    int n;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(DEFAULT_PORT);

    if (bind(socket_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        printf("bind socket error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }
    if (listen(socket_fd, 10) == -1) {
        printf("listen socket error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }
    printf("======waiting for client's request======\n");
    while (1) {
        int connect_fd;
        if ((connect_fd = accept(socket_fd, (struct sockaddr *)NULL, NULL)) == -1)
        {
            printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
            continue;
        }
        n = recv(connect_fd, buff, MAXLINE, 0);
        proc_client_cmd(buff, connect_fd);
    }
    close(socket_fd);
}

char *create_no_as_cJson()
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "Handler", "provisioning-input");
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "Version", "TEE.RA.1.0");
    cJSON_AddStringToObject(payload, "scenario", "sce_no_as");
    cJSON_AddStringToObject(payload, "Hash_alg", "HS256");
    cJSON_AddItemToObject(root, "Payload", payload);

    char *json_string = cJSON_Print(root);

    cJSON_Delete(root);

    return json_string;
}

int provisionNoAS()
{
    char *tmp_buf = create_no_as_cJson();
    if (!tmp_buf) {
        printf("provisionNoAS failed \n");
        return -1;
    }

    struct ra_buffer_data in;
    struct ra_buffer_data out;
    in.buf = tmp_buf;
    in.size = strlen(tmp_buf);
    printf("tmp_buf = %s \n", in.buf);

    out.size = 0x3000;
    out.buf = malloc(0x3000);
    if (!out.buf) {
        free(tmp_buf);
        return -1;
    }
    TEEC_Result result = RemoteAttest(&in, &out);
    if (result != TEEC_SUCCESS) {
        printf("open g_session is failed, result is 0x%x\n", result);
    }
    free(tmp_buf);
    printf("provisionNoAS result = %d\n", result);
    return result;
}

int main(int argc, char **argv)
{
    pthread_t th_vsock;
    pthread_t th_client;

    if (provisionNoAS()){
        return 0;
    }

    if (init_context()) {
        perror("init_context failed\n");
        return 0;
    }

    (void)pthread_create(&th_vsock, NULL, th_vsock_fun, NULL);
    (void)pthread_create(&th_client, NULL, th_pro_client, NULL);

    (void)pthread_join(th_vsock, NULL);
    (void)pthread_join(th_client, NULL);

    destroy_contex();

    return 0;
}

