/*
 * File Name: qca_guest_demo.c
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <linux/vm_sockets.h>

#include "ra_client_api.h"

#include "tee_client_api.h"
#include "securec.h"

#include "cJSON.h"
#include "sha256.h"
#include "b64.h"

#define DEFAULT_PORT 8000
#define MAXLINE 4096

#define SHAREMEM_LIMIT (0x100000) /* 1 MB */
#define PARAMS_RESERVED_SIZE (0x2000)
#define OUT_DATA_RESERVED_SIZE (0x3000)
#define REMOTE_ATTEST_CMD (0x1001)

#define USER_DATA_SIZE 64
#define NODE_LEN 8
#define VERSION_SIZE 11
#define TS_SIZE 22
#define UUID_SIZE 16
#define HASH_SIZE 32

unsigned char g_hexstr_hash_nsid[SHA256_BLOCK_SIZE * 2 + 1];
int g_nsid;

typedef struct
{
    uint32_t size;
    uint8_t *buf;
} buffer_data;

typedef struct
{
    uint8_t version[VERSION_SIZE];
    uint8_t timestamp[TS_SIZE];
    uint8_t nonce[USER_DATA_SIZE];
    uint8_t uuid[UUID_SIZE];
    uint32_t scenario;
    uint32_t sig_alg;  // Signature algorithm type
    uint32_t hash_alg; // Hash algorithm type
    uint8_t image_hash[HASH_SIZE];
    uint8_t hash[HASH_SIZE];
    uint8_t reserve[HASH_SIZE];
    // uint8_t		signature[SIG_SIZE];
    // uint8_t 	cert[CERT_SIZE];  //AK cert
    buffer_data *signature;
    buffer_data *cert;
} TA_report;

#define MAXSIZE 1000
#define DATABUFMIN 100
#define DATABUFMAX 20000

#define DEBUG 1

#ifdef DEBUG
static void debug(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

#define PRINTF_SIZE 16
static void dump_buff(const char *buffer, size_t bufLen)
{
    size_t i;
    if (buffer == NULL || bufLen == 0)
    {
        return;
    }

    // printf("\n--------------------------------------------------\n");
    printf("--------------------------------------------------\n");
    printf("buf_len = %d\n", (int)bufLen);
    for (i = 0; i < bufLen; i++)
    {
        if (i % PRINTF_SIZE == 0 && i != 0)
        {
            printf("\n");
        }
        printf("%02x ", *(buffer + i));
    }
    printf("\n--------------------------------------------------\n");
    return;
}
#else
#define debug(fmt, ...) \
    do                  \
    {                   \
    } while (0)
#define dump_buff(buffer, bufLen) \
    do                            \
    {                             \
    } while (0)
#endif

int get_nsid_and_hash()
{
    FILE *fp;
    char str_nsid[100] = {0};
    char container_id[256] = {0};
    SHA256_CTX ctx;
    BYTE hash_nsid[SHA256_BLOCK_SIZE];
    int i;

    fp = fopen("/tmp/qca_nsid", "r");
    memset(str_nsid, 0, sizeof(str_nsid));
    fgets(str_nsid, sizeof(str_nsid), fp);
    fclose(fp);

    g_nsid = atoi(str_nsid);

    sha256_init(&ctx);
    sha256_update(&ctx, str_nsid, strlen(str_nsid) - 1);
    sha256_final(&ctx, hash_nsid);

    memset(g_hexstr_hash_nsid, 0, SHA256_BLOCK_SIZE * 2 + 1);
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        sprintf(g_hexstr_hash_nsid + i * 2, "%02x", hash_nsid[i]);
    }
    printf("guest vm nsid str (len = %d): %s", strlen(str_nsid), str_nsid);
    printf("guest vm nsid int: %d \n", g_nsid);
    printf("guest vm nsid str sha256 hex str: %s \n", g_hexstr_hash_nsid);
    if (!g_nsid)
        return -1;
    return 0;
}

char *Convert(buffer_data *data)
{
    // determine whether the buffer is legal
    if (data == NULL) {
        printf("illegal buffer data pointer.");
        return NULL;
    }

    if (data->size > DATABUFMAX || data->size < DATABUFMIN) {
        printf("size of buffer is illegal.");
        return NULL;
    }

    cJSON *cj = cJSON_ParseWithLength(data->buf, data->size);
    if (cj == NULL) {
        printf("cjson parse report error.");
        return NULL;
    }

    char *json_string = cJSON_Print(cj);
    //printf("out_data = %s\n", json_string);
    cJSON_Delete(cj);

    return json_string;
}

char *create_VM_cJson()
{
    cJSON *root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "Handler", "report-input");

    cJSON *payload = cJSON_CreateObject();

    cJSON_AddStringToObject(payload, "Version", "TEE.RA.1.0");

    cJSON_AddStringToObject(payload, "Nonce", "4JeF994WNGepoFyvu-6hYqj0VT6kixdh82huGh2D19wm_Mjj1jZdzHxUYJHw_j0ZlQjBpRqxpVJJxGMFaO2aIQ");
    cJSON_AddStringToObject(payload, "Uuid", "e3d37f4a-f24c-48d0-8884-3bdd6c44e988");

    cJSON_AddStringToObject(payload, "Hash_alg", "HS256");
    cJSON_AddBoolToObject(payload, "With_tcb", false);
    cJSON_AddNullToObject(payload, "Daa_bsn");

    cJSON *container_info = cJSON_CreateObject();
    //cJSON_AddStringToObject(container_info, "id", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstuvwxyz01");
    cJSON_AddStringToObject(container_info, "id", g_hexstr_hash_nsid);
    cJSON_AddStringToObject(container_info, "type", "docker");

    cJSON_AddItemToObject(payload, "container_info", container_info);

    cJSON_AddItemToObject(root, "Payload", payload);

    char *json_string = cJSON_Print(root);

    cJSON_Delete(root);

    return json_string;
}

char *addFieldToPayload(char *buf)
{
    //printf("buf = %s\n", buf);
    cJSON *root = cJSON_Parse(buf);
    if (root == NULL) {
        printf("Error parsing JSON\n");
        return NULL;
    }
    cJSON *payload = cJSON_GetObjectItem(root, "payload");
    if (payload != NULL && cJSON_IsObject(payload)) {
        cJSON *container_info = cJSON_CreateObject();
        cJSON_AddStringToObject(container_info, "id", g_hexstr_hash_nsid);
        cJSON_AddStringToObject(container_info, "type", "docker");
        cJSON_AddItemToObject(payload, "container_info", container_info);
        //cJSON_AddItemToObject(root, "Payload", payload);
        char *newJsonStr = cJSON_Print(root);
        printf("Modified JSON: %s\n", newJsonStr);

        cJSON_Delete(root);

        return newJsonStr;
    } else {
        printf("Error: 'payload' node not found or not an object\n");
        cJSON_Delete(root);
        return NULL;
    }

}

char *get_report(char *buf)
{
    char *tmp_str = NULL;
    struct ra_buffer_data in;
    struct ra_buffer_data out;
    //char *in_buf = create_VM_cJson();
    if (!buf) {
        printf("in_buf is NULL\n");
        return NULL;
    }
    char *in_buf = addFieldToPayload(buf);
    if (!in_buf)
        return NULL;
    in.buf = in_buf;
    in.size = strlen(in_buf);
    //printf("in_buf = %s \n", in.buf);
    out.buf = malloc(0x4000);
    if (out.buf == NULL) {
        printf("malloc err\n");
        free(in_buf);
        return NULL;
    }
    out.size = 0x4000;
    if (out.size > SHAREMEM_LIMIT || (out.buf == NULL && out.size > 0) ||
        (out.buf != NULL && out.size < 0x3000)) {
        printf("check output failed\n");
        goto END;
    }

    TEEC_Result result = RemoteAttest(&in, &out);

    if (result != TEEC_SUCCESS) {
        printf("RemoteAttest error\n");
        goto END;
    }
    printf("ger report result = %d\n", result);
    tmp_str = Convert((buffer_data *)&out);
END:
    free(in_buf);
    free(out.buf);
    return tmp_str;
}

char *create_reg_cJson(char *str_hash_nsid, int insid)
{
    cJSON *root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "container_id", str_hash_nsid);
    cJSON_AddNumberToObject(root, "nsid", insid);
    char *json_string = cJSON_Print(root);
    cJSON *json_nsid = cJSON_GetObjectItem(root, "nsid");
    if (json_nsid == NULL){
        printf("err\n");
    }
    uint32_t nsid = cJSON_GetNumberValue(json_nsid);
    printf("nsid =%d\n", nsid);
    cJSON_Delete(root);
    return json_string;
}

#define CMD_OK          0xff000000
#define CMD_REGISTER_VM 0xff110011
#define CMD_SEND_REPORT 0xff110012

typedef struct {
    int packet_size;
    int cmd;
    int nsid;
    char data[];
} struct_packet_cmd_register;

typedef struct {
    int packet_size;
    int rsp;
    int ret;
} struct_packet_rsp_register;

int register_vm(int s)
{
    int ret = 0;
    struct_packet_cmd_register *packet_cmd;
    struct_packet_rsp_register packet_rsp = {0};
    char *tmp_str = NULL;
    tmp_str = create_reg_cJson(g_hexstr_hash_nsid, g_nsid);
    if (!tmp_str) {
        printf("err\n");
        return -1;
    }

    packet_cmd = malloc(sizeof(*packet_cmd) + strlen(tmp_str));
    if (!packet_cmd) {
        printf("ENOMEM\n");
        free(tmp_str);
        return -1;
    }
    packet_cmd->cmd = CMD_REGISTER_VM;
    packet_cmd->nsid = g_nsid;
    packet_cmd->packet_size = sizeof(*packet_cmd) + strlen(tmp_str);
    memcpy(packet_cmd->data, tmp_str, strlen(tmp_str));
    free(tmp_str);

    send(s, packet_cmd, packet_cmd->packet_size, 0);

    free(packet_cmd);

    (void)recv(s, &packet_rsp, sizeof(packet_rsp), 0);
    if (packet_rsp.rsp != CMD_OK){
        printf("send  cmd to host failed\n");
        return -1;
    } else {
        printf("send cmd to host success, ret = %d\n", packet_rsp.ret);
    }

    return 0;
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

void proc_get_report(int s)
{
    packet_cmd_client *packet_cmd;
    packet_rsp_client *packet_rsp;
    char *data;
    packet_cmd = malloc(sizeof(*packet_cmd) + 4096);
    if (!packet_cmd) {
        return;
    }
    while (1){
        int ret = recv(s, packet_cmd, sizeof(*packet_cmd) + 4096, 0);
        if (!ret)
            break;
        printf("recv :%s\n", packet_cmd->data);
        data = packet_cmd->data;
        char *tmp_str = get_report(data);

        if (tmp_str) {
            //printf("tmp_str = %s\n", tmp_str);
            packet_rsp = malloc(sizeof(*packet_rsp) + strlen(tmp_str));
            if (!packet_rsp){
                free(tmp_str);
                goto END;
            }
            memcpy(packet_rsp->data, tmp_str, strlen(tmp_str));
            packet_rsp->packet_size = sizeof(*packet_rsp) + strlen(tmp_str);
            packet_rsp->rsp = CMD_OK;
            packet_rsp->ret = 0;
            packet_rsp->cmd = CMD_SEND_REPORT;
            send(s, packet_rsp, packet_rsp->packet_size, 0);
            free(tmp_str);
            free(packet_rsp);
        } else {
            packet_rsp = malloc(sizeof(*packet_rsp));
            if (!packet_rsp){
                goto END;
            }
            packet_rsp->packet_size = sizeof(*packet_rsp);
            packet_rsp->rsp = CMD_OK;
            packet_rsp->ret = -1;
            packet_rsp->cmd = CMD_SEND_REPORT;
            send(s, packet_rsp, packet_rsp->packet_size, 0);
            free(packet_rsp);           
        }
    }
END:
    free(packet_cmd);
}

int main(int argc, char **argv)
{
    char *tmp_str = NULL;
    int s;
    struct sockaddr_vm addr;
    unsigned char uc_sockbuf[4096];
    size_t sizet_buf_recv;

    if(get_nsid_and_hash())
        return 0;

    s = socket(AF_VSOCK, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(struct sockaddr_vm));
    addr.svm_family = AF_VSOCK;
    addr.svm_port = 9999;
    addr.svm_cid = VMADDR_CID_HOST;

    connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_vm));

    if(register_vm(s)) {
        printf("register VM failed\n");
        close(s);
        return 0;
    }

    proc_get_report(s);

    close(s);
}

