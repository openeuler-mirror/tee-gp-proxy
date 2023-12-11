/* File Name: client.c */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "cJSON.h"

#define DEFAULT_PORT 8000

char g_uuid[37] = {0};
int g_nsid = 0;

char *create_cJson() {

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "Handler", "report-input");
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "Version", "TEE.RA.1.0");
    cJSON_AddStringToObject(payload, "Nonce", "Vu7DjhtjRTgUsmWUFu8qKcUkObFkJ8TIXrHDRnqU8tv81zmbKmxNDWPrXhs4xDqDkK48fR5ml7pgjsKxM1Yuew");
    //cJSON_AddStringToObject(payload, "Uuid", "e3d37f4a-f24c-48d0-8884-3bdd6c44e988");
    cJSON_AddStringToObject(payload, "Uuid", g_uuid);
    cJSON_AddStringToObject(payload, "Hash_alg", "HS256");
    cJSON_AddBoolToObject(payload, "With_tcb", false);
    cJSON_AddNullToObject(payload, "Daa_bsn");
    cJSON_AddItemToObject(root, "Payload", payload);

    char *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    return json_string;
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

#define CMD_CAN_NOT_CM_VM   0xff001100
#define CMD_OK              0xff000000

int get_report(int sockfd)
{
    int ret = 0;
    int recv_size;
    int buf_size = 0x4000 + sizeof(packet_rsp_client);
    packet_cmd_client *packet_cmd;
    packet_rsp_client *packet_rsp;
    char *tmp_str = create_cJson();
    printf("tmp_str = %s\n", tmp_str);
    if (!tmp_str) {
        printf("create_cJson err");
        return -1;
    }
    packet_cmd = malloc(sizeof(*packet_cmd) + strlen(tmp_str));
    if (!packet_cmd) {
        printf("malloc failed\n");
        free(tmp_str);
        return -1;
    }
    memcpy(packet_cmd->data, tmp_str, strlen(tmp_str));
    packet_cmd->cmd = 1;
    packet_cmd->nsid = g_nsid;
    packet_cmd->packet_size = sizeof(*packet_cmd) + strlen(tmp_str);

    packet_rsp = malloc(buf_size);
    if (!packet_rsp) {
        printf("malloc failed\n");
        free(tmp_str);
        free(packet_cmd);
        return -1;
    }

    send(sockfd, packet_cmd, packet_cmd->packet_size, 0);
    printf("after send to server\n");
    free(tmp_str);
    free(packet_cmd);

    /*接收*/
    recv_size = recv(sockfd, packet_rsp, buf_size, 0);
    if (packet_rsp->ret == 0 && packet_rsp->rsp == CMD_OK) {
        printf("get report success\n");
        printf("report = %s \n", packet_rsp->data);
    } else if(packet_rsp->rsp == CMD_CAN_NOT_CM_VM) {
        printf("VM Remote Proof Service is not running\n");
    } else {
        printf("get report failed\n");
    }
}

int get_nsid_uuid()
{
    FILE *file = fopen("data.txt", "r");

    if (file == NULL) {
        printf("open file failed\n");
        return -1;
    }

    if (fscanf(file, "%36s", g_uuid) != 1) {
        printf("cant't read UUID\n");
        fclose(file);
        return -1;
    }

    if (fscanf(file, "%d", &g_nsid) != 1) {
        printf("cant't read nsid\n");
        fclose(file);
        return -1;
    }

    fclose(file);

    printf("g_UUID: %s\n", g_uuid);
    printf("g_nsid: %d\n", g_nsid);

    return 0;
}

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_in servaddr;

    if (get_nsid_uuid()) {
        return 0;
    }
    if (argc != 2) {
        printf("usage: ./client <ipaddress>\n");
        exit(0);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DEFAULT_PORT);
    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0) {
        printf("inet_pton error for %s\n", argv[1]);
        exit(0);
    }

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        printf("connect error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    get_report(sockfd); 

    close(sockfd);
    exit(0);
}
