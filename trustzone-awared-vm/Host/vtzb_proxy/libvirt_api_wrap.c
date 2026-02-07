#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "libvirt_api_wrap.h"

#define PATH_SIZE 5
#define SOCKET_SIZE 7

/*
    parse xml <qemu:arg value='socket,path=/tmp/vm_vtzb_sock1,server=on,wait=off,id=vm01_vtzb_sock'/>
*/

static int match_chardev_socket_path(const char *value, const char *target_path)
{
    if ((value == NULL) || (target_path == NULL)) 
        return 0;

    // 必须是 socket 类型
    if (strncmp(value, "socket,", SOCKET_SIZE) != 0) 
        return -1;

    const char *p = strstr(value, "path=");
    if (p == NULL) 
        return -1;

    p += PATH_SIZE;
    const char *comma = strchr(p, ',');
    size_t xml_value_len = (comma - p);
    size_t target_length = strlen(target_path);

    if(target_length != xml_value_len){
        return -1;
    }

    if (strncmp(p, target_path, target_length) != 0) {
        return -1;
    }
    return 0;
}

static int has_serial_socket_path(const char *xml, const char *target_path)
{
    if (!xml || !target_path) 
        return 0;

    xmlDocPtr doc = xmlReadMemory(xml, strlen(xml), "domain.xml", NULL,
                                  XML_PARSE_NOBLANKS | XML_PARSE_NONET);
    if (!doc) 
        return 0;

    int found = 0;
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) 
        goto cleanup;

    xmlNodePtr node = root->children;
    while (node) {
        if (node->type == XML_ELEMENT_NODE &&
            xmlStrEqual(node->name, BAD_CAST "commandline")) {
            // 检查命名空间是否为 QEMU
            if (node->ns && node->ns->href && xmlStrEqual(node->ns->href, BAD_CAST QEMU_NS_URI)) {
                // 遍历 <qemu:arg> 子节点
                xmlNodePtr arg = node->children;
                while (arg) {
                    if (arg->type == XML_ELEMENT_NODE &&
                        xmlStrEqual(arg->name, BAD_CAST "arg")) {
                        xmlChar *value = xmlGetProp(arg, BAD_CAST "value");
                        if (value) {
                            found = match_chardev_socket_path((const char *)value, target_path);
                            if(found == 0){
                                tlogi("found ok ,domain name %s\n", value);
                                return 1;
                            }
                            xmlFree(value);
                        }
                    }
                    arg = arg->next;
                }
            }
        }
        node = node->next;
    }
cleanup:
    xmlFreeDoc(doc);
    return -1;
}

// 根据 socket 路径查找正在运行的 VM 名称（返回动态分配字符串）
char *find_domain_name_by_serial_socket(virConnectPtr conn, const char *socket_path)
{
    virDomainPtr *all_domains = NULL;
    int actual = virConnectListAllDomains(conn, &all_domains, 0);
    char *result = NULL;
    for (int i = 0; i < actual; i++) {
        virDomainPtr dom = all_domains[i];
        if (dom == NULL) 
            continue;
        char *xml = virDomainGetXMLDesc(dom, 0);
        if (xml == NULL) {
            virDomainFree(dom);
            continue;
        }

        if (has_serial_socket_path(xml, socket_path) == 1) {
            const char *name = virDomainGetName(dom);
            result = name ? strdup(name) : NULL;
            free(xml);
            virDomainFree(dom);
            break;
        }
        free(xml);
        virDomainFree(dom);
    }
    free(all_domains);
    return result;
}

virConnectPtr init_virt_conn()
{
    if (virEventRegisterDefaultImpl() < 0) {
        tloge("Failed to register event impl\n");
        return NULL;
    }

    virConnectPtr conn = virConnectOpen("qemu:///system");
    if (conn == NULL) {
        tloge("Failed to connect open \n");
        return NULL;
    }
    return conn;
}

void deinit_virt_conn(virConnectPtr conn_ptr)
{
    if (conn_ptr != NULL) {
        virConnectClose(conn_ptr);
    }
}

virDomainPtr init_domain_by_socket_path(virConnectPtr conn, const char *socket_path)
{
    char *domain_name = find_domain_name_by_serial_socket(conn, socket_path);
    if(domain_name == NULL){
        tloge("No VM found using socket: %s\n", socket_path);
        virConnectClose(conn);
        return NULL;
    }

    virDomainPtr dom = virDomainLookupByName(conn, domain_name);
    if (dom == NULL){
        tloge("Failed to lookup domain %s\n", domain_name);
        virConnectClose(conn);
        return NULL;
    }

    if(domain_name){
        free(domain_name);
    }
    return dom;
}

void deinit_domain(virDomainPtr dom)
{
    if(dom != NULL){
        virDomainFree(dom);
    }
}
