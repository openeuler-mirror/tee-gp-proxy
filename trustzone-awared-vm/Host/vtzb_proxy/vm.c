#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "errno.h"
#include "vm.h"
#include "agent.h"
#include "thread_pool.h"
#include "comm_structs.h"
#include "serial_port.h"

extern ThreadPool g_pool;
extern TimeOut g_time_out[THREAD_POOL_SIZE];

LIST_DECLARE(g_vm_list);
pthread_mutex_t g_mutex_vm = PTHREAD_MUTEX_INITIALIZER;

void add_session_list(int ptzfd, struct vm_file *vm_fp, TC_NS_ClientContext *clicontext)
{
    struct fd_file *fd_p = NULL;
    struct session *sessionp = NULL;
    fd_p = find_fd_file(ptzfd, vm_fp);
    if (!fd_p) {
        tloge("found the fd %d 's fd_file failed\n", ptzfd);
        return;
    }
    sessionp = (struct session *)malloc(sizeof(struct session)); 
    if (!sessionp) {
        tloge("malloc session for fd %d failed\n", ptzfd);
        return;
    }
    sessionp->session_id = clicontext->session_id;
    ListInit(&sessionp->head);
    pthread_mutex_lock(&fd_p->session_lock);
    ListInsertTail(&fd_p->session_head, &sessionp->head);
    pthread_mutex_unlock(&fd_p->session_lock);
}

static void do_remove_session(unsigned int session_id, struct fd_file *fd_p)
{
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    if (!fd_p) {
        tloge("fd_file is null\n");
        return ;
    }
    pthread_mutex_lock(&fd_p->session_lock);
    if (!LIST_EMPTY(&fd_p->session_head)) {
        LIST_FOR_EACH_SAFE(ptr, n, &fd_p->session_head) {
            struct session *sp = CONTAINER_OF(ptr, struct session, head);
            if (sp->session_id == session_id) {
                ListRemoveEntry(&(sp->head));
                free(sp);
            }
        }
    }
    pthread_mutex_unlock(&fd_p->session_lock);
}

void remove_session(int ptzfd, int session_id, struct vm_file *vm_fp)
{
    struct fd_file *fd_p = NULL;
    if (!vm_fp) {
        tloge("vm_file is null\n");
        return;
    }
    fd_p = find_fd_file(ptzfd, vm_fp);
    if (!fd_p) {
        tloge("found the fd %d 's fd_file failed\n", ptzfd);
        return;
    }
    do_remove_session(session_id, fd_p);
}

struct fd_file *find_fd_file(int ptzfd, struct vm_file *vm_fp)
{
    struct ListNode *ptr = NULL;
    struct fd_file *fd_p = NULL;
    int bfind = 0;
    if (!vm_fp) {
        tloge("vm_file is null\n");
        return NULL;
    }
    pthread_mutex_lock(&vm_fp->fd_lock);
    if (!LIST_EMPTY(&vm_fp->fds_head)) {
        LIST_FOR_EACH(ptr, &vm_fp->fds_head) {
            fd_p = CONTAINER_OF(ptr, struct fd_file, head);
            if (fd_p->ptzfd == ptzfd) {
                bfind = 1;
                break;
            }
        }
    }
    pthread_mutex_unlock(&vm_fp->fd_lock);
    if (bfind)
        return fd_p;

    return NULL;
}

void add_fd_list(int fd, uint32_t fd_type, struct vm_file *vm_fp)
{
    struct fd_file *fd_p;
    if (!vm_fp) {
        tloge("add fd_file failed, vm_fp is NULL\n");
        return;
    }
    fd_p = (struct fd_file *)malloc(sizeof(struct fd_file));
    if (!fd_p) {
        tloge("malloc fd_file failed\n");
        return;
    }
    fd_p->ptzfd = fd;
    fd_p->fd_type = fd_type;
    fd_p->agent.vmaddr = NULL;
    pthread_mutex_init(&fd_p->session_lock, NULL);
    ListInit(&fd_p->session_head);
    ListInit(&fd_p->head);

    pthread_mutex_lock(&vm_fp->fd_lock);
    ListInsertTail(&vm_fp->fds_head, &fd_p->head);
    pthread_mutex_unlock(&vm_fp->fd_lock);
}

static void do_remove_fd(struct fd_file *fd_p)
{
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    unsigned long buf[2] = {0};
    int ret = -1;
    ListRemoveEntry(&fd_p->head);
    pthread_mutex_lock(&fd_p->session_lock);
    if (!LIST_EMPTY(&fd_p->session_head)) {
        LIST_FOR_EACH_SAFE(ptr, n, &fd_p->session_head) {
            struct session *sp = CONTAINER_OF(ptr, struct session, head);
            ListRemoveEntry(&(sp->head));
            free(sp);
        }
    }
    pthread_mutex_unlock(&fd_p->session_lock);

    if(fd_p->agent.vmaddr) {
        restart_pool_thread(&g_pool, fd_p->agent.thd); 
        buf[0] = fd_p->agent.args.id;
        ret = ioctl(fd_p->ptzfd, TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT, buf);
        if (ret) {
            if(errno != EBUSY) {
                tloge("ioctl failed fd is %d ret is %d, error is %d, reason is %s, agent_args->args.id %x\n",\
                    fd_p->ptzfd, ret, errno, strerror(errno), fd_p->agent.args.id);
            }
        }
        fd_p->agent.vmaddr = NULL;
    }
    close(fd_p->ptzfd);
    free(fd_p);
}

int remove_fd(int ptzfd, struct vm_file *vm_fp)
{
    struct ListNode *ptr = NULL;
    struct ListNode *next_ptr = NULL;
    struct fd_file *fd_p = NULL;

    if (!vm_fp) {
        tloge("vm_file is null\n");
        return -EINVAL;
    }

    pthread_mutex_lock(&vm_fp->fd_lock);
    if (!LIST_EMPTY(&vm_fp->fds_head)) {
        LIST_FOR_EACH_SAFE(ptr, next_ptr, &vm_fp->fds_head) {
            fd_p = CONTAINER_OF(ptr, struct fd_file, head);
            if (fd_p->ptzfd == ptzfd) {
                do_remove_fd(fd_p);
            }
        }
    }
    pthread_mutex_unlock(&vm_fp->fd_lock);
    

    return 0;
}

struct vm_file *create_vm_file(uint32_t vmid)
{
    struct vm_file *tmp = NULL;
    pthread_mutex_lock(&g_mutex_vm);

    tlogd("create new vm_file for vmid %d\n", vmid);
    tmp = (struct vm_file *)malloc(sizeof(struct vm_file));
    if (!tmp) {
        tloge("Failed to allocate memory for vm_file\n");
        goto END;
    }
    pthread_mutex_init(&tmp->fd_lock, NULL);
    pthread_mutex_init(&tmp->shrd_mem_lock, NULL);
    ListInit(&tmp->head);
    ListInit(&tmp->fds_head);
    ListInit(&tmp->shrd_mem_head);
    tmp->vmpid = vmid;
    tmp->nsid = 0;
    ListInsertTail(&g_vm_list, &tmp->head);
END:
    pthread_mutex_unlock(&g_mutex_vm);
    return tmp;
}

static void unregister_nsid_vmid(struct vm_file * vm_file)
{
    int ret;
    if (vm_file->nsid == 0 || vm_file->vmpid == 0) {
        return;
    }
    struct_vm_group_info vm_info;
    int fd = open(TC_TEECD_PRIVATE_DEV_NAME, O_RDWR);
    if (fd < 0) {
        tloge("open %s failed\n", TC_TEECD_PRIVATE_DEV_NAME);
        return;
    }
    vm_info.vmid = vm_file->vmpid;
    vm_info.nsid = vm_file->nsid;
    ret = ioctl(fd, TC_NS_CLIENT_IOCTL_UNREGISTER_VM_VMID_NSID, &vm_info);
    if (ret) {
        tloge("vtz UNregister nsid vmid failed, vmid = %d, nsid = %d, ret = %d\n", vm_info.vmid, vm_info.nsid, ret);
    }
    close(fd);
    return;
}

void *destroy_vm_file(void *args)
{
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    struct fd_file *fd_p = NULL;
    struct vm_file * vm_file = (struct vm_file *)args;
    if (!vm_file)
        return NULL;
    pthread_mutex_lock(&vm_file->fd_lock);
    if (!LIST_EMPTY(&vm_file->fds_head)) {
        LIST_FOR_EACH_SAFE(ptr, n, &vm_file->fds_head) {
            fd_p = CONTAINER_OF(ptr, struct fd_file, head);
            do_remove_fd(fd_p);
        }
    }
    pthread_mutex_unlock(&vm_file->fd_lock);
    unregister_nsid_vmid(vm_file);
    pthread_mutex_lock(&g_mutex_vm);
    ListRemoveEntry(&(vm_file->head));
    free(vm_file);
    pthread_mutex_unlock(&g_mutex_vm);
    return NULL;
}

int set_start_time(pthread_t tid, int seq_num,
    struct serial_port_file *serial_port)
{
    int i;
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);
    pthread_mutex_lock(&g_pool.time_mutex);
    for (i = 0; i < THREAD_POOL_SIZE; i++) {
        if (g_time_out[i].flag == 0) {
            g_time_out[i].flag = 1;
            g_time_out[i].seq_num = seq_num;
            g_time_out[i].start_time = cur_time.tv_sec;
            g_time_out[i].tid = tid;
            g_time_out[i].serial_port = serial_port;
            break;
        }
    }
    pthread_mutex_unlock(&g_pool.time_mutex);
    return i;
}

void remove_start_time(int i)
{
    if (i >= THREAD_POOL_SIZE)
        return;
    pthread_mutex_lock(&g_pool.time_mutex);
    g_time_out[i].flag =0;
    g_time_out[i].seq_num = 0;
    g_time_out[i].start_time = 0;
    g_time_out[i].tid = 0;
    pthread_mutex_unlock(&g_pool.time_mutex);
}
