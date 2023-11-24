#include "errno.h"
#include "vm.h"
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
    if (!fd_p)
        return;
    sessionp = (struct session *)malloc(sizeof(struct session)); 
    if (!sessionp)
        return;
    sessionp->session_id = clicontext->session_id;
    sessionp->cliContext = *clicontext;
    debug("    uuid = %x \n", sessionp->cliContext.uuid);
    ListInit(&sessionp->head);
    pthread_mutex_lock(&fd_p->session_lock);
    ListInsertTail(&fd_p->session_head, &sessionp->head);
    pthread_mutex_unlock(&fd_p->session_lock);
}

void *Kill_useless_thread(void *args)
{
    pthread_t tid = (pthread_t)args;
    debug("before handle kill|cncel thread \n");
    int result = pthread_kill(tid, SIGUSR1);
    debug("result = %d \n", result);
    if (result == 0) {
        pthread_join(tid, NULL);
        replenish_thread_pool(&g_pool, tid);
    } else {
        debug("pthread_kill fail \n");
    }
    debug("after handle kill|cncel thread \n");
    return NULL;
}

static void try_kill_thread(struct session *sp)
{
    if (!sp)
        return;
    if (sp->thread_id != 0 && get_thread_session_id(&g_pool, sp->thread_id, sp->session_id)) {
        thread_pool_submit(&g_pool, Kill_useless_thread, (void *)(sp->thread_id));
    }
}

static void do_remove_session(unsigned int session_id, struct fd_file *fd_p)
{
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    if (!fd_p)
        return ;
    pthread_mutex_lock(&fd_p->session_lock);
    if (!LIST_EMPTY(&fd_p->session_head)) {
        LIST_FOR_EACH_SAFE(ptr, n, &fd_p->session_head) {
            struct session *sp = CONTAINER_OF(ptr, struct session, head);
            if (sp->session_id == session_id) {
                debug("remove session \n");
                ListRemoveEntry(&(sp->head));
                try_kill_thread(sp);
                free(sp);
            }
        }
    }
    pthread_mutex_unlock(&fd_p->session_lock);	
}

void remove_session(int ptzfd, int session_id, struct vm_file *vm_fp)
{
    struct fd_file *fd_p = NULL;
    if (!vm_fp)
        return;
    fd_p = find_fd_file(ptzfd, vm_fp);
    if (fd_p) {
        do_remove_session(session_id, fd_p);		
    }
}

struct fd_file *find_fd_file(int ptzfd, struct vm_file *vm_fp)
{
    struct ListNode *ptr = NULL;
    struct fd_file *fd_p = NULL;
    int bfind = 0;
    if (!vm_fp)
        return NULL;
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

void add_fd_list(int fd, struct vm_file *vm_fp)
{
    struct fd_file *fd_p;
    if (!vm_fp)
        return;
    fd_p = (struct fd_file *)malloc(sizeof(struct fd_file));
    if (!fd_p)
        return;
    fd_p->ptzfd = fd;
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
    unsigned int session_id;
    (void)session_id;
    if (!fd_p)
        return;
    debug("will close_remove_session\n");
    pthread_mutex_lock(&fd_p->session_lock);
    if (!LIST_EMPTY(&fd_p->session_head)) {
        LIST_FOR_EACH_SAFE(ptr, n, &fd_p->session_head) {
            struct session *sp = CONTAINER_OF(ptr, struct session, head);
            ListRemoveEntry(&(sp->head));
            try_kill_thread(sp);
            free(sp);
        }
    }
    pthread_mutex_unlock(&fd_p->session_lock);
}

int remove_fd(int ptzfd, struct vm_file *vm_fp)
{
    if (!vm_fp)
        return -EINVAL;
    struct fd_file *fd_p = find_fd_file(ptzfd, vm_fp);
    if (fd_p) {
        pthread_mutex_lock(&vm_fp->fd_lock);
        ListRemoveEntry(&fd_p->head);
        pthread_mutex_unlock(&vm_fp->fd_lock);
        do_remove_fd(fd_p);
        free(fd_p);
        return 0;
    }
    return -EINVAL;
}

struct vm_file *create_vm_file(uint32_t vmid)
{
    bool isfind = false;
    struct ListNode *ptr = NULL;
    struct vm_file *tmp = NULL;
    pthread_mutex_lock(&g_mutex_vm);
    if (!LIST_EMPTY(&g_vm_list)) {
        LIST_FOR_EACH(ptr, &g_vm_list) {
            tmp = CONTAINER_OF(ptr, struct vm_file, head);
            if (tmp->vmpid == vmid) {
                isfind = true;
                break;
            }
        }
    }

    if (!isfind) {
        tmp = (struct vm_file *)malloc(sizeof(struct vm_file));
        if (!tmp) {
            tloge("Failed to allocate memory for vm_file\n");
            goto END;
        }
        pthread_mutex_init(&tmp->fd_lock, NULL);
        pthread_mutex_init(&tmp->agents_lock, NULL);
        pthread_mutex_init(&tmp->shrd_mem_lock, NULL);
        ListInit(&tmp->head);
        ListInit(&tmp->fds_head);
        ListInit(&tmp->agents_head);
        ListInit(&tmp->shrd_mem_head);
        tmp->vmpid = vmid;
        ListInsertTail(&g_vm_list, &tmp->head);
    }
END:
    pthread_mutex_unlock(&g_mutex_vm);
    return tmp;
}

int destroy_vm_file(struct vm_file *vm_file)
{
    int ret = 0;
    struct ListNode *ptr = NULL;
    struct ListNode *n = NULL;
    struct fd_file *fd_p = NULL;
    if (!vm_file)
        return 0;
    pthread_mutex_lock(&vm_file->fd_lock);
    if (!LIST_EMPTY(&vm_file->fds_head)) {
        LIST_FOR_EACH_SAFE(ptr, n, &vm_file->fds_head) {
            fd_p = CONTAINER_OF(ptr, struct fd_file, head);
            ListRemoveEntry(&fd_p->head);
            do_remove_fd(fd_p);
            free(fd_p);
        }
    }
    pthread_mutex_unlock(&vm_file->fd_lock);
    free(vm_file);
    return ret;
}

void kill_open_session_thd(TimeOut t_out)
{
    struct_packet_rsp_session packet_rsp;
    pthread_t tid = t_out.tid;
    packet_rsp.packet_size = sizeof(packet_rsp);
    packet_rsp.seq_num = t_out.seq_num + 1;
    packet_rsp.ret = -1;
    thread_pool_submit(&g_pool, Kill_useless_thread, (void *)tid);
    (void)send_to_vm(t_out.serial_port, &packet_rsp, sizeof(packet_rsp));
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
