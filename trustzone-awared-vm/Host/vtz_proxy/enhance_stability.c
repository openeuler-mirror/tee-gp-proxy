#include <sys/file.h>
#include "enhance_stability.h"
#include "config.h"

#define VTZ_PROXY_LOCK_FILE "/var/run/vtz_proxy.lock"
static int g_lock_fd = -1;

extern ThreadPool g_pool;
extern struct serial_port_file *g_serial_array[SERIAL_PORT_NUM_MAX];

int acquire_singleton_lock(void) {
    int lock_fd;

    lock_fd = open(VTZ_PROXY_LOCK_FILE, O_CREAT | O_RDWR, 0644);
    if (lock_fd == -1) {
        perror("vtz_proxy: Failed to create lock file");
        return -1;
    }

    if (flock(lock_fd, LOCK_EX | LOCK_NB) == -1) {
        if (errno == EWOULDBLOCK) {
            fprintf(stderr, "vtz_proxy: Another instance is already running\n");
        } else {
            perror("vtz_proxy: Failed to acquire lock");
        }
        close(lock_fd);
        return -1;
    }

    g_lock_fd = lock_fd;

    return 0;
}

void release_singleton_lock(void) {
    if (g_lock_fd == -1)
        return;

    flock(g_lock_fd, LOCK_UN);
    close(g_lock_fd);
    unlink(VTZ_PROXY_LOCK_FILE);
    g_lock_fd = -1;
}

static void cleanup_resources(void) {
    VtzConfig *cfg = get_global_config();
    int serial_port_num = cfg->max_vm_count;
    for (int i = 0; i < serial_port_num; i++) {
        if (g_serial_array[i] && g_serial_array[i]->vm_file) {
            release_vm_file(g_serial_array[i], i);
        }
    }
    thread_pool_destroy(&g_pool);
    release_singleton_lock();
}

static void signal_handler(int signum) {
   
    switch (signum) {
        case SIGCHLD: {
            pid_t pid;
            int status;
            while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            }
            break;
        }
        case SIGINT:
        case SIGTERM:
            cleanup_resources();
            exit(0);
            break;
        case SIGSEGV:
        case SIGABRT:
        case SIGILL:
        case SIGFPE:
            cleanup_resources();
            exit(EXIT_FAILURE);
            break;
        case SIGPIPE:
            break;
        default:
            break;
    }
}

int register_signal_handlers(void) {
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;

    int signals[] = {SIGCHLD, SIGINT, SIGTERM, SIGSEGV, SIGABRT, SIGILL, SIGFPE, SIGPIPE};
    int sig_num = sizeof(signals) / sizeof(signals[0]);
    
    for (int i = 0; i < sig_num; i++) {
        if (sigaction(signals[i], &sa, NULL) < 0) {
            tloge("vtz_proxy: register signal handler failed");
            return -1;
        }
    }

    tlogi("vtz_proxy: register signal handlers success");
    return 0;
}
