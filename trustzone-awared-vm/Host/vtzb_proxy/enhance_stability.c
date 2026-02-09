#include "enhance_stability.h"
#include "config.h"

extern ThreadPool g_pool;
extern struct serial_port_file *g_serial_array[SERIAL_PORT_NUM_MAX];
int daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return -1;
    }
    if (pid > 0) {
        exit(0);
    }

    if (setsid() < 0) {
        perror("setsid failed");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return -1;
    }
    if (pid > 0) {
        exit(0);
    }

    if (chdir("/") != 0) {
        perror("chdir failed");
        return -1;
    }
    umask(0);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY); 

    tlogi("vtz_proxy: daemonize success");
    return 0;
}

static void cleanup_resources(void) {
    tlogi("vtz_proxy: start cleanup resources...");
    VtzbConfig *cfg = get_global_config();
    int serial_port_num = cfg->max_vm_count;
    for (int i = 0; i < serial_port_num; i++) {
        if (g_serial_array[i] && g_serial_array[i]->vm_file) {
            release_vm_file(g_serial_array[i], i);
        }
    }
    thread_pool_destroy(&g_pool);
    tlogi("vtz_proxy: cleanup resources done");
}

static void signal_handler(int signum) {
   
    switch (signum) {
        case SIGCHLD: {
            pid_t pid;
            int status;
            while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                tloge("child process %d exited, status: %d", pid, status);
            }
            break;
        }
        case SIGINT:
        case SIGTERM:
            tloge("receive signal %d (exit), prepare to exit", signum);
            cleanup_resources();
            exit(0);
            break;
        case SIGSEGV:
        case SIGABRT:
        case SIGILL:
        case SIGFPE:
            tloge("crash by signal %d (%s)", signum, strsignal(signum));
            cleanup_resources();
            exit(EXIT_FAILURE);
            break;
        case SIGPIPE:
            tloge("receive signal %d (SIGPIPE), ignore", signum);
            break;
        default:
            tloge("receive unknown signal %d", signum);
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
