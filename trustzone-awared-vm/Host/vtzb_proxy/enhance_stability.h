#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include "tlogcat.h"
#include "thread_pool.h"
#include "agent.h"

int acquire_singleton_lock(void);
int register_signal_handlers(void);