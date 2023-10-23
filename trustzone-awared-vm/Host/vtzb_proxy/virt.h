#ifndef VTZB_VIRT_H
#define VTZB_VIRT_H

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int safepoll(struct pollfd *fds, nfds_t nfds, int timeout);
ssize_t safewrite(int fd, const void *buf, size_t count, bool eagain_ret);
ssize_t saferead(int fd, void *buf, size_t count, bool eagain_ret);

#endif // VTZB_VIRT_H
