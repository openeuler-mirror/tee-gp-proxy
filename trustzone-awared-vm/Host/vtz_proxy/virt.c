#include "virt.h"

int safepoll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int ret;

    do {
        ret = poll(fds, nfds, timeout);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1)
        ret = -errno;

    return ret;
}

ssize_t safewrite(int fd, const void *buf, size_t count, bool eagain_ret)
{
    ssize_t ret;
    size_t len;
    int flags;
    bool nonblock;

    nonblock = false;
    flags = fcntl(fd, F_GETFL);
    if (flags > 0 && flags & O_NONBLOCK)
        nonblock = true;

    len = count;
    while (len > 0) {
        ret = write(fd, buf, len);
        if (ret == -1) {
            if (errno == EINTR)
                continue;

            if (errno == EAGAIN) {
                if (nonblock && eagain_ret) {
                    return -EAGAIN;
                } else {
                    continue;
                }
            }
            return -errno;
        } else if (ret == 0) {
            break;
        } else {
            buf += ret;
            len -= ret;
        }
    }
    return count - len;
}

ssize_t saferead(int fd, void *buf, size_t count, bool eagain_ret)
{
    size_t ret, len;
    int flags;
    bool nonblock;

    nonblock = false;
    flags = fcntl(fd, F_GETFL);
    if (flags > 0 && flags & O_NONBLOCK)
        nonblock = true;

    len = count;
    while (len > 0) {
        ret = read(fd, buf, len);
        if ((int)ret == -1) {
            if (errno == EINTR)
                continue;

            if (errno == EAGAIN) {
                if (nonblock && eagain_ret) {
                    return -EAGAIN;
                } else {
                    continue;
                }
            }
            return -errno;
        } else if (ret == 0) {
            break;
        } else {
            buf += ret;
            len -= ret;
        }
    }
    return count - len;
}