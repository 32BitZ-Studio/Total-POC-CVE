#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/uio.h>
#include <stdio.h>

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    static ssize_t (*real_writev)(int, const struct iovec *, int) = NULL;
    if (!real_writev) {
        real_writev = dlsym(RTLD_NEXT, "writev");
    }

    fprintf(stderr, "🔥 writev(fd=%d, iovcnt=%d)\n", fd, iovcnt);
    return real_writev(fd, iov, iovcnt);
}
