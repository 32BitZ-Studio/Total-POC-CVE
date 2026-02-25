#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/filter.h>

#include <syslog.h>

struct sock_filter code[] = {
	{ 0x28,  0,  0, 0x0000000c },
	{ 0x15,  7,  0, 0x000086dd },
	{ 0x15,  0, 15, 0x00000800 },
	{ 0x30,  0,  0, 0x00000010 },
	{ 0x64,  0,  0, 0x00000008 },
	{ 0x07,  0,  0, 0000000000 },
	{ 0x30,  0,  0, 0x00000011 },
	{ 0x4c,  0,  0, 0000000000 },
	{ 0x05,  0,  0, 0x00000005 },
	{ 0x30,  0,  0, 0x00000012 },
	{ 0x64,  0,  0, 0x00000008 },
	{ 0x07,  0,  0, 0000000000 },
	{ 0x30,  0,  0, 0x00000013 },
	{ 0x4c,  0,  0, 0000000000 },
	{ 0x07,  0,  0, 0000000000 },
	{ 0x80,  0,  0, 0000000000 },
	{ 0x1c,  0,  0, 0000000000 },
	{ 0x25,  1,  0, 0x00000111 },
	{ 0x06,  0,  0, 0000000000 },
	{ 0x06,  0,  0, 0xffffffff },
};

struct sock_fprog bpf = {
	.len = sizeof(code) / sizeof(code[0]),
	.filter = code
};

int open_socket() {
	int sock, ret;

	syslog(LOG_INFO, "opening raw socket");
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) goto quit;
	
	syslog(LOG_INFO, "attach a bpf filter");
	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret < 0) goto close_quit;
	
	return sock;
	
close_quit:
	close(sock);
quit:
	return 1;
}
