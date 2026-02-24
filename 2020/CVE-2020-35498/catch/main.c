#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/filter.h>

#include <syslog.h>

#define BUF_LEN 10240
#define MAX_BAD 100

extern int open_socket();

volatile sig_atomic_t done = 0;

void term(int sig) {
	done = 1;
}

void setup_term() {
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = term;
	sigaction(SIGTERM, &action, NULL);
}

int main(int argc, const char *argv[]) {
	int sock, ret;
	char buf[BUF_LEN];
	ssize_t len;
	int total_bad;

	openlog("security-capture", LOG_PID, LOG_USER);

	total_bad = 0;
	setup_term();
	sock = open_socket();

	syslog(LOG_INFO, "running recv loop");
	while (!done) {
		len = recv(sock, buf, BUF_LEN, 0);
		if (len < 0) {
			usleep(100);
			continue;
		}
		
		if (total_bad < MAX_BAD) {
			syslog(LOG_WARNING, "got bad packet");
			if (!total_bad) {
				int fd = open("/tmp/bad_packet", O_CREAT | O_RDWR, 0644);
				write(fd, buf, len);
				close(fd);
			}
			total_bad++;
		}
	}

	close(sock);
	syslog(LOG_INFO, "stopped safely");
	return 0;
	
close_quit:
	close(sock);
quit:
	return 1;
}
