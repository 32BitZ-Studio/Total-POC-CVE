#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFFER_SIZE 4096

int main(void) {

	int fd, flag, times = 0;
	char buffer[BUFFER_SIZE] = {0};

	char *config_file = "/etc/redis.conf";

	fd = open(config_file, O_RDONLY, 0600);
	if (fd < 0)
	{
		printf("open config file failed\n");
		return -1;
	}
	printf("Reading config file ...\n");

	while ((flag = read(fd, buffer, BUFFER_SIZE)) > 0) {
		times++;
		//WL: debugging
		if (times >= 48) {
			printf("%s", buffer);
		}
	}
	printf("\n");

	close(fd);
	return 0;
}
