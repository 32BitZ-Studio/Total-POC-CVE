#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <string.h>
#include <errno.h>

#define LINE_BUFFER 1024

int file_exists(char *filename)
{
	return (access(filename, 0) == 0);
}

char * get_password(char *pass_buf) {
	//TODO: fetch redis password from a secure network channnel built via RA
	//here we hardcode the password
	pass_buf = "admin123456";
	return pass_buf;
}

int set_password(char* input_filename, char* output_filename, char *password) {
	FILE* input_fp;
	FILE* output_fp;
	char* line = (char *)malloc(LINE_BUFFER);
	size_t len = 0;
	ssize_t read;

	if ((input_fp = fopen(input_filename, "r")) == NULL) {
		printf("input file open failed!\n");
		return -1;
	}

	if ((output_fp = fopen(output_filename, "w")) == NULL) {
		printf("output file open failed!\n");
		return -1;
	}

	char* strret;
	int lines = 0;
	printf("Run ./take_snapshot_step-1.sh NOW!\n");
	sleep(1);
	while ((read = getline(&line, &len, input_fp)) != -1) {
		lines++;
		//search the 'requirepass' field
		strret = strstr(line, "requirepass ");
		if (strret != NULL) {
			//replace the password
			strcpy(line, "requirepass ");
			strcat(line, password);
			strcat(line, "\n");
		}

		//Optional: intercepting window reserved for the attack
		if (lines > 4521 && lines < 4594) {
			usleep(100000);
			//sleep 0.1 s
			printf("[DEBUG] line %d: %s", lines, line);
		}

		fwrite(line, strlen(line), 1, output_fp);
	}

	free(line);
	fclose(input_fp);
	fclose(output_fp);
	return 0;
}

int main(void) {

	char *input_file = "/etc/redis.conf.template", *output_file = "/etc/redis.conf";
	

	// check if the redis.conf exists
	if (file_exists(output_file)) {
		return 0;
	}
	char *pass_buf = (char *)malloc(12 * sizeof(char));
	pass_buf = get_password(pass_buf);
	set_password(input_file, output_file, pass_buf);

	printf("Redis config file loaded.\n");
	return 0;
}
