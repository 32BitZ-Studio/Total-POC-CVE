#include <stdio.h>
extern char **environ;
void main(int argc, char *argv[])
{
	printf("argv:%x\t\t\n",argv);
	printf("environ:%x\t\n",env);
	return 0;
}
