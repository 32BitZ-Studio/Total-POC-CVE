#pragma once
#include <Windows.h>
typedef struct {
	HANDLE read;
	HANDLE write;
} PIPES;
typedef struct {
	char previousSize;
	char poolIndex;
	char blockSize;
	char poolType;
	int tag;
	void* processBilled;
}PoolHeader;

//struct LIST_ENTRY64
//{
//	ULONGLONG Flink;                                                        //0x0
//	ULONGLONG Blink;                                                        //0x8
//};

typedef struct {
	struct LIST_ENTRY64 Link;
	UCHAR* name;
	ULONGLONG value_len;
	UCHAR* value;
}PipeAttr;

int spray_heap(PIPES* pipes, int spray_count, char* buffer, int spray_size);
void free_heap(PIPES* pipes, int idx);
int pipe_write_attr(PIPES* pipes, char* name, void* value, int size);
void pipe_init(PIPES* pipes);
int pipe_delete_attr(PIPES* pipes, char* name);
void dump_mem(void* addr, int size);
void DEBUG_IMP(char* file, int line, char* fmt, ...);
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)


#define DEBUG(x,...) DEBUG_IMP(__FILENAME__,__LINE__,x,##__VA_ARGS__)
