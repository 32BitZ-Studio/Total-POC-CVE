#pragma once
#include <Windows.h>

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;
#define ALIGN(x,v) ((x + v - 1)&((-v)&0xffffffff))
typedef struct _FILE_GET_EA_INFORMATION {
	ULONG NextEntryOffset;
	UCHAR EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, * PFILE_GET_EA_INFORMATION;

