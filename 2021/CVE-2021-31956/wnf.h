#pragma once
#include <Windows.h>
#pragma comment(lib,"ntdll.lib")

//0x8 bytes (sizeof)
//typedef struct _WNF_STATE_NAME
//{
//    ULONGLONG Data;                                                          //0x0
//}WNF_STATE_NAME,*PWNF_STATE_NAME;

typedef ULONGLONG WNF_STATE_NAME,*PWNF_STATE_NAME;

typedef const WNF_STATE_NAME* PCWNF_STATE_NAME;

//0x10 bytes (sizeof)
typedef struct _WNF_TYPE_ID
{
    struct _GUID TypeId;                                                    //0x0
}WNF_TYPE_ID,*PWNF_TYPE_ID;

typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;
typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

NTSTATUS NTAPI NtUpdateWnfStateData(
    _In_ PWNF_STATE_NAME StateName,
    _In_reads_bytes_opt_(Length) const VOID* Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const PVOID ExplicitScope,
    _In_ WNF_CHANGE_STAMP MatchingChangeStamp,
    _In_ ULONG CheckStamp
);
//0x4 bytes (sizeof)
enum _WNF_STATE_NAME_LIFETIME
{
    WnfWellKnownStateName = 0,
    WnfPermanentStateName = 1,
    WnfPersistentStateName = 2,
    WnfTemporaryStateName = 3
};
typedef enum _WNF_STATE_NAME_LIFETIME WNF_STATE_NAME_LIFETIME;

//0x4 bytes (sizeof)
enum _WNF_DATA_SCOPE
{
    WnfDataScopeSystem = 0,
    WnfDataScopeSession = 1,
    WnfDataScopeUser = 2,
    WnfDataScopeProcess = 3,
    WnfDataScopeMachine = 4,
    WnfDataScopePhysicalMachine = 5
};
typedef enum _WNF_DATA_SCOPE WNF_DATA_SCOPE;
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateWnfStateName(
    _Out_ PWNF_STATE_NAME StateName,
    _In_ WNF_STATE_NAME_LIFETIME NameLifetime,
    _In_ WNF_DATA_SCOPE DataScope,
    _In_ BOOLEAN PersistData,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_ ULONG MaximumStateSize,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
);
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryWnfStateData(
    _In_ PWNF_STATE_NAME StateName,
    _In_opt_ PWNF_TYPE_ID TypeId,
    _In_opt_ const VOID* ExplicitScope,
    _Out_ PWNF_CHANGE_STAMP ChangeStamp,
    _Out_writes_bytes_to_opt_(*BufferSize, *BufferSize) PVOID Buffer,
    _Inout_ PULONG BufferSize);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteWnfStateData(
     _In_ PCWNF_STATE_NAME StateName,
     _In_opt_ const PVOID ExplicitScope
);


//0x4 bytes (sizeof)
typedef struct _WNF_NODE_HEADER
{
    USHORT NodeTypeCode;                                                    //0x0
    USHORT NodeByteSize;                                                    //0x2
}WNF_NODE_HEADER,*PWNF_NODE_HEADER;

//0x10 bytes (sizeof)
typedef struct _WNF_STATE_DATA
{
    struct _WNF_NODE_HEADER Header;                                         //0x0
    ULONG AllocatedSize;                                                    //0x4
    ULONG DataSize;                                                         //0x8
    ULONG ChangeStamp;                                                      //0xc
}WNF_STATE_DATA,*PWNF_STATE_DATA;


//0x8 bytes (sizeof)
struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};
//0x8 bytes (sizeof)
struct _WNF_LOCK
{
    struct _EX_PUSH_LOCK PushLock;                                          //0x0
};
//0x8 bytes (sizeof)
struct _EX_RUNDOWN_REF
{
    union
    {
        ULONGLONG Count;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};
//0x18 bytes (sizeof)
struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;                                                    //0x10
            UCHAR Balance : 2;                                                //0x10
        };
        ULONGLONG ParentValue;                                              //0x10
    };
};
//0x8 bytes (sizeof)
struct _WNF_STATE_NAME_STRUCT
{
    ULONGLONG Version : 4;                                                    //0x0
    ULONGLONG NameLifetime : 2;                                               //0x0
    ULONGLONG DataScope : 4;                                                  //0x0
    ULONGLONG PermanentData : 1;                                              //0x0
    ULONGLONG Sequence : 53;                                                  //0x0
};
//0x18 bytes (sizeof)
struct _WNF_STATE_NAME_REGISTRATION
{
    ULONG MaxStateSize;                                                     //0x0
    struct _WNF_TYPE_ID* TypeId;                                            //0x8
    struct _SECURITY_DESCRIPTOR* SecurityDescriptor;                        //0x10
};
//0xa8 bytes (sizeof)
typedef struct _WNF_NAME_INSTANCE
{
    struct _WNF_NODE_HEADER Header;                                         //0x0
    struct _EX_RUNDOWN_REF RunRef;                                          //0x8
    struct _RTL_BALANCED_NODE TreeLinks;                                    //0x10
    struct _WNF_STATE_NAME_STRUCT StateName;                                //0x28
    struct _WNF_SCOPE_INSTANCE* ScopeInstance;                              //0x30
    struct _WNF_STATE_NAME_REGISTRATION StateNameInfo;                      //0x38
    struct _WNF_LOCK StateDataLock;                                         //0x50
    struct _WNF_STATE_DATA* StateData;                                      //0x58
    ULONG CurrentChangeStamp;                                               //0x60
    VOID* PermanentDataStore;                                               //0x68
    struct _WNF_LOCK StateSubscriptionListLock;                             //0x70
    struct _LIST_ENTRY StateSubscriptionListHead;                           //0x78
    struct _LIST_ENTRY TemporaryNameListEntry;                              //0x88
    struct _EPROCESS* CreatorProcess;                                       //0x98
    LONG DataSubscribersCount;                                              //0xa0
    LONG CurrentDeliveryCount;                                              //0xa4
} WNF_NAME_INSTANCE;