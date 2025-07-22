#pragma once

#pragma warning(push)
#pragma warning(disable:4201)

#ifdef WINNT
#pragma region LDT_ENTRY
typedef struct _LDT_ENTRY {
    USHORT    LimitLow;
    USHORT    BaseLow;
    union {
        struct {
            UCHAR    BaseMid;
            UCHAR    Flags1;     // Declare as bytes to avoid alignment
            UCHAR    Flags2;     // Problems.
            UCHAR    BaseHi;
        } Bytes;
        struct {
            DWORD32   BaseMid : 8;
            DWORD32   Type : 5;
            DWORD32   Dpl : 2;
            DWORD32   Pres : 1;
            DWORD32   LimitHi : 4;
            DWORD32   Sys : 1;
            DWORD32   Reserved_0 : 1;
            DWORD32   Default_Big : 1;
            DWORD32   Granularity : 1;
            DWORD32   BaseHi : 8;
        } Bits;
    } HighWord;
} LDT_ENTRY, * PLDT_ENTRY;
#pragma endregion
#pragma region WOW64_CONTEXT

#define WOW64_SIZE_OF_80387_REGISTERS      80

#define WOW64_MAXIMUM_SUPPORTED_EXTENSION     512

typedef struct _WOW64_FLOATING_SAVE_AREA {
    DWORD32   ControlWord;
    DWORD32   StatusWord;
    DWORD32   TagWord;
    DWORD32   ErrorOffset;
    DWORD32   ErrorSelector;
    DWORD32   DataOffset;
    DWORD32   DataSelector;
    UCHAR    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
    DWORD32   Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;
typedef WOW64_FLOATING_SAVE_AREA* PWOW64_FLOATING_SAVE_AREA;
typedef struct _WOW64_CONTEXT {
    //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

    DWORD32 ContextFlags;

    //
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
    // included in CONTEXT_FULL.
    //

    DWORD32   Dr0;
    DWORD32   Dr1;
    DWORD32   Dr2;
    DWORD32   Dr3;
    DWORD32   Dr6;
    DWORD32   Dr7;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
    //

    WOW64_FLOATING_SAVE_AREA FloatSave;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
    //

    DWORD32   SegGs;
    DWORD32   SegFs;
    DWORD32   SegEs;
    DWORD32   SegDs;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_INTEGER.
    //

    DWORD32   Edi;
    DWORD32   Esi;
    DWORD32   Ebx;
    DWORD32   Edx;
    DWORD32   Ecx;
    DWORD32   Eax;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_CONTROL.
    //

    DWORD32   Ebp;
    DWORD32   Eip;
    DWORD32   SegCs;              // MUST BE SANITIZED
    DWORD32   EFlags;             // MUST BE SANITIZED
    DWORD32   Esp;
    DWORD32   SegSs;

    //
    // This section is specified/returned if the ContextFlags word
    // contains the flag CONTEXT_EXTENDED_REGISTERS.
    // The format and contexts are processor specific
    //

    UCHAR    ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

} WOW64_CONTEXT;
typedef WOW64_CONTEXT* PWOW64_CONTEXT;

#define WOW64_CONTEXT_i386      0x00010000    // this assumes that i386 and
#define WOW64_CONTEXT_i486      0x00010000    // i486 have identical context records

#define WOW64_CONTEXT_CONTROL               (WOW64_CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
#define WOW64_CONTEXT_INTEGER               (WOW64_CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
#define WOW64_CONTEXT_SEGMENTS              (WOW64_CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
#define WOW64_CONTEXT_FLOATING_POINT        (WOW64_CONTEXT_i386 | 0x00000008L) // 387 state
#define WOW64_CONTEXT_DEBUG_REGISTERS       (WOW64_CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
#define WOW64_CONTEXT_EXTENDED_REGISTERS    (WOW64_CONTEXT_i386 | 0x00000020L) // cpu specific extensions

#define WOW64_CONTEXT_FULL      (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)

#define WOW64_CONTEXT_ALL       (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS | \
                                 WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_DEBUG_REGISTERS | \
                                 WOW64_CONTEXT_EXTENDED_REGISTERS)

#define WOW64_CONTEXT_XSTATE                (WOW64_CONTEXT_i386 | 0x00000040L)

#define WOW64_CONTEXT_EXCEPTION_ACTIVE      0x08000000
#define WOW64_CONTEXT_SERVICE_ACTIVE        0x10000000
#define WOW64_CONTEXT_EXCEPTION_REQUEST     0x40000000
#define WOW64_CONTEXT_EXCEPTION_REPORTING   0x80000000

#define THREAD_CSWITCH_PMU_DISABLE  FALSE

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define va_start _crt_va_start
#define va_arg _crt_va_arg
#define va_end _crt_va_end

#pragma endregion
#else
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib,"Version.lib")
#pragma warning(disable:4201)
#pragma region NT_STATUS
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define STATUS_FILE_INVALID              ((NTSTATUS)0xC0000098L)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth

#pragma endregion

#pragma region STRING
typedef struct _UNICODE_STRING32
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        DWORD32 dummy;
    };
    DWORD32 Buffer;
}UNICODE_STRING32;

typedef struct _UNICODE_STRING64
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        DWORD64 dummy;
    };
    DWORD64 Buffer;
}UNICODE_STRING64;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} ANSI_STRING;
typedef ANSI_STRING* PANSI_STRING;
typedef const ANSI_STRING* PCANSI_STRING;
#pragma endregion
#pragma region KERNEL_DEF
typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID* PCLIENT_ID;

typedef enum _KWAIT_REASON {
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrSpare0,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    WrIoRing,
    WrMdlCache,
    MaximumWaitReason
} KWAIT_REASON;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef enum _KPROFILE_SOURCE {
    ProfileTime,
    ProfileAlignmentFixup,
    ProfileTotalIssues,
    ProfilePipelineDry,
    ProfileLoadInstructions,
    ProfilePipelineFrozen,
    ProfileBranchInstructions,
    ProfileTotalNonissues,
    ProfileDcacheMisses,
    ProfileIcacheMisses,
    ProfileCacheMisses,
    ProfileBranchMispredictions,
    ProfileStoreInstructions,
    ProfileFpInstructions,
    ProfileIntegerInstructions,
    Profile2Issue,
    Profile3Issue,
    Profile4Issue,
    ProfileSpecialInstructions,
    ProfileTotalCycles,
    ProfileIcacheIssues,
    ProfileDcacheAccesses,
    ProfileMemoryBarrierCycles,
    ProfileLoadLinkedIssues,
    ProfileMaximum
} KPROFILE_SOURCE;

#ifndef _DEFINED__WNF_STATE_NAME
#define _DEFINED__WNF_STATE_NAME
typedef struct _WNF_STATE_NAME {
    ULONG Data[2];
} WNF_STATE_NAME;

typedef struct _WNF_STATE_NAME* PWNF_STATE_NAME;
typedef const struct _WNF_STATE_NAME* PCWNF_STATE_NAME;
#endif

typedef struct _PROCESS_WS_WATCH_INFORMATION {
    PVOID FaultingPc;
    PVOID FaultingVa;
} PROCESS_WS_WATCH_INFORMATION, * PPROCESS_WS_WATCH_INFORMATION;

typedef struct _TIME_FIELDS
{
    short Year; // 1601...
    short Month; // 1..12
    short Day; // 1..31
    short Hour; // 0..23
    short Minute; // 0..59
    short Second; // 0..59
    short Milliseconds; // 0..999
    short Weekday; // 0..6 = Sunday..Saturday
} TIME_FIELDS, * PTIME_FIELDS;

typedef enum _WAIT_TYPE {
    WaitAll,
    WaitAny,
    WaitNotification,
    WaitDequeue,
    WaitDpc
} WAIT_TYPE;

typedef struct _RTL_BUFFER {
    PWCHAR    Buffer;
    PWCHAR    StaticBuffer;
    SIZE_T    Size;
    SIZE_T    StaticSize;
    SIZE_T    ReservedForAllocatedSize; // for future doubling
    PVOID     ReservedForIMalloc; // for future pluggable growth
} RTL_BUFFER, * PRTL_BUFFER;
typedef struct _RTL_UNICODE_STRING_BUFFER {
    UNICODE_STRING String;
    RTL_BUFFER     ByteBuffer;
    WCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

#endif // WINNT

#pragma region PEB

#pragma once
#pragma pack(push,1)

typedef struct _CLIENT_ID32 {
    DWORD32 UniqueProcess;
    DWORD32 UniqueThread;
} CLIENT_ID32;

typedef struct _CLIENT_ID64 {
    DWORD64 UniqueProcess;
    DWORD64 UniqueThread;
} CLIENT_ID64;

typedef struct _TEB32
{
    NT_TIB32 NtTib;
    unsigned int EnvironmentPointer;
    CLIENT_ID32 ClientId;
    DWORD32 ActiveRpcHandle;
    DWORD32 ThreadLocalStoragePointer;
    DWORD32 ProcessEnvironmentBlock;
    DWORD32 LastErrorValue;
    DWORD32 CountOfOwnedCriticalSections;
    DWORD32 CsrClientThread;
    DWORD32 Win32ThreadInfo;
    DWORD32 User32Reserved[26];
    //rest of the structure is not defined for now, as it is not needed
}TEB32;

typedef struct _TEB64
{
    NT_TIB64 NtTib;
    DWORD64 EnvironmentPointer;
    CLIENT_ID64 ClientId;
    DWORD64 ActiveRpcHandle;
    DWORD64 ThreadLocalStoragePointer;
    DWORD64 ProcessEnvironmentBlock;
    DWORD32 LastErrorValue;
    DWORD32 CountOfOwnedCriticalSections;
    DWORD64 CsrClientThread;
    DWORD64 Win32ThreadInfo;
    DWORD32 User32Reserved[26];
    //rest of the structure is not defined for now, as it is not needed
}TEB64;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    DWORD32 DllBase;
    DWORD32 EntryPoint;
    union
    {
        DWORD32 SizeOfImage;
        DWORD32 dummy01;
    };
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    DWORD32 Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY32 HashLinks;
        struct
        {
            DWORD32 SectionPointer;
            DWORD32 CheckSum;
        };
    };
    union
    {
        DWORD32 LoadedImports;
        DWORD32 TimeDateStamp;
    };
    DWORD32 EntryPointActivationContext;
    DWORD32 PatchInformation;
    LIST_ENTRY32 ForwarderLinks;
    LIST_ENTRY32 ServiceTagLinks;
    LIST_ENTRY32 StaticLinks;
    DWORD32 ContextInformation;
    DWORD32 OriginalBase;
    LARGE_INTEGER LoadTime;
}LDR_DATA_TABLE_ENTRY32;


typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    DWORD64 DllBase;
    DWORD64 EntryPoint;
    union
    {
        DWORD32 SizeOfImage;
        DWORD64 dummy01;
    };
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    DWORD32 Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY64 HashLinks;
        struct
        {
            DWORD64 SectionPointer;
            DWORD64 CheckSum;
        };
    };
    union
    {
        DWORD64 LoadedImports;
        DWORD32 TimeDateStamp;
    };
    DWORD64 EntryPointActivationContext;
    DWORD64 PatchInformation;
    LIST_ENTRY64 ForwarderLinks;
    LIST_ENTRY64 ServiceTagLinks;
    LIST_ENTRY64 StaticLinks;
    DWORD64 ContextInformation;
    DWORD64 OriginalBase;
    LARGE_INTEGER LoadTime;
}LDR_DATA_TABLE_ENTRY64;

typedef struct _PEB_LDR_DATA32
{
    DWORD32 Length;
    DWORD32 Initialized;
    DWORD32 SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    DWORD32 EntryInProgress;
    DWORD32 ShutdownInProgress;
    DWORD32 ShutdownThreadId;

}PEB_LDR_DATA32;
typedef struct _PEB_LDR_DATA64
{
    DWORD32 Length;
    DWORD32 Initialized;
    DWORD64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    DWORD32 EntryInProgress;
    DWORD32 ShutdownInProgress;
    DWORD32 ShutdownThreadId;

}PEB_LDR_DATA64;

typedef struct _PEB32
{
    union
    {
        struct
        {
            UCHAR InheritedAddressSpace;
            UCHAR ReadImageFileExecOptions;
            UCHAR BeingDebugged;
            UCHAR BitField;
        };
        DWORD32 dummy01;
    };
    DWORD32 Mutant;
    DWORD32 ImageBaseAddress;
    DWORD32 Ldr;
    DWORD32 ProcessParameters;
    DWORD32 SubSystemData;
    DWORD32 ProcessHeap;
    DWORD32 FastPebLock;
    DWORD32 AtlThunkSListPtr;
    DWORD32 IFEOKey;
    DWORD32 CrossProcessFlags;
    DWORD32 UserSharedInfoPtr;    //KernelCallbackTable
    DWORD32 SystemReserved;
    DWORD32 AtlThunkSListPtr32;
    DWORD32 ApiSetMap;
    DWORD32 TlsExpansionCounter;
    DWORD32 TlsBitmap;
    DWORD32 TlsBitmapBits[2];
    DWORD32 ReadOnlySharedMemoryBase;
    DWORD32 HotpatchInformation;
    DWORD32 ReadOnlyStaticServerData;
    DWORD32 AnsiCodePageData;
    DWORD32 OemCodePageData;
    DWORD32 UnicodeCaseTableData;
    DWORD32 NumberOfProcessors;
    union
    {
        DWORD32 NtGlobalFlag;
        DWORD64 dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    DWORD32 HeapSegmentReserve;
    DWORD32 HeapSegmentCommit;
    DWORD32 HeapDeCommitTotalFreeThreshold;
    DWORD32 HeapDeCommitFreeBlockThreshold;
    USHORT NumberOfHeaps;
    USHORT MaximumNumberOfHeaps;
    DWORD32 ProcessHeaps;
    DWORD32 GdiSharedHandleTable;
    DWORD32 ProcessStarterHelper;
    DWORD32 GdiDCAttributeList;
    DWORD32 LoaderLock;
    DWORD32 OSMajorVersion;
    DWORD32 OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    DWORD32 OSPlatformId;
    DWORD32 ImageSubsystem;
    DWORD32 ImageSubsystemMajorVersion;
    DWORD32 ImageSubsystemMinorVersion;
    DWORD32 ActiveProcessAffinityMask;
    DWORD32 GdiHandleBuffer[34];
    DWORD32 PostProcessInitRoutine;
    DWORD32 TlsExpansionBitmap;
    DWORD32 TlsExpansionBitmapBits[32];
    DWORD32 SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    DWORD32 pShimData;
    DWORD32 AppCompatInfo;
    UNICODE_STRING32 CSDVersion;
    DWORD32 ActivationContextData;
    DWORD32 ProcessAssemblyStorageMap;
    DWORD32 SystemDefaultActivationContextData;
    DWORD32 SystemAssemblyStorageMap;
    DWORD32 MinimumStackCommit;
    DWORD32 FlsCallback;
    LIST_ENTRY32 FlsListHead;
    DWORD32 FlsBitmap;
    DWORD32 FlsBitmapBits[4];
    DWORD32 FlsHighIndex;
    DWORD32 WerRegistrationData;
    DWORD32 WerShipAssertPtr;
    DWORD32 pContextData;
    DWORD32 pImageHeaderHash;
    DWORD32 TracingFlags;
} PEB32;

typedef struct _PEB64
{
    union
    {
        struct
        {
            UCHAR InheritedAddressSpace;
            UCHAR ReadImageFileExecOptions;
            UCHAR BeingDebugged;
            UCHAR BitField;
        };
        DWORD64 dummy01;
    };
    DWORD64 Mutant;
    DWORD64 ImageBaseAddress;
    DWORD64 Ldr;
    DWORD64 ProcessParameters;
    DWORD64 SubSystemData;
    DWORD64 ProcessHeap;
    DWORD64 FastPebLock;
    DWORD64 AtlThunkSListPtr;
    DWORD64 IFEOKey;
    DWORD64 CrossProcessFlags;
    DWORD64 UserSharedInfoPtr;    //KernelCallbackTable
    DWORD32 SystemReserved;
    DWORD32 AtlThunkSListPtr32;
    DWORD64 ApiSetMap;
    DWORD64 TlsExpansionCounter;
    DWORD64 TlsBitmap;
    DWORD32 TlsBitmapBits[2];
    DWORD64 ReadOnlySharedMemoryBase;
    DWORD64 HotpatchInformation;
    DWORD64 ReadOnlyStaticServerData;
    DWORD64 AnsiCodePageData;
    DWORD64 OemCodePageData;
    DWORD64 UnicodeCaseTableData;
    DWORD32 NumberOfProcessors;
    union
    {
        DWORD32 NtGlobalFlag;
        DWORD32 dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    DWORD64 HeapSegmentReserve;
    DWORD64 HeapSegmentCommit;
    DWORD64 HeapDeCommitTotalFreeThreshold;
    DWORD64 HeapDeCommitFreeBlockThreshold;
    DWORD32 NumberOfHeaps;
    DWORD32 MaximumNumberOfHeaps;
    DWORD64 ProcessHeaps;
    DWORD64 GdiSharedHandleTable;
    DWORD64 ProcessStarterHelper;
    DWORD64 GdiDCAttributeList;
    DWORD64 LoaderLock;
    DWORD32 OSMajorVersion;
    DWORD32 OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    DWORD32 OSPlatformId;
    DWORD32 ImageSubsystem;
    DWORD32 ImageSubsystemMajorVersion;
    DWORD64 ImageSubsystemMinorVersion;
    DWORD64 ActiveProcessAffinityMask;
    DWORD64 GdiHandleBuffer[30];
    DWORD64 PostProcessInitRoutine;
    DWORD64 TlsExpansionBitmap;
    DWORD32 TlsExpansionBitmapBits[32];
    DWORD64 SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    DWORD64 pShimData;
    DWORD64 AppCompatInfo;
    UNICODE_STRING64 CSDVersion;
    DWORD64 ActivationContextData;
    DWORD64 ProcessAssemblyStorageMap;
    DWORD64 SystemDefaultActivationContextData;
    DWORD64 SystemAssemblyStorageMap;
    DWORD64 MinimumStackCommit;
    DWORD64 FlsCallback;
    LIST_ENTRY64 FlsListHead;
    DWORD64 FlsBitmap;
    DWORD32 FlsBitmapBits[4];
    DWORD64 FlsHighIndex;
    DWORD64 WerRegistrationData;
    DWORD64 WerShipAssertPtr;
    DWORD64 pContextData;
    DWORD64 pImageHeaderHash;
    DWORD64 TracingFlags;
} PEB64;

#pragma pack(pop)

#pragma endregion
#pragma region SYSTEM_INFORMATION_CLASS

typedef enum _SYSTEM_INFORMATION_CLASS_EX
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
    SystemLocksInformation, // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation, // not implemented
    SystemNonPagedPoolInformation, // not implemented
    SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation, // not implemented // 20
    SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
    SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation, // s (kernel-mode only)
    SystemUnloadGdiDriverInformation, // s (kernel-mode only)
    SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0, // not implemented
    SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeperation, // s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
    SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
    SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate, // not implemented
    SystemSessionDetach, // not implemented
    SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend, // s (kernel-mode only)
    SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage, // q; s: ULONG
    SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
    SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation, // q: ULONG
    SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode, // q: ULONG // 70
    SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
    SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemWow64SharedInformationObsolete, // not implemented
    SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
    SystemVerifierTriageInformation, // not implemented
    SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
    SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx, // not implemented
    SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation, // s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
    SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
    SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation,
    SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,
    SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION
    SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
    SystemCriticalProcessErrorLogInformation,
    SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation, // 150
    SystemSoftRebootInformation, // q: ULONG
    SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,
    SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
    SystemInterruptSteeringInformation, // SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT // 180
    SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition,
    SystemKernelDebuggingAllowed, // s: ULONG
    SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,
    SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation, // q: ULONG_PTR // since REDSTONE3
    SystemSecureDumpEncryptionInformation,
    SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation,
    SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,
    SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
    SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
    SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation, // since 20H2
    SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation,
    SystemDifClearRuleClassInformation,
    SystemDifApplyPluginVerificationOnDriver,
    SystemDifRemovePluginVerificationOnDriver, // 220
    SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation, // SYSTEM_BUILD_VERSION_INFORMATION
    SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation, // SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation,
    SystemDpcWatchdogInformation2,
    SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx  // 230
    SystemSingleProcessorRelationshipInformation,
    SystemXfgCheckFailureInformation,
    SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,
    SystemOriginalImageFeatureInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS_EX;

typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT MaximumProcessors;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, * PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG AvailablePagedPoolPages;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
    ULONGLONG CcTotalDirtyPages; // since THRESHOLD
    ULONGLONG CcDirtyPageThreshold; // since THRESHOLD
    LONGLONG ResidentAvailablePages; // since THRESHOLD
    ULONGLONG SharedCommittedPages; // since THRESHOLD
} SYSTEM_PERFORMANCE_INFORMATION, * PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, * PSYSTEM_TIMEOFDAY_INFORMATION;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, * PKTHREAD_STATE;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    KTHREAD_STATE ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

// private
typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
    SYSTEM_THREAD_INFORMATION ThreadInfo;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32StartAddress;
    PVOID TebBase; // since VISTA
    ULONG_PTR Reserved2;
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
    ULONG HardFaultCount; // since WIN7
    ULONG NumberOfThreadsHighWatermark; // since WIN7
    ULONGLONG CycleTime; // since WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
    // SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
    // SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
    ULONG Length;
    ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, * PSYSTEM_CALL_COUNT_INFORMATION;

typedef struct _SYSTEM_DEVICE_INFORMATION
{
    ULONG NumberOfDisks;
    ULONG NumberOfFloppies;
    ULONG NumberOfCdRoms;
    ULONG NumberOfTapes;
    ULONG NumberOfSerialPorts;
    ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, * PSYSTEM_DEVICE_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, * PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_FLAGS_INFORMATION
{
    ULONG Flags; // NtGlobalFlag
} SYSTEM_FLAGS_INFORMATION, * PSYSTEM_FLAGS_INFORMATION;

// private
typedef struct _SYSTEM_CALL_TIME_INFORMATION
{
    ULONG Length;
    ULONG TotalCalls;
    LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, * PSYSTEM_CALL_TIME_INFORMATION;

// private
typedef struct _RTL_PROCESS_LOCK_INFORMATION
{
    PVOID Address;
    USHORT Type;
    USHORT CreatorBackTraceIndex;
    HANDLE OwningThread;
    LONG LockCount;
    ULONG ContentionCount;
    ULONG EntryCount;
    LONG RecursionCount;
    ULONG NumberOfWaitingShared;
    ULONG NumberOfWaitingExclusive;
} RTL_PROCESS_LOCK_INFORMATION, * PRTL_PROCESS_LOCK_INFORMATION;

// private
typedef struct _RTL_PROCESS_LOCKS
{
    ULONG NumberOfLocks;
    RTL_PROCESS_LOCK_INFORMATION Locks[1];
} RTL_PROCESS_LOCKS, * PRTL_PROCESS_LOCKS;

// private
typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION
{
    PCHAR SymbolicBackTrace;
    ULONG TraceCount;
    USHORT Index;
    USHORT Depth;
    PVOID BackTrace[32];
} RTL_PROCESS_BACKTRACE_INFORMATION, * PRTL_PROCESS_BACKTRACE_INFORMATION;

// private
typedef struct _RTL_PROCESS_BACKTRACES
{
    ULONG CommittedMemory;
    ULONG ReservedMemory;
    ULONG NumberOfBackTraceLookups;
    ULONG NumberOfBackTraces;
    RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
} RTL_PROCESS_BACKTRACES, * PRTL_PROCESS_BACKTRACES;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfObjects;
    ULONG NumberOfHandles;
    ULONG TypeIndex;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG PoolType;
    bool SecurityRequired;
    bool WaitableObject;
    UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, * PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION
{
    ULONG NextEntryOffset;
    PVOID Object;
    HANDLE CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Flags;
    LONG PointerCount;
    LONG HandleCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    HANDLE ExclusiveProcessId;
    PVOID SecurityDescriptor;
    UNICODE_STRING NameInfo;
} SYSTEM_OBJECT_INFORMATION, * PSYSTEM_OBJECT_INFORMATION;

typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG TotalInUse;
    ULONG PeakUsage;
    UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, * PSYSTEM_PAGEFILE_INFORMATION;

typedef struct _SYSTEM_VDM_INSTEMUL_INFO
{
    ULONG SegmentNotPresent;
    ULONG VdmOpcode0F;
    ULONG OpcodeESPrefix;
    ULONG OpcodeCSPrefix;
    ULONG OpcodeSSPrefix;
    ULONG OpcodeDSPrefix;
    ULONG OpcodeFSPrefix;
    ULONG OpcodeGSPrefix;
    ULONG OpcodeOPER32Prefix;
    ULONG OpcodeADDR32Prefix;
    ULONG OpcodeINSB;
    ULONG OpcodeINSW;
    ULONG OpcodeOUTSB;
    ULONG OpcodeOUTSW;
    ULONG OpcodePUSHF;
    ULONG OpcodePOPF;
    ULONG OpcodeINTnn;
    ULONG OpcodeINTO;
    ULONG OpcodeIRET;
    ULONG OpcodeINBimm;
    ULONG OpcodeINWimm;
    ULONG OpcodeOUTBimm;
    ULONG OpcodeOUTWimm;
    ULONG OpcodeINB;
    ULONG OpcodeINW;
    ULONG OpcodeOUTB;
    ULONG OpcodeOUTW;
    ULONG OpcodeLOCKPrefix;
    ULONG OpcodeREPNEPrefix;
    ULONG OpcodeREPPrefix;
    ULONG OpcodeHLT;
    ULONG OpcodeCLI;
    ULONG OpcodeSTI;
    ULONG BopCount;
} SYSTEM_VDM_INSTEMUL_INFO, * PSYSTEM_VDM_INSTEMUL_INFO;

#define MM_WORKING_SET_MAX_HARD_ENABLE 0x1
#define MM_WORKING_SET_MAX_HARD_DISABLE 0x2
#define MM_WORKING_SET_MIN_HARD_ENABLE 0x4
#define MM_WORKING_SET_MIN_HARD_DISABLE 0x8

typedef struct _SYSTEM_FILECACHE_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, * PSYSTEM_FILECACHE_INFORMATION;

// Can be used instead of SYSTEM_FILECACHE_INFORMATION
typedef struct _SYSTEM_BASIC_WORKING_SET_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
} SYSTEM_BASIC_WORKING_SET_INFORMATION, * PSYSTEM_BASIC_WORKING_SET_INFORMATION;

typedef struct _SYSTEM_POOLTAG
{
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, * PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, * PSYSTEM_POOLTAG_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, * PSYSTEM_INTERRUPT_INFORMATION;

typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
    ULONG Spare;
    ULONG DpcQueueDepth;
    ULONG MinimumDpcRate;
    ULONG AdjustDpcThreshold;
    ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, * PSYSTEM_DPC_BEHAVIOR_INFORMATION;

typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    ULONG TimeIncrement;
    bool Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, * PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE
{
    ULONGLONG TimeAdjustment;
    ULONGLONG TimeIncrement;
    bool Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE, * PSYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    bool Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, * PSYSTEM_SET_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE
{
    ULONGLONG TimeAdjustment;
    bool Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE, * PSYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE;

#ifndef _TRACEHANDLE_DEFINED
#define _TRACEHANDLE_DEFINED
typedef ULONG64 TRACEHANDLE, * PTRACEHANDLE;
#endif

typedef enum _EVENT_TRACE_INFORMATION_CLASS
{
    EventTraceKernelVersionInformation, // EVENT_TRACE_VERSION_INFORMATION
    EventTraceGroupMaskInformation, // EVENT_TRACE_GROUPMASK_INFORMATION
    EventTracePerformanceInformation, // EVENT_TRACE_PERFORMANCE_INFORMATION
    EventTraceTimeProfileInformation, // EVENT_TRACE_TIME_PROFILE_INFORMATION
    EventTraceSessionSecurityInformation, // EVENT_TRACE_SESSION_SECURITY_INFORMATION
    EventTraceSpinlockInformation, // EVENT_TRACE_SPINLOCK_INFORMATION
    EventTraceStackTracingInformation, // EVENT_TRACE_SYSTEM_EVENT_INFORMATION
    EventTraceExecutiveResourceInformation, // EVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION
    EventTraceHeapTracingInformation, // EVENT_TRACE_HEAP_TRACING_INFORMATION
    EventTraceHeapSummaryTracingInformation, // EVENT_TRACE_HEAP_TRACING_INFORMATION
    EventTracePoolTagFilterInformation, // EVENT_TRACE_TAG_FILTER_INFORMATION
    EventTracePebsTracingInformation, // EVENT_TRACE_SYSTEM_EVENT_INFORMATION
    EventTraceProfileConfigInformation, // EVENT_TRACE_PROFILE_COUNTER_INFORMATION
    EventTraceProfileSourceListInformation, // EVENT_TRACE_PROFILE_LIST_INFORMATION
    EventTraceProfileEventListInformation, // EVENT_TRACE_SYSTEM_EVENT_INFORMATION
    EventTraceProfileCounterListInformation, // EVENT_TRACE_PROFILE_COUNTER_INFORMATION
    EventTraceStackCachingInformation, // EVENT_TRACE_STACK_CACHING_INFORMATION
    EventTraceObjectTypeFilterInformation, // EVENT_TRACE_TAG_FILTER_INFORMATION
    EventTraceSoftRestartInformation, // EVENT_TRACE_SOFT_RESTART_INFORMATION
    EventTraceLastBranchConfigurationInformation, // REDSTONE3
    EventTraceLastBranchEventListInformation,
    EventTraceProfileSourceAddInformation, // EVENT_TRACE_PROFILE_ADD_INFORMATION // REDSTONE4
    EventTraceProfileSourceRemoveInformation, // EVENT_TRACE_PROFILE_REMOVE_INFORMATION
    EventTraceProcessorTraceConfigurationInformation,
    EventTraceProcessorTraceEventListInformation,
    EventTraceCoverageSamplerInformation, // EVENT_TRACE_COVERAGE_SAMPLER_INFORMATION
    EventTraceUnifiedStackCachingInformation, // sicne 21H1
    MaxEventTraceInfoClass
} EVENT_TRACE_INFORMATION_CLASS;

typedef struct _EVENT_TRACE_VERSION_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG EventTraceKernelVersion;
} EVENT_TRACE_VERSION_INFORMATION, * PEVENT_TRACE_VERSION_INFORMATION;

#define PERF_MASK_INDEX         (0xe0000000)
#define PERF_MASK_GROUP         (~PERF_MASK_INDEX)
#define PERF_NUM_MASKS          8

#define PERF_GET_MASK_INDEX(GM) (((GM) & PERF_MASK_INDEX) >> 29)
#define PERF_GET_MASK_GROUP(GM) ((GM) & PERF_MASK_GROUP)
#define PERFINFO_OR_GROUP_WITH_GROUPMASK(Group, pGroupMask) \
    (pGroupMask)->Masks[PERF_GET_MASK_INDEX(Group)] |= PERF_GET_MASK_GROUP(Group);

// Masks[0]
#define PERF_PROCESS            EVENT_TRACE_FLAG_PROCESS
#define PERF_THREAD             EVENT_TRACE_FLAG_THREAD
#define PERF_PROC_THREAD        EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD
#define PERF_LOADER             EVENT_TRACE_FLAG_IMAGE_LOAD
#define PERF_PERF_COUNTER       EVENT_TRACE_FLAG_PROCESS_COUNTERS
#define PERF_FILENAME           EVENT_TRACE_FLAG_DISK_FILE_IO
#define PERF_DISK_IO            EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_DISK_IO
#define PERF_DISK_IO_INIT       EVENT_TRACE_FLAG_DISK_IO_INIT
#define PERF_ALL_FAULTS         EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS
#define PERF_HARD_FAULTS        EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS
#define PERF_VAMAP              EVENT_TRACE_FLAG_VAMAP
#define PERF_NETWORK            EVENT_TRACE_FLAG_NETWORK_TCPIP
#define PERF_REGISTRY           EVENT_TRACE_FLAG_REGISTRY
#define PERF_DBGPRINT           EVENT_TRACE_FLAG_DBGPRINT
#define PERF_JOB                EVENT_TRACE_FLAG_JOB
#define PERF_ALPC               EVENT_TRACE_FLAG_ALPC
#define PERF_SPLIT_IO           EVENT_TRACE_FLAG_SPLIT_IO
#define PERF_DEBUG_EVENTS       EVENT_TRACE_FLAG_DEBUG_EVENTS
#define PERF_FILE_IO            EVENT_TRACE_FLAG_FILE_IO
#define PERF_FILE_IO_INIT       EVENT_TRACE_FLAG_FILE_IO_INIT
#define PERF_NO_SYSCONFIG       EVENT_TRACE_FLAG_NO_SYSCONFIG

// Masks[1]
#define PERF_MEMORY             0x20000001
#define PERF_PROFILE            0x20000002  // equivalent to EVENT_TRACE_FLAG_PROFILE
#define PERF_CONTEXT_SWITCH     0x20000004  // equivalent to EVENT_TRACE_FLAG_CSWITCH
#define PERF_FOOTPRINT          0x20000008
#define PERF_DRIVERS            0x20000010  // equivalent to EVENT_TRACE_FLAG_DRIVER
#define PERF_REFSET             0x20000020
#define PERF_POOL               0x20000040
#define PERF_POOLTRACE          0x20000041
#define PERF_DPC                0x20000080  // equivalent to EVENT_TRACE_FLAG_DPC
#define PERF_COMPACT_CSWITCH    0x20000100
#define PERF_DISPATCHER         0x20000200  // equivalent to EVENT_TRACE_FLAG_DISPATCHER
#define PERF_PMC_PROFILE        0x20000400
#define PERF_PROFILING          0x20000402
#define PERF_PROCESS_INSWAP     0x20000800
#define PERF_AFFINITY           0x20001000
#define PERF_PRIORITY           0x20002000
#define PERF_INTERRUPT          0x20004000  // equivalent to EVENT_TRACE_FLAG_INTERRUPT
#define PERF_VIRTUAL_ALLOC      0x20008000  // equivalent to EVENT_TRACE_FLAG_VIRTUAL_ALLOC
#define PERF_SPINLOCK           0x20010000
#define PERF_SYNC_OBJECTS       0x20020000
#define PERF_DPC_QUEUE          0x20040000
#define PERF_MEMINFO            0x20080000
#define PERF_CONTMEM_GEN        0x20100000
#define PERF_SPINLOCK_CNTRS     0x20200000
#define PERF_SPININSTR          0x20210000
#define PERF_SESSION            0x20400000
#define PERF_PFSECTION          0x20400000
#define PERF_MEMINFO_WS         0x20800000
#define PERF_KERNEL_QUEUE       0x21000000
#define PERF_INTERRUPT_STEER    0x22000000
#define PERF_SHOULD_YIELD       0x24000000
#define PERF_WS                 0x28000000

// Masks[2]
#define PERF_ANTI_STARVATION    0x40000001
#define PERF_PROCESS_FREEZE     0x40000002
#define PERF_PFN_LIST           0x40000004
#define PERF_WS_DETAIL          0x40000008
#define PERF_WS_ENTRY           0x40000010
#define PERF_HEAP               0x40000020
#define PERF_SYSCALL            0x40000040  // equivalent to EVENT_TRACE_FLAG_SYSTEMCALL
#define PERF_UMS                0x40000080
#define PERF_BACKTRACE          0x40000100
#define PERF_VULCAN             0x40000200
#define PERF_OBJECTS            0x40000400
#define PERF_EVENTS             0x40000800
#define PERF_FULLTRACE          0x40001000
#define PERF_DFSS               0x40002000
#define PERF_PREFETCH           0x40004000
#define PERF_PROCESSOR_IDLE     0x40008000
#define PERF_CPU_CONFIG         0x40010000
#define PERF_TIMER              0x40020000
#define PERF_CLOCK_INTERRUPT    0x40040000
#define PERF_LOAD_BALANCER      0x40080000
#define PERF_CLOCK_TIMER        0x40100000
#define PERF_IDLE_SELECTION     0x40200000
#define PERF_IPI                0x40400000
#define PERF_IO_TIMER           0x40800000
#define PERF_REG_HIVE           0x41000000
#define PERF_REG_NOTIF          0x42000000
#define PERF_PPM_EXIT_LATENCY   0x44000000
#define PERF_WORKER_THREAD      0x48000000

// Masks[4]
#define PERF_OPTICAL_IO         0x80000001
#define PERF_OPTICAL_IO_INIT    0x80000002
#define PERF_DLL_INFO           0x80000008
#define PERF_DLL_FLUSH_WS       0x80000010
#define PERF_OB_HANDLE          0x80000040
#define PERF_OB_OBJECT          0x80000080
#define PERF_WAKE_DROP          0x80000200
#define PERF_WAKE_EVENT         0x80000400
#define PERF_DEBUGGER           0x80000800
#define PERF_PROC_ATTACH        0x80001000
#define PERF_WAKE_COUNTER       0x80002000
#define PERF_POWER              0x80008000
#define PERF_SOFT_TRIM          0x80010000
#define PERF_CC                 0x80020000
#define PERF_FLT_IO_INIT        0x80080000
#define PERF_FLT_IO             0x80100000
#define PERF_FLT_FASTIO         0x80200000
#define PERF_FLT_IO_FAILURE     0x80400000
#define PERF_HV_PROFILE         0x80800000
#define PERF_WDF_DPC            0x81000000
#define PERF_WDF_INTERRUPT      0x82000000
#define PERF_CACHE_FLUSH        0x84000000

// Masks[5]
#define PERF_HIBER_RUNDOWN      0xA0000001

// Masks[6]
#define PERF_SYSCFG_SYSTEM      0xC0000001
#define PERF_SYSCFG_GRAPHICS    0xC0000002
#define PERF_SYSCFG_STORAGE     0xC0000004
#define PERF_SYSCFG_NETWORK     0xC0000008
#define PERF_SYSCFG_SERVICES    0xC0000010
#define PERF_SYSCFG_PNP         0xC0000020
#define PERF_SYSCFG_OPTICAL     0xC0000040
#define PERF_SYSCFG_ALL         0xDFFFFFFF

// Masks[7] - Control Mask. All flags that change system behavior go here.
#define PERF_CLUSTER_OFF        0xE0000001
#define PERF_MEMORY_CONTROL     0xE0000002

typedef ULONG PERFINFO_MASK;

typedef struct _PERFINFO_GROUPMASK
{
    ULONG Masks[PERF_NUM_MASKS];
} PERFINFO_GROUPMASK, * PPERFINFO_GROUPMASK;

typedef struct _EVENT_TRACE_GROUPMASK_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    PERFINFO_GROUPMASK EventTraceGroupMasks;
} EVENT_TRACE_GROUPMASK_INFORMATION, * PEVENT_TRACE_GROUPMASK_INFORMATION;

typedef struct _EVENT_TRACE_PERFORMANCE_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    LARGE_INTEGER LogfileBytesWritten;
} EVENT_TRACE_PERFORMANCE_INFORMATION, * PEVENT_TRACE_PERFORMANCE_INFORMATION;

typedef struct _EVENT_TRACE_TIME_PROFILE_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG ProfileInterval;
} EVENT_TRACE_TIME_PROFILE_INFORMATION, * PEVENT_TRACE_TIME_PROFILE_INFORMATION;

typedef struct _EVENT_TRACE_SESSION_SECURITY_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG SecurityInformation;
    TRACEHANDLE TraceHandle;
    UCHAR SecurityDescriptor[1];
} EVENT_TRACE_SESSION_SECURITY_INFORMATION, * PEVENT_TRACE_SESSION_SECURITY_INFORMATION;

typedef struct _EVENT_TRACE_SPINLOCK_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG SpinLockSpinThreshold;
    ULONG SpinLockAcquireSampleRate;
    ULONG SpinLockContentionSampleRate;
    ULONG SpinLockHoldThreshold;
} EVENT_TRACE_SPINLOCK_INFORMATION, * PEVENT_TRACE_SPINLOCK_INFORMATION;

typedef struct _EVENT_TRACE_SYSTEM_EVENT_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    ULONG HookId[1];
} EVENT_TRACE_SYSTEM_EVENT_INFORMATION, * PEVENT_TRACE_SYSTEM_EVENT_INFORMATION;

typedef struct _EVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG ReleaseSamplingRate;
    ULONG ContentionSamplingRate;
    ULONG NumberOfExcessiveTimeouts;
} EVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION, * PEVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION;

typedef struct _EVENT_TRACE_HEAP_TRACING_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG ProcessId;
} EVENT_TRACE_HEAP_TRACING_INFORMATION, * PEVENT_TRACE_HEAP_TRACING_INFORMATION;

typedef struct _EVENT_TRACE_TAG_FILTER_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    ULONG Filter[1];
} EVENT_TRACE_TAG_FILTER_INFORMATION, * PEVENT_TRACE_TAG_FILTER_INFORMATION;

typedef struct _EVENT_TRACE_PROFILE_COUNTER_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    ULONG ProfileSource[1];
} EVENT_TRACE_PROFILE_COUNTER_INFORMATION, * PEVENT_TRACE_PROFILE_COUNTER_INFORMATION;

typedef struct _PROFILE_SOURCE_INFO
{
    ULONG NextEntryOffset;
    ULONG Source;
    ULONG MinInterval;
    ULONG MaxInterval;
    PVOID Reserved;
    WCHAR Description[1];
} PROFILE_SOURCE_INFO, * PPROFILE_SOURCE_INFO;

typedef struct _EVENT_TRACE_PROFILE_LIST_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    ULONG Spare;
    struct _PROFILE_SOURCE_INFO* Profile[1];
} EVENT_TRACE_PROFILE_LIST_INFORMATION, * PEVENT_TRACE_PROFILE_LIST_INFORMATION;

typedef struct _EVENT_TRACE_STACK_CACHING_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    bool Enabled;
    UCHAR Reserved[3];
    ULONG CacheSize;
    ULONG BucketCount;
} EVENT_TRACE_STACK_CACHING_INFORMATION, * PEVENT_TRACE_STACK_CACHING_INFORMATION;

typedef struct _EVENT_TRACE_SOFT_RESTART_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    TRACEHANDLE TraceHandle;
    bool PersistTraceBuffers;
    WCHAR FileName[1];
} EVENT_TRACE_SOFT_RESTART_INFORMATION, * PEVENT_TRACE_SOFT_RESTART_INFORMATION;

typedef struct _EVENT_TRACE_PROFILE_ADD_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    bool PerfEvtEventSelect;
    bool PerfEvtUnitSelect;
    ULONG PerfEvtType;
    ULONG CpuInfoHierarchy[0x3];
    ULONG InitialInterval;
    bool AllowsHalt;
    bool Persist;
    WCHAR ProfileSourceDescription[0x1];
} EVENT_TRACE_PROFILE_ADD_INFORMATION, * PEVENT_TRACE_PROFILE_ADD_INFORMATION;

typedef struct _EVENT_TRACE_PROFILE_REMOVE_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    KPROFILE_SOURCE ProfileSource;
    ULONG CpuInfoHierarchy[0x3];
} EVENT_TRACE_PROFILE_REMOVE_INFORMATION, * PEVENT_TRACE_PROFILE_REMOVE_INFORMATION;

typedef struct _EVENT_TRACE_COVERAGE_SAMPLER_INFORMATION
{
    EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
    bool CoverageSamplerInformationClass;
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    UCHAR Reserved;
    HANDLE SamplerHandle;
} EVENT_TRACE_COVERAGE_SAMPLER_INFORMATION, * PEVENT_TRACE_COVERAGE_SAMPLER_INFORMATION;

typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
    ULONG AlignmentFixupCount;
    ULONG ExceptionDispatchCount;
    ULONG FloatingEmulationCount;
    ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, * PSYSTEM_EXCEPTION_INFORMATION;

typedef enum _SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS
{
    SystemCrashDumpDisable,
    SystemCrashDumpReconfigure,
    SystemCrashDumpInitializationComplete
} SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS, * PSYSTEM_CRASH_DUMP_CONFIGURATION_CLASS;

typedef struct _SYSTEM_CRASH_DUMP_STATE_INFORMATION
{
    SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS CrashDumpConfigurationClass;
} SYSTEM_CRASH_DUMP_STATE_INFORMATION, * PSYSTEM_CRASH_DUMP_STATE_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    bool KernelDebuggerEnabled;
    bool KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
    ULONG ContextSwitches;
    ULONG FindAny;
    ULONG FindLast;
    ULONG FindIdeal;
    ULONG IdleAny;
    ULONG IdleCurrent;
    ULONG IdleLast;
    ULONG IdleIdeal;
    ULONG PreemptAny;
    ULONG PreemptCurrent;
    ULONG PreemptLast;
    ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, * PSYSTEM_CONTEXT_SWITCH_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
    ULONG RegistryQuotaAllowed;
    ULONG RegistryQuotaUsed;
    SIZE_T PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, * PSYSTEM_REGISTRY_QUOTA_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_IDLE_INFORMATION
{
    ULONGLONG IdleTime;
    ULONGLONG C1Time;
    ULONGLONG C2Time;
    ULONGLONG C3Time;
    ULONG C1Transitions;
    ULONG C2Transitions;
    ULONG C3Transitions;
    ULONG Padding;
} SYSTEM_PROCESSOR_IDLE_INFORMATION, * PSYSTEM_PROCESSOR_IDLE_INFORMATION;

typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
{
    ULONG VetoType;
    UNICODE_STRING VetoList;
} SYSTEM_LEGACY_DRIVER_INFORMATION, * PSYSTEM_LEGACY_DRIVER_INFORMATION;

typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
    USHORT CurrentDepth;
    USHORT MaximumDepth;
    ULONG TotalAllocates;
    ULONG AllocateMisses;
    ULONG TotalFrees;
    ULONG FreeMisses;
    ULONG Type;
    ULONG Tag;
    ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, * PSYSTEM_LOOKASIDE_INFORMATION;

// private
typedef struct _SYSTEM_RANGE_START_INFORMATION
{
    ULONG_PTR SystemRangeStart;
} SYSTEM_RANGE_START_INFORMATION, * PSYSTEM_RANGE_START_INFORMATION;

typedef struct _SYSTEM_VERIFIER_INFORMATION_LEGACY // pre-19H1
{
    ULONG NextEntryOffset;
    ULONG Level;
    UNICODE_STRING DriverName;

    ULONG RaiseIrqls;
    ULONG AcquireSpinLocks;
    ULONG SynchronizeExecutions;
    ULONG AllocationsAttempted;

    ULONG AllocationsSucceeded;
    ULONG AllocationsSucceededSpecialPool;
    ULONG AllocationsWithNoTag;
    ULONG TrimRequests;

    ULONG Trims;
    ULONG AllocationsFailed;
    ULONG AllocationsFailedDeliberately;
    ULONG Loads;

    ULONG Unloads;
    ULONG UnTrackedPool;
    ULONG CurrentPagedPoolAllocations;
    ULONG CurrentNonPagedPoolAllocations;

    ULONG PeakPagedPoolAllocations;
    ULONG PeakNonPagedPoolAllocations;

    SIZE_T PagedPoolUsageInBytes;
    SIZE_T NonPagedPoolUsageInBytes;
    SIZE_T PeakPagedPoolUsageInBytes;
    SIZE_T PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION_LEGACY, * PSYSTEM_VERIFIER_INFORMATION_LEGACY;

typedef struct _SYSTEM_VERIFIER_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG Level;
    ULONG RuleClasses[2];
    ULONG TriageContext;
    ULONG AreAllDriversBeingVerified;

    UNICODE_STRING DriverName;

    ULONG RaiseIrqls;
    ULONG AcquireSpinLocks;
    ULONG SynchronizeExecutions;
    ULONG AllocationsAttempted;

    ULONG AllocationsSucceeded;
    ULONG AllocationsSucceededSpecialPool;
    ULONG AllocationsWithNoTag;
    ULONG TrimRequests;

    ULONG Trims;
    ULONG AllocationsFailed;
    ULONG AllocationsFailedDeliberately;
    ULONG Loads;

    ULONG Unloads;
    ULONG UnTrackedPool;
    ULONG CurrentPagedPoolAllocations;
    ULONG CurrentNonPagedPoolAllocations;

    ULONG PeakPagedPoolAllocations;
    ULONG PeakNonPagedPoolAllocations;

    SIZE_T PagedPoolUsageInBytes;
    SIZE_T NonPagedPoolUsageInBytes;
    SIZE_T PeakPagedPoolUsageInBytes;
    SIZE_T PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, * PSYSTEM_VERIFIER_INFORMATION;

// private
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

// private
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    struct _IMAGE_EXPORT_DIRECTORY* ExportSectionPointer;
    ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, * PSYSTEM_GDI_DRIVER_INFORMATION;

// geoffchappell
#ifdef _WIN64
#define MAXIMUM_NODE_COUNT 0x40
#else
#define MAXIMUM_NODE_COUNT 0x10
#endif

// private
typedef struct _SYSTEM_NUMA_INFORMATION
{
    ULONG HighestNodeNumber;
    ULONG Reserved;
    union
    {
        GROUP_AFFINITY ActiveProcessorsGroupAffinity[MAXIMUM_NODE_COUNT];
        ULONGLONG AvailableMemory[MAXIMUM_NODE_COUNT];
        ULONGLONG Pad[MAXIMUM_NODE_COUNT * 2];
    };
} SYSTEM_NUMA_INFORMATION, * PSYSTEM_NUMA_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_POWER_INFORMATION
{
    UCHAR CurrentFrequency;
    UCHAR ThermalLimitFrequency;
    UCHAR ConstantThrottleFrequency;
    UCHAR DegradedThrottleFrequency;
    UCHAR LastBusyFrequency;
    UCHAR LastC3Frequency;
    UCHAR LastAdjustedBusyFrequency;
    UCHAR ProcessorMinThrottle;
    UCHAR ProcessorMaxThrottle;
    ULONG NumberOfFrequencies;
    ULONG PromotionCount;
    ULONG DemotionCount;
    ULONG ErrorCount;
    ULONG RetryCount;
    ULONGLONG CurrentFrequencyTime;
    ULONGLONG CurrentProcessorTime;
    ULONGLONG CurrentProcessorIdleTime;
    ULONGLONG LastProcessorTime;
    ULONGLONG LastProcessorIdleTime;
    ULONGLONG Energy;
} SYSTEM_PROCESSOR_POWER_INFORMATION, * PSYSTEM_PROCESSOR_POWER_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union
    {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    SIZE_T SizeInBytes;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef struct _SYSTEM_POOL_ENTRY
{
    bool Allocated;
    bool Spare0;
    USHORT AllocatorBackTraceIndex;
    ULONG Size;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
        PVOID ProcessChargedQuota;
    };
} SYSTEM_POOL_ENTRY, * PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION
{
    SIZE_T TotalSize;
    PVOID FirstEntry;
    USHORT EntryOverhead;
    bool PoolTagPresent;
    bool Spare0;
    ULONG NumberOfEntries;
    SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, * PSYSTEM_POOL_INFORMATION;

typedef struct _SYSTEM_SESSION_POOLTAG_INFORMATION
{
    SIZE_T NextEntryOffset;
    ULONG SessionId;
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_SESSION_POOLTAG_INFORMATION, * PSYSTEM_SESSION_POOLTAG_INFORMATION;

typedef struct _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
{
    SIZE_T NextEntryOffset;
    ULONG SessionId;
    ULONG ViewFailures;
    SIZE_T NumberOfBytesAvailable;
    SIZE_T NumberOfBytesAvailableContiguous;
} SYSTEM_SESSION_MAPPED_VIEW_INFORMATION, * PSYSTEM_SESSION_MAPPED_VIEW_INFORMATION;

typedef enum _WATCHDOG_HANDLER_ACTION
{
    WdActionSetTimeoutValue,
    WdActionQueryTimeoutValue,
    WdActionResetTimer,
    WdActionStopTimer,
    WdActionStartTimer,
    WdActionSetTriggerAction,
    WdActionQueryTriggerAction,
    WdActionQueryState
} WATCHDOG_HANDLER_ACTION;

typedef NTSTATUS(*PSYSTEM_WATCHDOG_HANDLER)(_In_ WATCHDOG_HANDLER_ACTION Action, _In_ PVOID Context, _Inout_ PULONG DataValue, _In_ bool NoLocks);

// private
typedef struct _SYSTEM_WATCHDOG_HANDLER_INFORMATION
{
    PSYSTEM_WATCHDOG_HANDLER WdHandler;
    PVOID Context;
} SYSTEM_WATCHDOG_HANDLER_INFORMATION, * PSYSTEM_WATCHDOG_HANDLER_INFORMATION;

typedef enum _WATCHDOG_INFORMATION_CLASS
{
    WdInfoTimeoutValue = 0,
    WdInfoResetTimer = 1,
    WdInfoStopTimer = 2,
    WdInfoStartTimer = 3,
    WdInfoTriggerAction = 4,
    WdInfoState = 5,
    WdInfoTriggerReset = 6,
    WdInfoNop = 7,
    WdInfoGeneratedLastReset = 8,
    WdInfoInvalid = 9,
} WATCHDOG_INFORMATION_CLASS;

// private
typedef struct _SYSTEM_WATCHDOG_TIMER_INFORMATION
{
    WATCHDOG_INFORMATION_CLASS WdInfoClass;
    ULONG DataValue;
} SYSTEM_WATCHDOG_TIMER_INFORMATION, PSYSTEM_WATCHDOG_TIMER_INFORMATION;

#if (PHNT_MODE != PHNT_MODE_KERNEL)
// private
typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
    SystemFirmwareTableEnumerate,
    SystemFirmwareTableGet,
    SystemFirmwareTableMax
} SYSTEM_FIRMWARE_TABLE_ACTION;

// private
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    ULONG ProviderSignature; // (same as the GetSystemFirmwareTable function)
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, * PSYSTEM_FIRMWARE_TABLE_INFORMATION;
#endif

#if (PHNT_MODE != PHNT_MODE_KERNEL)
// private
typedef NTSTATUS(__cdecl* PFNFTH)(
    _Inout_ PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo
    );

// private
typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
{
    ULONG ProviderSignature;
    bool Register;
    PFNFTH FirmwareTableHandler;
    PVOID DriverObject;
} SYSTEM_FIRMWARE_TABLE_HANDLER, * PSYSTEM_FIRMWARE_TABLE_HANDLER;
#endif

// private
typedef struct _SYSTEM_MEMORY_LIST_INFORMATION
{
    ULONG_PTR ZeroPageCount;
    ULONG_PTR FreePageCount;
    ULONG_PTR ModifiedPageCount;
    ULONG_PTR ModifiedNoWritePageCount;
    ULONG_PTR BadPageCount;
    ULONG_PTR PageCountByPriority[8];
    ULONG_PTR RepurposedPagesByPriority[8];
    ULONG_PTR ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION, * PSYSTEM_MEMORY_LIST_INFORMATION;

// private
typedef enum _SYSTEM_MEMORY_LIST_COMMAND
{
    MemoryCaptureAccessedBits,
    MemoryCaptureAndResetAccessedBits,
    MemoryEmptyWorkingSets,
    MemoryFlushModifiedList,
    MemoryPurgeStandbyList,
    MemoryPurgeLowPriorityStandbyList,
    MemoryCommandMax
} SYSTEM_MEMORY_LIST_COMMAND;

// private
typedef struct _SYSTEM_THREAD_CID_PRIORITY_INFORMATION
{
    CLIENT_ID ClientId;
    KPRIORITY Priority;
} SYSTEM_THREAD_CID_PRIORITY_INFORMATION, * PSYSTEM_THREAD_CID_PRIORITY_INFORMATION;

// private
typedef struct _SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION
{
    ULONGLONG CycleTime;
} SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION, * PSYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION;

// private
typedef struct _SYSTEM_VERIFIER_ISSUE
{
    ULONGLONG IssueType;
    PVOID Address;
    ULONGLONG Parameters[2];
} SYSTEM_VERIFIER_ISSUE, * PSYSTEM_VERIFIER_ISSUE;

// private
typedef struct _SYSTEM_VERIFIER_CANCELLATION_INFORMATION
{
    ULONG CancelProbability;
    ULONG CancelThreshold;
    ULONG CompletionThreshold;
    ULONG CancellationVerifierDisabled;
    ULONG AvailableIssues;
    SYSTEM_VERIFIER_ISSUE Issues[128];
} SYSTEM_VERIFIER_CANCELLATION_INFORMATION, * PSYSTEM_VERIFIER_CANCELLATION_INFORMATION;

// private
typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
    bool TraceEnable;
    bool TracePermanent;
    UNICODE_STRING TraceProcessName;
    UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, * PSYSTEM_REF_TRACE_INFORMATION;

// private
typedef struct _SYSTEM_SPECIAL_POOL_INFORMATION
{
    ULONG PoolTag;
    ULONG Flags;
} SYSTEM_SPECIAL_POOL_INFORMATION, * PSYSTEM_SPECIAL_POOL_INFORMATION;

// private
typedef struct _SYSTEM_PROCESS_ID_INFORMATION
{
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, * PSYSTEM_PROCESS_ID_INFORMATION;

// private
typedef struct _SYSTEM_HYPERVISOR_QUERY_INFORMATION
{
    bool HypervisorConnected;
    bool HypervisorDebuggingEnabled;
    bool HypervisorPresent;
    bool Spare0[5];
    ULONGLONG EnabledEnlightenments;
} SYSTEM_HYPERVISOR_QUERY_INFORMATION, * PSYSTEM_HYPERVISOR_QUERY_INFORMATION;

// private
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
{
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
    union
    {
        ULONGLONG BootFlags;
        struct
        {
            ULONGLONG DbgMenuOsSelection : 1; // REDSTONE4
            ULONGLONG DbgHiberBoot : 1;
            ULONGLONG DbgSoftBoot : 1;
            ULONGLONG DbgMeasuredLaunch : 1;
            ULONGLONG DbgMeasuredLaunchCapable : 1; // 19H1
            ULONGLONG DbgSystemHiveReplace : 1;
            ULONGLONG DbgMeasuredLaunchSmmProtections : 1;
            ULONGLONG DbgMeasuredLaunchSmmLevel : 7; // 20H1
        };
    };
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, * PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

// private
typedef struct _SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION
{
    ULONG FlagsToEnable;
    ULONG FlagsToDisable;
} SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION, * PSYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION;

// private
typedef enum _COVERAGE_REQUEST_CODES
{
    CoverageAllModules = 0,
    CoverageSearchByHash = 1,
    CoverageSearchByName = 2
} COVERAGE_REQUEST_CODES;

// private
typedef struct _COVERAGE_MODULE_REQUEST
{
    COVERAGE_REQUEST_CODES RequestType;
    union
    {
        UCHAR MD5Hash[16];
        UNICODE_STRING ModuleName;
    } SearchInfo;
} COVERAGE_MODULE_REQUEST, * PCOVERAGE_MODULE_REQUEST;

// private
typedef struct _COVERAGE_MODULE_INFO
{
    ULONG ModuleInfoSize;
    ULONG IsBinaryLoaded;
    UNICODE_STRING ModulePathName;
    ULONG CoverageSectionSize;
    UCHAR CoverageSection[1];
} COVERAGE_MODULE_INFO, * PCOVERAGE_MODULE_INFO;

// private
typedef struct _COVERAGE_MODULES
{
    ULONG ListAndReset;
    ULONG NumberOfModules;
    COVERAGE_MODULE_REQUEST ModuleRequestInfo;
    COVERAGE_MODULE_INFO Modules[1];
} COVERAGE_MODULES, * PCOVERAGE_MODULES;

// private
typedef struct _SYSTEM_PREFETCH_PATCH_INFORMATION
{
    ULONG PrefetchPatchCount;
} SYSTEM_PREFETCH_PATCH_INFORMATION, * PSYSTEM_PREFETCH_PATCH_INFORMATION;

// private
typedef struct _SYSTEM_VERIFIER_FAULTS_INFORMATION
{
    ULONG Probability;
    ULONG MaxProbability;
    UNICODE_STRING PoolTags;
    UNICODE_STRING Applications;
} SYSTEM_VERIFIER_FAULTS_INFORMATION, * PSYSTEM_VERIFIER_FAULTS_INFORMATION;

// private
typedef struct _SYSTEM_VERIFIER_INFORMATION_EX
{
    ULONG VerifyMode;
    ULONG OptionChanges;
    UNICODE_STRING PreviousBucketName;
    ULONG IrpCancelTimeoutMsec;
    ULONG VerifierExtensionEnabled;
#ifdef _WIN64
    ULONG Reserved[1];
#else
    ULONG Reserved[3];
#endif
} SYSTEM_VERIFIER_INFORMATION_EX, * PSYSTEM_VERIFIER_INFORMATION_EX;

// private
typedef struct _SYSTEM_SYSTEM_PARTITION_INFORMATION
{
    UNICODE_STRING SystemPartition;
} SYSTEM_SYSTEM_PARTITION_INFORMATION, * PSYSTEM_SYSTEM_PARTITION_INFORMATION;

// private
typedef struct _SYSTEM_SYSTEM_DISK_INFORMATION
{
    UNICODE_STRING SystemDisk;
} SYSTEM_SYSTEM_DISK_INFORMATION, * PSYSTEM_SYSTEM_DISK_INFORMATION;

// private
typedef struct _SYSTEM_NUMA_PROXIMITY_MAP
{
    ULONG NodeProximityId;
    USHORT NodeNumber;
} SYSTEM_NUMA_PROXIMITY_MAP, * PSYSTEM_NUMA_PROXIMITY_MAP;

// private (Windows 8.1 and above)
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT
{
    ULONGLONG Hits;
    UCHAR PercentFrequency;
} SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT, * PSYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT;

// private (Windows 7 and Windows 8)
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT_WIN8
{
    ULONG Hits;
    UCHAR PercentFrequency;
} SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT_WIN8, * PSYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT_WIN8;

// private
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION
{
    ULONG ProcessorNumber;
    ULONG StateCount;
    SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT States[1];
} SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION, * PSYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION;

// private
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
{
    ULONG ProcessorCount;
    ULONG Offsets[1];
} SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION, * PSYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION;

#define CODEINTEGRITY_OPTION_ENABLED 0x01
#define CODEINTEGRITY_OPTION_TESTSIGN 0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED 0x04
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED 0x08
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED 0x10
#define CODEINTEGRITY_OPTION_TEST_BUILD 0x20
#define CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD 0x40
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED 0x80
#define CODEINTEGRITY_OPTION_FLIGHT_BUILD 0x100
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED 0x200
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED 0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED 0x1000
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED 0x2000
#define CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED 0x4000
#define CODEINTEGRITY_OPTION_WHQL_AUDITMODE_ENABLED 0x8000

// private
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

// private
typedef struct _SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
{
    ULONG Operation;
} SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION, * PSYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION;

// private
typedef enum _SYSTEM_VA_TYPE
{
    SystemVaTypeAll,
    SystemVaTypeNonPagedPool,
    SystemVaTypePagedPool,
    SystemVaTypeSystemCache,
    SystemVaTypeSystemPtes,
    SystemVaTypeSessionSpace,
    SystemVaTypeMax
} SYSTEM_VA_TYPE, * PSYSTEM_VA_TYPE;

// private
typedef struct _SYSTEM_VA_LIST_INFORMATION
{
    SIZE_T VirtualSize;
    SIZE_T VirtualPeak;
    SIZE_T VirtualLimit;
    SIZE_T AllocationFailures;
} SYSTEM_VA_LIST_INFORMATION, * PSYSTEM_VA_LIST_INFORMATION;

// rev
typedef enum _STORE_INFORMATION_CLASS
{
    StorePageRequest = 1,
    StoreStatsRequest = 2, // (requires SeProfileSingleProcessPrivilege) // SmProcessStatsRequest
    StoreCreateRequest = 3,
    StoreDeleteRequest = 4,
    StoreListRequest = 5, // SmProcessListRequest
    Available1 = 6,
    StoreEmptyRequest = 7,
    CacheListRequest = 8, // SmcProcessListRequest
    CacheCreateRequest = 9,
    CacheDeleteRequest = 10,
    CacheStoreCreateRequest = 11,
    CacheStoreDeleteRequest = 12,
    CacheStatsRequest = 13, // SmcProcessStatsRequest
    Available2 = 14,
    RegistrationRequest = 15, // SmProcessRegistrationRequest
    GlobalCacheStatsRequest = 16,
    StoreResizeRequest = 17,
    CacheStoreResizeRequest = 18,
    SmConfigRequest = 19,
    StoreHighMemoryPriorityRequest = 20, // SM_STORE_HIGH_MEM_PRIORITY_REQUEST
    SystemStoreTrimRequest = 21, // SM_SYSTEM_STORE_TRIM_REQUEST
    MemCompressionInfoRequest = 22,  // q: SM_MEM_COMPRESSION_INFO_REQUEST // SmProcessCompressionInfoRequest
    ProcessStoreInfoRequest = 23, // SmProcessProcessStoreInfoRequest
    StoreInformationMax
} STORE_INFORMATION_CLASS;

// rev
#define SYSTEM_STORE_INFORMATION_VERSION 1

// rev
typedef struct _STORE_INFORMATION
{
    _In_ ULONG Version;
    _In_ STORE_INFORMATION_CLASS StoreInformationClass;
    _Inout_ PVOID Data;
    _Inout_ ULONG Length;
} STORE_INFORMATION, * PSTORE_INFORMATION;

// rev
typedef struct _SM_STORE_HIGH_MEM_PRIORITY_REQUEST
{
    ULONG Version : 8;
    ULONG SetHighMemoryPriority : 1;
    ULONG Spare : 23;
    HANDLE ProcessHandle;
} SM_STORE_HIGH_MEM_PRIORITY_REQUEST, * PSM_STORE_HIGH_MEM_PRIORITY_REQUEST;

// rev
typedef struct _SM_SYSTEM_STORE_TRIM_REQUEST
{
    ULONG Version : 8;
    ULONG Spare : 24;
    SIZE_T PagesToTrim; // ULONG?
} SM_SYSTEM_STORE_TRIM_REQUEST, * PSM_SYSTEM_STORE_TRIM_REQUEST;

// rev
#define SYSTEM_STORE_COMPRESSION_INFORMATION_VERSION 3

// rev
typedef struct _SM_MEM_COMPRESSION_INFO_REQUEST
{
    ULONG Version : 8;
    ULONG Spare : 24;
    ULONG CompressionPid;
    ULONG WorkingSetSize; // ULONGLONG?
    ULONGLONG TotalDataCompressed;
    ULONGLONG TotalCompressedSize;
    ULONGLONG TotalUniqueDataCompressed;
} SM_MEM_COMPRESSION_INFO_REQUEST, * PSM_MEM_COMPRESSION_INFO_REQUEST;

// private
typedef struct _SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS
{
    HANDLE KeyHandle;
    PUNICODE_STRING ValueNamePointer;
    PULONG RequiredLengthPointer;
    PUCHAR Buffer;
    ULONG BufferLength;
    ULONG Type;
    PUCHAR AppendBuffer;
    ULONG AppendBufferLength;
    bool CreateIfDoesntExist;
    bool TruncateExistingValue;
} SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS, * PSYSTEM_REGISTRY_APPEND_STRING_PARAMETERS;

// msdn
typedef struct _SYSTEM_VHD_BOOT_INFORMATION
{
    bool OsDiskIsVhd;
    ULONG OsVhdFilePathOffset;
    WCHAR OsVhdParentVolume[ANYSIZE_ARRAY];
} SYSTEM_VHD_BOOT_INFORMATION, * PSYSTEM_VHD_BOOT_INFORMATION;

// private
typedef struct _PS_CPU_QUOTA_QUERY_ENTRY
{
    ULONG SessionId;
    ULONG Weight;
} PS_CPU_QUOTA_QUERY_ENTRY, * PPS_CPU_QUOTA_QUERY_ENTRY;

// private
typedef struct _PS_CPU_QUOTA_QUERY_INFORMATION
{
    ULONG SessionCount;
    PS_CPU_QUOTA_QUERY_ENTRY SessionInformation[1];
} PS_CPU_QUOTA_QUERY_INFORMATION, * PPS_CPU_QUOTA_QUERY_INFORMATION;

// private
typedef struct _SYSTEM_ERROR_PORT_TIMEOUTS
{
    ULONG StartTimeout;
    ULONG CommTimeout;
} SYSTEM_ERROR_PORT_TIMEOUTS, * PSYSTEM_ERROR_PORT_TIMEOUTS;

// private
typedef struct _SYSTEM_LOW_PRIORITY_IO_INFORMATION
{
    ULONG LowPriReadOperations;
    ULONG LowPriWriteOperations;
    ULONG KernelBumpedToNormalOperations;
    ULONG LowPriPagingReadOperations;
    ULONG KernelPagingReadsBumpedToNormal;
    ULONG LowPriPagingWriteOperations;
    ULONG KernelPagingWritesBumpedToNormal;
    ULONG BoostedIrpCount;
    ULONG BoostedPagingIrpCount;
    ULONG BlanketBoostCount;
} SYSTEM_LOW_PRIORITY_IO_INFORMATION, * PSYSTEM_LOW_PRIORITY_IO_INFORMATION;

// symbols
typedef enum _TPM_BOOT_ENTROPY_RESULT_CODE
{
    TpmBootEntropyStructureUninitialized,
    TpmBootEntropyDisabledByPolicy,
    TpmBootEntropyNoTpmFound,
    TpmBootEntropyTpmError,
    TpmBootEntropySuccess
} TPM_BOOT_ENTROPY_RESULT_CODE;

// Contents of KeLoaderBlock->Extension->TpmBootEntropyResult (TPM_BOOT_ENTROPY_LDR_RESULT).
// EntropyData is truncated to 40 bytes.

// private
typedef struct _TPM_BOOT_ENTROPY_NT_RESULT
{
    ULONGLONG Policy;
    TPM_BOOT_ENTROPY_RESULT_CODE ResultCode;
    NTSTATUS ResultStatus;
    ULONGLONG Time;
    ULONG EntropyLength;
    UCHAR EntropyData[40];
} TPM_BOOT_ENTROPY_NT_RESULT, * PTPM_BOOT_ENTROPY_NT_RESULT;

// private
typedef struct _SYSTEM_VERIFIER_COUNTERS_INFORMATION
{
    SYSTEM_VERIFIER_INFORMATION Legacy;
    ULONG RaiseIrqls;
    ULONG AcquireSpinLocks;
    ULONG SynchronizeExecutions;
    ULONG AllocationsWithNoTag;
    ULONG AllocationsFailed;
    ULONG AllocationsFailedDeliberately;
    SIZE_T LockedBytes;
    SIZE_T PeakLockedBytes;
    SIZE_T MappedLockedBytes;
    SIZE_T PeakMappedLockedBytes;
    SIZE_T MappedIoSpaceBytes;
    SIZE_T PeakMappedIoSpaceBytes;
    SIZE_T PagesForMdlBytes;
    SIZE_T PeakPagesForMdlBytes;
    SIZE_T ContiguousMemoryBytes;
    SIZE_T PeakContiguousMemoryBytes;
    ULONG ExecutePoolTypes; // REDSTONE2
    ULONG ExecutePageProtections;
    ULONG ExecutePageMappings;
    ULONG ExecuteWriteSections;
    ULONG SectionAlignmentFailures;
    ULONG UnsupportedRelocs;
    ULONG IATInExecutableSection;
} SYSTEM_VERIFIER_COUNTERS_INFORMATION, * PSYSTEM_VERIFIER_COUNTERS_INFORMATION;

// private
typedef struct _SYSTEM_ACPI_AUDIT_INFORMATION
{
    ULONG RsdpCount;
    ULONG SameRsdt : 1;
    ULONG SlicPresent : 1;
    ULONG SlicDifferent : 1;
} SYSTEM_ACPI_AUDIT_INFORMATION, * PSYSTEM_ACPI_AUDIT_INFORMATION;

// private
typedef struct _SYSTEM_BASIC_PERFORMANCE_INFORMATION
{
    SIZE_T AvailablePages;
    SIZE_T CommittedPages;
    SIZE_T CommitLimit;
    SIZE_T PeakCommitment;
} SYSTEM_BASIC_PERFORMANCE_INFORMATION, * PSYSTEM_BASIC_PERFORMANCE_INFORMATION;

// begin_msdn

typedef struct _QUERY_PERFORMANCE_COUNTER_FLAGS
{
    union
    {
        struct
        {
            ULONG KernelTransition : 1;
            ULONG Reserved : 31;
        };
        ULONG ul;
    };
} QUERY_PERFORMANCE_COUNTER_FLAGS;

typedef struct _SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION
{
    ULONG Version;
    QUERY_PERFORMANCE_COUNTER_FLAGS Flags;
    QUERY_PERFORMANCE_COUNTER_FLAGS ValidFlags;
} SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION, * PSYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION;

// end_msdn

// private
typedef enum _SYSTEM_PIXEL_FORMAT
{
    SystemPixelFormatUnknown,
    SystemPixelFormatR8G8B8,
    SystemPixelFormatR8G8B8X8,
    SystemPixelFormatB8G8R8,
    SystemPixelFormatB8G8R8X8
} SYSTEM_PIXEL_FORMAT;

// private
typedef struct _SYSTEM_BOOT_GRAPHICS_INFORMATION
{
    LARGE_INTEGER FrameBuffer;
    ULONG Width;
    ULONG Height;
    ULONG PixelStride;
    ULONG Flags;
    SYSTEM_PIXEL_FORMAT Format;
    ULONG DisplayRotation;
} SYSTEM_BOOT_GRAPHICS_INFORMATION, * PSYSTEM_BOOT_GRAPHICS_INFORMATION;

// private
typedef struct _MEMORY_SCRUB_INFORMATION
{
    HANDLE Handle;
    ULONG PagesScrubbed;
} MEMORY_SCRUB_INFORMATION, * PMEMORY_SCRUB_INFORMATION;

// private
typedef struct _PEBS_DS_SAVE_AREA32
{
    ULONG BtsBufferBase;
    ULONG BtsIndex;
    ULONG BtsAbsoluteMaximum;
    ULONG BtsInterruptThreshold;
    ULONG PebsBufferBase;
    ULONG PebsIndex;
    ULONG PebsAbsoluteMaximum;
    ULONG PebsInterruptThreshold;
    ULONG PebsGpCounterReset[8];
    ULONG PebsFixedCounterReset[4];
} PEBS_DS_SAVE_AREA32, * PPEBS_DS_SAVE_AREA32;

// private
typedef struct _PEBS_DS_SAVE_AREA64
{
    ULONGLONG BtsBufferBase;
    ULONGLONG BtsIndex;
    ULONGLONG BtsAbsoluteMaximum;
    ULONGLONG BtsInterruptThreshold;
    ULONGLONG PebsBufferBase;
    ULONGLONG PebsIndex;
    ULONGLONG PebsAbsoluteMaximum;
    ULONGLONG PebsInterruptThreshold;
    ULONGLONG PebsGpCounterReset[8];
    ULONGLONG PebsFixedCounterReset[4];
} PEBS_DS_SAVE_AREA64, * PPEBS_DS_SAVE_AREA64;

// private
typedef union _PEBS_DS_SAVE_AREA
{
    PEBS_DS_SAVE_AREA32 As32Bit;
    PEBS_DS_SAVE_AREA64 As64Bit;
} PEBS_DS_SAVE_AREA, * PPEBS_DS_SAVE_AREA;

// private
typedef struct _PROCESSOR_PROFILE_CONTROL_AREA
{
    PEBS_DS_SAVE_AREA PebsDsSaveArea;
} PROCESSOR_PROFILE_CONTROL_AREA, * PPROCESSOR_PROFILE_CONTROL_AREA;

// private
typedef struct _SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
{
    PROCESSOR_PROFILE_CONTROL_AREA ProcessorProfileControlArea;
    bool Allocate;
} SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA, * PSYSTEM_PROCESSOR_PROFILE_CONTROL_AREA;

// private
typedef struct _MEMORY_COMBINE_INFORMATION
{
    HANDLE Handle;
    ULONG_PTR PagesCombined;
} MEMORY_COMBINE_INFORMATION, * PMEMORY_COMBINE_INFORMATION;

// rev
#define MEMORY_COMBINE_FLAGS_COMMON_PAGES_ONLY 0x4

// private
typedef struct _MEMORY_COMBINE_INFORMATION_EX
{
    HANDLE Handle;
    ULONG_PTR PagesCombined;
    ULONG Flags;
} MEMORY_COMBINE_INFORMATION_EX, * PMEMORY_COMBINE_INFORMATION_EX;

// private
typedef struct _MEMORY_COMBINE_INFORMATION_EX2
{
    HANDLE Handle;
    ULONG_PTR PagesCombined;
    ULONG Flags;
    HANDLE ProcessHandle;
} MEMORY_COMBINE_INFORMATION_EX2, * PMEMORY_COMBINE_INFORMATION_EX2;

// private
typedef struct _SYSTEM_ENTROPY_TIMING_INFORMATION
{
    VOID(NTAPI* EntropyRoutine)(PVOID, ULONG);
    VOID(NTAPI* InitializationRoutine)(PVOID, ULONG, PVOID);
    PVOID InitializationContext;
} SYSTEM_ENTROPY_TIMING_INFORMATION, * PSYSTEM_ENTROPY_TIMING_INFORMATION;

// private
typedef struct _SYSTEM_CONSOLE_INFORMATION
{
    ULONG DriverLoaded : 1;
    ULONG Spare : 31;
} SYSTEM_CONSOLE_INFORMATION, * PSYSTEM_CONSOLE_INFORMATION;

// private
typedef struct _SYSTEM_PLATFORM_BINARY_INFORMATION
{
    ULONG64 PhysicalAddress;
    PVOID HandoffBuffer;
    PVOID CommandLineBuffer;
    ULONG HandoffBufferSize;
    ULONG CommandLineBufferSize;
} SYSTEM_PLATFORM_BINARY_INFORMATION, * PSYSTEM_PLATFORM_BINARY_INFORMATION;

// private
typedef struct _SYSTEM_POLICY_INFORMATION
{
    PVOID InputData;
    PVOID OutputData;
    ULONG InputDataSize;
    ULONG OutputDataSize;
    ULONG Version;
} SYSTEM_POLICY_INFORMATION, * PSYSTEM_POLICY_INFORMATION;

// private
typedef struct _SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
{
    ULONG NumberOfLogicalProcessors;
    ULONG NumberOfCores;
} SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION, * PSYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION;

// private
typedef struct _SYSTEM_DEVICE_DATA_INFORMATION
{
    UNICODE_STRING DeviceId;
    UNICODE_STRING DataName;
    ULONG DataType;
    ULONG DataBufferLength;
    PVOID DataBuffer;
} SYSTEM_DEVICE_DATA_INFORMATION, * PSYSTEM_DEVICE_DATA_INFORMATION;

// private
typedef struct _PHYSICAL_CHANNEL_RUN
{
    ULONG NodeNumber;
    ULONG ChannelNumber;
    ULONGLONG BasePage;
    ULONGLONG PageCount;
    ULONG Flags;
} PHYSICAL_CHANNEL_RUN, * PPHYSICAL_CHANNEL_RUN;

// private
typedef struct _SYSTEM_MEMORY_TOPOLOGY_INFORMATION
{
    ULONGLONG NumberOfRuns;
    ULONG NumberOfNodes;
    ULONG NumberOfChannels;
    PHYSICAL_CHANNEL_RUN Run[1];
} SYSTEM_MEMORY_TOPOLOGY_INFORMATION, * PSYSTEM_MEMORY_TOPOLOGY_INFORMATION;

// private
typedef struct _SYSTEM_MEMORY_CHANNEL_INFORMATION
{
    ULONG ChannelNumber;
    ULONG ChannelHeatIndex;
    ULONGLONG TotalPageCount;
    ULONGLONG ZeroPageCount;
    ULONGLONG FreePageCount;
    ULONGLONG StandbyPageCount;
} SYSTEM_MEMORY_CHANNEL_INFORMATION, * PSYSTEM_MEMORY_CHANNEL_INFORMATION;

// private
typedef struct _SYSTEM_BOOT_LOGO_INFORMATION
{
    ULONG Flags;
    ULONG BitmapOffset;
} SYSTEM_BOOT_LOGO_INFORMATION, * PSYSTEM_BOOT_LOGO_INFORMATION;

// private
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
    ULONG Spare0;
    LARGE_INTEGER AvailableTime;
    LARGE_INTEGER Spare1;
    LARGE_INTEGER Spare2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX, * PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX;

// private
typedef struct _SYSTEM_SECUREBOOT_POLICY_INFORMATION
{
    GUID PolicyPublisher;
    ULONG PolicyVersion;
    ULONG PolicyOptions;
} SYSTEM_SECUREBOOT_POLICY_INFORMATION, * PSYSTEM_SECUREBOOT_POLICY_INFORMATION;

// private
typedef struct _SYSTEM_PAGEFILE_INFORMATION_EX
{
    union // HACK union declaration for convenience (dmex)
    {
        SYSTEM_PAGEFILE_INFORMATION Info;
        struct
        {
            ULONG NextEntryOffset;
            ULONG TotalSize;
            ULONG TotalInUse;
            ULONG PeakUsage;
            UNICODE_STRING PageFileName;
        };
    };

    ULONG MinimumSize;
    ULONG MaximumSize;
} SYSTEM_PAGEFILE_INFORMATION_EX, * PSYSTEM_PAGEFILE_INFORMATION_EX;

// private
typedef struct _SYSTEM_SECUREBOOT_INFORMATION
{
    bool SecureBootEnabled;
    bool SecureBootCapable;
} SYSTEM_SECUREBOOT_INFORMATION, * PSYSTEM_SECUREBOOT_INFORMATION;

// private
typedef struct _PROCESS_DISK_COUNTERS
{
    ULONGLONG BytesRead;
    ULONGLONG BytesWritten;
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG FlushOperationCount;
} PROCESS_DISK_COUNTERS, * PPROCESS_DISK_COUNTERS;

// private
typedef union _ENERGY_STATE_DURATION
{
    ULONGLONG Value;
    struct
    {
        ULONG LastChangeTime;
        ULONG Duration : 31;
        ULONG IsInState : 1;
    };
} ENERGY_STATE_DURATION, * PENERGY_STATE_DURATION;

typedef struct _PROCESS_ENERGY_VALUES
{
    ULONGLONG Cycles[4][2];
    ULONGLONG DiskEnergy;
    ULONGLONG NetworkTailEnergy;
    ULONGLONG MBBTailEnergy;
    ULONGLONG NetworkTxRxBytes;
    ULONGLONG MBBTxRxBytes;
    union
    {
        ENERGY_STATE_DURATION Durations[3];
        struct
        {
            ENERGY_STATE_DURATION ForegroundDuration;
            ENERGY_STATE_DURATION DesktopVisibleDuration;
            ENERGY_STATE_DURATION PSMForegroundDuration;
        };
    };
    ULONG CompositionRendered;
    ULONG CompositionDirtyGenerated;
    ULONG CompositionDirtyPropagated;
    ULONG Reserved1;
    ULONGLONG AttributedCycles[4][2];
    ULONGLONG WorkOnBehalfCycles[4][2];
} PROCESS_ENERGY_VALUES, * PPROCESS_ENERGY_VALUES;

typedef union _TIMELINE_BITMAP
{
    ULONGLONG Value;
    struct
    {
        ULONG EndTime;
        ULONG Bitmap;
    };
} TIMELINE_BITMAP, * PTIMELINE_BITMAP;

typedef struct _PROCESS_ENERGY_VALUES_EXTENSION
{
    union
    {
        TIMELINE_BITMAP Timelines[14]; // 9 for REDSTONE2, 14 for REDSTONE3/4/5
        struct
        {
            TIMELINE_BITMAP CpuTimeline;
            TIMELINE_BITMAP DiskTimeline;
            TIMELINE_BITMAP NetworkTimeline;
            TIMELINE_BITMAP MBBTimeline;
            TIMELINE_BITMAP ForegroundTimeline;
            TIMELINE_BITMAP DesktopVisibleTimeline;
            TIMELINE_BITMAP CompositionRenderedTimeline;
            TIMELINE_BITMAP CompositionDirtyGeneratedTimeline;
            TIMELINE_BITMAP CompositionDirtyPropagatedTimeline;
            TIMELINE_BITMAP InputTimeline; // REDSTONE3
            TIMELINE_BITMAP AudioInTimeline;
            TIMELINE_BITMAP AudioOutTimeline;
            TIMELINE_BITMAP DisplayRequiredTimeline;
            TIMELINE_BITMAP KeyboardInputTimeline;
        };
    };

    union // REDSTONE3
    {
        ENERGY_STATE_DURATION Durations[5];
        struct
        {
            ENERGY_STATE_DURATION InputDuration;
            ENERGY_STATE_DURATION AudioInDuration;
            ENERGY_STATE_DURATION AudioOutDuration;
            ENERGY_STATE_DURATION DisplayRequiredDuration;
            ENERGY_STATE_DURATION PSMBackgroundDuration;
        };
    };

    ULONG KeyboardInput;
    ULONG MouseInput;
} PROCESS_ENERGY_VALUES_EXTENSION, * PPROCESS_ENERGY_VALUES_EXTENSION;

typedef struct _PROCESS_EXTENDED_ENERGY_VALUES
{
    PROCESS_ENERGY_VALUES Base;
    PROCESS_ENERGY_VALUES_EXTENSION Extension;
} PROCESS_EXTENDED_ENERGY_VALUES, * PPROCESS_EXTENDED_ENERGY_VALUES;

// private
typedef enum _SYSTEM_PROCESS_CLASSIFICATION
{
    SystemProcessClassificationNormal,
    SystemProcessClassificationSystem,
    SystemProcessClassificationSecureSystem,
    SystemProcessClassificationMemCompression,
    SystemProcessClassificationRegistry, // REDSTONE4
    SystemProcessClassificationMaximum
} SYSTEM_PROCESS_CLASSIFICATION;

// private
typedef struct _SYSTEM_PROCESS_INFORMATION_EXTENSION
{
    PROCESS_DISK_COUNTERS DiskCounters;
    ULONGLONG ContextSwitches;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG HasStrongId : 1;
            ULONG Classification : 4; // SYSTEM_PROCESS_CLASSIFICATION
            ULONG BackgroundActivityModerated : 1;
            ULONG Spare : 26;
        };
    };
    ULONG UserSidOffset;
    ULONG PackageFullNameOffset; // since THRESHOLD
    PROCESS_ENERGY_VALUES EnergyValues; // since THRESHOLD
    ULONG AppIdOffset; // since THRESHOLD
    SIZE_T SharedCommitCharge; // since THRESHOLD2
    ULONG JobObjectId; // since REDSTONE
    ULONG SpareUlong; // since REDSTONE
    ULONGLONG ProcessSequenceNumber;
} SYSTEM_PROCESS_INFORMATION_EXTENSION, * PSYSTEM_PROCESS_INFORMATION_EXTENSION;

// private
typedef struct _SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
{
    bool EfiLauncherEnabled;
} SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION, * PSYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION;

// private
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
{
    bool DebuggerAllowed;
    bool DebuggerEnabled;
    bool DebuggerPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

// private
typedef struct _SYSTEM_ELAM_CERTIFICATE_INFORMATION
{
    HANDLE ElamDriverFile;
} SYSTEM_ELAM_CERTIFICATE_INFORMATION, * PSYSTEM_ELAM_CERTIFICATE_INFORMATION;

// private
typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
{
    ULONG Version;
    ULONG AbnormalResetOccurred;
    ULONG OfflineMemoryDumpCapable;
    LARGE_INTEGER ResetDataAddress;
    ULONG ResetDataSize;
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2, * POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2;

// private
typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1
{
    ULONG Version;
    ULONG AbnormalResetOccurred;
    ULONG OfflineMemoryDumpCapable;
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1, * POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1;

// private
typedef struct _SYSTEM_PROCESSOR_FEATURES_INFORMATION
{
    ULONGLONG ProcessorFeatureBits;
    ULONGLONG Reserved[3];
} SYSTEM_PROCESSOR_FEATURES_INFORMATION, * PSYSTEM_PROCESSOR_FEATURES_INFORMATION;

// EDID v1.4 standard data format
typedef struct _SYSTEM_EDID_INFORMATION
{
    UCHAR Edid[128];
} SYSTEM_EDID_INFORMATION, * PSYSTEM_EDID_INFORMATION;

// private
typedef struct _SYSTEM_MANUFACTURING_INFORMATION
{
    ULONG Options;
    UNICODE_STRING ProfileName;
} SYSTEM_MANUFACTURING_INFORMATION, * PSYSTEM_MANUFACTURING_INFORMATION;

// private
typedef struct _SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
{
    bool Enabled;
} SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION, * PSYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION;

// private
typedef struct _HV_DETAILS
{
    ULONG Data[4];
} HV_DETAILS, * PHV_DETAILS;

// private
typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION
{
    HV_DETAILS HvVendorAndMaxFunction;
    HV_DETAILS HypervisorInterface;
    HV_DETAILS HypervisorVersion;
    HV_DETAILS HvFeatures;
    HV_DETAILS HwFeatures;
    HV_DETAILS EnlightenmentInfo;
    HV_DETAILS ImplementationLimits;
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION, * PSYSTEM_HYPERVISOR_DETAIL_INFORMATION;

// private
typedef struct _SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION
{
    ULONGLONG Cycles[2][4];
} SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION, * PSYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION;

// private
typedef struct _SYSTEM_TPM_INFORMATION
{
    ULONG Flags;
} SYSTEM_TPM_INFORMATION, * PSYSTEM_TPM_INFORMATION;

// private
typedef struct _SYSTEM_VSM_PROTECTION_INFORMATION
{
    bool DmaProtectionsAvailable;
    bool DmaProtectionsInUse;
    bool HardwareMbecAvailable; // REDSTONE4 (CVE-2018-3639)
    bool ApicVirtualizationAvailable; // 20H1
} SYSTEM_VSM_PROTECTION_INFORMATION, * PSYSTEM_VSM_PROTECTION_INFORMATION;

// private
typedef struct _SYSTEM_KERNEL_DEBUGGER_FLAGS
{
    bool KernelDebuggerIgnoreUmExceptions;
} SYSTEM_KERNEL_DEBUGGER_FLAGS, * PSYSTEM_KERNEL_DEBUGGER_FLAGS;

// private
typedef struct _SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
{
    ULONG Options;
    ULONG HVCIOptions;
    ULONGLONG Version;
    GUID PolicyGuid;
} SYSTEM_CODEINTEGRITYPOLICY_INFORMATION, * PSYSTEM_CODEINTEGRITYPOLICY_INFORMATION;

// private
typedef struct _SYSTEM_ISOLATED_USER_MODE_INFORMATION
{
    bool SecureKernelRunning : 1;
    bool HvciEnabled : 1;
    bool HvciStrictMode : 1;
    bool DebugEnabled : 1;
    bool FirmwarePageProtection : 1;
    bool EncryptionKeyAvailable : 1;
    bool SpareFlags : 2;
    bool TrustletRunning : 1;
    bool HvciDisableAllowed : 1;
    bool SpareFlags2 : 6;
    bool Spare0[6];
    ULONGLONG Spare1;
} SYSTEM_ISOLATED_USER_MODE_INFORMATION, * PSYSTEM_ISOLATED_USER_MODE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
    USHORT NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageChecksum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

// private
typedef struct _SYSTEM_SINGLE_MODULE_INFORMATION
{
    PVOID TargetModuleAddress;
    RTL_PROCESS_MODULE_INFORMATION_EX ExInfo;
} SYSTEM_SINGLE_MODULE_INFORMATION, * PSYSTEM_SINGLE_MODULE_INFORMATION;

// private
typedef struct _SYSTEM_INTERRUPT_CPU_SET_INFORMATION
{
    ULONG Gsiv;
    USHORT Group;
    ULONGLONG CpuSets;
} SYSTEM_INTERRUPT_CPU_SET_INFORMATION, * PSYSTEM_INTERRUPT_CPU_SET_INFORMATION;

// private
typedef struct _SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
{
    SYSTEM_SECUREBOOT_POLICY_INFORMATION PolicyInformation;
    ULONG PolicySize;
    UCHAR Policy[1];
} SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION, * PSYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION;

// private
typedef struct _SYSTEM_ROOT_SILO_INFORMATION
{
    ULONG NumberOfSilos;
    ULONG SiloIdList[1];
} SYSTEM_ROOT_SILO_INFORMATION, * PSYSTEM_ROOT_SILO_INFORMATION;

// private
typedef struct _SYSTEM_CPU_SET_TAG_INFORMATION
{
    ULONGLONG Tag;
    ULONGLONG CpuSets[1];
} SYSTEM_CPU_SET_TAG_INFORMATION, * PSYSTEM_CPU_SET_TAG_INFORMATION;

// private
typedef struct _SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
{
    ULONG ExtentCount;
    ULONG ValidStructureSize;
    ULONG NextExtentIndex;
    ULONG ExtentRestart;
    ULONG CycleCount;
    ULONG TimeoutCount;
    ULONGLONG CycleTime;
    ULONGLONG CycleTimeMax;
    ULONGLONG ExtentTime;
    ULONG ExtentTimeIndex;
    ULONG ExtentTimeMaxIndex;
    ULONGLONG ExtentTimeMax;
    ULONGLONG HyperFlushTimeMax;
    ULONGLONG TranslateVaTimeMax;
    ULONGLONG DebugExemptionCount;
    ULONGLONG TbHitCount;
    ULONGLONG TbMissCount;
    ULONGLONG VinaPendingYield;
    ULONGLONG HashCycles;
    ULONG HistogramOffset;
    ULONG HistogramBuckets;
    ULONG HistogramShift;
    ULONG Reserved1;
    ULONGLONG PageNotPresentCount;
} SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION, * PSYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION;

// private
typedef struct _SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION
{
    ULONG PlatformManifestSize;
    UCHAR PlatformManifest[1];
} SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION, * PSYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION;

// private
typedef struct _SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT
{
    ULONG Gsiv;
    UCHAR ControllerInterrupt;
    UCHAR EdgeInterrupt;
    UCHAR IsPrimaryInterrupt;
    GROUP_AFFINITY TargetAffinity;
} SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, * PSYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT;

typedef union _SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT
{
    ULONG AsULONG;
    struct
    {
        ULONG Enabled : 1;
        ULONG Reserved : 31;
    };
} SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT, * PSYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT;

#if !defined(NTDDI_WIN10_CO) || (NTDDI_VERSION < NTDDI_WIN10_CO)
// private
typedef struct _SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION
{
    ULONG Machine : 16;
    ULONG KernelMode : 1;
    ULONG UserMode : 1;
    ULONG Native : 1;
    ULONG Process : 1;
    ULONG WoW64Container : 1;
    ULONG ReservedZero0 : 11;
} SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION;
#endif

// private
typedef struct _SYSTEM_MEMORY_USAGE_INFORMATION
{
    ULONGLONG TotalPhysicalBytes;
    ULONGLONG AvailableBytes;
    LONGLONG ResidentAvailableBytes;
    ULONGLONG CommittedBytes;
    ULONGLONG SharedCommittedBytes;
    ULONGLONG CommitLimitBytes;
    ULONGLONG PeakCommitmentBytes;
} SYSTEM_MEMORY_USAGE_INFORMATION, * PSYSTEM_MEMORY_USAGE_INFORMATION;

// private
typedef struct _SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
{
    HANDLE ImageFile;
    ULONG Type; // REDSTONE4
} SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION, * PSYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION;

// private
typedef struct _SYSTEM_PHYSICAL_MEMORY_INFORMATION
{
    ULONGLONG TotalPhysicalBytes;
    ULONGLONG LowestPhysicalAddress;
    ULONGLONG HighestPhysicalAddress;
} SYSTEM_PHYSICAL_MEMORY_INFORMATION, * PSYSTEM_PHYSICAL_MEMORY_INFORMATION;

// private
typedef enum _SYSTEM_ACTIVITY_MODERATION_STATE
{
    SystemActivityModerationStateSystemManaged,
    SystemActivityModerationStateUserManagedAllowThrottling,
    SystemActivityModerationStateUserManagedDisableThrottling,
    MaxSystemActivityModerationState
} SYSTEM_ACTIVITY_MODERATION_STATE;

// private - REDSTONE2
typedef struct _SYSTEM_ACTIVITY_MODERATION_EXE_STATE // REDSTONE3: Renamed SYSTEM_ACTIVITY_MODERATION_INFO
{
    UNICODE_STRING ExePathNt;
    SYSTEM_ACTIVITY_MODERATION_STATE ModerationState;
} SYSTEM_ACTIVITY_MODERATION_EXE_STATE, * PSYSTEM_ACTIVITY_MODERATION_EXE_STATE;

typedef enum _SYSTEM_ACTIVITY_MODERATION_APP_TYPE
{
    SystemActivityModerationAppTypeClassic,
    SystemActivityModerationAppTypePackaged,
    MaxSystemActivityModerationAppType
} SYSTEM_ACTIVITY_MODERATION_APP_TYPE;

// private - REDSTONE3
typedef struct _SYSTEM_ACTIVITY_MODERATION_INFO
{
    UNICODE_STRING Identifier;
    SYSTEM_ACTIVITY_MODERATION_STATE ModerationState;
    SYSTEM_ACTIVITY_MODERATION_APP_TYPE AppType;
} SYSTEM_ACTIVITY_MODERATION_INFO, * PSYSTEM_ACTIVITY_MODERATION_INFO;

// private
typedef struct _SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
{
    HANDLE UserKeyHandle;
} SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS, * PSYSTEM_ACTIVITY_MODERATION_USER_SETTINGS;

// private
typedef struct _SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG Locked : 1;
            ULONG UnlockApplied : 1; // Unlockable field removed 19H1
            ULONG UnlockIdValid : 1;
            ULONG Reserved : 29;
        };
    };
    UCHAR UnlockId[32]; // REDSTONE4
} SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION, * PSYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION;

// private
typedef struct _SYSTEM_FLUSH_INFORMATION
{
    ULONG SupportedFlushMethods;
    ULONG ProcessorCacheFlushSize;
    ULONGLONG SystemFlushCapabilities;
    ULONGLONG Reserved[2];
} SYSTEM_FLUSH_INFORMATION, * PSYSTEM_FLUSH_INFORMATION;

// private
typedef struct _SYSTEM_WRITE_CONSTRAINT_INFORMATION
{
    ULONG WriteConstraintPolicy;
    ULONG Reserved;
} SYSTEM_WRITE_CONSTRAINT_INFORMATION, * PSYSTEM_WRITE_CONSTRAINT_INFORMATION;

// private
typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION
{
    union
    {
        ULONG KvaShadowFlags;
        struct
        {
            ULONG KvaShadowEnabled : 1;
            ULONG KvaShadowUserGlobal : 1;
            ULONG KvaShadowPcid : 1;
            ULONG KvaShadowInvpcid : 1;
            ULONG KvaShadowRequired : 1; // REDSTONE4
            ULONG KvaShadowRequiredAvailable : 1;
            ULONG InvalidPteBit : 6;
            ULONG L1DataCacheFlushSupported : 1;
            ULONG L1TerminalFaultMitigationPresent : 1;
            ULONG Reserved : 18;
        };
    };
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, * PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

// private
typedef struct _SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
{
    HANDLE FileHandle;
    ULONG ImageSize;
    PVOID Image;
} SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION, * PSYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION;

// private
typedef struct _SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION
{
    PVOID HypervisorSharedUserVa;
} SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION, * PSYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION;

// private
typedef struct _SYSTEM_FIRMWARE_PARTITION_INFORMATION
{
    UNICODE_STRING FirmwarePartition;
} SYSTEM_FIRMWARE_PARTITION_INFORMATION, * PSYSTEM_FIRMWARE_PARTITION_INFORMATION;

// private
typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG BpbEnabled : 1;
            ULONG BpbDisabledSystemPolicy : 1;
            ULONG BpbDisabledNoHardwareSupport : 1;
            ULONG SpecCtrlEnumerated : 1;
            ULONG SpecCmdEnumerated : 1;
            ULONG IbrsPresent : 1;
            ULONG StibpPresent : 1;
            ULONG SmepPresent : 1;
            ULONG SpeculativeStoreBypassDisableAvailable : 1; // REDSTONE4 (CVE-2018-3639)
            ULONG SpeculativeStoreBypassDisableSupported : 1;
            ULONG SpeculativeStoreBypassDisabledSystemWide : 1;
            ULONG SpeculativeStoreBypassDisabledKernel : 1;
            ULONG SpeculativeStoreBypassDisableRequired : 1;
            ULONG BpbDisabledKernelToUser : 1;
            ULONG SpecCtrlRetpolineEnabled : 1;
            ULONG SpecCtrlImportOptimizationEnabled : 1;
            ULONG EnhancedIbrs : 1; // since 19H1
            ULONG HvL1tfStatusAvailable : 1;
            ULONG HvL1tfProcessorNotAffected : 1;
            ULONG HvL1tfMigitationEnabled : 1;
            ULONG HvL1tfMigitationNotEnabled_Hardware : 1;
            ULONG HvL1tfMigitationNotEnabled_LoadOption : 1;
            ULONG HvL1tfMigitationNotEnabled_CoreScheduler : 1;
            ULONG EnhancedIbrsReported : 1;
            ULONG MdsHardwareProtected : 1; // since 19H2
            ULONG MbClearEnabled : 1;
            ULONG MbClearReported : 1;
            ULONG Reserved : 5;
        };
    };
} SYSTEM_SPECULATION_CONTROL_INFORMATION, * PSYSTEM_SPECULATION_CONTROL_INFORMATION;

// private
typedef struct _SYSTEM_DMA_GUARD_POLICY_INFORMATION
{
    bool DmaGuardPolicyEnabled;
} SYSTEM_DMA_GUARD_POLICY_INFORMATION, * PSYSTEM_DMA_GUARD_POLICY_INFORMATION;

// private
typedef struct _SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
{
    UCHAR EnclaveLaunchSigner[32];
} SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION, * PSYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION;

// private
typedef struct _SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
{
    ULONGLONG WorkloadClass;
    ULONGLONG CpuSets[1];
} SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION, * PSYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION;

// private
typedef struct _SYSTEM_SECURITY_MODEL_INFORMATION
{
    union
    {
        ULONG SecurityModelFlags;
        struct
        {
            ULONG SModeAdminlessEnabled : 1;
            ULONG AllowDeviceOwnerProtectionDowngrade : 1;
            ULONG Reserved : 30;
        };
    };
} SYSTEM_SECURITY_MODEL_INFORMATION, * PSYSTEM_SECURITY_MODEL_INFORMATION;

// private
typedef struct _SYSTEM_FEATURE_CONFIGURATION_INFORMATION
{
    ULONGLONG ChangeStamp;
    struct _RTL_FEATURE_CONFIGURATION* Configuration; // see ntrtl.h for types
} SYSTEM_FEATURE_CONFIGURATION_INFORMATION, * PSYSTEM_FEATURE_CONFIGURATION_INFORMATION;

// private
typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY
{
    ULONGLONG ChangeStamp;
    PVOID Section;
    ULONGLONG Size;
} SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY, * PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY;

// private
typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
{
    ULONGLONG OverallChangeStamp;
    SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY Descriptors[3];
} SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION, * PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION;

// private
typedef struct _RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET
{
    ULONG Data[2];
} RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET, * PRTL_FEATURE_USAGE_SUBSCRIPTION_TARGET;

// private
typedef struct _SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
{
    ULONG FeatureId;
    USHORT ReportingKind;
    USHORT ReportingOptions;
    RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET ReportingTarget;
} SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS, * PSYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS;

// private
typedef union _SECURE_SPECULATION_CONTROL_INFORMATION
{
    ULONG KvaShadowSupported : 1;
    ULONG KvaShadowEnabled : 1;
    ULONG KvaShadowUserGlobal : 1;
    ULONG KvaShadowPcid : 1;
    ULONG MbClearEnabled : 1;
    ULONG L1TFMitigated : 1; // since 20H2
    ULONG BpbEnabled : 1;
    ULONG IbrsPresent : 1;
    ULONG EnhancedIbrs : 1;
    ULONG StibpPresent : 1;
    ULONG SsbdSupported : 1;
    ULONG SsbdRequired : 1;
    ULONG BpbKernelToUser : 1;
    ULONG BpbUserToKernel : 1;
    ULONG Reserved : 18;
} SECURE_SPECULATION_CONTROL_INFORMATION, * PSECURE_SPECULATION_CONTROL_INFORMATION;

// private
typedef struct _SYSTEM_FIRMWARE_RAMDISK_INFORMATION
{
    ULONG Version;
    ULONG BlockSize;
    ULONG_PTR BaseAddress;
    SIZE_T Size;
} SYSTEM_FIRMWARE_RAMDISK_INFORMATION, * PSYSTEM_FIRMWARE_RAMDISK_INFORMATION;

// private
typedef struct _SYSTEM_SHADOW_STACK_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG CetCapable : 1;
            ULONG UserCetAllowed : 1;
            ULONG ReservedForUserCet : 6;
            ULONG KernelCetEnabled : 1;
            ULONG KernelCetAuditModeEnabled : 1;
            ULONG ReservedForKernelCet : 6;       // since Windows 10 build 21387
            ULONG Reserved : 16;
        };
    };
} SYSTEM_SHADOW_STACK_INFORMATION, * PSYSTEM_SHADOW_STACK_INFORMATION;

// private
typedef union _SYSTEM_BUILD_VERSION_INFORMATION_FLAGS
{
    ULONG Value32;
    struct
    {
        ULONG IsTopLevel : 1;
        ULONG IsChecked : 1;
    };
} SYSTEM_BUILD_VERSION_INFORMATION_FLAGS, * PSYSTEM_BUILD_VERSION_INFORMATION_FLAGS;

// private
typedef struct _SYSTEM_BUILD_VERSION_INFORMATION
{
    USHORT LayerNumber;
    USHORT LayerCount;
    ULONG OsMajorVersion;
    ULONG OsMinorVersion;
    ULONG NtBuildNumber;
    ULONG NtBuildQfe;
    UCHAR LayerName[128];
    UCHAR NtBuildBranch[128];
    UCHAR NtBuildLab[128];
    UCHAR NtBuildLabEx[128];
    UCHAR NtBuildStamp[26];
    UCHAR NtBuildArch[16];
    SYSTEM_BUILD_VERSION_INFORMATION_FLAGS Flags;
} SYSTEM_BUILD_VERSION_INFORMATION, * PSYSTEM_BUILD_VERSION_INFORMATION;

// private
typedef struct _SYSTEM_POOL_LIMIT_MEM_INFO
{
    ULONGLONG MemoryLimit;
    ULONGLONG NotificationLimit;
} SYSTEM_POOL_LIMIT_MEM_INFO, * PSYSTEM_POOL_LIMIT_MEM_INFO;

// private
typedef struct _SYSTEM_POOL_LIMIT_INFO
{
    ULONG PoolTag;
    SYSTEM_POOL_LIMIT_MEM_INFO MemLimits[2];
    WNF_STATE_NAME NotificationHandle;
} SYSTEM_POOL_LIMIT_INFO, * PSYSTEM_POOL_LIMIT_INFO;

// private
typedef struct _SYSTEM_POOL_LIMIT_INFORMATION
{
    ULONG Version;
    ULONG EntryCount;
    SYSTEM_POOL_LIMIT_INFO LimitEntries[1];
} SYSTEM_POOL_LIMIT_INFORMATION, * PSYSTEM_POOL_LIMIT_INFORMATION;

// private
//typedef struct _SYSTEM_POOL_ZEROING_INFORMATION
//{
//    bool PoolZeroingSupportPresent;
//} SYSTEM_POOL_ZEROING_INFORMATION, *PSYSTEM_POOL_ZEROING_INFORMATION;

// private
typedef struct _HV_MINROOT_NUMA_LPS
{
    ULONG NodeIndex;
    ULONG_PTR Mask[16];
} HV_MINROOT_NUMA_LPS, * PHV_MINROOT_NUMA_LPS;

// private
typedef enum _SYSTEM_IOMMU_STATE
{
    IommuStateBlock,
    IommuStateUnblock
} SYSTEM_IOMMU_STATE;

// private
typedef struct _SYSTEM_IOMMU_STATE_INFORMATION
{
    SYSTEM_IOMMU_STATE State;
    PVOID Pdo;
} SYSTEM_IOMMU_STATE_INFORMATION, * PSYSTEM_IOMMU_STATE_INFORMATION;

// private
typedef struct _SYSTEM_HYPERVISOR_MINROOT_INFORMATION
{
    ULONG NumProc;
    ULONG RootProc;
    ULONG RootProcNumaNodesSpecified;
    USHORT RootProcNumaNodes[64];
    ULONG RootProcPerCore;
    ULONG RootProcPerNode;
    ULONG RootProcNumaNodesLpsSpecified;
    HV_MINROOT_NUMA_LPS RootProcNumaNodeLps[64];
} SYSTEM_HYPERVISOR_MINROOT_INFORMATION, * PSYSTEM_HYPERVISOR_MINROOT_INFORMATION;

// private
typedef struct _SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
{
    ULONG RangeCount;
    ULONG_PTR RangeArray[1];
} SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION, * PSYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION;

// private
typedef struct _SYSTEM_POINTER_AUTH_INFORMATION
{
    union
    {
        USHORT SupportedFlags;
        struct
        {
            USHORT AddressAuthSupported : 1;
            USHORT AddressAuthQarma : 1;
            USHORT GenericAuthSupported : 1;
            USHORT GenericAuthQarma : 1;
            USHORT SupportedReserved : 12;
        };
    };
    union
    {
        USHORT EnabledFlags;
        struct
        {
            USHORT UserPerProcessIpAuthEnabled : 1;
            USHORT UserGlobalIpAuthEnabled : 1;
            USHORT UserEnabledReserved : 6;
            USHORT KernelIpAuthEnabled : 1;
            USHORT KernelEnabledReserved : 7;
        };
    };
} SYSTEM_POINTER_AUTH_INFORMATION, * PSYSTEM_POINTER_AUTH_INFORMATION;
#pragma endregion
#pragma region PROCESS_INFORMATION_CLASS
typedef enum _PROCESS_INFORMATION_CLASS_EX
{
#ifndef WINNT
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: bool
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // s: KAFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,
    ProcessAllowedCpuSetsInformation,
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: bool (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // 80
    ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
#endif // !WINNT
    ProcessManageWritesToExecutableMemory = 83, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // qs: bool (kernel-mode only) // INT2E // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures,
    ProcessAltPrefetchParam, // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx,
    ProcessMembershipInformation,
    ProcessEffectiveIoPriority,
    ProcessEffectivePagePriority,
    //MaxProcessInfoClass
} PROCESS_INFORMATION_CLASS_EX;

#define PROCESS_EXCEPTION_PORT_ALL_STATE_FLAGS ((ULONG_PTR)((1UL << PROCESS_EXCEPTION_PORT_ALL_STATE_BITS) - 1))

typedef struct _PROCESS_LDT_INFORMATION
{
    ULONG Start;
    ULONG Length;
    LDT_ENTRY LdtEntries[1];
} PROCESS_LDT_INFORMATION, * PPROCESS_LDT_INFORMATION;

typedef struct _PROCESS_LDT_SIZE
{
    ULONG Length;
} PROCESS_LDT_SIZE, * PPROCESS_LDT_SIZE;

// psapi:PSAPI_WS_WATCH_INFORMATION_EX
typedef struct _PROCESS_WS_WATCH_INFORMATION_EX
{
    PROCESS_WS_WATCH_INFORMATION BasicInfo;
    ULONG_PTR FaultingThreadId;
    ULONG_PTR Flags;
} PROCESS_WS_WATCH_INFORMATION_EX, * PPROCESS_WS_WATCH_INFORMATION_EX;

#define PROCESS_PRIORITY_CLASS_UNKNOWN 0
#define PROCESS_PRIORITY_CLASS_IDLE 1
#define PROCESS_PRIORITY_CLASS_NORMAL 2
#define PROCESS_PRIORITY_CLASS_HIGH 3
#define PROCESS_PRIORITY_CLASS_REALTIME 4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL 5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL 6

typedef struct _PROCESS_PRIORITY_CLASS
{
    bool Foreground;
    UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS, * PPROCESS_PRIORITY_CLASS;

typedef struct _PROCESS_FOREGROUND_BACKGROUND
{
    bool Foreground;
} PROCESS_FOREGROUND_BACKGROUND, * PPROCESS_FOREGROUND_BACKGROUND;

#if (PHNT_MODE != PHNT_MODE_KERNEL)

typedef struct _PROCESS_DEVICEMAP_INFORMATION
{
    union
    {
        struct
        {
            HANDLE DirectoryHandle;
        } Set;
        struct
        {
            ULONG DriveMap;
            UCHAR DriveType[32];
        } Query;
    };
} PROCESS_DEVICEMAP_INFORMATION, * PPROCESS_DEVICEMAP_INFORMATION;

#define PROCESS_LUID_DOSDEVICES_ONLY 0x00000001

typedef struct _PROCESS_DEVICEMAP_INFORMATION_EX
{
    union
    {
        struct
        {
            HANDLE DirectoryHandle;
        } Set;
        struct
        {
            ULONG DriveMap;
            UCHAR DriveType[32];
        } Query;
    };
    ULONG Flags; // PROCESS_LUID_DOSDEVICES_ONLY
} PROCESS_DEVICEMAP_INFORMATION_EX, * PPROCESS_DEVICEMAP_INFORMATION_EX;

typedef struct _PROCESS_SESSION_INFORMATION
{
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, * PPROCESS_SESSION_INFORMATION;

#define PROCESS_HANDLE_EXCEPTIONS_ENABLED 0x00000001

#define PROCESS_HANDLE_RAISE_EXCEPTION_ON_INVALID_HANDLE_CLOSE_DISABLED 0x00000000
#define PROCESS_HANDLE_RAISE_EXCEPTION_ON_INVALID_HANDLE_CLOSE_ENABLED 0x00000001

typedef struct _PROCESS_HANDLE_TRACING_ENABLE
{
    ULONG Flags;
} PROCESS_HANDLE_TRACING_ENABLE, * PPROCESS_HANDLE_TRACING_ENABLE;

#define PROCESS_HANDLE_TRACING_MAX_SLOTS 0x20000

typedef struct _PROCESS_HANDLE_TRACING_ENABLE_EX
{
    ULONG Flags;
    ULONG TotalSlots;
} PROCESS_HANDLE_TRACING_ENABLE_EX, * PPROCESS_HANDLE_TRACING_ENABLE_EX;

#define PROCESS_HANDLE_TRACING_MAX_STACKS 16

#define PROCESS_HANDLE_TRACE_TYPE_OPEN 1
#define PROCESS_HANDLE_TRACE_TYPE_CLOSE 2
#define PROCESS_HANDLE_TRACE_TYPE_BADREF 3

typedef struct _PROCESS_HANDLE_TRACING_ENTRY
{
    HANDLE Handle;
    CLIENT_ID ClientId;
    ULONG Type;
    PVOID Stacks[PROCESS_HANDLE_TRACING_MAX_STACKS];
} PROCESS_HANDLE_TRACING_ENTRY, * PPROCESS_HANDLE_TRACING_ENTRY;

typedef struct _PROCESS_HANDLE_TRACING_QUERY
{
    HANDLE Handle;
    ULONG TotalTraces;
    PROCESS_HANDLE_TRACING_ENTRY HandleTrace[1];
} PROCESS_HANDLE_TRACING_QUERY, * PPROCESS_HANDLE_TRACING_QUERY;

#endif

// private
typedef struct _THREAD_TLS_INFORMATION
{
    ULONG Flags;
    PVOID NewTlsData;
    PVOID OldTlsData;
    HANDLE ThreadId;
} THREAD_TLS_INFORMATION, * PTHREAD_TLS_INFORMATION;

// private
typedef enum _PROCESS_TLS_INFORMATION_TYPE
{
    ProcessTlsReplaceIndex,
    ProcessTlsReplaceVector,
    MaxProcessTlsOperation
} PROCESS_TLS_INFORMATION_TYPE, * PPROCESS_TLS_INFORMATION_TYPE;

// private
typedef struct _PROCESS_TLS_INFORMATION
{
    ULONG Flags;
    ULONG OperationType;
    ULONG ThreadDataCount;
    ULONG TlsIndex;
    ULONG PreviousCount;
    THREAD_TLS_INFORMATION ThreadData[1];
} PROCESS_TLS_INFORMATION, * PPROCESS_TLS_INFORMATION;

// private
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

// private
typedef struct _PROCESS_STACK_ALLOCATION_INFORMATION
{
    SIZE_T ReserveSize;
    SIZE_T ZeroBits;
    PVOID StackBase;
} PROCESS_STACK_ALLOCATION_INFORMATION, * PPROCESS_STACK_ALLOCATION_INFORMATION;

// private
typedef struct _PROCESS_STACK_ALLOCATION_INFORMATION_EX
{
    ULONG PreferredNode;
    ULONG Reserved0;
    ULONG Reserved1;
    ULONG Reserved2;
    PROCESS_STACK_ALLOCATION_INFORMATION AllocInfo;
} PROCESS_STACK_ALLOCATION_INFORMATION_EX, * PPROCESS_STACK_ALLOCATION_INFORMATION_EX;

// private
typedef union _PROCESS_AFFINITY_UPDATE_MODE
{
    ULONG Flags;
    struct
    {
        ULONG EnableAutoUpdate : 1;
        ULONG Permanent : 1;
        ULONG Reserved : 30;
    };
} PROCESS_AFFINITY_UPDATE_MODE, * PPROCESS_AFFINITY_UPDATE_MODE;

// private
typedef union _PROCESS_MEMORY_ALLOCATION_MODE
{
    ULONG Flags;
    struct
    {
        ULONG TopDown : 1;
        ULONG Reserved : 31;
    };
} PROCESS_MEMORY_ALLOCATION_MODE, * PPROCESS_MEMORY_ALLOCATION_MODE;

// private
typedef struct _PROCESS_HANDLE_INFORMATION
{
    ULONG HandleCount;
    ULONG HandleCountHighWatermark;
} PROCESS_HANDLE_INFORMATION, * PPROCESS_HANDLE_INFORMATION;

// private
typedef struct _PROCESS_CYCLE_TIME_INFORMATION
{
    ULONGLONG AccumulatedCycles;
    ULONGLONG CurrentCycleCount;
} PROCESS_CYCLE_TIME_INFORMATION, * PPROCESS_CYCLE_TIME_INFORMATION;

// private
typedef struct _PROCESS_WINDOW_INFORMATION
{
    ULONG WindowFlags;
    USHORT WindowTitleLength;
    WCHAR WindowTitle[1];
} PROCESS_WINDOW_INFORMATION, * PPROCESS_WINDOW_INFORMATION;

// private
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

// private
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;


#if !defined(NTDDI_WIN10_CO) || (NTDDI_VERSION < NTDDI_WIN10_CO)
typedef struct _PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY
{
    union {
        ULONG Flags;
        struct {
            ULONG EnforceRedirectionTrust : 1;
            ULONG AuditRedirectionTrust : 1;
            ULONG ReservedFlags : 30;
        };
    };
} PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY, * PPROCESS_MITIGATION_REDIRECTION_TRUST_POLICY;
#endif

// private
typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION
{
    PROCESS_MITIGATION_POLICY Policy;
    union
    {
        PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
        PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY SystemCallFilterPolicy;
        PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
        PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY SideChannelIsolationPolicy;
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY UserShadowStackPolicy;
        PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY RedirectionTrustPolicy;
    };
} PROCESS_MITIGATION_POLICY_INFORMATION, * PPROCESS_MITIGATION_POLICY_INFORMATION;
/*
typedef struct _PROCESS_KEEPALIVE_COUNT_INFORMATION
{
    ULONG WakeCount;
    ULONG NoWakeCount;
} PROCESS_KEEPALIVE_COUNT_INFORMATION, * PPROCESS_KEEPALIVE_COUNT_INFORMATION;

typedef struct _PROCESS_REVOKE_FILE_HANDLES_INFORMATION
{
    UNICODE_STRING TargetDevicePath;
} PROCESS_REVOKE_FILE_HANDLES_INFORMATION, * PPROCESS_REVOKE_FILE_HANDLES_INFORMATION;
*/
// begin_private
typedef enum _PROCESS_WORKING_SET_OPERATION
{
    ProcessWorkingSetSwap,
    ProcessWorkingSetEmpty,
    ProcessWorkingSetOperationMax
} PROCESS_WORKING_SET_OPERATION;

typedef struct _PROCESS_WORKING_SET_CONTROL
{
    ULONG Version;
    PROCESS_WORKING_SET_OPERATION Operation;
    ULONG Flags;
} PROCESS_WORKING_SET_CONTROL, * PPROCESS_WORKING_SET_CONTROL;

typedef enum _PS_PROTECTED_TYPE
{
    PsProtectedTypeNone,
    PsProtectedTypeProtectedLight,
    PsProtectedTypeProtected,
    PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
    PsProtectedSignerNone,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

#define PS_PROTECTED_SIGNER_MASK 0xFF
#define PS_PROTECTED_AUDIT_MASK 0x08
#define PS_PROTECTED_TYPE_MASK 0x07

// vProtectionLevel.Level = PsProtectedValue(PsProtectedSignerCodeGen, false, PsProtectedTypeProtectedLight)
#define PsProtectedValue(aSigner, aAudit, aType) ( \
    ((aSigner & PS_PROTECTED_SIGNER_MASK) << 4) | \
    ((aAudit & PS_PROTECTED_AUDIT_MASK) << 3) | \
    (aType & PS_PROTECTED_TYPE_MASK)\
    )

// InitializePsProtection(&vProtectionLevel, PsProtectedSignerCodeGen, false, PsProtectedTypeProtectedLight)
#define InitializePsProtection(aProtectionLevelPtr, aSigner, aAudit, aType) { \
    (aProtectionLevelPtr)->Signer = aSigner; \
    (aProtectionLevelPtr)->Audit = aAudit; \
    (aProtectionLevelPtr)->Type = aType; \
    }

typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_FAULT_INFORMATION
{
    ULONG FaultFlags;
    ULONG AdditionalInfo;
} PROCESS_FAULT_INFORMATION, * PPROCESS_FAULT_INFORMATION;

typedef struct _PROCESS_TELEMETRY_ID_INFORMATION
{
    ULONG HeaderSize;
    ULONG ProcessId;
    ULONGLONG ProcessStartKey;
    ULONGLONG CreateTime;
    ULONGLONG CreateInterruptTime;
    ULONGLONG CreateUnbiasedInterruptTime;
    ULONGLONG ProcessSequenceNumber;
    ULONGLONG SessionCreateTime;
    ULONG SessionId;
    ULONG BootId;
    ULONG ImageChecksum;
    ULONG ImageTimeDateStamp;
    ULONG UserSidOffset;
    ULONG ImagePathOffset;
    ULONG PackageNameOffset;
    ULONG RelativeAppNameOffset;
    ULONG CommandLineOffset;
} PROCESS_TELEMETRY_ID_INFORMATION, * PPROCESS_TELEMETRY_ID_INFORMATION;

typedef struct _PROCESS_COMMIT_RELEASE_INFORMATION
{
    ULONG Version;
    struct
    {
        ULONG Eligible : 1;
        ULONG ReleaseRepurposedMemResetCommit : 1;
        ULONG ForceReleaseMemResetCommit : 1;
        ULONG Spare : 29;
    };
    SIZE_T CommitDebt;
    SIZE_T CommittedMemResetSize;
    SIZE_T RepurposedMemResetSize;
} PROCESS_COMMIT_RELEASE_INFORMATION, * PPROCESS_COMMIT_RELEASE_INFORMATION;

typedef struct _PROCESS_JOB_MEMORY_INFO
{
    ULONGLONG SharedCommitUsage;
    ULONGLONG PrivateCommitUsage;
    ULONGLONG PeakPrivateCommitUsage;
    ULONGLONG PrivateCommitLimit;
    ULONGLONG TotalCommitLimit;
} PROCESS_JOB_MEMORY_INFO, * PPROCESS_JOB_MEMORY_INFO;
/*
typedef struct _PROCESS_CHILD_PROCESS_INFORMATION
{
    bool ProhibitChildProcesses;
    bool AlwaysAllowSecureChildProcess; // REDSTONE3
    bool AuditProhibitChildProcesses;
} PROCESS_CHILD_PROCESS_INFORMATION, * PPROCESS_CHILD_PROCESS_INFORMATION;
*/
#define POWER_THROTTLING_PROCESS_CURRENT_VERSION 1
#define POWER_THROTTLING_PROCESS_EXECUTION_SPEED 0x1
#define POWER_THROTTLING_PROCESS_DELAYTIMERS 0x2
/*
typedef struct _POWER_THROTTLING_PROCESS_STATE
{
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} POWER_THROTTLING_PROCESS_STATE, * PPOWER_THROTTLING_PROCESS_STATE;
*/
typedef struct _WIN32K_SYSCALL_FILTER
{
    ULONG FilterState;
    ULONG FilterSet;
} WIN32K_SYSCALL_FILTER, * PWIN32K_SYSCALL_FILTER;

typedef struct _PROCESS_WAKE_INFORMATION
{
    ULONGLONG NotificationChannel;
    ULONG WakeCounters[7];
    struct _JOBOBJECT_WAKE_FILTER* WakeFilter;
} PROCESS_WAKE_INFORMATION, * PPROCESS_WAKE_INFORMATION;

typedef struct _PROCESS_ENERGY_TRACKING_STATE
{
    ULONG StateUpdateMask;
    ULONG StateDesiredValue;
    ULONG StateSequence;
    ULONG UpdateTag : 1;
    WCHAR Tag[64];
} PROCESS_ENERGY_TRACKING_STATE, * PPROCESS_ENERGY_TRACKING_STATE;
/*
typedef struct _MANAGE_WRITES_TO_EXECUTABLE_MEMORY
{
    ULONG Version : 8;
    ULONG ProcessEnableWriteExceptions : 1;
    ULONG ThreadAllowWrites : 1;
    ULONG Spare : 22;
    PVOID KernelWriteToExecutableSignal; // 19H1
} MANAGE_WRITES_TO_EXECUTABLE_MEMORY, * PMANAGE_WRITES_TO_EXECUTABLE_MEMORY;
*/
#define POWER_THROTTLING_THREAD_CURRENT_VERSION 1
#define POWER_THROTTLING_THREAD_EXECUTION_SPEED 0x1
#define POWER_THROTTLING_THREAD_VALID_FLAGS (POWER_THROTTLING_THREAD_EXECUTION_SPEED)
/*
typedef struct _POWER_THROTTLING_THREAD_STATE
{
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} POWER_THROTTLING_THREAD_STATE, * PPOWER_THROTTLING_THREAD_STATE;
*/
#define PROCESS_READWRITEVM_LOGGING_ENABLE_READVM 1
#define PROCESS_READWRITEVM_LOGGING_ENABLE_WRITEVM 2
#define PROCESS_READWRITEVM_LOGGING_ENABLE_READVM_V 1UL
#define PROCESS_READWRITEVM_LOGGING_ENABLE_WRITEVM_V 2UL

typedef union _PROCESS_READWRITEVM_LOGGING_INFORMATION
{
    UCHAR Flags;
    struct
    {
        UCHAR EnableReadVmLogging : 1;
        UCHAR EnableWriteVmLogging : 1;
        UCHAR Unused : 6;
    };
} PROCESS_READWRITEVM_LOGGING_INFORMATION, * PPROCESS_READWRITEVM_LOGGING_INFORMATION;

typedef struct _PROCESS_UPTIME_INFORMATION
{
    ULONGLONG QueryInterruptTime;
    ULONGLONG QueryUnbiasedTime;
    ULONGLONG EndInterruptTime;
    ULONGLONG TimeSinceCreation;
    ULONGLONG Uptime;
    ULONGLONG SuspendedTime;
    union
    {
        ULONG HangCount : 4;
        ULONG GhostCount : 4;
        ULONG Crashed : 1;
        ULONG Terminated : 1;
    };
} PROCESS_UPTIME_INFORMATION, * PPROCESS_UPTIME_INFORMATION;

typedef union _PROCESS_SYSTEM_RESOURCE_MANAGEMENT
{
    ULONG Flags;
    struct
    {
        ULONG Foreground : 1;
        ULONG Reserved : 31;
    };
} PROCESS_SYSTEM_RESOURCE_MANAGEMENT, * PPROCESS_SYSTEM_RESOURCE_MANAGEMENT;

// private
typedef struct _PROCESS_SECURITY_DOMAIN_INFORMATION
{
    ULONGLONG SecurityDomain;
} PROCESS_SECURITY_DOMAIN_INFORMATION, * PPROCESS_SECURITY_DOMAIN_INFORMATION;

// private
typedef struct _PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
{
    HANDLE ProcessHandle;
} PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION, * PPROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION;

// private
typedef union _PROCESS_LOGGING_INFORMATION
{
    ULONG Flags;
    struct
    {
        ULONG EnableReadVmLogging : 1;
        ULONG EnableWriteVmLogging : 1;
        ULONG EnableProcessSuspendResumeLogging : 1;
        ULONG EnableThreadSuspendResumeLogging : 1;
        ULONG Reserved : 28;
    };
} PROCESS_LOGGING_INFORMATION, * PPROCESS_LOGGING_INFORMATION;

// private
typedef struct _PROCESS_LEAP_SECOND_INFORMATION
{
    ULONG Flags;
    ULONG Reserved;
} PROCESS_LEAP_SECOND_INFORMATION, * PPROCESS_LEAP_SECOND_INFORMATION;

// private
typedef struct _PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
{
    ULONGLONG ReserveSize;
    ULONGLONG CommitSize;
    ULONG PreferredNode;
    ULONG Reserved;
    PVOID Ssp;
} PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION, * PPROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION;

// private
typedef struct _PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
{
    PVOID Ssp;
} PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION, * PPROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION;

#pragma endregion
#pragma region THREAD_INFORMATION_CLASS

typedef enum _THREAD_INFORMATION_CLASS_EX
{
    /*
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority, // s: LONG
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup, // s: bool
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
    ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress, // s: ULONG_PTR
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // q: bool; s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated, // q: ULONG // 20
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority, // q: ULONG
    ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context, // qs: WOW64_CONTEXT
    ThreadGroupInformation, // q: GROUP_AFFINITY // 30
    ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
    ThreadCounterProfiling, // q: bool; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
    ThreadCpuAccountingInformation, // q: bool; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount, // q: ULONG // since WINBLUE
    */
    ThreadHeterogeneousCpuPolicy = 36, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, // q: GUID
    ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
    //ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
    //ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity = 43, // qs: ULONG; s: 0 disables, otherwise enables
    ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
    //ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive = 46, // s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE
    ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange, // since WIN11
    ThreadApplyStateChange,
    ThreadStrongerBadHandleChecks, // since 22H1
    ThreadEffectiveIoPriority,
    ThreadEffectivePagePriority,
    //MaxThreadInfoClass
} THREAD_INFORMATION_CLASS_EX;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

// private
typedef struct _THREAD_LAST_SYSCALL_INFORMATION
{
    PVOID FirstArgument;
    USHORT SystemCallNumber;
#ifdef WIN64
    USHORT Pad[0x3]; // since REDSTONE2
#else
    USHORT Pad[0x1]; // since REDSTONE2
#endif
    ULONG64 WaitTime;
} THREAD_LAST_SYSCALL_INFORMATION, * PTHREAD_LAST_SYSCALL_INFORMATION;

// private
typedef struct _THREAD_CYCLE_TIME_INFORMATION
{
    ULONGLONG AccumulatedCycles;
    ULONGLONG CurrentCycleCount;
} THREAD_CYCLE_TIME_INFORMATION, * PTHREAD_CYCLE_TIME_INFORMATION;

// private
typedef struct _THREAD_TEB_INFORMATION
{
    PVOID TebInformation; // buffer to place data in
    ULONG TebOffset; // offset in TEB to begin reading from
    ULONG BytesToRead; // number of bytes to read
} THREAD_TEB_INFORMATION, * PTHREAD_TEB_INFORMATION;

// symbols
typedef struct _COUNTER_READING
{
    HARDWARE_COUNTER_TYPE Type;
    ULONG Index;
    ULONG64 Start;
    ULONG64 Total;
} COUNTER_READING, * PCOUNTER_READING;

// symbols
typedef struct _THREAD_PERFORMANCE_DATA
{
    USHORT Size;
    USHORT Version;
    PROCESSOR_NUMBER ProcessorNumber;
    ULONG ContextSwitches;
    ULONG HwCountersCount;
    ULONG64 UpdateCount;
    ULONG64 WaitReasonBitMap;
    ULONG64 HardwareCounters;
    COUNTER_READING CycleTime;
    COUNTER_READING HwCounters[MAX_HW_COUNTERS];
} THREAD_PERFORMANCE_DATA, * PTHREAD_PERFORMANCE_DATA;

// private
typedef struct _THREAD_PROFILING_INFORMATION
{
    ULONG64 HardwareCounters;
    ULONG Flags;
    ULONG Enable;
    PTHREAD_PERFORMANCE_DATA PerformanceData;
} THREAD_PROFILING_INFORMATION, * PTHREAD_PROFILING_INFORMATION;

// private
typedef struct _RTL_UMS_CONTEXT
{
    SINGLE_LIST_ENTRY Link;
    CONTEXT Context;
    PVOID Teb;
    PVOID UserContext;
    volatile ULONG ScheduledThread : 1;
    volatile ULONG Suspended : 1;
    volatile ULONG VolatileContext : 1;
    volatile ULONG Terminated : 1;
    volatile ULONG DebugActive : 1;
    volatile ULONG RunningOnSelfThread : 1;
    volatile ULONG DenyRunningOnSelfThread : 1;
    volatile LONG Flags;
    volatile ULONG64 KernelUpdateLock : 2;
    volatile ULONG64 PrimaryClientID : 62;
    volatile ULONG64 ContextLock;
    struct _RTL_UMS_CONTEXT* PrimaryUmsContext;
    ULONG SwitchCount;
    ULONG KernelYieldCount;
    ULONG MixedYieldCount;
    ULONG YieldCount;
} RTL_UMS_CONTEXT, * PRTL_UMS_CONTEXT;

// private
typedef enum _THREAD_UMS_INFORMATION_COMMAND
{
    UmsInformationCommandInvalid,
    UmsInformationCommandAttach,
    UmsInformationCommandDetach,
    UmsInformationCommandQuery
} THREAD_UMS_INFORMATION_COMMAND;

// private
typedef struct _RTL_UMS_COMPLETION_LIST
{
    PSINGLE_LIST_ENTRY ThreadListHead;
    PVOID CompletionEvent;
    ULONG CompletionFlags;
    SINGLE_LIST_ENTRY InternalListHead;
} RTL_UMS_COMPLETION_LIST, * PRTL_UMS_COMPLETION_LIST;

// private
typedef struct _THREAD_UMS_INFORMATION
{
    THREAD_UMS_INFORMATION_COMMAND Command;
    PRTL_UMS_COMPLETION_LIST CompletionList;
    PRTL_UMS_CONTEXT UmsContext;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG IsUmsSchedulerThread : 1;
            ULONG IsUmsWorkerThread : 1;
            ULONG SpareBits : 30;
        };
    };
} THREAD_UMS_INFORMATION, * PTHREAD_UMS_INFORMATION;

// private
typedef struct _THREAD_NAME_INFORMATION
{
    UNICODE_STRING ThreadName;
} THREAD_NAME_INFORMATION, * PTHREAD_NAME_INFORMATION;

// private
typedef struct _ALPC_WORK_ON_BEHALF_TICKET
{
    ULONG ThreadId;
    ULONG ThreadCreationTimeLow;
} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

// private
typedef struct _RTL_WORK_ON_BEHALF_TICKET_EX
{
    ALPC_WORK_ON_BEHALF_TICKET Ticket;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG CurrentThread : 1;
            ULONG Reserved1 : 31;
        };
    };
    ULONG Reserved2;
} RTL_WORK_ON_BEHALF_TICKET_EX, * PRTL_WORK_ON_BEHALF_TICKET_EX;

#if (PHNT_MODE != PHNT_MODE_KERNEL)
// private
typedef enum _SUBSYSTEM_INFORMATION_TYPE
{
    SubsystemInformationTypeWin32,
    SubsystemInformationTypeWSL,
    MaxSubsystemInformationType
} SUBSYSTEM_INFORMATION_TYPE;
#endif

// private
typedef enum _THREAD_WORKLOAD_CLASS
{
    ThreadWorkloadClassDefault,
    ThreadWorkloadClassGraphics,
    MaxThreadWorkloadClass
} THREAD_WORKLOAD_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS_EX
{
    ObjectBasicInformation_EX, // OBJECT_BASIC_INFORMATION
    ObjectNameInformation, // OBJECT_NAME_INFORMATION
    ObjectTypeInformation_EX, // OBJECT_TYPE_INFORMATION
    ObjectTypesInformation, // OBJECT_TYPES_INFORMATION
    ObjectHandleFlagInformation, // OBJECT_HANDLE_FLAG_INFORMATION
    ObjectSessionInformation,
    ObjectSessionObjectInformation,
    MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS_EX;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
    bool Inherit;
    bool ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;
#ifndef WINNT

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

#endif // !WINNT

#pragma endregion

#pragma region FUNCTION_TYPE
typedef NTSTATUS(NTAPI* NtSuspendThread_TYPE)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

typedef NTSTATUS(NTAPI* NtResumeThread_TYPE)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );
typedef NTSTATUS(NTAPI* NtSetEvent_TYPE)(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
    );
typedef NTSTATUS(NTAPI* NtCreateThread_TYPE)(
    __out PHANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE ProcessHandle,
    __out PCLIENT_ID ClientId,
    __in PCONTEXT ThreadContext,
    __in PVOID InitialTeb,
    __in bool CreateSuspended
    );
typedef NTSTATUS(NTAPI* NtCreateThreadEx_TYPE)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG CreateThreadFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximunStackSize,
    PVOID pUnkown
    );

typedef NTSTATUS(NTAPI* NtQueueApcThread_TYPE)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_TYPE)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_TYPE)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

#pragma endregion

#pragma region FUNCTION
#ifdef __cplusplus
extern "C" {
#endif
    NTSTATUS NTAPI ZwQuerySystemInformation(
        _In_ ULONG/*SYSTEM_INFORMATION_CLASS*/ SystemInformationClass,
        _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
        _In_ ULONG SystemInformationLength,
        _Out_opt_ PULONG ReturnLength
    );

    NTSTATUS NTAPI ZwQueryInformationProcess(
        HANDLE           ProcessHandle,
        ULONG/*PROCESSINFOCLASS*/ ProcessInformationClass,
        PVOID            ProcessInformation,
        ULONG            ProcessInformationLength,
        PULONG           ReturnLength
    );

    NTSTATUS NTAPI ZwQueryInformationThread(
        HANDLE          ThreadHandle,
        ULONG/*THREADINFOCLASS*/ ThreadInformationClass,
        PVOID           ThreadInformation,
        ULONG           ThreadInformationLength,
        PULONG          ReturnLength
    );
    NTSTATUS NTAPI ZwWaitForMultipleObjects(
        ULONG Count,
        HANDLE Object[],
        WAIT_TYPE WaitType,
        bool Alertable,
        PLARGE_INTEGER Time);

    NTSTATUS NTAPI ZwProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T ProtectSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
    NTSTATUS NTAPI ZwOpenThread(
        _Out_ PHANDLE            ThreadHandle,
        _In_  ACCESS_MASK        DesiredAccess,
        _In_  POBJECT_ATTRIBUTES ObjectAttributes,
        _In_  PCLIENT_ID         ClientId
    );
#ifdef WINNT
    NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize);
    NTKERNELAPI PCSTR NTAPI PsGetProcessImageFileName(
        __in PEPROCESS Process
    );
    NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(
        __in PEPROCESS Process
    );
    NTKERNELAPI PPEB NTAPI PsGetProcessPeb(
        PEPROCESS Process
    );
    NTKERNELAPI NTSTATUS ObReferenceObjectByName(
        IN PUNICODE_STRING ObjectName,
        IN ULONG Attributes,
        IN PACCESS_STATE PassedAccessState OPTIONAL,
        IN ACCESS_MASK DesiredAccess OPTIONAL,
        IN POBJECT_TYPE ObjectType,
        IN KPROCESSOR_MODE AccessMode,
        IN OUT PVOID ParseContext OPTIONAL,
        OUT PVOID* Object
    );
    NTKERNELAPI NTSTATUS NTAPI PsGetContextThread(
        __in PETHREAD Thread,
        __inout PCONTEXT ThreadContext,
        __in KPROCESSOR_MODE Mode
    );

    NTKERNELAPI NTSTATUS NTAPI PsSetContextThread(
        __in PETHREAD Thread,
        __inout PCONTEXT ThreadContext,
        __in KPROCESSOR_MODE Mode
    );
    NTKERNELAPI NTSTATUS NTAPI KeUserModeCallback(
        IN ULONG ApiNumber,
        IN PVOID InputBuffer,
        IN ULONG InputLength,
        OUT PVOID* OutputBuffer,
        IN PULONG OutputLength
    );
    int sprintf(char* DstBuf, const char* Format, ...);
    int sprintf_s(char* DstBuf, size_t SizeInBytes, const char* Format, ...);

    int vsprintf(char* DstBuf, const char* Format, va_list ArgList);
    int vsprintf_s(char* DstBuf, size_t SizeInBytes, const char* Format, va_list ArgList);

    int _snprintf(char* DstBuf, size_t SizeInBytes, const char* Format, ...);
    int _snprintf_s(char* DstBuf, size_t SizeInBytes, size_t MaxCount, const char* Format, ...);

    int _vsnprintf(char* DstBuf, size_t SizeInBytes, const char* Format, va_list ArgList);
    int _vsnprintf_s(char* DstBuf, size_t SizeInBytes, size_t MaxCount, const char* Format, va_list ArgList);

    int swprintf(wchar_t* Dst, const wchar_t* Format, ...);
    int swprintf_s(wchar_t* Dst, size_t SizeInWords, const wchar_t* Format, ...);

    int vswprintf(wchar_t* Dst, const wchar_t* Format, va_list ArgList);
    int vswprintf_s(wchar_t* Dst, size_t SizeInWords, const wchar_t* Format, va_list ArgList);

    typedef enum _KAPC_ENVIRONMENT {
        OriginalApcEnvironment,
        AttachedApcEnvironment,
        CurrentApcEnvironment,
        InsertApcEnvironment
    } KAPC_ENVIRONMENT;

    typedef
        _Function_class_(KNORMAL_ROUTINE)
        _IRQL_requires_max_(PASSIVE_LEVEL)
        _IRQL_requires_min_(PASSIVE_LEVEL)
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        VOID
        KNORMAL_ROUTINE(
            _In_opt_ PVOID NormalContext,
            _In_opt_ PVOID SystemArgument1,
            _In_opt_ PVOID SystemArgument2
        );
    typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

    typedef
        _Function_class_(KKERNEL_ROUTINE)
        _IRQL_requires_max_(APC_LEVEL)
        _IRQL_requires_min_(APC_LEVEL)
        _IRQL_requires_(APC_LEVEL)
        _IRQL_requires_same_
        VOID
        KKERNEL_ROUTINE(
            _In_ struct _KAPC* Apc,
            _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
            _Inout_ PVOID* NormalContext,
            _Inout_ PVOID* SystemArgument1,
            _Inout_ PVOID* SystemArgument2
        );
    typedef KKERNEL_ROUTINE* PKKERNEL_ROUTINE;

    typedef
        _Function_class_(KRUNDOWN_ROUTINE)
        _IRQL_requires_max_(PASSIVE_LEVEL)
        _IRQL_requires_min_(PASSIVE_LEVEL)
        _IRQL_requires_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        VOID
        KRUNDOWN_ROUTINE(
            _In_ struct _KAPC* Apc
        );
    typedef KRUNDOWN_ROUTINE* PKRUNDOWN_ROUTINE;

    NTKERNELAPI
        _IRQL_requires_same_
        _When_(Environment != OriginalApcEnvironment, __drv_reportError("Caution: "
            "Using an APC environment other than the original environment can lead to "
            "a system bugcheck if the target thread is attached to a process with APCs "
            "disabled. APC environments should be used with care."))
        VOID
        KeInitializeApc(
            _Out_ PRKAPC Apc,
            _In_ PRKTHREAD Thread,
            _In_ KAPC_ENVIRONMENT Environment,
            _In_ PKKERNEL_ROUTINE KernelRoutine,
            _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
            _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
            _In_opt_ KPROCESSOR_MODE ProcessorMode,
            _In_opt_ PVOID NormalContext
        );

    NTKERNELAPI
        _Must_inspect_result_
        _IRQL_requires_max_(DISPATCH_LEVEL)
        _IRQL_requires_min_(PASSIVE_LEVEL)
        _IRQL_requires_same_
        bool
        KeInsertQueueApc(
            _Inout_ PRKAPC Apc,
            _In_opt_ PVOID SystemArgument1,
            _In_opt_ PVOID SystemArgument2,
            _In_ KPRIORITY Increment
        );
#else

    NTSYSAPI NTSTATUS NTAPI NtGetContextThread(
        IN HANDLE ThreadHandle,
        IN OUT PCONTEXT ThreadContext
    );

    NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
        IN HANDLE ThreadHandle,
        IN PCONTEXT ThreadContext
    );

    NTSYSAPI NTSTATUS NTAPI ZwClose(
        _In_ HANDLE Handle
    );
    NTSYSAPI VOID NTAPI RtlTimeToTimeFields(
        _In_ PLARGE_INTEGER Time,
        _Out_ PTIME_FIELDS TimeFields
    );
    NTSYSAPI NTSTATUS NTAPI ZwLoadDriver(
        _In_ PUNICODE_STRING DriverServiceName
    );

    NTSYSAPI NTSTATUS NTAPI ZwUnloadDriver(
        _In_ PUNICODE_STRING DriverServiceName
    );
    NTSYSAPI VOID NTAPI RtlInitUnicodeString(
        PUNICODE_STRING         DestinationString,
        PCWSTR SourceString
    );
    NTSYSAPI VOID NTAPI RtlInitAnsiString(
        _Out_ PANSI_STRING DestinationString,
        _In_opt_z_ __drv_aliasesMem PCSTR SourceString
    );
    NTSYSAPI NTSTATUS NTAPI RtlAnsiStringToUnicodeString(
        _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
        _When_(!AllocateDestinationString, _Inout_)
        PUNICODE_STRING DestinationString,
        _In_ PCANSI_STRING SourceString,
        _In_ bool AllocateDestinationString
    );
    NTSYSAPI NTSTATUS NTAPI RtlUnicodeStringToAnsiString(
        _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
        _When_(!AllocateDestinationString, _Inout_)
        PANSI_STRING DestinationString,
        _In_ PCUNICODE_STRING SourceString,
        _In_ bool AllocateDestinationString
    );
    NTSYSAPI VOID NTAPI RtlFreeUnicodeString(
        _Inout_ _At_(UnicodeString->Buffer, _Frees_ptr_opt_)
        PUNICODE_STRING UnicodeString
    );
    NTSYSAPI VOID NTAPI RtlFreeAnsiString(
        _Inout_ _At_(AnsiString->Buffer, _Frees_ptr_opt_)
        PANSI_STRING AnsiString
    );
    NTSYSAPI LONG NTAPI RtlCompareUnicodeString(
        _In_ PCUNICODE_STRING String1,
        _In_ PCUNICODE_STRING String2,
        _In_ bool CaseInSensitive
    );
    NTSYSAPI NTSTATUS NTAPI RtlNtPathNameToDosPathName(
        ULONG Flags,
        PRTL_UNICODE_STRING_BUFFER Path,
        PULONG Disposition,
        PWSTR* FilePart
    );
    NTSYSAPI bool NTAPI RtlDosPathNameToNtPathName_U(IN PCWSTR DosName,
        OUT PUNICODE_STRING NtName,
        OUT PCWSTR* PartName,
        OUT PVOID RelativeName
    );
    NTSYSAPI NTSTATUS NTAPI RtlGetVersion(
        _Out_
        _At_(lpVersionInformation->dwOSVersionInfoSize, _Pre_ _Valid_)
        _When_(lpVersionInformation->dwOSVersionInfoSize == sizeof(RTL_OSVERSIONINFOEXW),
            _At_((PRTL_OSVERSIONINFOEXW)lpVersionInformation, _Out_))
        PRTL_OSVERSIONINFOW lpVersionInformation
    );
    NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _Inout_ PVOID* BaseAddress,
        _In_ ULONG_PTR ZeroBits,
        _Inout_ PSIZE_T RegionSize,
        _In_ ULONG AllocationType,
        _In_ ULONG Protect
    );
    NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _Inout_ PVOID* BaseAddress,
        _Inout_ PSIZE_T RegionSize,
        _In_ ULONG FreeType
    );
    NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _In_opt_ PVOID BaseAddress,
        _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
        _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
        _In_ SIZE_T MemoryInformationLength,
        _Out_opt_ PSIZE_T ReturnLength
    );
    NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject(
        HANDLE      SourceProcessHandle,
        HANDLE      SourceHandle,
        HANDLE      TargetProcessHandle,
        PHANDLE     TargetHandle,
        ACCESS_MASK DesiredAccess,
        ULONG       HandleAttributes,
        ULONG       Options
    );
    NTSYSAPI NTSTATUS NTAPI NtGetContextThread(
        IN HANDLE ThreadHandle,
        IN OUT PCONTEXT ThreadContext
    );

    NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
        IN HANDLE ThreadHandle,
        IN PCONTEXT ThreadContext
    );
    NTSYSAPI NTSTATUS NTAPI ZwCreateEvent(
        _Out_ PHANDLE EventHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ EVENT_TYPE EventType,
        _In_ bool InitialState
    );
    NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
        _In_ HANDLE Handle,
        _In_ bool Alertable,
        _In_opt_ PLARGE_INTEGER Timeout
    );
    NTSYSAPI NTSTATUS NTAPI ZwCreateThread(
        __out PHANDLE ThreadHandle,
        __in ACCESS_MASK DesiredAccess,
        __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
        __in HANDLE ProcessHandle,
        __out CLIENT_ID ClientId,
        __in PCONTEXT ThreadContext,
        __in PVOID InitialTeb,
        __in bool CreateSuspended
    );
    NTSYSAPI NTSTATUS NTAPI ZwCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID lpStartAddress,
        PVOID lpParameter,
        ULONG CreateThreadFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximunStackSize,
        PVOID pUnkown
    );
    NTSYSAPI NTSTATUS NTAPI ZwSetInformationThread(
        _In_ HANDLE ThreadHandle,
        _In_ enum THREADINFOCLASS ThreadInformationClass,
        _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
        _In_ ULONG ThreadInformationLength
    );
    #endif // WINNT


#ifdef __cplusplus
}
#endif
#pragma endregion

#pragma warning(pop)