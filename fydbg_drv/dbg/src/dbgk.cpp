#include <ntifs.h>
#include "dbgk.h"
#include <fylib\include\fylib.hpp>

#define MAX_ID 0x1000
#pragma warning(disable:4201)

//���DebugPort
static volatile PVOID ProcessDebugPortList[MAX_ID / 4] = { NULL };
//���ThreadContext
static volatile PVOID ThreadContextList[MAX_ID / 4] = { NULL };

inline static PVOID GetDebugPort(PEPROCESS Process)
{
    return ProcessDebugPortList[(ULONG)(ULONG64)PsGetProcessId(Process) / 4];
}
inline static PVOID GetThreadContext(PETHREAD Thread)
{
    return ThreadContextList[(ULONG)(ULONG64)PsGetThreadId(Thread) / 4];
}

typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, * PPORT_MESSAGE;

//
// Debug Message API Number
//
typedef enum _DBGKM_APINUMBER
{
    DbgKmExceptionApi = 0,
    DbgKmCreateThreadApi = 1,
    DbgKmCreateProcessApi = 2,
    DbgKmExitThreadApi = 3,
    DbgKmExitProcessApi = 4,
    DbgKmLoadDllApi = 5,
    DbgKmUnloadDllApi = 6,
    DbgKmErrorReportApi = 7,
    DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;

/* Types of LPC messages */
#define UNUSED_MSG_TYPE                 0
#define LPC_REQUEST                     1
#define LPC_REPLY                       2
#define LPC_DATAGRAM                    3
#define LPC_LOST_REPLY                  4
#define LPC_PORT_CLOSED                 5
#define LPC_CLIENT_DIED                 6
#define LPC_EXCEPTION                   7
#define LPC_DEBUG_EVENT                 8
#define LPC_ERROR_EVENT                 9
#define LPC_CONNECTION_REQUEST         10

//
// Debug Message Structures
//
typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, * PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, * PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, * PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, * PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, * PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, * PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, * PDBGKM_UNLOAD_DLL;

//
// LPC Debug Message
//
typedef struct _DBGKM_MSG
{
    PORT_MESSAGE h;
    DBGKM_APINUMBER ApiNumber;
    NTSTATUS ReturnedStatus;
    union
    {
        DBGKM_EXCEPTION Exception;
        DBGKM_CREATE_THREAD CreateThread;
        DBGKM_CREATE_PROCESS CreateProcess;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    };
    UCHAR Undef[0x40];
} DBGKM_MSG, * PDBGKM_MSG;

//
// Debug Event Flags
//
#define DEBUG_EVENT_READ                  (0x01)
#define DEBUG_EVENT_NOWAIT                (0x02)
#define DEBUG_EVENT_INACTIVE              (0x04)
#define DEBUG_EVENT_RELEASE               (0x08)
#define DEBUG_EVENT_PROTECT_FAILED        (0x10)
#define DEBUG_EVENT_SUSPEND               (0x20)

//
// Debug Object
//
typedef struct _DEBUG_OBJECT
{
    KEVENT EventsPresent;
    FAST_MUTEX Mutex;
    LIST_ENTRY EventList;
    union
    {
        ULONG Flags;
        struct
        {
            UCHAR DebuggerInactive : 1;
            UCHAR KillProcessOnExit : 1;
        };
    };
} DEBUG_OBJECT, * PDEBUG_OBJECT;

/* User Mode Debugging Manager Tag */
#define TAG_DEBUG_EVENT 'EgbD'

//
// Debug Event
//
typedef struct _DEBUG_EVENT
{
    LIST_ENTRY EventList;
    KEVENT ContinueEvent;
    CLIENT_ID ClientId;
    PEPROCESS Process;
    PETHREAD Thread;
    NTSTATUS Status;
    ULONG Flags;
    PETHREAD BackoutThread;
    DBGKM_MSG ApiMsg;
} DEBUG_EVENT, * PDEBUG_EVENT;

static BOOLEAN(NTAPI *DbgkpSuspendProcess)(PEPROCESS Process) = NULL;
static VOID(NTAPI* PsThawMultiProcess)(PEPROCESS Process, ULONG64, ULONG64) = NULL;
static PVOID(NTAPI* PsQueryThreadStartAddress)(PETHREAD Thread, BOOLEAN Flags) = NULL;  //Flags=FALSE
static NTSTATUS(NTAPI* MmGetFileNameForAddress)(PVOID Address, PUNICODE_STRING ModuleName) = NULL;
static PFAST_MUTEX pDbgkpProcessDebugPortMutex = NULL;

static const PIMAGE_NT_HEADERS RtlImageNtHeader(void* ImageBase)
{
    return (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
}

static HANDLE GetFileNameForAddress(PVOID Address)
{
    HANDLE FileHandle = NULL;
    UNICODE_STRING FileName = { 0 };
    if (NT_SUCCESS(MmGetFileNameForAddress(Address, &FileName)))
    {
        OBJECT_ATTRIBUTES ObjectAttr;
        IO_STATUS_BLOCK IoStatusBlock;
        InitializeObjectAttributes(&ObjectAttr, &FileName, OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE/*0x640*/, NULL, NULL);
        ZwOpenFile(&FileHandle, GENERIC_READ | SYNCHRONIZE/*0x80100000*/, &ObjectAttr, &IoStatusBlock, FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA/*7*/, FILE_SYNCHRONOUS_IO_NONALERT/*0x20*/);
        RtlFreeUnicodeString(&FileName);
    }
    return FileHandle;
}

static NTSTATUS DbgkpQueueMessage(PEPROCESS Process, PETHREAD Thread, PDBGKM_MSG Message, ULONG Flags, PVOID TargetObject)
{
    PDEBUG_EVENT DebugEvent;
    DEBUG_EVENT LocalDebugEvent;
    PDEBUG_OBJECT DebugObject;
    NTSTATUS Status;
    BOOLEAN NewEvent;
    PAGED_CODE();

    /* Check if we have to allocate a debug event */
    NewEvent = (Flags & DEBUG_EVENT_NOWAIT) ? TRUE : FALSE;
    if (NewEvent)
    {
        /* Allocate it */
        //DebugEvent = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEBUG_EVENT), TAG_DEBUG_EVENT);
        DebugEvent = (PDEBUG_EVENT)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_REQUIRED_START, sizeof(DEBUG_EVENT), TAG_DEBUG_EVENT);
        if (!DebugEvent) return STATUS_INSUFFICIENT_RESOURCES;

        memset(DebugEvent, 0, sizeof(DEBUG_EVENT));
        /* Set flags */
        DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;

        /* Reference the thread and process */
        ObReferenceObject(Thread);
        ObReferenceObject(Process);

        /* Set the current thread */
        DebugEvent->BackoutThread = PsGetCurrentThread();

        /* Set the debug object */
        DebugObject = (PDEBUG_OBJECT)TargetObject;
    }
    else
    {
        memset(&LocalDebugEvent, 0, sizeof(LocalDebugEvent));
        /* Use the debug event on the stack */
        DebugEvent = &LocalDebugEvent;
        DebugEvent->Flags = Flags;

        /* Acquire the port lock */
        //ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
        ExAcquireFastMutex(pDbgkpProcessDebugPortMutex);

        /* Get the debug object */
        //DebugObject = Process->DebugPort;
        DebugObject = (PDEBUG_OBJECT)GetDebugPort(Process);
    }

    /* Setup the Debug Event */
    KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
    DebugEvent->Process = Process;
    DebugEvent->Thread = Thread;
    DebugEvent->ApiMsg = *Message;
    //DebugEvent->ClientId = Thread->Cid;
    DebugEvent->ClientId.UniqueThread = PsGetThreadId(Thread);
    DebugEvent->ClientId.UniqueProcess = PsGetThreadProcessId(Thread);

    /* Check if we have a port object */
    if (!DebugObject)
    {
        /* Fail */
        Status = STATUS_PORT_NOT_SET;
    }
    else
    {
        /* Acquire the debug object mutex */
        ExAcquireFastMutex(&DebugObject->Mutex);

        /* Check if a debugger is active */
        if (!DebugObject->DebuggerInactive)
        {
            /* Add the event into the object's list */
            InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);

            /* Check if we have to signal it */
            if (!NewEvent)
            {
                /* Signal it */
                KeSetEvent(&DebugObject->EventsPresent,
                    IO_NO_INCREMENT,
                    FALSE);
            }

            /* Set success */
            Status = STATUS_SUCCESS;
        }
        else
        {
            /* No debugger */
            Status = STATUS_DEBUGGER_INACTIVE;
        }

        /* Release the object lock */
        ExReleaseFastMutex(&DebugObject->Mutex);
    }

    /* Check if we had acquired the port lock */
    if (!NewEvent)
    {
        /* Release it */
        //ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
        ExReleaseFastMutex(pDbgkpProcessDebugPortMutex);

        /* Check if we got here through success */
        if (NT_SUCCESS(Status))
        {
            /* Wait on the continue event */
            KeWaitForSingleObject(&DebugEvent->ContinueEvent, Executive, KernelMode, FALSE, NULL);

            /* Copy API Message back */
            *Message = DebugEvent->ApiMsg;

            /* Set return status */
            Status = DebugEvent->Status;
        }
    }
    else
    {
        /* Check if we failed */
        if (!NT_SUCCESS(Status))
        {
            /* Dereference the process and thread */
            ObDereferenceObject(Thread);
            ObDereferenceObject(Process);

            /* Free the debug event */
            ExFreePoolWithTag(DebugEvent, TAG_DEBUG_EVENT);
        }
    }

    /* Return status */
    return Status;
}

static NTSTATUS NTAPI DbgkpSendApiMessage(PEPROCESS Process, ULONG Flags, PDBGKM_MSG ApiMsg)
{
    NTSTATUS Status;
	BOOLEAN SupendProcess = FALSE;
    if (PsGetCurrentProcess() == Process && (Flags & 1))
	{
		SupendProcess = DbgkpSuspendProcess(Process);
	}
    Status = DbgkpQueueMessage(Process, KeGetCurrentThread(), ApiMsg, 2, NULL);
	PsThawMultiProcess(Process, 0i64, 1i64);
	KeLeaveCriticalRegion();
    return Status;
}

BOOLEAN DbgkForwardException(PEPROCESS Process, PEXCEPTION_RECORD ExceptionRecord, BOOLEAN SecondChance)
{
    BOOLEAN Result = FALSE;
    if (GetDebugPort(Process))
    {
        DBGKM_MSG Msg = { 0 };
        Msg.h.u1.s1.DataLength = 8 + sizeof(DBGKM_EXCEPTION);
        Msg.h.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + 8 + sizeof(DBGKM_EXCEPTION);
        Msg.h.u2.s2.Type = LPC_DEBUG_EVENT;
        Msg.ApiNumber = DbgKmExceptionApi;
        Msg.Exception.ExceptionRecord = *ExceptionRecord;
        Msg.Exception.FirstChance = !SecondChance;
        NTSTATUS Status = DbgkpSendApiMessage(Process, 1, &Msg);
        if (NT_SUCCESS(Status) && NT_SUCCESS(Msg.ReturnedStatus))
        {
            Result = TRUE;
        }
    }
    return Result;
}

VOID DbgkCreateThread(PEPROCESS Process, PETHREAD Thread)
{
    //���Thread���ǵ�ǰ�߳��޷�����
    if (Thread == PsGetCurrentThread())
    {
        if (GetDebugPort(Process))
        {
            DBGKM_MSG Msg = { 0 };
            Msg.h.u1.s1.DataLength = 8 + sizeof(DBGKM_CREATE_THREAD);
            Msg.h.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + 8 + sizeof(DBGKM_CREATE_THREAD);
            Msg.h.u2.s2.Type = LPC_DEBUG_EVENT;
            Msg.ApiNumber = DbgKmCreateThreadApi;
            Msg.CreateThread.StartAddress = PsQueryThreadStartAddress(Thread, FALSE);
            DbgkpSendApiMessage(Process, 1, &Msg);
        }
    }
}

VOID DbgkCreateMinimalProcess(PEPROCESS Process)
{
    if (GetDebugPort(Process))
    {
        DBGKM_MSG Msg = { 0 };
        Msg.h.u1.s1.DataLength = 8 + sizeof(DBGKM_CREATE_PROCESS);
        Msg.h.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + 8 + sizeof(DBGKM_CREATE_PROCESS);
        Msg.h.u2.s2.Type = LPC_DEBUG_EVENT;
        Msg.ApiNumber = DbgKmCreateProcessApi;
        DbgkpSendApiMessage(Process, 1, &Msg);
    }
}

VOID DbgkExitThread(PEPROCESS Process, PETHREAD Thread, NTSTATUS ExitStatus)
{
    //���Thread���ǵ�ǰ�߳��޷�����
    if (Thread == PsGetCurrentThread())
    {
        if (GetDebugPort(Process))
        {
            DBGKM_MSG Msg = { 0 };
            Msg.h.u1.s1.DataLength = 8 + sizeof(DBGKM_EXIT_THREAD);
            Msg.h.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + 8 + sizeof(DBGKM_EXIT_THREAD);
            Msg.h.u2.s2.Type = LPC_DEBUG_EVENT;
            Msg.ApiNumber = DbgKmExitThreadApi;
            Msg.ExitThread.ExitStatus = ExitStatus;
            DbgkpSendApiMessage(Process, 1, &Msg);
        }
    }
}

VOID DbgkExitProcess(PEPROCESS Process, NTSTATUS ExitStatus)
{
    if (GetDebugPort(Process))
    {
        //Process->ExitTime.QuadPart = MEMORY[0xFFFFF78000000014];
        DBGKM_MSG Msg = { 0 };
        Msg.h.u1.s1.DataLength = 8 + sizeof(DBGKM_EXIT_PROCESS);
        Msg.h.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + 8 + sizeof(DBGKM_EXIT_PROCESS);
        Msg.h.u2.s2.Type = LPC_DEBUG_EVENT;
        Msg.ApiNumber = DbgKmExitProcessApi;
        Msg.ExitProcess.ExitStatus = ExitStatus;
        DbgkpSendApiMessage(Process, 1, &Msg);
    }
}

VOID DbgkMapViewOfSection(PEPROCESS Process, PVOID BaseAddress)
{
    if (GetDebugPort(Process))
    {
        HANDLE FileHandle = GetFileNameForAddress(BaseAddress);
        if (FileHandle)
        {
            DBGKM_MSG Msg = { 0 };
            Msg.h.u1.s1.DataLength = 8 + sizeof(DBGKM_LOAD_DLL);
            Msg.h.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + 8 + sizeof(DBGKM_LOAD_DLL);
            Msg.h.u2.s2.Type = LPC_DEBUG_EVENT;
            Msg.ApiNumber = DbgKmLoadDllApi;
            Msg.LoadDll.FileHandle = FileHandle;
            Msg.LoadDll.BaseOfDll = BaseAddress;
            Msg.LoadDll.DebugInfoFileOffset = 0;
            Msg.LoadDll.DebugInfoSize = 0;
            Msg.LoadDll.NamePointer = NULL;
            DbgkpSendApiMessage(Process, 1, &Msg);
        }
    }
}

VOID DbgkUnMapViewOfSection(PEPROCESS Process, PVOID BaseAddress)
{
    if (GetDebugPort(Process))
    {
        DBGKM_MSG Msg = { 0 };
        Msg.h.u1.s1.DataLength = 8 + sizeof(DBGKM_UNLOAD_DLL);
        Msg.h.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + 8 + sizeof(DBGKM_UNLOAD_DLL);
        Msg.h.u2.s2.Type = LPC_DEBUG_EVENT;
        Msg.ApiNumber = DbgKmUnloadDllApi;
        Msg.UnloadDll.BaseAddress = BaseAddress;
        DbgkpSendApiMessage(Process, 1, &Msg);
    }
}

static NTSTATUS DbgkPostModuleMessage(PEPROCESS Process, PETHREAD Thread, PVOID ImageBase, PVOID DebugPort)
{
    NTSTATUS result = STATUS_SUCCESS;
    if (GetDebugPort(Process))
    {
        PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ImageBase);
        HANDLE FileHandle = GetFileNameForAddress(ImageBase);
        if (FileHandle)
        {
            DBGKM_MSG Msg = { 0 };
            Msg.h.u1.s1.DataLength = 8 + sizeof(DBGKM_LOAD_DLL);
            Msg.h.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + 8 + sizeof(DBGKM_LOAD_DLL);
            Msg.h.u2.s2.Type = LPC_DEBUG_EVENT;
            Msg.ApiNumber = DbgKmLoadDllApi;
            Msg.LoadDll.FileHandle = FileHandle;
            Msg.LoadDll.BaseOfDll = ImageBase;
            Msg.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
            Msg.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
            Msg.LoadDll.NamePointer = NULL;

            if (DebugPort)
            {
                result = DbgkpQueueMessage(Process, Thread, &Msg, 2, DebugPort);
            }
            else
            {
                result = DbgkpSendApiMessage(Process, 3, &Msg);
            }
            ObCloseHandle(FileHandle, KernelMode);
        }
    }
    return result;
}

VOID DbgkpPostModuleMessages(PEPROCESS Process, PETHREAD Thread, PVOID DebugPort)
{
    KAPC_STATE ApcState;
    BOOLEAN Attach = FALSE;
    if (Process != PsGetCurrentProcess())
    {
        KeStackAttachProcess(Process, &ApcState);
        Attach = TRUE;
    }
    PEB64* peb64 = (PEB64*)PsGetProcessPeb(Process);
    if (peb64)
    {
        LIST_ENTRY64* ListHead = &((PEB_LDR_DATA64*)peb64->Ldr)->InLoadOrderModuleList;
        for (LIST_ENTRY64* NextEntry = (LIST_ENTRY64*)ListHead->Flink; NextEntry != ListHead; NextEntry = (LIST_ENTRY64*)NextEntry->Flink)
        {
            LDR_DATA_TABLE_ENTRY64* LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
            DbgkPostModuleMessage(Process, Thread, (PVOID)LdrEntry->DllBase, DebugPort);
        }
    }

    PEB32* peb32 = (PEB32*)PsGetProcessWow64Process(Process);
    if (peb32)
    {
        LIST_ENTRY32* ListHead = &((PEB_LDR_DATA32*)peb32->Ldr)->InLoadOrderModuleList;
        for (LIST_ENTRY32* NextEntry = (LIST_ENTRY32*)ListHead->Flink; NextEntry != ListHead; NextEntry = (LIST_ENTRY32*)NextEntry->Flink)
        {
            LDR_DATA_TABLE_ENTRY32* LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
            DbgkPostModuleMessage(Process, Thread, (PVOID)LdrEntry->DllBase, DebugPort);
        }
    }

    if (Attach)
    {
        KeUnstackDetachProcess(&ApcState);
    }
}

BOOLEAN DbgkInitialize()
{
    PVOID ntoskrnl_base = FYLIB::GetSystemModuleBase("ntoskrnl.exe", NULL);
    *(PVOID*)&DbgkpSuspendProcess = (PUCHAR)ntoskrnl_base + 0x0912674;
    *(PVOID*)&PsThawMultiProcess = (PUCHAR)ntoskrnl_base + 0x03DF510;
    *(PVOID*)&PsQueryThreadStartAddress = (PUCHAR)ntoskrnl_base + 0x040FE40;
    *(PVOID*)&MmGetFileNameForAddress = (PUCHAR)ntoskrnl_base + 0x08C1EB8;
    *(PVOID*)&pDbgkpProcessDebugPortMutex = (PUCHAR)ntoskrnl_base + 0x0F8DB40;

    return TRUE;
}

VOID DbgkUnInitialize()
{

}