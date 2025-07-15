#include <ntifs.h>
#include "ntoskrnl.h"
#include "dbgk.h"
#include <fylib\include\fylib.hpp>

#pragma warning(disable:4201)

namespace dbgk
{
    static constexpr auto MAX_ID = 0x1000;
    //存放DebugPort
    static volatile PVOID ProcessDebugPortList[MAX_ID / 4] = { NULL };
    //存放ThreadContext
    static volatile PVOID ThreadContextList[MAX_ID / 4] = { NULL };

    inline static PVOID GetDebugPort(PEPROCESS Process)
    {
        return ProcessDebugPortList[(ULONG)(ULONG64)PsGetProcessId(Process) / 4];
    }
    inline static PVOID GetThreadContext(PETHREAD Thread)
    {
        return ThreadContextList[(ULONG)(ULONG64)PsGetThreadId(Thread) / 4];
    }

    static BOOLEAN(NTAPI* DbgkpSuspendProcess)(PEPROCESS Process) = NULL;
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
        //如果Thread不是当前线程无法发送
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
        //如果Thread不是当前线程无法发送
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

    VOID DbgkPostModuleMessages(PEPROCESS Process, PETHREAD Thread)
    {
        if (GetDebugPort(Process))
        {
            DbgkpPostModuleMessages(Process, Thread, NULL);
        }
    }

    BOOLEAN Initialize()
    {
        PVOID ntoskrnl_base = FYLIB::GetSystemModuleBase("ntoskrnl.exe", NULL);
        *(PVOID*)&DbgkpSuspendProcess = (PUCHAR)ntoskrnl_base + 0x0912674;
        *(PVOID*)&PsThawMultiProcess = (PUCHAR)ntoskrnl_base + 0x03DF510;
        *(PVOID*)&PsQueryThreadStartAddress = (PUCHAR)ntoskrnl_base + 0x040FE40;
        *(PVOID*)&MmGetFileNameForAddress = (PUCHAR)ntoskrnl_base + 0x08C1EB8;
        *(PVOID*)&pDbgkpProcessDebugPortMutex = (PUCHAR)ntoskrnl_base + 0x0F8DB40;
        return TRUE;
    }

    VOID UnInitialize()
    {

    }
}
