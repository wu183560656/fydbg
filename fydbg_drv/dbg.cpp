#include <ntifs.h>
#include "ntoskrnl.h"
#include <fylib\fylib.hpp>

namespace dbg
{
	static volatile PVOID _ProcessDebugPortList[0x10000 / 4] = { NULL };
    FAST_MUTEX _ProcessDebugPortList_Mutex;

    static volatile PCONTEXT _ThreadContextList[0x10000 / 4] = { NULL };
    FAST_MUTEX _ThreadContextList_Mutex;

    //一些内部成员
    static BOOLEAN(NTAPI* DbgkpSuspendProcess)(PEPROCESS Process) = NULL;
    static VOID(NTAPI* PsThawMultiProcess)(PEPROCESS Process, ULONG64, ULONG64) = NULL;
    static PVOID(NTAPI* PsQueryThreadStartAddress)(PETHREAD Thread, BOOLEAN Flags) = NULL;  //Flags=FALSE
    static NTSTATUS(NTAPI* MmGetFileNameForAddress)(PVOID Address, PUNICODE_STRING ModuleName) = NULL;
    static PFAST_MUTEX DbgkpProcessDebugPortMutex_ptr = NULL;
    static POBJECT_TYPE DbgkDebugObjectType_ptr = NULL;
    static ULONG EPROCESS_RundownProtect_Offset = 0;
    static NTSTATUS(NTAPI* DbgkpPostFakeProcessCreateMessages)(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD* LastThread) = NULL;

    /*
    static const PIMAGE_NT_HEADERS RtlImageNtHeader(void* ImageBase)
    {
        return (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
    }
    */
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
            ExAcquireFastMutex(DbgkpProcessDebugPortMutex_ptr);

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
            ExReleaseFastMutex(DbgkpProcessDebugPortMutex_ptr);

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
    /*
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

    static VOID DbgkpPostModuleMessages(PEPROCESS Process, PETHREAD Thread, PVOID DebugPort)
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
    */
	static VOID CreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) noexcept
	{
		(ParentId);
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			if (Create)
			{
				DbgkCreateMinimalProcess(Process);
			}
			else
			{
				NTSTATUS ExitStatus = PsGetProcessExitStatus(Process);
				DbgkExitProcess(Process, ExitStatus);
			}
			ObReferenceObject(Process);
		}
	}

	static VOID CreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) noexcept
	{
		PEPROCESS Process = NULL;
		PETHREAD Thread = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &Thread)))
			{
				if (Create)
				{
					DbgkCreateThread(Process, Thread);
				}
				else
				{
					NTSTATUS ExitStatus = PsGetThreadExitStatus(Thread);
					DbgkExitThread(Process, Thread, ExitStatus);
				}
				ObReferenceObject(Thread);
			}
			ObReferenceObject(Process);
		}
	}

	static VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) noexcept
	{
		(FullImageName);
		if (ProcessId)
		{
			PEPROCESS Process = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
			{
				ImageInfo->ImageSelector;
				DbgkMapViewOfSection(Process, ImageInfo->ImageBase);
				ObReferenceObject(Process);
			}
		}
	}

    static PVOID RtlDispatchException_Address = NULL;
	static PVOID RtlDispatchExceptionNewCode_Address = NULL;

    static NTSTATUS DbgkpSetProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT DebugObject, NTSTATUS Status, PETHREAD LastThread)
    {
        (Process);
        (DebugObject);
        (Status);
        (LastThread);
        return STATUS_SUCCESS;
    }
    static NTSTATUS DbgkClearProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT DebugObject)
    {
        (Process);
        (DebugObject);
        return STATUS_SUCCESS;
	}

	NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle)
	{
        PEPROCESS Process;
        PDEBUG_OBJECT DebugObject;
        //KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
        KPROCESSOR_MODE PreviousMode = KernelMode;
        PETHREAD LastThread;
        NTSTATUS Status;
        PAGED_CODE();

        /* Reference the process */
        Status = ObReferenceObjectByHandle(ProcessHandle,
            0x800/*PROCESS_SUSPEND_RESUME*/,
            *PsProcessType,
            PreviousMode,
            (PVOID*)&Process,
            NULL);
        if (!NT_SUCCESS(Status)) return Status;

        /* Don't allow debugging the current process or the system process */
        if ((Process == PsGetCurrentProcess()) ||
            (Process == PsInitialSystemProcess))
        {
            /* Dereference and fail */
            ObDereferenceObject(Process);
            return STATUS_ACCESS_DENIED;
        }

        /* Reference the debug object */
        Status = ObReferenceObjectByHandle(DebugHandle,
            DEBUG_OBJECT_ADD_REMOVE_PROCESS,
            DbgkDebugObjectType_ptr,
            PreviousMode,
            (PVOID*)&DebugObject,
            NULL);
        if (!NT_SUCCESS(Status))
        {
            /* Dereference the process and exit */
            ObDereferenceObject(Process);
            return Status;
        }

        /* Acquire process rundown protection */
        //if (!ExAcquireRundownProtection(&Process->RundownProtect))
        if (!ExAcquireRundownProtection((PEX_RUNDOWN_REF)(PUCHAR)Process + EPROCESS_RundownProtect_Offset))
        {
            /* Dereference the process and debug object and exit */
            ObDereferenceObject(Process);
            ObDereferenceObject(DebugObject);
            return STATUS_PROCESS_IS_TERMINATING;
        }

        /* Send fake create messages for debuggers to have a consistent state */
        Status = DbgkpPostFakeProcessCreateMessages(Process,
            DebugObject,
            &LastThread);
        Status = DbgkpSetProcessDebugObject(Process,
            DebugObject,
            Status,
            LastThread);

        /* Release rundown protection */
        //ExReleaseRundownProtection(&Process->RundownProtect);
        ExReleaseRundownProtection((PEX_RUNDOWN_REF)(PUCHAR)Process + EPROCESS_RundownProtect_Offset);

        /* Dereference the process and debug object and return status */
        ObDereferenceObject(Process);
        ObDereferenceObject(DebugObject);
        return Status;

	}

	NTSTATUS NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugHandle)
	{
        PEPROCESS Process;
        PDEBUG_OBJECT DebugObject;
        KPROCESSOR_MODE PreviousMode = KernelMode;
        NTSTATUS Status;
        PAGED_CODE();

        /* Reference the process */
        Status = ObReferenceObjectByHandle(ProcessHandle,
            0x800/*PROCESS_SUSPEND_RESUME*/,
            *PsProcessType,
            PreviousMode,
            (PVOID*)&Process,
            NULL);
        if (!NT_SUCCESS(Status)) return Status;

        /* Reference the debug object */
        Status = ObReferenceObjectByHandle(DebugHandle,
            DEBUG_OBJECT_ADD_REMOVE_PROCESS,
            DbgkDebugObjectType_ptr,
            PreviousMode,
            (PVOID*)&DebugObject,
            NULL);
        if (!NT_SUCCESS(Status))
        {
            /* Dereference the process and exit */
            ObDereferenceObject(Process);
            return Status;
        }

        /* Remove the debug object */
        Status = DbgkClearProcessDebugObject(Process, DebugObject);

        /* Dereference the process and debug object and return status */
        ObDereferenceObject(Process);
        ObDereferenceObject(DebugObject);
        return Status;
	}

	NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
	{
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
        PETHREAD Thread = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_GET_CONTEXT, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL)))
        {
            //是否32位进程
            BOOLEAN IsWow64 = PsGetProcessWow64Process(PsGetThreadProcess(Thread)) != NULL;
            if (!IsWow64)
            {
                ULONG ThreadId = (ULONG)PsGetThreadId(Thread);
                ExAcquireFastMutex(&_ThreadContextList_Mutex);
                {
                    PCONTEXT Context = _ThreadContextList[ThreadId / 4];
                    if (Context)
                    {
                        if (ThreadContext->ContextFlags & CONTEXT_CONTROL)
                        {
                            ThreadContext->SegCs = Context->SegCs;
                        }
                        if (ThreadContext->ContextFlags & CONTEXT_INTEGER)
                        {
							ThreadContext->Rax = Context->Rax;
							ThreadContext->Rcx = Context->Rcx;
							ThreadContext->Rdx = Context->Rdx;
							ThreadContext->Rbx = Context->Rbx;
							ThreadContext->Rsp = Context->Rsp;
							ThreadContext->Rbp = Context->Rbp;
							ThreadContext->Rsi = Context->Rsi;
							ThreadContext->Rdi = Context->Rdi;
							ThreadContext->R8 = Context->R8;
							ThreadContext->R9 = Context->R9;
							ThreadContext->R10 = Context->R10;
							ThreadContext->R11 = Context->R11;
							ThreadContext->R12 = Context->R12;
							ThreadContext->R13 = Context->R13;
							ThreadContext->R14 = Context->R14;
							ThreadContext->R15 = Context->R15;
							ThreadContext->Rip = Context->Rip;
                        }
                        if (ThreadContext->ContextFlags & CONTEXT_SEGMENTS)
                        {
                            ThreadContext->SegDs = Context->SegDs;
                            ThreadContext->SegEs = Context->SegEs;
                            ThreadContext->SegSs = Context->SegSs;
                            ThreadContext->SegFs = Context->SegFs;
                            ThreadContext->SegGs = Context->SegGs;
                        }
                        if (ThreadContext->ContextFlags & CONTEXT_FLOATING_POINT)
                        {
                            ThreadContext->FltSave = Context->FltSave;
                        }
                        if (ThreadContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)
                        {
                            ThreadContext->Dr0 = Context->Dr0;
                            ThreadContext->Dr1 = Context->Dr1;
                            ThreadContext->Dr2 = Context->Dr2;
                            ThreadContext->Dr3 = Context->Dr3;
                            ThreadContext->Dr6 = Context->Dr6;
                            ThreadContext->Dr7 = Context->Dr7;
                        }
                    }
                }
            }
            ExReleaseFastMutex(&_ThreadContextList_Mutex);
			ObReferenceObject(Thread);
        }
        return Status;
	}

	NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
	{
        (ThreadHandle);
        (ThreadContext);
        return STATUS_NOT_IMPLEMENTED;
	}

    NTSTATUS Initialize()
    {
        PVOID ntoskrnl_base = FYLIB::GetSystemModuleBase("ntoskrnl.exe", NULL);
        *(PVOID*)&DbgkpSuspendProcess = (PUCHAR)ntoskrnl_base + 0x0912674;
        *(PVOID*)&PsThawMultiProcess = (PUCHAR)ntoskrnl_base + 0x03DF510;
        *(PVOID*)&PsQueryThreadStartAddress = (PUCHAR)ntoskrnl_base + 0x040FE40;
        *(PVOID*)&MmGetFileNameForAddress = (PUCHAR)ntoskrnl_base + 0x08C1EB8;
        *(PVOID*)&DbgkpProcessDebugPortMutex_ptr = (PUCHAR)ntoskrnl_base + 0x0F8DB40;
        *(PVOID*)&DbgkDebugObjectType_ptr = (PUCHAR)ntoskrnl_base + 0x0F8DB40;

        //初始化互斥体
        ExInitializeFastMutex(&_ThreadContextList_Mutex);
		ExInitializeFastMutex(&_ProcessDebugPortList_Mutex);
        

        NTSTATUS result;
        if (NT_SUCCESS(result = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE)))
        {
            if (NT_SUCCESS(result = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine)))
            {
                if (NT_SUCCESS(result = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine)))
                {
                    result = STATUS_SUCCESS;



                    if (!NT_SUCCESS(result))
                    {
                        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
                    }
                }
                if (!NT_SUCCESS(result))
                {
                    PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
                }
            }
            if (!NT_SUCCESS(result))
            {
                PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
            }
        }

        return STATUS_SUCCESS;
    }
    VOID UnInitialize()
    {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
        PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
        PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
    }
}