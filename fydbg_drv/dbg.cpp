#include <ntifs.h>
#include "ntoskrnl.h"
#include <fylib\fylib.hpp>
#include <iocode.h>

namespace dbg
{
	static bool Initialized = false;

	static volatile PDEBUG_OBJECT _ProcessDebugPortList[0x10000 / 4] = { NULL };
    static volatile PCONTEXT _ThreadContextList[0x10000 / 4] = { NULL };
	static volatile PWOW64_CONTEXT _Wow64ThreadContextList[0x10000 / 4] = { NULL };
    //一些内部成员
    static BOOLEAN(NTAPI* DbgkpSuspendProcess)(PEPROCESS Process) = NULL;
    static VOID(NTAPI* PsThawMultiProcess)(PEPROCESS Process, ULONG64, ULONG64) = NULL;
    static PVOID(NTAPI* PsQueryThreadStartAddress)(PETHREAD Thread, BOOLEAN Flags) = NULL;  //Flags=FALSE
    static NTSTATUS(NTAPI* MmGetFileNameForAddress)(PVOID Address, PUNICODE_STRING ModuleName) = NULL;
    static PFAST_MUTEX DbgkpProcessDebugPortMutex_ptr = NULL;
    static POBJECT_TYPE DbgkDebugObjectType_ptr = NULL;
    static ULONG EPROCESS_RundownProtect_Offset = 0;
    static NTSTATUS(NTAPI* DbgkpPostFakeProcessCreateMessages)(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD* LastThread) = NULL;
    static NTSTATUS(NTAPI* DbgkpPostFakeThreadMessages)(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD StartThread, PETHREAD* FirstThread, PETHREAD* LastThread) = NULL;
    static PETHREAD(NTAPI* PsGetNextProcessThread)(IN PEPROCESS 	Process, IN PETHREAD Thread 	OPTIONAL) = NULL;
    static VOID(NTAPI* DbgkpWakeTarget)(PDEBUG_EVENT DebugEvent) = NULL;
    static ULONG ETHREAD_RundownProtect_Offset = 0;

    static VOID PspSetCrossThreadFlag(PETHREAD Thread, LONG Flags)
    {
        UNREFERENCED_PARAMETER(Thread);
        UNREFERENCED_PARAMETER(Flags);
        return;
    }
    static VOID NTAPI DbgkpMarkProcessPeb(IN PEPROCESS 	Process)
    {
        UNREFERENCED_PARAMETER(Process);
        return;
    }
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
            DebugObject = _ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4];
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

    BOOLEAN DbgkForwardException(PEPROCESS Process, PEXCEPTION_RECORD ExceptionRecord, BOOLEAN SecondChance, PCONTEXT UserContext)
    {
        if (!Initialized)
        {
            return FALSE;
        }

        BOOLEAN Result = FALSE;
        if (_ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4])
        {
			ULONG ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
            _ThreadContextList[ThreadId / 4] = UserContext;
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
            _ThreadContextList[ThreadId / 4] = NULL;
        }
        return Result;
    }

    VOID DbgkCreateThread(PEPROCESS Process, PETHREAD Thread)
    {
        if (!Initialized)
        {
            return;
        }

        //如果Thread不是当前线程无法发送
        if (Thread == PsGetCurrentThread())
        {
            if (_ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4])
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
        if (!Initialized)
        {
            return;
        }

        if (_ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4])
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
        if (!Initialized)
        {
            return;
        }

        //如果Thread不是当前线程无法发送
        if (Thread == PsGetCurrentThread())
        {
            if (_ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4])
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
        if (!Initialized)
        {
            return;
        }

        if (_ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4])
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
        if (!Initialized)
        {
            return;
        }

        if (_ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4])
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
        if (!Initialized)
        {
            return;
        }

        if (_ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4])
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
        if (_ProcessDebugPortList[((ULONG)(ULONG_PTR)PsGetProcessId(Process)) / 4])
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

#pragma pack(push, 1)
    /*
    90 90 90 E8 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48 B8 88 77 66 55 44 33 22 11 FF E0 90 90 90 90 48 87 2C 24 48 83 EC 70 48 89 4C 24 58 48 89 54 24 60 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 48 C7 44 24 30 18 00 00 00 48 8D 44 24 58 48 89 44 24 28 48 C7 44 24 20 78 56 34 12 4C 8D 4C 24 48 4D 31 C0 48 31 D2 48 8B 4D 00 48 8B 45 08 48 C7 44 24 68 01 00 00 00 FF D0 85 C0 B0 01 74 3A 48 8B 4C 24 58 48 8B 54 24 60 48 8D 45 10 FF D0 84 C0 75 26 4C 8D 4C 24 48 4D 31 C0 48 31 D2 48 8B 4D 00 48 8B 45 08 48 C7 44 24 68 00 00 00 00 FF D0 85 C0 B0 01 74 02 30 C0 48 83 C4 70 5D C3
    */
    struct
    {
        /*
        0000017E8DFF0000 | 90                         | nop                                     |
        0000017E8DFF0001 | 90                         | nop                                     |
        0000017E8DFF0002 | 90                         | nop                                     |
        0000017E8DFF0003 | E8 30000000                | call 17E8DFF0038                        | CALL 0
        */
        UCHAR const_code_1[0x8] = { 0x90,0x90,0x90,0xe8,0x30,0x00,0x00,0x00 };
        ULONG64 DeviceHandle = 0;
        ULONG64 NtDeviceIoControlFile = 0;
        //offset=0x18
        UCHAR RtlDispatchExceptionOldCode[0x10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
        /*
        mov rax,0x1122334455667788
        */
        UCHAR const_code_2[0x2] = { 0x48,0xb8/*,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11*/ };

        ULONG64 RtlDispatchExceptionJmpAddress = 0;
        /*
        jmp rax
        */
        UCHAR const_code_3[0x6] = { 0xFF,0xE0,0x90,0x90,0x90,0x90 };
        //offset=0x38
            /*
            *
            0000017E8DFF0038 | 48:872C24                  | xchg qword ptr ss:[rsp],rbp             |
            0000017E8DFF003C | 48:83EC 70                 | sub rsp,70                              |
            0000017E8DFF0040 | 48:894C24 58               | mov qword ptr ss:[rsp+58],rcx           |	FORWARD_EXCEPTION_PARAM.ExceptionRecord
            0000017E8DFF0045 | 48:895424 60               | mov qword ptr ss:[rsp+60],rdx           |	FORWARD_EXCEPTION_PARAM.pContext
            0000017E8DFF004A | 48:C74424 40 00000000      | mov qword ptr ss:[rsp+40],0             |	OutputBufferLength
            0000017E8DFF0053 | 48:C74424 38 00000000      | mov qword ptr ss:[rsp+38],0             |	OutputBuffer
            0000017E8DFF005C | 48:C74424 30 18000000      | mov qword ptr ss:[rsp+30],18            |	InputBufferLength
            0000017E8DFF0065 | 48:8D4424 58               | lea rax,qword ptr ss:[rsp+58]           |
            0000017E8DFF006A | 48:894424 28               | mov qword ptr ss:[rsp+28],rax           |	InputBuffer
            0000017E8DFF006F | 48:C74424 20 78563412      | mov qword ptr ss:[rsp+20],12345678      |	IoControlCode
            */
        UCHAR const_code_4[0x3C] = { 0x48,0x87,0x2c,0x24,0x48,0x83,0xec,0x70,0x48,0x89,0x4c,0x24,0x58,0x48,0x89,0x54,0x24,0x60,0x48,0xc7,0x44,0x24,0x40,0x00,0x00,0x00,0x00,0x48,0xc7,0x44,0x24,0x38,0x00,0x00,0x00,0x00,0x48,0xc7,0x44,0x24,0x30,0x18,0x00,0x00,0x00,0x48,0x8d,0x44,0x24,0x58,0x48,0x89,0x44,0x24,0x28,0x48,0xc7,0x44,0x24,0x20/*,0x78,0x56,0x34,0x12*/ };
        ULONG32 IoCode = IO_CODE_FORWARD_EXCEPTION;
        /*
        0000017E8DFF0078 | 4C:8D4C24 48               | lea r9,qword ptr ss:[rsp+48]            |	IoStatusBlock
        0000017E8DFF007D | 4D:31C0                    | xor r8,r8                               |	ApcContext
        0000017E8DFF0080 | 48:31D2                    | xor rdx,rdx                             |	ApcRoutine
        0000017E8DFF0083 | 48:8B4D 00                 | mov rcx,qword ptr ss:[rbp]              |	DeviceHandle
        0000017E8DFF0087 | 48:8B45 08                 | mov rax,qword ptr ss:[rbp+8]            |
        0000017E8DFF008B | 48:C74424 68 01000000      | mov qword ptr ss:[rsp+68],1             |	FORWARD_EXCEPTION_PARAM.First = TRUE
        0000017E8DFF0094 | FFD0                       | call rax                                |	call NtDeviceIoControlFile
        0000017E8DFF0096 | 85C0                       | test eax,eax                            |
        0000017E8DFF0098 | B0 01                      | mov al,1                                |
        0000017E8DFF009A | 74 3A                      | je 17E8DFF00D6                          |
        0000017E8DFF009C | 48:8B4C24 58               | mov rcx,qword ptr ss:[rsp+58]           |	ExceptionRecord
        0000017E8DFF00A1 | 48:8B5424 60               | mov rdx,qword ptr ss:[rsp+60]           |	pContext
        0000017E8DFF00A6 | 48:8D45 10                 | lea rax,qword ptr ss:[rbp+10]           |
        0000017E8DFF00AA | FFD0                       | call rax                                |	call OldRtlDispatchExceptionNewCode
        0000017E8DFF00AC | 84C0                       | test al,al                              |
        0000017E8DFF00AE | 75 26                      | jne 17E8DFF00D6                         |
        0000017E8DFF00B0 | 4C:8D4C24 48               | lea r9,qword ptr ss:[rsp+48]            |	IoStatusBlock
        0000017E8DFF00B5 | 4D:31C0                    | xor r8,r8                               |	ApcContext
        0000017E8DFF00B8 | 48:31D2                    | xor rdx,rdx                             |	ApcRoutine
        0000017E8DFF00BB | 48:8B4D 00                 | mov rcx,qword ptr ss:[rbp]              |	DeviceHandle
        0000017E8DFF00BF | 48:8B45 08                 | mov rax,qword ptr ss:[rbp+8]            |
        0000017E8DFF00C3 | 48:C74424 68 00000000      | mov qword ptr ss:[rsp+68],0             |	FORWARD_EXCEPTION_PARAM.First = FALSE
        0000017E8DFF00CC | FFD0                       | call rax                                |	call NtDeviceIoControlFile
        0000017E8DFF00CE | 85C0                       | test eax,eax                            |
        0000017E8DFF00D0 | B0 01                      | mov al,1                                |
        0000017E8DFF00D2 | 74 02                      | je 17E8DFF00D6                          |
        0000017E8DFF00D4 | 30C0                       | xor al,al                               |
        0000017E8DFF00D6 | 48:83C4 70                 | add rsp,70                              |
        0000017E8DFF00DA | 5D                         | pop rbp                                 |
        0000017E8DFF00DB | C3                         | ret                                     |
        */
        UCHAR const_code_5[0x64] = { 0x4c,0x8d,0x4c,0x24,0x48,0x4d,0x31,0xc0,0x48,0x31,0xd2,0x48,0x8b,0x4d,0x00,0x48,0x8b,0x45,0x08,0x48,0xc7,0x44,0x24,0x68,0x01,0x00,0x00,0x00,0xff,0xd0,0x85,0xc0,0xb0,0x01,0x74,0x3a,0x48,0x8b,0x4c,0x24,0x58,0x48,0x8b,0x54,0x24,0x60,0x48,0x8d,0x45,0x10,0xff,0xd0,0x84,0xc0,0x75,0x26,0x4c,0x8d,0x4c,0x24,0x48,0x4d,0x31,0xc0,0x48,0x31,0xd2,0x48,0x8b,0x4d,0x00,0x48,0x8b,0x45,0x08,0x48,0xc7,0x44,0x24,0x68,0x00,0x00,0x00,0x00,0xff,0xd0,0x85,0xc0,0xb0,0x01,0x74,0x02,0x30,0xc0,0x48,0x83,0xc4,0x70,0x5d,0xc3 };
    }RtlDispatchExceptionNewCode;
    /*
    90 90 90 E8 18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 B8 44 33 22 11 FF E0 90 87 2C 24 83 EC 40 8B 44 24 48 89 44 24 20 C7 44 24 24 00 00 00 00 8B 44 24 4C 89 44 24 28 C7 44 24 2C 00 00 00 00 C7 44 24 30 00 00 00 00 C7 44 24 34 00 00 00 00 6A 00 6A 00 6A 18 8D 44 24 20 50 68 44 33 22 11 8D 44 24 10 50 6A 00 6A 00 8B 45 00 50 8B 45 08 C7 44 24 30 01 00 00 00 FF D0 85 C0 B0 01 74 45 8B 44 24 20 50 8B 44 24 28 50 8D 45 10 FF D0 84 C0 75 32 6A 00 6A 00 6A 18 8D 44 24 20 50 68 44 33 22 11 8D 44 24 10 50 6A 00 6A 00 8B 45 00 50 8B 45 08 C7 44 24 30 00 00 00 00 FF D0 85 C0 B0 01 74 02 30 C0 83 C4 40 5D C2 08 00
    */
    struct
    {
        /*
            01400000 | 90                       | nop                           |
            01400001 | 90                       | nop                           |
            01400002 | 90                       | nop                           |
            01400003 | E8 18000000              | call 1400020                  | call 0
        */
        UCHAR const_code_1[8] = { 0x90,0x90,0x90,0xe8,0x30,0x00,0x00,0x00 };
        ULONG64 DeviceHandle = 0;
        ULONG64 NtDeviceIoControlFile = 0;
        //offset=0x18
        UCHAR RtlDispatchExceptionOldCode[0x10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
        /*
        mov eax,0x11223344
        */
        UCHAR const_code_2[0x1] = { 0xb8/*,0x44,0x33,0x22,0x11*/ };

        ULONG32 RtlDispatchExceptionJmpAddress = 0;
        /*
        jmp eax
        */
        UCHAR const_code_3[0x3] = { 0xFF,0xE0,0x90 };
        //offset=0x30
        /*
        01400030 | 872C24                   | xchg dword ptr ss:[esp],ebp                |
        01400033 | 83EC 40                  | sub esp,40                                 |
        01400036 | 8B4424 48                | mov eax,dword ptr ss:[esp+48]              |
        0140003A | 894424 20                | mov dword ptr ss:[esp+20],eax              |	FORWARD_EXCEPTION_PARAM.ExceptionRecord
        0140003E | C74424 24 00000000       | mov dword ptr ss:[esp+24],0                |
        01400046 | 8B4424 4C                | mov eax,dword ptr ss:[esp+4C]              |
        0140004A | 894424 28                | mov dword ptr ss:[esp+28],eax              |	FORWARD_EXCEPTION_PARAM.pContext
        0140004E | C74424 2C 00000000       | mov dword ptr ss:[esp+2C],0                |
        01400056 | C74424 30 00000000       | mov dword ptr ss:[esp+30],0                |
        0140005E | C74424 34 00000000       | mov dword ptr ss:[esp+34],0                |
        01400066 | C74424 38 44332211       | mov dword ptr ss:[esp+38],11223344         |
        */
        UCHAR const_code_4[0x3A] = { 0x87,0x2c,0x24,0x83,0xec,0x40,0x8b,0x44,0x24,0x48,0x89,0x44,0x24,0x20,0xc7,0x44,0x24,0x24,0x00,0x00,0x00,0x00,0x8b,0x44,0x24,0x4c,0x89,0x44,0x24,0x28,0xc7,0x44,0x24,0x2c,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x30,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x34,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x38/*,0x44,0x33,0x22,0x11 */ };
        ULONG32 IoCode = IO_CODE_FORWARD_EXCEPTION;
        /*
        0140006E | 6A 00                    | push 0                                     |	OutputBufferLength
        01400070 | 6A 00                    | push 0                                     |	OutputBuffer
        01400072 | 6A 18                    | push 18                                    |	InputBufferLength
        01400074 | 8D4424 20                | lea eax,dword ptr ss:[esp+20]              |
        01400078 | 50                       | push eax                                   |	InputBuffer
        01400079 | 8B4424 38                | mov eax,dword ptr ss:[esp+38]              |
        0140007D | 50                       | push eax                                   |	IoControlCode
        0140007E | 8D4424 10                | lea eax,dword ptr ss:[esp+10]              |
        01400082 | 50                       | push eax                                   |	IoStatusBlock
        01400083 | 6A 00                    | push 0                                     |	ApcContext
        01400085 | 6A 00                    | push 0                                     |	ApcRoutine
        01400087 | 8B45 00                  | mov eax,dword ptr ss:[ebp]                 |
        0140008A | 50                       | push eax                                   |	DeviceHandle
        0140008B | 8B45 08                  | mov eax,dword ptr ss:[ebp+8]               |
        0140008E | C74424 30 01000000       | mov dword ptr ss:[esp+30],1                |	FORWARD_EXCEPTION_PARAM.First = TRUE
        01400096 | FFD0                     | call eax                                   |	call NtDeviceIoControlFile
        01400098 | 85C0                     | test eax,eax                               |
        0140009A | B0 01                    | mov al,1                                   |
        0140009C | 74 45                    | je 14000E3                                 |
        0140009E | 8B4424 20                | mov eax,dword ptr ss:[esp+20]              |
        014000A2 | 50                       | push eax                                   |	ExceptionRecord
        014000A3 | 8B4424 28                | mov eax,dword ptr ss:[esp+28]              |
        014000A7 | 50                       | push eax                                   |	pContext
        014000A8 | 8D45 10                  | lea eax,dword ptr ss:[ebp+10]              |
        014000AB | FFD0                     | call eax                                   |	call OldRtlDispatchExceptionNewCode
        014000AD | 84C0                     | test al,al                                 |
        014000AF | 75 32                    | jne 14000E3                                |
        014000B1 | 6A 00                    | push 0                                     |	OutputBufferLength
        014000B3 | 6A 00                    | push 0                                     |	OutputBuffer
        014000B5 | 6A 18                    | push 18                                    |	InputBufferLength
        014000B7 | 8D4424 20                | lea eax,dword ptr ss:[esp+20]              |
        014000BB | 50                       | push eax                                   |	InputBuffer
        014000BC | 8B4424 38                | mov eax,dword ptr ss:[esp+38]              |
        014000C0 | 50                       | push eax                                   |	IoControlCode
        014000C1 | 8D4424 10                | lea eax,dword ptr ss:[esp+10]              |
        014000C5 | 50                       | push eax                                   |	IoStatusBlock
        014000C6 | 6A 00                    | push 0                                     |	ApcContext
        014000C8 | 6A 00                    | push 0                                     |	ApcRoutine
        014000CA | 8B45 00                  | mov eax,dword ptr ss:[ebp]                 |
        014000CD | 50                       | push eax                                   |	DeviceHandle
        014000CE | 8B45 08                  | mov eax,dword ptr ss:[ebp+8]               |
        014000D1 | C74424 30 00000000       | mov dword ptr ss:[esp+30],0                |	FORWARD_EXCEPTION_PARAM.First = FALSE
        014000D9 | FFD0                     | call eax                                   |	call NtDeviceIoControlFile
        014000DB | 85C0                     | test eax,eax                               |
        014000DD | B0 01                    | mov al,1                                   |
        014000DF | 74 02                    | je 14000E3                                 |
        014000E1 | 30C0                     | xor al,al                                  |
        014000E3 | 83C4 40                  | add esp,40                                 |
        014000E6 | 5D                       | pop ebp                                    |
        014000E7 | C2 0800                  | ret 8                                      |
        */
        UCHAR const_code_5[0x7C] = { 0x6a,0x00,0x6a,0x00,0x6a,0x18,0x8d,0x44,0x24,0x20,0x50,0x8b,0x44,0x24,0x38,0x50,0x8d,0x44,0x24,0x10,0x50,0x6a,0x00,0x6a,0x00,0x8b,0x45,0x00,0x50,0x8b,0x45,0x08,0xc7,0x44,0x24,0x30,0x01,0x00,0x00,0x00,0xff,0xd0,0x85,0xc0,0xb0,0x01,0x74,0x45,0x8b,0x44,0x24,0x20,0x50,0x8b,0x44,0x24,0x28,0x50,0x8d,0x45,0x10,0xff,0xd0,0x84,0xc0,0x75,0x32,0x6a,0x00,0x6a,0x00,0x6a,0x18,0x8d,0x44,0x24,0x20,0x50,0x8b,0x44,0x24,0x38,0x50,0x8d,0x44,0x24,0x10,0x50,0x6a,0x00,0x6a,0x00,0x8b,0x45,0x00,0x50,0x8b,0x45,0x08,0xc7,0x44,0x24,0x30,0x00,0x00,0x00,0x00,0xff,0xd0,0x85,0xc0,0xb0,0x01,0x74,0x02,0x30,0xc0,0x83,0xc4,0x40,0x5d,0xc2,0x08,0x00 };
    }Wow64RtlDispatchExceptionNewCode;
#pragma pack(pop)
    static PVOID RtlDispatchExceptionAddress = NULL;
    static PVOID RtlDispatchExceptionNewCodeAddress = NULL;
    static UCHAR RtlDispatchExceptionJmpCodeBuffer[5] = { 0x90,0x90,0x90,0x90,0x90 };
    static UCHAR RtlDispatchExceptioBackCode[5] = { 0x90,0x90,0x90,0x90,0x90 };
    static PVOID Wow64RtlDispatchExceptionAddress = NULL;
    static PVOID Wow64RtlDispatchExceptionNewCodeAddress = NULL;
    static UCHAR Wow64RtlDispatchExceptionJmpCodeBuffer[5] = { 0x90,0x90,0x90,0x90,0x90 };
    static UCHAR Wow64RtlDispatchExceptioBackCode[5] = { 0x90,0x90,0x90,0x90,0x90 };

    static VOID DbgkpAddProcessUserExceptionFiltering(PEPROCESS Process)
    {
        if(PsGetProcessWow64Process(Process))
        {
            
        }
        else
        {

        }
    }
    static VOID DbgkpRemoveProcessUserExceptionFiltering(PEPROCESS Process)
    {
        if (PsGetProcessWow64Process(Process))
        {

        }
        else
        {

        }
    }

    static NTSTATUS DbgkpSetProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT DebugObject, NTSTATUS MsgStatus, PETHREAD LastThread)
    {
        ULONG ProcessDebugObjectListIndex = (ULONG)(ULONG_PTR)PsGetProcessId(Process) / 4;

        NTSTATUS Status;
        LIST_ENTRY TempList;
        BOOLEAN GlobalHeld = FALSE, DoSetEvent = TRUE;
        PETHREAD ThisThread, FirstThread;
        PLIST_ENTRY NextEntry;
        PDEBUG_EVENT DebugEvent;
        PETHREAD EventThread;
        PAGED_CODE();

        /* Initialize the temporary list */
        InitializeListHead(&TempList);

        /* Check if we have a success message */
        if (NT_SUCCESS(MsgStatus))
        {
            /* Then default to STATUS_SUCCESS */
            Status = STATUS_SUCCESS;
        }
        else
        {
            /* No last thread, and set the failure code */
            LastThread = NULL;
            Status = MsgStatus;
        }

        /* Now check what status we have here */
        if (NT_SUCCESS(Status))
        {
            /* Acquire the global lock */
        ThreadScan:
            GlobalHeld = TRUE;
            //ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
            ExAcquireFastMutex(DbgkpProcessDebugPortMutex_ptr);

            /* Check if we already have a port */
            //if (Process->DebugPort)
            if(_ProcessDebugPortList[ProcessDebugObjectListIndex])
            {
                /* Set failure */
                Status = STATUS_PORT_ALREADY_SET;
            }
            else
            {
                /* Otherwise, set the port and reference the thread */
                //Process->DebugPort = DebugObject;
                _ProcessDebugPortList[ProcessDebugObjectListIndex] = DebugObject;
				DbgkpAddProcessUserExceptionFiltering(Process);

                ObReferenceObject(LastThread);

                /* Get the next thread */
                ThisThread = PsGetNextProcessThread(Process, LastThread);
                if (ThisThread)
                {
                    /* Clear the debug port and release the lock */
                    //Process->DebugPort = NULL;
                    _ProcessDebugPortList[ProcessDebugObjectListIndex] = NULL;
                    //ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
                    ExReleaseFastMutex(DbgkpProcessDebugPortMutex_ptr);
                    GlobalHeld = FALSE;

                    /* Dereference the thread */
                    ObDereferenceObject(LastThread);

                    /* Post fake messages */
                    Status = DbgkpPostFakeThreadMessages(Process,
                        DebugObject,
                        ThisThread,
                        &FirstThread,
                        &LastThread);
                    if (!NT_SUCCESS(Status))
                    {
                        /* Clear the last thread */
                        LastThread = NULL;
                    }
                    else
                    {
                        /* Dereference the first thread and re-acquire the lock */
                        ObDereferenceObject(FirstThread);
                        goto ThreadScan;
                    }
                }
            }
        }

        /* Acquire the debug object's lock */
        ExAcquireFastMutex(&DebugObject->Mutex);

        /* Check our status here */
        if (NT_SUCCESS(Status))
        {
            /* Check if we're disconnected */
            if (DebugObject->DebuggerInactive)
            {
                /* Set status */
                //Process->DebugPort = NULL;
                _ProcessDebugPortList[ProcessDebugObjectListIndex] = NULL;
                Status = STATUS_DEBUGGER_INACTIVE;
            }
            else
            {
                /* Set the process flags */
                /*
                PspSetProcessFlag(Process,
                    PSF_NO_DEBUG_INHERIT_BIT |
                    PSF_CREATE_REPORTED_BIT);
*/
                /* Reference the debug object */
                ObReferenceObject(DebugObject);
            }
        }

        /* Loop the events list */
        NextEntry = DebugObject->EventList.Flink;
        while (NextEntry != &DebugObject->EventList)
        {
            /* Get the debug event and go to the next entry */
            DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);
            NextEntry = NextEntry->Flink;

            /* Check for if the debug event queue needs flushing */
            if ((DebugEvent->Flags & DEBUG_EVENT_INACTIVE) &&
                (DebugEvent->BackoutThread == PsGetCurrentThread()))
            {
                /* Get the event's thread */
                EventThread = DebugEvent->Thread;

                /* Check if the status is success */
                if ((MsgStatus == STATUS_SUCCESS) &&
                    //(EventThread->GrantedAccess) &&
                    //(!EventThread->SystemThread))
                    !PsIsSystemThread(EventThread))
                {
                    /* Check if we couldn't acquire rundown for it */
                    if (DebugEvent->Flags & DEBUG_EVENT_PROTECT_FAILED)
                    {
                        /* Set the skip termination flag */
                        //PspSetCrossThreadFlag(EventThread, CT_SKIP_CREATION_MSG_BIT);
                        PspSetCrossThreadFlag(EventThread, 0x80/*CT_SKIP_CREATION_MSG_BIT*/);

                        /* Insert it into the temp list */
                        RemoveEntryList(&DebugEvent->EventList);
                        InsertTailList(&TempList, &DebugEvent->EventList);
                    }
                    else
                    {
                        /* Do we need to signal the event */
                        if (DoSetEvent)
                        {
                            /* Do it */
                            DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
                            KeSetEvent(&DebugObject->EventsPresent,
                                IO_NO_INCREMENT,
                                FALSE);
                            DoSetEvent = FALSE;
                        }

                        /* Clear the backout thread */
                        DebugEvent->BackoutThread = NULL;

                        /* Set skip flag */
                        //PspSetCrossThreadFlag(EventThread, CT_SKIP_CREATION_MSG_BIT);
                        PspSetCrossThreadFlag(EventThread, 0x80/*CT_SKIP_CREATION_MSG_BIT*/);
                    }
                }
                else
                {
                    /* Insert it into the temp list */
                    RemoveEntryList(&DebugEvent->EventList);
                    InsertTailList(&TempList, &DebugEvent->EventList);
                }

                /* Check if the lock is held */
                if (DebugEvent->Flags & DEBUG_EVENT_RELEASE)
                {
                    /* Release it */
                    DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
                    //ExReleaseRundownProtection(&EventThread->RundownProtect);
                    ExReleaseRundownProtection((PEX_RUNDOWN_REF)((PUCHAR)EventThread + ETHREAD_RundownProtect_Offset));
                }
            }
        }

        /* Release the debug object */
        ExReleaseFastMutex(&DebugObject->Mutex);

        /* Release the global lock if acquired */
        //if (GlobalHeld) ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
        if (GlobalHeld) ExReleaseFastMutex(DbgkpProcessDebugPortMutex_ptr);

        /* Check if there's a thread to dereference */
        if (LastThread) ObDereferenceObject(LastThread);

        /* Loop our temporary list */
        while (!IsListEmpty(&TempList))
        {
            /* Remove the event */
            NextEntry = RemoveHeadList(&TempList);
            DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);

            /* Wake it */
            DbgkpWakeTarget(DebugEvent);
        }

        /* Check if we got here through success and mark the PEB, then return */
        if (NT_SUCCESS(Status)) DbgkpMarkProcessPeb(Process);
        return Status;
    }
    static NTSTATUS DbgkClearProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT SourceDebugObject)
    {
        ULONG ProcessDebugObjectListIndex = (ULONG)(ULONG_PTR)PsGetProcessId(Process) / 4;

        PDEBUG_OBJECT DebugObject;
        PDEBUG_EVENT DebugEvent;
        LIST_ENTRY TempList;
        PLIST_ENTRY NextEntry;
        PAGED_CODE();

        /* Acquire the port lock */
        //ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
        ExAcquireFastMutex(DbgkpProcessDebugPortMutex_ptr);

        /* Get the Process Debug Object */
        //DebugObject = Process->DebugPort;
		DbgkpRemoveProcessUserExceptionFiltering(Process);
        DebugObject = _ProcessDebugPortList[ProcessDebugObjectListIndex];
        /*
         * Check if the process had an object and it matches,
         * or if the process had an object but none was specified
         * (in which we are called from NtTerminateProcess)
         */
        if ((DebugObject) &&
            ((DebugObject == SourceDebugObject) ||
                (SourceDebugObject == NULL)))
        {
            /* Clear the debug port */
            //Process->DebugPort = NULL;
            _ProcessDebugPortList[ProcessDebugObjectListIndex] = NULL;

            /* Release the port lock and remove the PEB flag */
            //ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
            ExReleaseFastMutex(DbgkpProcessDebugPortMutex_ptr);
            DbgkpMarkProcessPeb(Process);
        }
        else
        {
            /* Release the port lock and fail */
            //ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
            ExReleaseFastMutex(DbgkpProcessDebugPortMutex_ptr);
            return STATUS_PORT_NOT_SET;
        }

        /* Initialize the temporary list */
        InitializeListHead(&TempList);

        /* Acquire the Object */
        ExAcquireFastMutex(&DebugObject->Mutex);

        /* Loop the events */
        NextEntry = DebugObject->EventList.Flink;
        while (NextEntry != &DebugObject->EventList)
        {
            /* Get the Event and go to the next entry */
            DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);
            NextEntry = NextEntry->Flink;

            /* Check that it belongs to the specified process */
            if (DebugEvent->Process == Process)
            {
                /* Insert it into the temporary list */
                RemoveEntryList(&DebugEvent->EventList);
                InsertTailList(&TempList, &DebugEvent->EventList);
            }
        }

        /* Release the Object */
        ExReleaseFastMutex(&DebugObject->Mutex);

        /* Release the initial reference */
        ObDereferenceObject(DebugObject);

        /* Loop our temporary list */
        while (!IsListEmpty(&TempList))
        {
            /* Remove the event */
            NextEntry = RemoveHeadList(&TempList);
            DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);

            /* Wake it up */
            DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
            DbgkpWakeTarget(DebugEvent);
        }

        /* Return Success */
        return STATUS_SUCCESS;
	}

	NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle)
	{
        if (!Initialized)
        {
			return STATUS_UNSUCCESSFUL;
        }

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
        if (!Initialized)
        {
            return STATUS_UNSUCCESSFUL;
        }

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
        if (!Initialized)
        {
            return STATUS_UNSUCCESSFUL;
        }

		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
        PETHREAD Thread = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_GET_CONTEXT, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL)))
        {
            //是否32位进程
            BOOLEAN IsWow64 = PsGetProcessWow64Process(PsGetThreadProcess(Thread)) != NULL;
            if (!IsWow64)
            {
                ULONG ThreadId = (ULONG)(ULONG_PTR)PsGetThreadId(Thread);
                PCONTEXT Context = _ThreadContextList[ThreadId / 4];
                if (Context)
                {
                    if (ThreadContext->ContextFlags & CONTEXT_INTEGER)
                    {
                        ThreadContext->Rax = Context->Rax;
                        ThreadContext->Rcx = Context->Rcx;
                        ThreadContext->Rdx = Context->Rdx;
                        ThreadContext->Rbx = Context->Rbx;
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
                    }
                    if (ThreadContext->ContextFlags & CONTEXT_FLOATING_POINT)
                    {
                        ThreadContext->MxCsr = Context->MxCsr;
                        ThreadContext->FltSave = Context->FltSave;
                    }
                    if (ThreadContext->ContextFlags & CONTEXT_CONTROL)
                    {
                        ThreadContext->Rip = Context->Rip;
                        ThreadContext->Rsp = Context->Rsp;
                        ThreadContext->EFlags = Context->EFlags;
                        ThreadContext->SegCs = Context->SegCs;
                        ThreadContext->SegSs = Context->SegSs;
                    }
                    if (ThreadContext->ContextFlags & CONTEXT_SEGMENTS)
                    {
                        ThreadContext->SegDs = Context->SegDs;
                        ThreadContext->SegEs = Context->SegEs;
                        ThreadContext->SegFs = Context->SegFs;
                        ThreadContext->SegGs = Context->SegGs;
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
                    Status = STATUS_SUCCESS;
                }
            }
			ObReferenceObject(Thread);
        }
        return Status;
	}

	NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
	{
        if (!Initialized)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
        PETHREAD Thread = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_GET_CONTEXT, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL)))
        {
            //是否32位进程
            BOOLEAN IsWow64 = PsGetProcessWow64Process(PsGetThreadProcess(Thread)) != NULL;
            if (!IsWow64)
            {
                ULONG ThreadId = (ULONG)(ULONG_PTR)PsGetThreadId(Thread);
                PCONTEXT Context = _ThreadContextList[ThreadId / 4];
                if (Context)
                {
                    if (ThreadContext->ContextFlags & CONTEXT_INTEGER)
                    {
                        Context->Rax = ThreadContext->Rax;
                        Context->Rcx = ThreadContext->Rcx;
                        Context->Rdx = ThreadContext->Rdx;
                        Context->Rbx = ThreadContext->Rbx;
                        Context->Rbp = ThreadContext->Rbp;
                        Context->Rsi = ThreadContext->Rsi;
                        Context->Rdi = ThreadContext->Rdi;
                        Context->R8 = ThreadContext->R8;
                        Context->R9 = ThreadContext->R9;
                        Context->R10 = ThreadContext->R10;
                        Context->R11 = ThreadContext->R11;
                        Context->R12 = ThreadContext->R12;
                        Context->R13 = ThreadContext->R13;
                        Context->R14 = ThreadContext->R14;
                        Context->R15 = ThreadContext->R15;
                    }
                    if (ThreadContext->ContextFlags & CONTEXT_FLOATING_POINT)
                    {
						Context->MxCsr = ThreadContext->MxCsr;
                        Context->FltSave = ThreadContext->FltSave;
                    }
                    if (ThreadContext->ContextFlags & CONTEXT_CONTROL)
                    {
						Context->Rip = ThreadContext->Rip;
						Context->Rsp = ThreadContext->Rsp;
                        Context->EFlags = ThreadContext->EFlags;
                        Context->SegCs = ThreadContext->SegCs;
                        Context->SegSs = ThreadContext->SegSs;
                    }
                    if (ThreadContext->ContextFlags & CONTEXT_SEGMENTS)
                    {
                         Context->SegDs = ThreadContext->SegDs;
                         Context->SegEs = ThreadContext->SegEs;
                         Context->SegFs = ThreadContext->SegFs;
                         Context->SegGs = ThreadContext->SegGs;
                    }
                    if (ThreadContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)
                    {
                        Context->Dr0 = ThreadContext->Dr0;
                        Context->Dr1 = ThreadContext->Dr1;
                        Context->Dr2 = ThreadContext->Dr2;
                        Context->Dr3 = ThreadContext->Dr3;
                        Context->Dr6 = ThreadContext->Dr6;
                        Context->Dr7 = ThreadContext->Dr7;
                    }
                    Status = STATUS_SUCCESS;
                }
            }
            ObReferenceObject(Thread);
        }
        return Status;
	}
    NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
    {
        if (!Initialized)
        {
            return STATUS_UNSUCCESSFUL;
        }

        if (ThreadInformationClass != THREADINFOCLASS::ThreadWow64Context || ThreadInformationLength < sizeof(WOW64_CONTEXT))
        {
            return STATUS_NOT_IMPLEMENTED;
        }
		PWOW64_CONTEXT BufferContext = (PWOW64_CONTEXT)ThreadInformation;
        NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
        PETHREAD Thread = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_GET_CONTEXT, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL)))
        {
            //是否32位进程
            BOOLEAN IsWow64 = PsGetProcessWow64Process(PsGetThreadProcess(Thread)) != NULL;
            if (IsWow64)
            {
                ULONG ThreadId = (ULONG)(ULONG_PTR)PsGetThreadId(Thread);
                PWOW64_CONTEXT Context = _Wow64ThreadContextList[ThreadId / 4];
                if (Context)
                {
                    if(BufferContext->ContextFlags & WOW64_CONTEXT_INTEGER)
                    {
                        BufferContext->Eax = Context->Eax;
                        BufferContext->Ecx = Context->Ecx;
                        BufferContext->Edx = Context->Edx;
                        BufferContext->Ebx = Context->Ebx;
                        BufferContext->Ebp = Context->Ebp;
                        BufferContext->Esi = Context->Esi;
                        BufferContext->Edi = Context->Edi;
					}
                    if(BufferContext->ContextFlags & WOW64_CONTEXT_FLOATING_POINT)
                    {
                        BufferContext->FloatSave = Context->FloatSave;
					}
                    if (BufferContext->ContextFlags & WOW64_CONTEXT_CONTROL)
                    {
                        BufferContext->Eip = Context->Eip;
                        BufferContext->Esp = Context->Esp;
                        BufferContext->EFlags = Context->EFlags;
                        BufferContext->SegCs = Context->SegCs;
                        BufferContext->SegSs = Context->SegSs;
                    }
                    if(BufferContext->ContextFlags & WOW64_CONTEXT_SEGMENTS)
                    {
                        BufferContext->SegDs = Context->SegDs;
                        BufferContext->SegEs = Context->SegEs;
                        BufferContext->SegFs = Context->SegFs;
                        BufferContext->SegGs = Context->SegGs;
					}
                    if (BufferContext->ContextFlags & WOW64_CONTEXT_DEBUG_REGISTERS)
                    {
                        BufferContext->Dr0 = Context->Dr0;
                        BufferContext->Dr1 = Context->Dr1;
                        BufferContext->Dr2 = Context->Dr2;
                        BufferContext->Dr3 = Context->Dr3;
                        BufferContext->Dr6 = Context->Dr6;
                        BufferContext->Dr7 = Context->Dr7;
                    }
                    if (ReturnLength)
                    {
						*ReturnLength = sizeof(WOW64_CONTEXT);
                    }
					Status = STATUS_SUCCESS;
                }
            }
            ObReferenceObject(Thread);
        }
        return Status;
    }
    NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
    {
        if (!Initialized)
        {
            return STATUS_UNSUCCESSFUL;
        }

        if (ThreadInformationClass != THREADINFOCLASS::ThreadWow64Context || ThreadInformationLength < sizeof(WOW64_CONTEXT))
        {
            return STATUS_NOT_IMPLEMENTED;
        }
        PWOW64_CONTEXT BufferContext = (PWOW64_CONTEXT)ThreadInformation;
        NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
        PETHREAD Thread = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_GET_CONTEXT, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL)))
        {
            //是否32位进程
            BOOLEAN IsWow64 = PsGetProcessWow64Process(PsGetThreadProcess(Thread)) != NULL;
            if (IsWow64)
            {
                ULONG ThreadId = (ULONG)(ULONG_PTR)PsGetThreadId(Thread);
                PWOW64_CONTEXT Context = _Wow64ThreadContextList[ThreadId / 4];
                if (Context)
                {
                    if (BufferContext->ContextFlags & WOW64_CONTEXT_INTEGER)
                    {
                        Context->Eax = BufferContext->Eax;
                        Context->Ecx = BufferContext->Ecx;
                        Context->Edx = BufferContext->Edx;
                        Context->Ebx = BufferContext->Ebx;
                        Context->Ebp = BufferContext->Ebp;
                        Context->Esi = BufferContext->Esi;
                        Context->Edi = BufferContext->Edi;
                    }
                    if (BufferContext->ContextFlags & WOW64_CONTEXT_FLOATING_POINT)
                    {
                        Context->FloatSave = BufferContext->FloatSave;
                    }
                    if (BufferContext->ContextFlags & WOW64_CONTEXT_CONTROL)
                    {
                        Context->Eip = BufferContext->Eip;
                        Context->Esp = BufferContext->Esp;
                        Context->EFlags = BufferContext->EFlags;
                        Context->SegCs = BufferContext->SegCs;
                        Context->SegSs = BufferContext->SegSs;
                    }
                    if (BufferContext->ContextFlags & WOW64_CONTEXT_SEGMENTS)
                    {
                        Context->SegDs = BufferContext->SegDs;
                        Context->SegEs = BufferContext->SegEs;
                        Context->SegFs = BufferContext->SegFs;
                        Context->SegGs = BufferContext->SegGs;
                    }
                    if (BufferContext->ContextFlags & WOW64_CONTEXT_DEBUG_REGISTERS)
                    {
                        Context->Dr0 = BufferContext->Dr0;
                        Context->Dr1 = BufferContext->Dr1;
                        Context->Dr2 = BufferContext->Dr2;
                        Context->Dr3 = BufferContext->Dr3;
                        Context->Dr6 = BufferContext->Dr6;
                        Context->Dr7 = BufferContext->Dr7;
                    }
                    Status = STATUS_SUCCESS;
                }
            }
            ObReferenceObject(Thread);
        }
        return Status;
    }

    NTSTATUS Initialize(DBG_INIT_PARAM* pParam)
    {
        PVOID ntoskrnl_base = FYLIB::GetSystemModuleBase("ntoskrnl.exe", NULL);
        *(PVOID*)&DbgkpSuspendProcess = (PUCHAR)ntoskrnl_base + pParam->DbgkpSuspendProcessOffset;
        *(PVOID*)&PsThawMultiProcess = (PUCHAR)ntoskrnl_base + pParam->PsThawMultiProcessOffset;
        *(PVOID*)&PsQueryThreadStartAddress = (PUCHAR)ntoskrnl_base + pParam->PsQueryThreadStartAddressOffset;
        *(PVOID*)&MmGetFileNameForAddress = (PUCHAR)ntoskrnl_base + pParam->MmGetFileNameForAddressOffset;
        *(PVOID*)&DbgkpProcessDebugPortMutex_ptr = (PUCHAR)ntoskrnl_base + pParam->DbgkpProcessDebugPortMutexOffset;
        *(PVOID*)&DbgkDebugObjectType_ptr = (PUCHAR)ntoskrnl_base + pParam->DbgkDebugObjectTypeOffset;
		EPROCESS_RundownProtect_Offset = pParam->EPROCESS_RundownProtect_Offset;
		*(PVOID*)&DbgkpPostFakeProcessCreateMessages = (PUCHAR)ntoskrnl_base + pParam->DbgkpPostFakeProcessCreateMessagesOffset;
		*(PVOID*)&DbgkpPostFakeThreadMessages = (PUCHAR)ntoskrnl_base + pParam->DbgkpPostFakeThreadMessagesOffset;
		*(PVOID*)&PsGetNextProcessThread = (PUCHAR)ntoskrnl_base + pParam->PsGetNextProcessThreadOffset;
		*(PVOID*)&DbgkpWakeTarget = (PUCHAR)ntoskrnl_base + pParam->DbgkpWakeTargetOffset;
		ETHREAD_RundownProtect_Offset = pParam->ETHREAD_RundownProtect_Offset;

        HANDLE _ExplorerHandle;
        ULONG _ExplorerPid = FYLIB::GetProcessIdByProcessName(L"explorer.exe");
        CLIENT_ID ExplorerClientId = { (HANDLE)_ExplorerPid, NULL };
        OBJECT_ATTRIBUTES ObjectAttributes;
        InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
        if (NT_SUCCESS(ZwOpenProcess(&_ExplorerHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ExplorerClientId)))
        {
            PVOID NtdllBase = FYLIB::PROCESS::GetModuleHandleX64W(_ExplorerHandle, L"ntdll.dll");
			RtlDispatchExceptionAddress = (PUCHAR)NtdllBase + pParam->RtlDispatchExceptionOffset;
			RtlDispatchExceptionNewCodeAddress = (PUCHAR)NtdllBase + pParam->RtlDispatchExceptionNewCodeOffset;

			Wow64RtlDispatchExceptionAddress = (PUCHAR)NtdllBase + pParam->Wow64RtlDispatchExceptionOffset;
			Wow64RtlDispatchExceptionNewCodeAddress = (PUCHAR)NtdllBase + pParam->Wow64RtlDispatchExceptionNewCodeOffset;
            /*
            RtlDispatchExceptionAddress = NULL;
            RtlDispatchExceptionNewCodeAddress = NULL;
            RtlDispatchExceptionJmpCodeBuffer[5] = { 0x90,0x90,0x90,0x90,0x90 };
            RtlDispatchExceptioBackCode[5] = { 0x90,0x90,0x90,0x90,0x90 };
            Wow64RtlDispatchExceptionAddress = NULL;
            Wow64RtlDispatchExceptionNewCodeAddress = NULL;
            Wow64RtlDispatchExceptionJmpCodeBuffer[5] = { 0x90,0x90,0x90,0x90,0x90 };
            Wow64RtlDispatchExceptioBackCode[5] = { 0x90,0x90,0x90,0x90,0x90 };
            */
            ZwClose(_ExplorerHandle);
        }


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