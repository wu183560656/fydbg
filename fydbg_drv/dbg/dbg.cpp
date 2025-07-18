#include <ntifs.h>
#include <fylib\include\fylib.hpp>

#include "dbg.h"

#include "ntoskrnl.h"
#include "dbgk.h"

namespace dbg
{
	static PDEVICE_OBJECT _pDeviceObject = NULL;
	static UNICODE_STRING _DeviceName;
	static UNICODE_STRING _SymLinkName;


	static VOID CreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) noexcept
	{
		(ParentId);
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			if (Create)
			{
				dbgk::DbgkCreateMinimalProcess(Process);
			}
			else
			{
				NTSTATUS ExitStatus = PsGetProcessExitStatus(Process);
				dbgk::DbgkExitProcess(Process, ExitStatus);
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
					dbgk::DbgkCreateThread(Process, Thread);
				}
				else
				{
					NTSTATUS ExitStatus = PsGetThreadExitStatus(Thread);
					dbgk::DbgkExitThread(Process, Thread, ExitStatus);
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
				dbgk::DbgkMapViewOfSection(Process, ImageInfo->ImageBase);
				ObReferenceObject(Process);
			}
		}
	}

	static NTSTATUS AttachProcess(PEPROCESS Process, PDEVICE_OBJECT pDeviceObject)
	{
		KAPC_STATE ApcState;
		HANDLE hDeviceHandle = NULL;
		KeStackAttachProcess(Process, &ApcState);
		{
			//为目标进程生成设备句柄
			ZwCreateFile(&hDeviceHandle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, NULL, NULL, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0, NULL, 0);

			ZwClose(hDeviceHandle);

		}
		KeUnstackDetachProcess(&ApcState);
	}

	VOID UnInitialize()
	{
		dbgk::UnInitialize();
		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
		PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
		PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
		_pDeviceObject = NULL;
	}
	NTSTATUS Initialize(PDRIVER_OBJECT DriverObject,PCWSTR DriverName,)
	{
		NTSTATUS result;
		if (dbgk::Initialize())
		{
			if (NT_SUCCESS(result = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE)))
			{
				if (NT_SUCCESS(result = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine)))
				{
					if (NT_SUCCESS(result = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine)))
					{
						//创建设备对象
						RtlInitUnicodeString(&_DeviceName, L"\\Device\\fy_dbg");
						if (NT_SUCCESS(Result = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDeviceObject)))
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
			_pDeviceObject = pDeviceObject;


			if (!NT_SUCCESS(result))
			{
				dbgk::UnInitialize();
			}
		}
		return STATUS_SUCCESS;
	}
	NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
	{
		NTSTATUS Status;
		PEPROCESS Process = NULL;
		PVOID DebugObject = NULL;
		Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
		Status = ObReferenceObjectByHandle(DebugObjectHandle, DEBUG_OBJECT_ALL_ACCESS, (POBJECT_TYPE)dbgk::PsDebugObjectType(), KernelMode, &DebugObject, NULL);
		if (!NT_SUCCESS(Status))
		{
			ObReferenceObject(Process);
			return Status;
		}
		if (dbgk::SetDebugPort(Process, DebugObject))
		{
			ObReferenceObject(Process);
			ObReferenceObject(DebugObject);
		}
	}
	NTSTATUS NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
	{

	}

	NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
	{

	}

	NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
	{

	}
}