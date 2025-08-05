#include <ntifs.h>
#include <fylib\fylib.hpp>

#include <iocode.h>

#include "ntoskrnl.h"
#include "ssdt.h"
#include "dbg.h"

static PDEVICE_OBJECT pDeviceObject = NULL;
static UNICODE_STRING DriverName;
static UNICODE_STRING SymLinkName;

static ULONG NtDebugActiveProcessSSDTIndex = 0;
static ULONG NtRemoveProcessDebugSSDTIndex = 0;
static ULONG NtGetContextThreadSSDTIndex = 0;
static ULONG NtSetContextThreadSSDTIndex = 0;


static NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath)
{
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(
		&ObjectAttributes,
		pUsDriverPath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		0,
		0);

	NTSTATUS Status = IoCreateFileEx(&FileHandle,
		SYNCHRONIZE | DELETE,
		&ObjectAttributes,
		&IoStatusBlock,
		nullptr,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		nullptr,
		0,
		CreateFileTypeNone,
		nullptr,
		IO_NO_PARAMETER_CHECKING,
		nullptr);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	PFILE_OBJECT FileObject;
	Status = ObReferenceObjectByHandleWithTag(FileHandle,
		SYNCHRONIZE | DELETE,
		*IoFileObjectType,
		KernelMode,
		'eliF',
		reinterpret_cast<PVOID*>(&FileObject),
		nullptr);
	if (!NT_SUCCESS(Status))
	{
		ObCloseHandle(FileHandle, KernelMode);
		return Status;
	}

	const PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
	SectionObjectPointer->ImageSectionObject = nullptr;

	// call MmFlushImageSection, make think no backing image and let NTFS to release file lock
	CONST BOOLEAN ImageSectionFlushed = MmFlushImageSection(SectionObjectPointer, MmFlushForDelete);

	ObfDereferenceObject(FileObject);
	ObCloseHandle(FileHandle, KernelMode);

	if (ImageSectionFlushed)
	{
		// chicken fried rice
		Status = ZwDeleteFile(&ObjectAttributes);
		if (NT_SUCCESS(Status))
		{
			return Status;
		}
	}
	return Status;
}


static NTSTATUS IrpDeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION pStackLocation = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	NTSTATUS Information = 0;
	switch (pStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IO_CODE_DBG_INIT:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength >= sizeof(DBG_INIT_PARAM)
			&& MmIsAddressValid(Irp->MdlAddress))
		{
			DBG_INIT_PARAM* pParam = (DBG_INIT_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			Status = dbg::Initialize(pParam);
		}
		break;
	}
	case IO_CODE_SYSTEM_CALL:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength >= sizeof(SYSTEM_CALL_PARAM)
			&& pStackLocation->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG64)
			&& MmIsAddressValid(Irp->MdlAddress))
		{
			SYSTEM_CALL_PARAM* pParam = (SYSTEM_CALL_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			ULONG64* pOut = (ULONG64*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
			if (pOut)
			{
				//一些特殊请求处理
				if (pParam->ssdt_index == NtDebugActiveProcessSSDTIndex)
				{
					Status = dbg::NtDebugActiveProcess((HANDLE)pParam->args[0], (HANDLE)pParam->args[1]);
				}
				else if (pParam->ssdt_index == NtRemoveProcessDebugSSDTIndex)
				{
					Status = dbg::NtRemoveProcessDebug((HANDLE)pParam->args[0], (HANDLE)pParam->args[1]);
				}
				else if (pParam->ssdt_index == NtGetContextThreadSSDTIndex)
				{
					Status = dbg::NtGetContextThread((HANDLE)pParam->args[0], (PCONTEXT)pParam->args[1]);
				}
				else if (pParam->ssdt_index == NtSetContextThreadSSDTIndex)
				{
					Status = dbg::NtSetContextThread((HANDLE)pParam->args[0], (PCONTEXT)pParam->args[1]);
				}
				if (!NT_SUCCESS(Status))
				{
					Status = ssdt::SwitchToKernelModeCall((ULONG)pParam->ssdt_index, pParam->args);
				}
				*pOut = Status;
				Information = sizeof(ULONG64);
			}
		}
		break;
	}
	case IO_CODE_FORWARD_EXCEPTION:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength >= sizeof(FORWARD_EXCEPTION_PARAM)
			&& MmIsAddressValid(Irp->MdlAddress))
		{
			FORWARD_EXCEPTION_PARAM* pParam = (FORWARD_EXCEPTION_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			if (dbg::DbgkForwardException(PsGetCurrentProcess(), pParam->ExceptionRecord, pParam->First == false, pParam->pContext))
			{
				Status = STATUS_SUCCESS;
			}
		}
		break;
	}
	default:
		break;
	}
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_NOT_IMPLEMENTED;
};

static VOID CreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) noexcept
{
	(ParentId);
	PEPROCESS Process = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		if (Create)
		{
			dbg::DbgkCreateMinimalProcess(Process);
		}
		else
		{
			NTSTATUS ExitStatus = PsGetProcessExitStatus(Process);
			dbg::DbgkExitProcess(Process, ExitStatus);
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
				dbg::DbgkCreateThread(Process, Thread);
			}
			else
			{
				NTSTATUS ExitStatus = PsGetThreadExitStatus(Thread);
				dbg::DbgkExitThread(Process, Thread, ExitStatus);
			}
			ObReferenceObject(Thread);
		}
		ObReferenceObject(Process);
	}
}

static VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) noexcept
{
	UNREFERENCED_PARAMETER(FullImageName);
	if (ProcessId)
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			ImageInfo->ImageSelector;
			dbg::DbgkMapViewOfSection(Process, ImageInfo->ImageBase);
			ObReferenceObject(Process);
		}
	}
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS Result;
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = [](_In_ struct _DRIVER_OBJECT* DriverObject)->VOID{
		UNREFERENCED_PARAMETER(DriverObject);

		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
		PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
		PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);

		IoDeleteSymbolicLink(&SymLinkName);
		IoDeleteDevice(pDeviceObject);
		pDeviceObject = NULL;
	};
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlHandler;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = [](PDEVICE_OBJECT DeviceObject, PIRP Irp)->NTSTATUS {
		UNREFERENCED_PARAMETER(DeviceObject);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = [](PDEVICE_OBJECT DeviceObject, PIRP Irp)->NTSTATUS {
		UNREFERENCED_PARAMETER(DeviceObject);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};

	//创建设备对象
	RtlInitUnicodeString(&DriverName, DRVIER_NAME);
	if (NT_SUCCESS(Result = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDeviceObject)))
	{
		//创建符号链接
		pDeviceObject->Flags |= DO_BUFFERED_IO;
		RtlInitUnicodeString(&SymLinkName, SYMBOL_LINK_NANM);
		if (NT_SUCCESS(Result = IoCreateSymbolicLink(&SymLinkName, &DriverName)))
		{
			//进程回调
			if (NT_SUCCESS(Result = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE)))
			{
				//线程回调
				if (NT_SUCCESS(Result = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine)))
				{
					//模块回调
					if (NT_SUCCESS(Result = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine)))
					{
						Result = STATUS_SUCCESS;

						if (!NT_SUCCESS(Result))
						{
							PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
						}
					}
					if (!NT_SUCCESS(Result))
					{
						PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
					}
				}
				if (!NT_SUCCESS(Result))
				{
					PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
				}
			}
			if (!NT_SUCCESS(Result))
			{
				IoDeleteSymbolicLink(&SymLinkName);
			}
		}
		if (!NT_SUCCESS(Result))
		{
			IoDeleteDevice(pDeviceObject);
			pDeviceObject = NULL;
		}
	}

	if (NT_SUCCESS(Result))
	{
		typedef struct _KLDR_DATA_TABLE_ENTRY
		{
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY InMemoryOrderLinks;
			LIST_ENTRY InInitializationOrderLinks;
			PVOID      DllBase;
			PVOID      EntryPoint;
			UINT64    SizeOfImage;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
		}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

		PUNICODE_STRING pusDriverPath = NULL;
		pusDriverPath = &((PKLDR_DATA_TABLE_ENTRY)(DriverObject->DriverSection))->FullDllName;
		DelDriverFile(pusDriverPath);
	}
	return Result;
}