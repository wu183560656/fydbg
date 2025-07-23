#include <ntifs.h>
#include <fylib\fylib.hpp>

#include "ntoskrnl.h"
#include "ssdt.h"
#include "dbg.h"

#include <iocode.h>

static PDEVICE_OBJECT pDeviceObject = NULL;
static UNICODE_STRING DriverName;
static UNICODE_STRING SymLinkName;

static ULONG NtDebugActiveProcessSSDTIndex = 0;
static ULONG NtRemoveProcessDebugSSDTIndex = 0;
static ULONG NtGetContextThreadSSDTIndex = 0;
static ULONG NtSetContextThreadSSDTIndex = 0;

static NTSTATUS IrpDeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION pStackLocation = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	NTSTATUS Information = 0;
	switch (pStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
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

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS Result;
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = [](_In_ struct _DRIVER_OBJECT* DriverObject)->VOID{
		UNREFERENCED_PARAMETER(DriverObject);
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

	if (!dbg::Initialize())
	{
		return STATUS_FAIL_CHECK;
	}

	//创建设备对象
	RtlInitUnicodeString(&DriverName, DRVIER_NAME);
	if (NT_SUCCESS(Result = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDeviceObject)))
	{
		//创建符号链接
		pDeviceObject->Flags |= DO_BUFFERED_IO;
		RtlInitUnicodeString(&SymLinkName, SYMBOL_LINK_NANM);
		if (NT_SUCCESS(Result = IoCreateSymbolicLink(&SymLinkName, &DriverName)))
		{
			Result = STATUS_SUCCESS;
			
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
	return Result;
}