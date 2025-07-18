#include <ntifs.h>

#include "ntoskrnl.h"
#include "ssdt.h"
#include "dbg.h"

#include <iocode.h>


static PDEVICE_OBJECT pDeviceObject = NULL;
static UNICODE_STRING DriverName;
static UNICODE_STRING SymLinkName;

static NTSTATUS IrpDeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION pStackLocation = IoGetCurrentIrpStackLocation(Irp);
	Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	Irp->IoStatus.Information = 0;
	switch (pStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_NtDebugActiveProcess:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength <= sizeof(IOCTL_NtDebugActiveProcess_PARAM))
		{
			IOCTL_NtDebugActiveProcess_PARAM* p = (IOCTL_NtDebugActiveProcess_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			Irp->IoStatus.Status = dbg::NtDebugActiveProcess(p->ProcessHandle, p->DebugObjectHandle);
		}
		break;
	}
	case IOCTL_NtRemoveProcessDebug:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength <= sizeof(IOCTL_NtRemoveProcessDebug_PARAM))
		{
			IOCTL_NtRemoveProcessDebug_PARAM* p = (IOCTL_NtRemoveProcessDebug_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			Irp->IoStatus.Status = dbg::NtDebugActiveProcess(p->ProcessHandle, p->DebugObjectHandle);
		}
		break;
	}
	case IOCTL_NtReadVirtualMemory:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength <= sizeof(IOCTL_NtReadVirtualMemory_PARAM))
		{
			IOCTL_NtReadVirtualMemory_PARAM* p = (IOCTL_NtReadVirtualMemory_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			Irp->IoStatus.Status = ssdt::NtReadVirtualMemory(p->ProcessHandle, p->BaseAddress, p->Buffer, p->NumberOfBytesToRead, p->NumberOfBytesRead);
		}
		break;
	}
	case IOCTL_NtWriteVirtualMemory:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength <= sizeof(IOCTL_NtWriteVirtualMemory_PARAM))
		{
			IOCTL_NtWriteVirtualMemory_PARAM* p = (IOCTL_NtWriteVirtualMemory_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			Irp->IoStatus.Status = ssdt::NtWriteVirtualMemory(p->ProcessHandle, p->BaseAddress, p->Buffer, p->NumberOfBytesToWrite, p->NumberOfBytesWritten);
		}
		break;
	}
	case IOCTL_NtGetContextThread:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength <= sizeof(IOCTL_NtGetContextThread_PARAM))
		{
			IOCTL_NtGetContextThread_PARAM* p = (IOCTL_NtGetContextThread_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			if (dbg::NtGetContextThread(p->ThreadHandle, p->ThreadContext))
			{
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Status = ssdt::NtGetContextThread(p->ThreadHandle, p->ThreadContext);
			}
		}
		break;
	}
	case IOCTL_NtSetContextThread:
	{
		if (pStackLocation->Parameters.DeviceIoControl.InputBufferLength <= sizeof(IOCTL_NtSetContextThread_PARAM))
		{
			IOCTL_NtSetContextThread_PARAM* p = (IOCTL_NtSetContextThread_PARAM*)pStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
			if (dbg::NtSetContextThread(p->ThreadHandle, p->ThreadContext))
			{
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Status = ssdt::NtSetContextThread(p->ThreadHandle, p->ThreadContext);
			}
		}
		break;
	}
	default:
	{
		Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	}
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
	RtlInitUnicodeString(&DriverName, L"\\Device\\fy_dbg");
	if (NT_SUCCESS(Result = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDeviceObject)))
	{
		//创建符号链接
		pDeviceObject->Flags |= DO_BUFFERED_IO;
		RtlInitUnicodeString(&SymLinkName, L"\\??\\fy_dbg");
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