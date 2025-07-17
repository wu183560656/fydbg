#include <ntifs.h>

#include "dbg\dbg.h"

static PDEVICE_OBJECT pDeviceObject = NULL;
static UNICODE_STRING DriverName;
static UNICODE_STRING SymLinkName;

static NTSTATUS IrpDeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_NOT_IMPLEMENTED;
};

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS Result;
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = [](_In_ struct _DRIVER_OBJECT* DriverObject)->VOID{
		UNREFERENCED_PARAMETER(DriverObject);
		dbg::UnInitialize();
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
	RtlInitUnicodeString(&DriverName, L"\\Device\\fy_dbg");
	if (NT_SUCCESS(Result = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDeviceObject)))
	{
		//创建符号链接
		pDeviceObject->Flags |= DO_BUFFERED_IO;
		RtlInitUnicodeString(&SymLinkName, L"\\??\\fy_dbg");
		if (NT_SUCCESS(Result = IoCreateSymbolicLink(&SymLinkName, &DriverName)))
		{
			//初始化dbg
			if (NT_SUCCESS(Result = dbg::Initialize(pDeviceObject)))
			{
				Result = STATUS_SUCCESS;

				if (!NT_SUCCESS(Result))
				{
					dbg::UnInitialize();
					return Result;
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
	return Result;
}