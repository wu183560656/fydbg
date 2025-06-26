#include <ntifs.h>

#include "dbg/include.h"

static VOID DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}