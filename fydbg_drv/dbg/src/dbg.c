#include <ntifs.h>
#include "dbgk.h"


static VOID CreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
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

static VOID CreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
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
static VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	(FullImageName);
	if (ProcessId)
	{
		PEPROCESS Process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
		{
			ImageInfo->ImageSelector;
			DbgkMapViewOfSection(Process, NULL, ImageInfo->ImageBase);
			ObReferenceObject(Process);
		}
	}
}

NTSTATUS Initialize(DRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
	PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	return -1;
}

VOID UnInitialize()
{
	PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
}