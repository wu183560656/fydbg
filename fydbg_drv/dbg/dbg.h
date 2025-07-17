#pragma once
namespace dbg
{
	VOID UnInitialize();
	NTSTATUS Initialize(PDRIVER_OBJECT DriverObject);
	NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
	NTSTATUS NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
	NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
	NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
}
