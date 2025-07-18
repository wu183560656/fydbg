#pragma once
namespace dbg
{
	NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle);
	NTSTATUS NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugHandle);
	NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PVOID ThreadContext);
	NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PVOID ThreadContext);
	NTSTATUS Initialize();
	VOID UnInitialize();
};

