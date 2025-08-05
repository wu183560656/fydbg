#pragma once
namespace dbg
{
	NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle);
	NTSTATUS NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugHandle);
	NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
	NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
	NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);

	BOOLEAN DbgkForwardException(PEPROCESS Process, PEXCEPTION_RECORD ExceptionRecord, BOOLEAN SecondChance, PCONTEXT UserContext);
	VOID DbgkCreateThread(PEPROCESS Process, PETHREAD Thread);
	VOID DbgkCreateMinimalProcess(PEPROCESS Process);
	VOID DbgkExitThread(PEPROCESS Process, PETHREAD Thread, NTSTATUS ExitStatus);
	VOID DbgkExitProcess(PEPROCESS Process, NTSTATUS ExitStatus);
	VOID DbgkMapViewOfSection(PEPROCESS Process, PVOID BaseAddress);
	VOID DbgkUnMapViewOfSection(PEPROCESS Process, PVOID BaseAddress);

	NTSTATUS Initialize(DBG_INIT_PARAM* pParam);
};

