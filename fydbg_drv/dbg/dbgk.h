#pragma once
namespace dbgk
{
	PVOID GetDebugPort(PEPROCESS Process) noexcept;
	BOOLEAN SetDebugPort(PEPROCESS Process, PVOID DebugObject) noexcept;
	PVOID GetThreadContext(PETHREAD Thread) noexcept;
	BOOLEAN SetThreadContext(PETHREAD Thread, PCONTEXT Context) noexcept;

	BOOLEAN DbgkpSuspendProcess(PEPROCESS Process);
	VOID PsThawMultiProcess(PEPROCESS Process, ULONG64 p2, ULONG64 p3);
	PVOID PsQueryThreadStartAddress(PETHREAD Thread, BOOLEAN Flags);
	NTSTATUS MmGetFileNameForAddress(PVOID Address, PUNICODE_STRING ModuleName);
	PFAST_MUTEX DbgkpProcessDebugPortMutex();
	PVOID PsDebugObjectType();

	BOOLEAN DbgkForwardException(PEPROCESS Process, PEXCEPTION_RECORD ExceptionRecord, BOOLEAN SecondChance);
	VOID DbgkCreateThread(PEPROCESS Process, PETHREAD Thread);
	VOID DbgkCreateMinimalProcess(PEPROCESS Process);
	VOID DbgkExitThread(PEPROCESS Process, PETHREAD Thread, NTSTATUS ExitStatus);
	VOID DbgkExitProcess(PEPROCESS Process, NTSTATUS ExitStatus);
	VOID DbgkMapViewOfSection(PEPROCESS Process, PVOID BaseAddress);
	VOID DbgkUnMapViewOfSection(PEPROCESS Process, PVOID BaseAddress);
	VOID DbgkPostModuleMessages(PEPROCESS Process, PETHREAD Thread);

	BOOLEAN Initialize();
	VOID UnInitialize();
}
