#pragma once

BOOLEAN DbgkForwardException(PEPROCESS Process, PEXCEPTION_RECORD ExceptionRecord, BOOLEAN SecondChance);
VOID DbgkCreateThread(PEPROCESS Process, PETHREAD Thread);
VOID DbgkCreateMinimalProcess(PEPROCESS Process);
VOID DbgkExitThread(PEPROCESS Process, PETHREAD Thread, NTSTATUS ExitStatus);
VOID DbgkExitProcess(PEPROCESS Process, NTSTATUS ExitStatus);
VOID DbgkMapViewOfSection(PEPROCESS Process, PVOID BaseAddress);
VOID DbgkUnMapViewOfSection(PEPROCESS Process, PVOID BaseAddress);

VOID DbgkpPostModuleMessages(PEPROCESS Process, PETHREAD Thread, PVOID DebugPort);

BOOLEAN DbgkInitialize();
VOID DbgkUnInitialize();