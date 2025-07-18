#pragma once
namespace ssdt
{
	NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PVOID ThreadContext);
	NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PVOID ThreadContext);

	NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
	NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
};

