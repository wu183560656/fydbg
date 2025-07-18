#include <ntifs.h>

namespace ssdt
{
	NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PVOID ThreadContext)
	{
		(ThreadHandle);
		(ThreadContext);
		return STATUS_NOT_IMPLEMENTED;
	}
	NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PVOID ThreadContext)
	{
		(ThreadHandle);
		(ThreadContext);
		return STATUS_NOT_IMPLEMENTED;
	}
	NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
	{
		(ProcessHandle);
		(BaseAddress);
		(Buffer);
		(NumberOfBytesToRead);
		(NumberOfBytesRead);
		return STATUS_NOT_IMPLEMENTED;
	}
	NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
	{
		(ProcessHandle);
		(BaseAddress);
		(Buffer);
		(NumberOfBytesToWrite);
		(NumberOfBytesWritten);
		return STATUS_NOT_IMPLEMENTED;
	}
};