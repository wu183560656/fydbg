#include <ntifs.h>
#include <fylib\fylib.hpp>

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



	NTSTATUS SwitchToKernelModeCall(ULONG SsdtIndex, PULONG64 Params)
	{
		FYLIB::ExSetPreviousMode(KernelMode);
		PVOID funAddress = FYLIB::SSDT::IndexToAddress(SsdtIndex, NULL);
		return ((NTSTATUS(*)(ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64, ULONG64))funAddress)(
			Params[0], Params[1], Params[2], Params[3], Params[4], Params[5], Params[6], Params[7], Params[8], Params[9], Params[10], Params[11], Params[12], Params[13], Params[14], Params[15]);
	}
};