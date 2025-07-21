#pragma once

#define IOCTL_NtDebugActiveProcess CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_OUT_DIRECT,FILE_READ_DATA | FILE_WRITE_DATA)
struct IOCTL_NtDebugActiveProcess_PARAM
{
	HANDLE ProcessHandle;
	HANDLE DebugObjectHandle;
};

#define IOCTL_NtRemoveProcessDebug CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_OUT_DIRECT,FILE_READ_DATA | FILE_WRITE_DATA)
struct IOCTL_NtRemoveProcessDebug_PARAM
{
	HANDLE ProcessHandle;
	HANDLE DebugObjectHandle;
};

#define IOCTL_NtReadVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_OUT_DIRECT,FILE_READ_DATA | FILE_WRITE_DATA)
struct IOCTL_NtReadVirtualMemory_PARAM
{
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer;
	SIZE_T NumberOfBytesToRead;
	PSIZE_T NumberOfBytesRead;
};

#define IOCTL_NtWriteVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_OUT_DIRECT,FILE_READ_DATA | FILE_WRITE_DATA)
struct IOCTL_NtWriteVirtualMemory_PARAM
{
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer;
	SIZE_T NumberOfBytesToWrite;
	PSIZE_T NumberOfBytesWritten;
};

#define IOCTL_NtGetContextThread CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_OUT_DIRECT,FILE_READ_DATA | FILE_WRITE_DATA)
struct IOCTL_NtGetContextThread_PARAM
{
	HANDLE ThreadHandle;
	PVOID ThreadContext;
};

#define IOCTL_NtSetContextThread CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_OUT_DIRECT,FILE_READ_DATA | FILE_WRITE_DATA)
struct IOCTL_NtSetContextThread_PARAM
{
	HANDLE ThreadHandle;
	PVOID ThreadContext;
};