#pragma once


namespace dbg
{
	NTSTATUS Initialize(DRIVER_OBJECT DriverObject);
	VOID UnInitialize();
}