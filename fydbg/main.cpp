#include <iostream>
#include <string>
#include <Windows.h>

#include <iocode.h>
#include <fylib\user\symbol.hpp>
#include <fylib\fylib.hpp>
#include "kdmapperHelper.h"

std::wstring CurrentPath;

static bool InitSymbol(DBG_INIT_PARAM* pPram, PULONG g_CiOptions_Offset)
{
	bool result = false;
    do
    {
        if (!SYMBOL::Initialize((CurrentPath + L"Pdb\\").c_str()))
        {
			std::cout << "Initialize Symbol Fail." << std::endl;
            break;
        }
		std::cout << "Load [ntoskrnl.exe] Pdb.." << std::endl;
        auto ntoskrnl = SYMBOL::GetModule(L"C:\\Windows\\System32\\ntoskrnl.exe");
        std::cout << "Load [ntdll.dll] Pdb.." << std::endl;
        auto ntdll = SYMBOL::GetModule(L"C:\\Windows\\System32\\ntdll.dll");
        std::cout << "Load [SysWOW64\\ntdll.dll] Pdb.." << std::endl;
		auto wow64_ntdll = SYMBOL::GetModule(L"C:\\Windows\\SysWOW64\\ntdll.dll");
        std::cout << "Load ci.dll Pdb.." << std::endl;
        auto ci = SYMBOL::GetModule(L"C:\\Windows\\System32\\ci.dll");
        if (!ntoskrnl.Valid() || !ntdll.Valid() || !wow64_ntdll.Valid() || !ci.Valid())
        {
			std::cout << "Load Pdb Fail." << std::endl;
            break;
        }

        pPram->DbgkpSuspendProcessOffset = ntoskrnl.GetRVAByName(L"DbgkpSuspendProcess");
        pPram->PsThawMultiProcessOffset = ntoskrnl.GetRVAByName(L"PsThawMultiProcess");
        pPram->PsQueryThreadStartAddressOffset = ntoskrnl.GetRVAByName(L"PsQueryThreadStartAddress");
        pPram->MmGetFileNameForAddressOffset = ntoskrnl.GetRVAByName(L"MmGetFileNameForAddress");
        pPram->DbgkpProcessDebugPortMutexOffset = ntoskrnl.GetRVAByName(L"DbgkpProcessDebugPortMutex");
        pPram->DbgkDebugObjectTypeOffset = ntoskrnl.GetRVAByName(L"DbgkDebugObjectType");
        pPram->EPROCESS_RundownProtect_Offset = ntoskrnl.GetStructByName(L"EPROCESS").GetField(L"RundownProtect").GetOffset();
        pPram->DbgkpPostFakeProcessCreateMessagesOffset = ntoskrnl.GetRVAByName(L"DbgkpPostFakeProcessCreateMessages");
        pPram->DbgkpPostFakeThreadMessagesOffset = ntoskrnl.GetRVAByName(L"DbgkpPostFakeThreadMessages");
        pPram->PsGetNextProcessThreadOffset = ntoskrnl.GetRVAByName(L"PsGetNextProcessThread");
        pPram->DbgkpWakeTargetOffset = ntoskrnl.GetRVAByName(L"DbgkpWakeTarget");
        pPram->ETHREAD_RundownProtect_Offset = ntoskrnl.GetStructByName(L"ETHREAD").GetField(L"RundownProtect").GetOffset();

        pPram->RtlDispatchExceptionOffset = ntdll.GetRVAByName(L"RtlDispatchException");
        pPram->RtlDispatchExceptionNewCodeOffset = 0;
        pPram->Wow64RtlDispatchExceptionOffset = wow64_ntdll.GetRVAByName(L"RtlDispatchException");
        pPram->Wow64RtlDispatchExceptionNewCodeOffset = 0;

		*g_CiOptions_Offset = ci.GetRVAByName(L"g_CiOptions");

        result = true;
    } while (false);
    return false;
}


int main()
{
    bool cancel_g_CiOptions = false;
	bool driver_Loaded = false;
    bool success = false;
    HANDLE driver_handle = INVALID_HANDLE_VALUE;
	std::wstring fileName = std::wstring(L"\\\\.\\") + SERVER_NAME;
    do
    {
        wchar_t PathBuffer[MAX_PATH] = { 0 };
        if (!GetModuleFileNameW(NULL, PathBuffer, sizeof(PathBuffer) / sizeof(*PathBuffer)))
        {
            break;
        }
        wchar_t* pos = PathBuffer + wcslen(PathBuffer);
        while (*pos != L'\\')*pos-- = 0;
        CurrentPath = PathBuffer;

        DBG_INIT_PARAM Param = {};
		ULONG g_CiOptions_Offset = 0;
        std::cout << "start Initialize Symbol.." << std::endl;
        if (!InitSymbol(&Param, &g_CiOptions_Offset))
        {
			std::cout << "Initialize Symbol Fail." << std::endl;
            break;
        }

        std::cout << "start Cancel g_CiOptions.." << std::endl;
        if (!kdmapperHelper::CancelCiOptions(g_CiOptions_Offset))
        {
			std::cout << "Cancel g_CiOptions Fail." << std::endl;
            break;
        }
        cancel_g_CiOptions = true;

        std::cout << "Start Load Driver.." << std::endl;
        std::wstring DriveFileName = CurrentPath + L"fydbg_drv.sys";
        std::wstring DriveFileNameTmp = CurrentPath + L"fydbg_drv_tmp.sys";
        std::wcout << L"Driver File:" << DriveFileName << std::endl;
        if (!CopyFileW(DriveFileName.c_str(), DriveFileNameTmp.c_str(), FALSE))
        {
			std::cout << "Copy Driver File Fail." << std::endl;
            break;
        }
        std::cout << "Start Load Driver.." << std::endl;
        if (!FYLIB::LoadDriver(SERVER_NAME, DriveFileNameTmp.c_str()))
        {
            std::cout << "Load Driver Fail." << std::endl;
            break;
        }
        driver_Loaded = true;

        driver_handle = CreateFileW(fileName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
        if (driver_handle == INVALID_HANDLE_VALUE)
        {
			std::cout << "Open Device Fail." << std::endl;
            break;
        }

        if (!DeviceIoControl(driver_handle, IO_CODE_DBG_INIT, NULL, 0, NULL, 0, NULL, NULL))
        {
			std::cout << "IO_CODE_DBG_INIT Fail." << std::endl;
        }

        success = true;
    } while (false);

    if (cancel_g_CiOptions)
    {
        if (driver_Loaded)
        {
            if (driver_handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(driver_handle);
            }
            FYLIB::UnLoadDriver(SERVER_NAME);
        }
        kdmapperHelper::RestoreCiOptions();
    }
    std::cout << (success ? "Success" : "Fail") << std::endl;
    return success ? 0 : 1;
}