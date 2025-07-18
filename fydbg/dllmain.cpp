#include <Windows.h>
#include <iocode.h>
#include <kdmapper\include\kdmapper.hpp>

struct HOOK_STR
{
    CHAR apiName[0x100];
    UCHAR backCode[0x20];
};

NtGdiDdDDIDestroyKeyedMutex_TYPE g_NtGdiDdDDIDestroyKeyedMutex = NULL;
HANDLE g_driverHandle = INVALID_HANDLE_VALUE;
ULONG g_hookIndex = 0;
HOOK_STR g_hooks[0x200] = { 0 };

extern"C" ULONG_PTR deviceiocontrol(DWORD64 sstdId, PVOID pRegArgs, PVOID pStackArgs)
{
    CALLSSDT_IN in = { NULL };
    CALLSSDT_OUT out = { NULL };
    in.SSDTIndex = sstdId;
    memcpy(in.Args, pRegArgs, 4 * sizeof(PVOID));
    memcpy(in.Args + 4, pStackArgs, sizeof(in.Args) - 4 * sizeof(PVOID));
    if (g_driverHandle != INVALID_HANDLE_VALUE)
    {
        DWORD retLength = -1;
        if (!DeviceIoControl(g_driverHandle, DEV_CALLSSDT, &in, sizeof(in), &out, sizeof(out), &retLength, NULL) || retLength != sizeof(out))
            return -1;
        else
            return out.ReturnCode;
    }
    else if (g_NtGdiDdDDIDestroyKeyedMutex)
    {
        struct
        {
            COMMAND_STR cmd;
            COMMAND_SSDTCALL args;
        }param;
        param.cmd.IoCode = DEV_CALLSSDT;
        param.cmd.DataSize = sizeof(param.args);
        memcpy(&param.args.in, &in, sizeof(param.args.in));
        memcpy(&param.args.out, &out, sizeof(param.args.out));
        if (g_NtGdiDdDDIDestroyKeyedMutex((ULONG_PTR)&param, COMMON_KEY1, COMMON_KEY2, COMMON_KEY3) == COMMON_SUCCESS)
        {
            return param.args.out.ReturnCode;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }
}
/*
00000201EF6B0000 | B8 22220000              | mov eax,2222                            |
00000201EF6B0005 | 49:BA 8877665544332211   | mov r10,1122334455667788                |
00000201EF6B000F | 41:FFE2                  | jmp r10                                 |
*/
const UCHAR HookCode[] = { 0xB8,0x22,0x22,0x00,0x00,0x49,0xBA,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x41,0xFF,0xE2 };
extern "C" void ASM_transfer();
bool ForwardNtApi(LPCSTR funName)
{
    if (g_hookIndex >= sizeof(g_hooks) / sizeof(g_hooks[0]))
        return false;

    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    if (hModule == NULL)
        return false;
    PVOID fun = GetProcAddress(hModule, funName);
    if (fun == NULL)
        return false;
    DWORD flOldProtect = 0;
    if (!VirtualProtect(fun, sizeof(HOOK_STR::backCode), PAGE_EXECUTE_READWRITE, &flOldProtect))
        return false;

    bool retCode = true;
    //检查是否是直接syscall函数
    if (((DWORD32*)fun)[0] == 0xB8D18B4C && ((DWORD64*)fun)[1] == 0x017FFE03082504F6 && ((DWORD64*)fun)[2] == 0xC32ECDC3050F0375)
    {
        HOOK_STR theHook = { 0 };
        strcpy_s(theHook.apiName, funName);
        memcpy(theHook.backCode, fun, sizeof(HOOK_STR::backCode));

        UCHAR newCode[sizeof(HookCode)];
        memcpy(newCode, HookCode, sizeof(HookCode));
        *(DWORD32*)(newCode + 1) = ((DWORD32*)fun)[1];
        *(PVOID*)(newCode + 7) = &ASM_transfer;
        memcpy(fun, newCode, sizeof(newCode));

        memcpy(g_hooks + g_hookIndex, &theHook, sizeof(theHook));
        g_hookIndex++;
        retCode = true;
    }
    VirtualProtect(fun, sizeof(HOOK_STR::backCode), flOldProtect, &flOldProtect);
    return retCode;
}

#define SERVER_NAME L"ntcall"
#define LINK_NAME L"\\\\.\\ntcall"

bool Start()
{
    bool result = false;
    //加载驱动
    /*
    g_driverHandle = CreateFileW(LINK_NAME, GENERIC_READ| GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (g_driverHandle == INVALID_HANDLE_VALUE)
    {
        if (AdjustPrivileges(L"SeLoadDriverPrivilege"))
        {
            WCHAR szFilePath[MAX_PATH + 1] = { 0 };
            GetModuleFileNameW(nullptr, szFilePath, MAX_PATH);
            (wcsrchr(szFilePath, L'\\'))[0] = 0;
            wcscat_s(szFilePath, L"\\ntdll_kernel.sys");
            if (LoadDriver(SERVER_NAME, szFilePath))
            {
                g_driverHandle = CreateFileW(LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
                if (g_driverHandle != INVALID_HANDLE_VALUE)
                {
                    UnLoadDriver(SERVER_NAME);
                    result = true;
                }
            }
        }
    }
    */
    HMODULE win32uBase = LoadLibraryA("win32u.dll");
    if (win32uBase)
    {
        NtGdiDdDDIDestroyKeyedMutex_TYPE fun = (NtGdiDdDDIDestroyKeyedMutex_TYPE)GetProcAddress(win32uBase, "NtGdiDdDDIDestroyKeyedMutex");
        if (fun)
        {
            COMMAND_STR command = { 0 };
            if (fun((ULONG_PTR)&command, COMMON_KEY1, COMMON_KEY2, COMMON_KEY3) == COMMON_FAIL)
            {
                g_NtGdiDdDDIDestroyKeyedMutex = fun;
                result = true;
            }
            else
            {
                WCHAR szFilePath[MAX_PATH + 1] = { 0 };
                GetModuleFileNameW(nullptr, szFilePath, MAX_PATH);
                (wcsrchr(szFilePath, L'\\'))[0] = 0;
                wcscat_s(szFilePath, L"\\ntdll_kernel.sys");
                std::ifstream file(szFilePath, std::ifstream::binary);
                if (file.is_open())
                {
                    file.seekg(0, std::ios::end);
                    std::streampos fileSize = file.tellg();
                    file.seekg(0, std::ios::beg);

                    char* drv_data = new char[fileSize];
                    file.read(drv_data, fileSize);
                    file.close();
                    HANDLE intelDriver = intel_driver::Load();
                    if (intelDriver)
                    {
                        if (kdmapper::MapDriver(intelDriver, (BYTE*)drv_data, NULL, NULL, false, true))
                        {
                            if (fun((ULONG_PTR)&command, COMMON_KEY1, COMMON_KEY2, COMMON_KEY3) == 0xbbbb0001)
                            {
                                g_NtGdiDdDDIDestroyKeyedMutex = fun;
                                result = true;
                            }
                        }
                        intel_driver::Unload(intelDriver);
                    }
                    delete[] drv_data;
                }
            }
        }
    }
    if (result)
    {
        //HOOK ntapis
        ForwardNtApi("NtReadVirtualMemory");
        ForwardNtApi("NtWriteVirtualMemory");
        ForwardNtApi("NtQueryInformationProcess");
        ForwardNtApi("NtQueryInformationThread");
        ForwardNtApi("NtAllocateVirtualMemory");
        ForwardNtApi("NtAllocateVirtualMemoryEx");
        ForwardNtApi("NtCreateThread");
        ForwardNtApi("NtCreateThreadEx");
        ForwardNtApi("NtFreeVirtualMemory");
    }
    return result;
}

void Exit()
{
    for (ULONG i = 0; i < g_hookIndex; i++)
    {
        HMODULE hModule = GetModuleHandleA("ntdll.dll");
        if (hModule != NULL)
        {
            PVOID fun = GetProcAddress(hModule, g_hooks[i].apiName);
            if (fun != NULL)
            {
                DWORD flOldProtect = 0;
                if (VirtualProtect(fun, sizeof(HOOK_STR::backCode), PAGE_EXECUTE_READWRITE, &flOldProtect))
                {
                    memcpy(fun, g_hooks[i].backCode, sizeof(HOOK_STR::backCode));
                    VirtualProtect(fun, sizeof(HOOK_STR::backCode), flOldProtect, &flOldProtect);
                }
            }
        }
    }
    memset(g_hooks, 0, sizeof(g_hooks));
    g_hookIndex = 0;

    if (g_driverHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_driverHandle);
        g_driverHandle = INVALID_HANDLE_VALUE;
    }
    //UnLoaddriver(SERVER_NAME);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        if (!Start())
        {
            MessageBoxA(NULL, "初始化失败", "错误", MB_OK);
            return FALSE;
        }
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        Exit();
        break;
    default:
        break;
    }
    return TRUE;
}

extern"C" __declspec(dllexport) void helloword()
{
    MessageBoxA(NULL, "helloword", "hello", MB_OK);
}