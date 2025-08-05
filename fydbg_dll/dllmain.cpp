#include <Windows.h>
#include <string>
#include <iocode.h>

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

static HANDLE g_driverHandle = INVALID_HANDLE_VALUE;
NTSTATUS(*funNtDeviceIoControlFile)(HANDLE FileHandle,
    HANDLE DeviceHandle,
    struct IO_APC_ROUTINE* ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
    );

extern"C" ULONG_PTR deviceiocontrol(DWORD64 sstdId, PVOID pRegArgs, PVOID pStackArgs)
{
    if (g_driverHandle == INVALID_HANDLE_VALUE || !funNtDeviceIoControlFile)
    {
        return -1;
    }
    SYSTEM_CALL_PARAM param = { NULL };
    param.ssdt_index = sstdId;
    ULONG64 out = 0;
    memcpy(param.args, pRegArgs, 4 * sizeof(PVOID));
    memcpy(param.args + 4, pStackArgs, sizeof(param.args) - 4 * sizeof(PVOID));
    DWORD retLength = -1;
	IO_STATUS_BLOCK StatusBlock = { 0 };
    NTSTATUS Status = funNtDeviceIoControlFile(g_driverHandle, NULL, NULL, NULL, &StatusBlock, IO_CODE_SYSTEM_CALL, &param, sizeof(param), &out, sizeof(out));
    if (Status < 0)
    {
        return Status;
    }
    if (StatusBlock.Status < 0)
    {
        return StatusBlock.Status;
    }
    return (ULONG_PTR)out;
}
/*
00000201EF6B0000 | B8 22220000              | mov eax,2222                            |
00000201EF6B0005 | 49:BA 8877665544332211   | mov r10,1122334455667788                |
00000201EF6B000F | 41:FFE2                  | jmp r10                                 |
*/
const UCHAR HookCode[] = { 0xB8,0x22,0x22,0x00,0x00,0x49,0xBA,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x41,0xFF,0xE2 };
extern "C" void WINAPI ASM_transfer();
bool ForwardNtApi(LPCSTR funName)
{
    if (!_strnicmp(funName, "NtDeviceIoControlFile", sizeof("NtDeviceIoControlFile")))
    {
        return false;
    }
    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    if (hModule == NULL)
    {
        return false;
    }
    PVOID fun = GetProcAddress(hModule, funName);
    if (fun == NULL)
    {
        return false;
    }
    DWORD flOldProtect = 0;
    if (VirtualProtect(fun, sizeof(HookCode), PAGE_EXECUTE_READWRITE, &flOldProtect))
    {
        return false;
    }
    bool result = false;
    //检查是否是直接syscall函数
    if (((DWORD32*)fun)[0] == 0xB8D18B4C && ((DWORD64*)fun)[1] == 0x017FFE03082504F6 && ((DWORD64*)fun)[2] == 0xC32ECDC3050F0375)
    {
        UCHAR newCode[sizeof(HookCode)];
        memcpy(newCode, HookCode, sizeof(HookCode));
        *(DWORD32*)(newCode + 1) = ((DWORD32*)fun)[1];
        *(PVOID*)(newCode + 7) = &ASM_transfer;
        memcpy(fun, newCode, sizeof(newCode));
        result = true;
    }
    VirtualProtect(fun, sizeof(HookCode), flOldProtect, &flOldProtect);
    return result;
}


BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        std::wstring fileName = std::wstring(L"\\\\.\\") + SERVER_NAME;
        g_driverHandle = CreateFileW(fileName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
        if (g_driverHandle == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }
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
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
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