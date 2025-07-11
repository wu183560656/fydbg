#pragma once
#ifdef WINNT
	#include <ntifs.h>
	#include <ntimage.h>
#else
	#include <Windows.h>
	#include <TlHelp32.h>
#endif
#include <intrin.h>
#include "windowsex.h"

#pragma warning(push)
#pragma warning(disable:4996)
#pragma warning(disable:4201)
 
struct FYLIB
{
#pragma region Memory
public:
	static void* Malloc(size_t size) noexcept
	{
#ifdef WINNT
		return ExAllocatePoolWithTag(NonPagedPool, size, 'fylb');
#else
		return malloc(size);
#endif
	}
	static void Free(void* ptr) noexcept
	{
#ifdef WINNT
		return ExFreePoolWithTag(ptr, 'fylb');
#else
		return free(ptr);
#endif
	}
#pragma endregion

#pragma region String
public:
	static int MemCompare(const void* data_ptr, const char* des_str) noexcept
	{
		int result = 0;
		for (size_t i = 0; !result; i++)
		{
			int bit; 
			if (des_str[i] == '\0')
				break;
			else if (des_str[i] == '?')
				continue;
			else if (des_str[i] >= '0' && des_str[i] <= '9')
				bit = des_str[i] - '0';
			else if (des_str[i] >= 'a' && des_str[i] <= 'f')
				bit = des_str[i] - 'a' + 10;
			else if (des_str[i] >= 'A' && des_str[i] <= 'F')
				bit = des_str[i] - 'A' + 10;
			else
				bit = 0x10;
			result = (int)((((UCHAR*)data_ptr)[i / 2] >> (i % 2 ? 0 : 4)) & 0xF) - bit;
		}
		return result;
	}
	static void* MemFind(const void* data_ptr, size_t data_len, const char* des_str) noexcept
	{
		size_t mask_len = strlen(des_str) / 2 + (strlen(des_str) % 2 ? 1 : 0);
		for (SIZE_T Pos = 0; Pos <= data_len - mask_len; Pos++)
		{
			char* tmp = ((char*)data_ptr) + Pos;
			if (!MemCompare(tmp, des_str))
				return tmp;
		}
		return nullptr;
	}
	static PSTR NumberToStr(ULONG64 value, PSTR buffer, ULONG radix) noexcept
	{
		PCSTR T = "0123456789ABCDEF";
		if (radix != 2 && radix != 8 && radix != 10 && radix != 16)
			radix = 10;
		size_t len = 0;
		do {
			buffer[len++] = T[value % radix];
			value /= radix;
		} while (value);
		buffer[len] = '\0';
		for (int i = 0; i < len / 2; i++)
		{
			char tmp = buffer[i];
			buffer[i] = buffer[len - 1 - i];
			buffer[len - 1 - i] = tmp;
		}
		return buffer;
	}
	static ULONG64 StrToNumber(PCSTR str, ULONG radix, ULONG64 defvalue = 0) noexcept
	{
		if (radix < 2 || radix > 16)
			radix = 10;
		ULONG64 value = 0;
		int index = 0;
		UCHAR isError = 0;
		while (index < 100)
		{
			if (str[index] == '\0') {
				break;
			}
			else {
				switch (radix)
				{
				case 2:
					if (str[index] >= '0' && str[index] <= '1')
						value = value * radix + ((unsigned long long)str[index] - '0');
					else
						isError = 1;
					break;
				case 8:
					if (str[index] >= '0' && str[index] <= '7')
						value = value * radix + ((unsigned long long)str[index] - '0');
					else
						isError = 1;
					break;
				case 10:
					if (str[index] >= '0' && str[index] <= '9')
						value = value * radix + ((unsigned long long)str[index] - '0');
					else
						isError = 1;
					break;
				case 16:
					if (str[index] >= '0' && str[index] <= '9')
						value = value * radix + ((unsigned long long)str[index] - '0');
					else if (str[index] >= 'a' && str[index] <= 'f')
						value = value * radix + ((unsigned long long)str[index] - 'a' + 10);
					else if (str[index] >= 'A' && str[index] <= 'F')
						value = value * radix + ((unsigned long long)str[index] - 'A' + 10);
					else
						isError = 1;
					break;
				default:
					break;
				}
				if (isError)
					break;
			}
			index++;
		}
		value = defvalue;
		return value;
	}
	static PWSTR AscllStrToUnicodeStr(PCSTR str, PWSTR buffer, LONG* buffer_size_ptr) noexcept
	{
		ANSI_STRING aStr;
		UNICODE_STRING uStr = { 0 };
		RtlInitAnsiString(&aStr, str);
		PWSTR result = NULL;
		if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uStr, &aStr, true)))
		{
			*buffer_size_ptr = -1;
		}
		else
		{
			if (uStr.Buffer != NULL && *buffer_size_ptr < uStr.Length + 2)
			{
				*buffer_size_ptr = uStr.Length + 2;
			}
			else
			{
				*buffer_size_ptr = uStr.Length + 2;
				memcpy(buffer, uStr.Buffer, uStr.Length);
				buffer[uStr.MaximumLength / 2] = L'\0';
				result = buffer;
			}
			RtlFreeUnicodeString(&uStr);
		}
		return result;
	}
	static PSTR UnicodeStrToAscllStr(PCWSTR str, PSTR buffer, LONG* buffer_size_ptr) noexcept
	{
		ANSI_STRING aStr = { 0 };
		UNICODE_STRING uStr;
		RtlInitUnicodeString(&uStr, str);
		PSTR result = NULL;
		if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&aStr, &uStr, true)))
		{
			*buffer_size_ptr = -1;
		}
		else
		{
			if (aStr.Buffer != NULL && *buffer_size_ptr < aStr.Length + 1)
			{
				*buffer_size_ptr = aStr.Length + 1;
			}
			else
			{
				*buffer_size_ptr = aStr.Length + 1;
				memcpy(buffer, aStr.Buffer, aStr.Length);
				buffer[aStr.MaximumLength] = '\0';
				result = buffer;
			}
			RtlFreeAnsiString(&aStr);
		}
		return result;
	}
#pragma endregion

#pragma region ShellCode
public:
	struct alignas(0x10) xmm_t
	{
		unsigned char data[0x10];
	};
	struct context_x86_t
	{
		unsigned int dummy1, dummy2, dummy3, eflags;
		unsigned int eax, ecx, edx, ebx, esp, ebp, esi, edi;
		xmm_t xmm[8];
	};
	struct context_x64_t
	{
		unsigned __int64 dummy, rflags;
		unsigned __int64 rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
		unsigned __int64 r8, r9, r10, r11, r12, r13, r14, r15;
		xmm_t xmm[16];
	};
	//code return ecx[context_x86_t*]
	static int WriteX86RegisterSaveCode(PVOID Dst, SIZE_T Size)
	{
		static const constexpr unsigned char shell_code[] = {
			/*
				lea esp,[esp-0x100]
				mov [esp+0x010],eax
				mov [esp+0x014],ecx
				mov [esp+0x018],edx
				mov [esp+0x01c],ebx
				lea eax,[esp+0x100]
				mov [esp+0x020],eax
				mov [esp+0x024],ebp
				mov [esp+0x028],esi
				mov [esp+0x02c],edi
				pushfd
				pop eax
				mov [esp+0x0C],eax
				movups [esp+0x30],xmm0
				movups [esp+0x40],xmm1
				movups [esp+0x50],xmm2
				movups [esp+0x60],xmm3
				movups [esp+0x70],xmm4
				movups [esp+0x80],xmm5
				movups [esp+0x90],xmm6
				movups [esp+0xA0],xmm7
				mov ecx,esp
			*/
			0x8d,0xa4,0x24,0x00,0xff,0xff,0xff,0x89,0x44,0x24,0x10,0x89,0x4c,0x24,0x14,0x89,0x54,0x24,0x18,0x89,0x5c,0x24,0x1c,0x8d,0x84,0x24,0x00,0x01,0x00,0x00,0x89,0x44,0x24,0x20,0x89,0x6c,0x24,0x24,0x89,0x74,0x24,0x28,0x89,0x7c,0x24,0x2c,0x9c,0x58,0x89,0x44,0x24,0x0c,0x0f,0x11,0x44,0x24,0x30,0x0f,0x11,0x4c,0x24,0x40,0x0f,0x11,0x54,0x24,0x50,0x0f,0x11,0x5c,0x24,0x60,0x0f,0x11,0x64,0x24,0x70,0x0f,0x11,0xac,0x24,0x80,0x00,0x00,0x00,0x0f,0x11,0xb4,0x24,0x90,0x00,0x00,0x00,0x0f,0x11,0xbc,0x24,0xa0,0x00,0x00,0x00,0x89,0xe1
		};
		if (Dst && Size >= sizeof(shell_code))
		{
			memcpy(Dst, shell_code, sizeof(shell_code));
		}
		return sizeof(shell_code);
	}
	static int WriteX86RegisterRestoreCode(PVOID Dst, SIZE_T Size)
	{
		static const constexpr unsigned char shell_code[] = {
			/*
				mov eax,[esp+0x0C]
				push eax
				popfd
				mov edi,[esp+0x02c]
				mov esi,[esp+0x028]
				mov ebp,[esp+0x024]
				mov ebx,[esp+0x01c]
				mov edx,[esp+0x018]
				mov ecx,[esp+0x014]
				mov eax,[esp+0x010]
				movups xmm0,[esp+0x30]
				movups xmm1,[esp+0x40]
				movups xmm2,[esp+0x50]
				movups xmm3,[esp+0x60]
				movups xmm4,[esp+0x70]
				movups xmm5,[esp+0x80]
				movups xmm6,[esp+0x90]
				movups xmm7,[esp+0xA0]
				lea esp,[esp+0x100]
			*/
			0x8b,0x44,0x24,0x0c,0x50,0x9d,0x8b,0x7c,0x24,0x2c,0x8b,0x74,0x24,0x28,0x8b,0x6c,0x24,0x24,0x8b,0x5c,0x24,0x1c,0x8b,0x54,0x24,0x18,0x8b,0x4c,0x24,0x14,0x8b,0x44,0x24,0x10,0x0f,0x10,0x44,0x24,0x30,0x0f,0x10,0x4c,0x24,0x40,0x0f,0x10,0x54,0x24,0x50,0x0f,0x10,0x5c,0x24,0x60,0x0f,0x10,0x64,0x24,0x70,0x0f,0x10,0xac,0x24,0x80,0x00,0x00,0x00,0x0f,0x10,0xb4,0x24,0x90,0x00,0x00,0x00,0x0f,0x10,0xbc,0x24,0xa0,0x00,0x00,0x00,0x8d,0xa4,0x24,0x00,0x01,0x00,0x00
		};
		if (Dst && Size >= sizeof(shell_code))
		{
			memcpy(Dst, shell_code, sizeof(shell_code));
		}
		return sizeof(shell_code);
	}
	static int WriteX64RegisterSaveCode(PVOID Dst, SIZE_T Size)
	{
		static const constexpr unsigned char shell_code[] = {
			/*
				lea rsp,[rsp-0x200]
				mov [rsp+0x010],rax
				mov [rsp+0x018],rcx
				pushfq
				pop rax
				mov [rsp+0x008],rax
				lea rcx,[rsp+0x10]
				and rcx,-0x10
				mov rax,[rsp+0x018]
				mov [rcx+0x018],rax
				mov rax,[rsp+0x010]
				mov [rcx+0x010],rax
				mov rax,[rsp+0x008]
				mov [rcx+0x008],rax
				mov [rcx+0x020],rdx
				mov [rcx+0x028],rbx
				lea rax,[rsp+0x200]
				mov [rcx+0x030],rax
				mov [rcx+0x038],rbp
				mov [rcx+0x040],rsi
				mov [rcx+0x048],rdi
				mov [rcx+050h],r8
				mov [rcx+058h],r9
				mov [rcx+060h],r10
				mov [rcx+068h],r11
				mov [rcx+070h],r12
				mov [rcx+078h],r13
				mov [rcx+080h],r14
				mov [rcx+088h],r15
				movups [rcx+0x090],xmm0
				movups [rcx+0x0A0],xmm1
				movups [rcx+0x0B0],xmm2
				movups [rcx+0x0C0],xmm3
				movups [rcx+0x0D0],xmm4
				movups [rcx+0x0E0],xmm5
				movups [rcx+0x0F0],xmm6
				movups [rcx+0x100],xmm7
				movups [rcx+0x110],xmm8
				movups [rcx+0x120],xmm9
				movups [rcx+0x130],xmm10
				movups [rcx+0x140],xmm11
				movups [rcx+0x150],xmm12
				movups [rcx+0x160],xmm13
				movups [rcx+0x170],xmm14
				movups [rcx+0x180],xmm15
				mov rax,[rcx+0x010]
				push rcx
				test rsp,-0x10
				jz $lab1
				push -0x1
			$lab1:
				nop
			*/
			0x48,0x8d,0xa4,0x24,0x00,0xfe,0xff,0xff,0x48,0x89,0x44,0x24,0x10,0x48,0x89,0x4c,0x24,0x18,0x9c,0x58,0x48,0x89,0x44,0x24,0x08,0x48,0x8d,0x4c,0x24,0x10,0x48,0x83,0xe1,0xf0,0x48,0x8b,0x44,0x24,0x18,0x48,0x89,0x41,0x18,0x48,0x8b,0x44,0x24,0x10,0x48,0x89,0x41,0x10,0x48,0x8b,0x44,0x24,0x08,0x48,0x89,0x41,0x08,0x48,0x89,0x51,0x20,0x48,0x89,0x59,0x28,0x48,0x8d,0x84,0x24,0x00,0x02,0x00,0x00,0x48,0x89,0x41,0x30,0x48,0x89,0x69,0x38,0x48,0x89,0x71,0x40,0x48,0x89,0x79,0x48,0x4c,0x89,0x41,0x50,0x4c,0x89,0x49,0x58,0x4c,0x89,0x51,0x60,0x4c,0x89,0x59,0x68,0x4c,0x89,0x61,0x70,0x4c,0x89,0x69,0x78,0x4c,0x89,0xb1,0x80,0x00,0x00,0x00,0x4c,0x89,0xb9,0x88,0x00,0x00,0x00,0x0f,0x11,0x81,0x90,0x00,0x00,0x00,0x0f,0x11,0x89,0xa0,0x00,0x00,0x00,0x0f,0x11,0x91,0xb0,0x00,0x00,0x00,0x0f,0x11,0x99,0xc0,0x00,0x00,0x00,0x0f,0x11,0xa1,0xd0,0x00,0x00,0x00,0x0f,0x11,0xa9,0xe0,0x00,0x00,0x00,0x0f,0x11,0xb1,0xf0,0x00,0x00,0x00,0x0f,0x11,0xb9,0x00,0x01,0x00,0x00,0x44,0x0f,0x11,0x81,0x10,0x01,0x00,0x00,0x44,0x0f,0x11,0x89,0x20,0x01,0x00,0x00,0x44,0x0f,0x11,0x91,0x30,0x01,0x00,0x00,0x44,0x0f,0x11,0x99,0x40,0x01,0x00,0x00,0x44,0x0f,0x11,0xa1,0x50,0x01,0x00,0x00,0x44,0x0f,0x11,0xa9,0x60,0x01,0x00,0x00,0x44,0x0f,0x11,0xb1,0x70,0x01,0x00,0x00,0x44,0x0f,0x11,0xb9,0x80,0x01,0x00,0x00,0x48,0x8b,0x41,0x10,0x51,0x48,0xf7,0xc4,0xf0,0xff,0xff,0xff,0x74,0x02,0x6a,0xff,0x90
		};
		if (Dst && Size >= sizeof(shell_code))
		{
			memcpy(Dst, shell_code, sizeof(shell_code));
		}
		return sizeof(shell_code);
	}
	static int WriteX64RegisterRestoreCode(PVOID Dst, SIZE_T Size)
	{
		static const constexpr unsigned char shell_code[] = {
			/*
				pop rcx
				cmp rcx,-0x1
				jnz $lab2
				pop rcx
			$lab2:
				movups xmm15,[rcx+0x180]
				movups xmm14,[rcx+0x170]
				movups xmm13,[rcx+0x160]
				movups xmm12,[rcx+0x150]
				movups xmm11,[rcx+0x140]
				movups xmm10,[rcx+0x130]
				movups xmm9,[rcx+0x120]
				movups xmm8,[rcx+0x110]
				movups xmm7,[rcx+0x100]
				movups xmm6,[rcx+0x0F0]
				movups xmm5,[rcx+0x0E0]
				movups xmm4,[rcx+0x0D0]
				movups xmm3,[rcx+0x0C0]
				movups xmm2,[rcx+0x0B0]
				movups xmm1,[rcx+0x0A0]
				movups xmm0,[rcx+0x090]
				mov r15,[rcx+088h]
				mov r14,[rcx+080h]
				mov r13,[rcx+078h]
				mov r12,[rcx+070h]
				mov r11,[rcx+068h]
				mov r10,[rcx+060h]
				mov r9,[rcx+058h]
				mov r8,[rcx+050h]
				mov rdi,[rcx+0x048]
				mov rsi,[rcx+0x040]
				mov rbp,[rcx+0x038]
				mov rbx,[rcx+0x028]
				mov rdx,[rcx+0x020]
				mov rax,[rcx+0x008]
				push rax
				popfq
				mov rax,[rcx+0x010]
				mov rcx,[rcx+0x018]
				lea rsp,[rsp+0x200]
			*/
			0x59,0x48,0x83,0xf9,0xff,0x75,0x01,0x59,0x44,0x0f,0x10,0xb9,0x80,0x01,0x00,0x00,0x44,0x0f,0x10,0xb1,0x70,0x01,0x00,0x00,0x44,0x0f,0x10,0xa9,0x60,0x01,0x00,0x00,0x44,0x0f,0x10,0xa1,0x50,0x01,0x00,0x00,0x44,0x0f,0x10,0x99,0x40,0x01,0x00,0x00,0x44,0x0f,0x10,0x91,0x30,0x01,0x00,0x00,0x44,0x0f,0x10,0x89,0x20,0x01,0x00,0x00,0x44,0x0f,0x10,0x81,0x10,0x01,0x00,0x00,0x0f,0x10,0xb9,0x00,0x01,0x00,0x00,0x0f,0x10,0xb1,0xf0,0x00,0x00,0x00,0x0f,0x10,0xa9,0xe0,0x00,0x00,0x00,0x0f,0x10,0xa1,0xd0,0x00,0x00,0x00,0x0f,0x10,0x99,0xc0,0x00,0x00,0x00,0x0f,0x10,0x91,0xb0,0x00,0x00,0x00,0x0f,0x10,0x89,0xa0,0x00,0x00,0x00,0x0f,0x10,0x81,0x90,0x00,0x00,0x00,0x4c,0x8b,0xb9,0x88,0x00,0x00,0x00,0x4c,0x8b,0xb1,0x80,0x00,0x00,0x00,0x4c,0x8b,0x69,0x78,0x4c,0x8b,0x61,0x70,0x4c,0x8b,0x59,0x68,0x4c,0x8b,0x51,0x60,0x4c,0x8b,0x49,0x58,0x4c,0x8b,0x41,0x50,0x48,0x8b,0x79,0x48,0x48,0x8b,0x71,0x40,0x48,0x8b,0x69,0x38,0x48,0x8b,0x59,0x28,0x48,0x8b,0x51,0x20,0x48,0x8b,0x41,0x08,0x50,0x9d,0x48,0x8b,0x41,0x10,0x48,0x8b,0x49,0x18,0x48,0x8d,0xa4,0x24,0x00,0x02,0x00,0x00
		};
		if (Dst && Size >= sizeof(shell_code))
		{
			memcpy(Dst, shell_code, sizeof(shell_code));
		}
		return sizeof(shell_code);
	}
#pragma endregion

#pragma region Tools
public:
	static bool CreateDirs(PCWSTR DirPath) noexcept
	{
		wchar_t ParentDirPath[260] = { 0 };
		if (wcslen(DirPath) >= sizeof(ParentDirPath) / sizeof(ParentDirPath[0]))
		{
			return false;
		}
		HANDLE hDir = INVALID_HANDLE_VALUE;
#ifdef WINNT
		IO_STATUS_BLOCK IoStatus{};
		OBJECT_ATTRIBUTES ObjectAttr = { 0 };
		UNICODE_STRING DirNameUStr{};
		wchar_t NtDirName[260 + 3] = { 0 };
		wcscat_s(NtDirName, L"\\??\\");
		wcscat_s(NtDirName, DirPath);
		RtlInitUnicodeString(&DirNameUStr, NtDirName);
		InitializeObjectAttributes(&ObjectAttr, &DirNameUStr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
#endif // WINNT
		bool first = true;
		while (true)
		{
#ifdef WINNT
			NTSTATUS status = ZwCreateFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &ObjectAttr, &IoStatus, NULL, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
			if (!NT_SUCCESS(status) && status == STATUS_OBJECT_PATH_NOT_FOUND)
			{
#else
			hDir = CreateFileW(DirPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_NEW, 0x03000000/*CREATE_DIRECTORY*/ | FILE_ATTRIBUTE_DIRECTORY, NULL);
			if (hDir == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_EXISTS)
			{
#endif // WINNT
				if (first)
				{
					first = false;
					wcscpy(ParentDirPath, DirPath);
					auto Pos = wcschr(ParentDirPath, L'\\');
					auto RPos = wcsrchr(ParentDirPath, L'\\');
					if (RPos != Pos)
					{
						*RPos = L'\0';
						if (CreateDirs(ParentDirPath))
						{
							continue;
						}
					}
				}
			}
			break;
		}
		bool result = false;
		if (hDir != INVALID_HANDLE_VALUE)
		{
			result = true;
#ifdef WINNT
			ZwClose(hDir);
#else
			CloseHandle(hDir);
#endif // WINNT
		}
		return result;
	}
	static HANDLE OpenFile(PCWSTR FilePath, bool Create) noexcept
	{
		wchar_t DirPath[260] = { 0 };
		if (wcslen(FilePath) >= sizeof(DirPath) / sizeof(DirPath[0]))
		{
			return INVALID_HANDLE_VALUE;
		}
		HANDLE result = INVALID_HANDLE_VALUE;
#ifdef WINNT
		IO_STATUS_BLOCK IoStatus;
		OBJECT_ATTRIBUTES ObjectAttr = { 0 };
		UNICODE_STRING FileNameUStr;
		wchar_t NtFileName[260 + 3] = { 0 };
		wcscat_s(NtFileName, L"\\??\\");
		wcscat_s(NtFileName, FilePath);
		RtlInitUnicodeString(&FileNameUStr, NtFileName);
		InitializeObjectAttributes(&ObjectAttr, &FileNameUStr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
#endif
		bool first = true;
		while (true)
		{
#ifdef WINNT
			NTSTATUS status = ZwCreateFile(&result, GENERIC_WRITE | GENERIC_READ, &ObjectAttr, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
				Create ? FILE_OPEN_IF : FILE_OPEN,
				FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
			if(!NT_SUCCESS(status) && status == STATUS_OBJECT_PATH_NOT_FOUND)
			{
#else
			result = CreateFileW(FilePath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL,
				Create ? OPEN_ALWAYS : OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL, NULL);
			if (result == INVALID_HANDLE_VALUE && GetLastError() == 3)
			{
#endif // WINNT
				if (first && Create)
				{
					first = false;
					wcscpy(DirPath, FilePath);
					auto Pos = wcschr(DirPath, L'\\');
					auto RPos = wcsrchr(DirPath, L'\\');
					if (RPos != Pos)
					{
						*RPos = L'\0';
						if (CreateDirs(DirPath))
						{
							continue;
						}
					}
				}
			}
			break;
		}
		return result;
	}
	static VOID CloseFile(HANDLE hFile) noexcept
	{
#ifdef WINNT
		ZwClose(hFile);
#else
		CloseHandle(hFile);
#endif
	}
	static void DebugPrint(PCSTR Flag, PCSTR Format, ...) noexcept
	{
		char stack_buffer[1024] = { 0 };

		char* buffer_ptr = stack_buffer;
		ULONG buffer_count = (int)sizeof(stack_buffer);
		ULONG buffer_pos = 0;
		int len;
		if (Flag)
		{
			len = _snprintf(buffer_ptr + buffer_pos, buffer_count - buffer_pos, "%s-> ", Flag);
			buffer_pos = len >= 0 ? buffer_pos + len : buffer_count;
		}
		va_list ap;
		va_start(ap, Format);
		len = _vsnprintf(buffer_ptr + buffer_pos, buffer_count - buffer_pos, Format, ap);
		buffer_pos = len >= 0 ? buffer_pos + len : buffer_count;
		va_end(ap);

		char write_buffer[2048] = { 0 };
		ULONG write_buffer_pos = 0;
		for (ULONG buffer_index = 0; buffer_index < buffer_pos; buffer_index++)
		{
			switch (buffer_ptr[buffer_index])
			{
			case '\n':
				write_buffer[write_buffer_pos++] = '\\';
				write_buffer[write_buffer_pos++] = 'n';
				break;
			case '\\':
				write_buffer[write_buffer_pos++] = '\\';
				write_buffer[write_buffer_pos++] = '\\';
				break;
			case '\t':
				write_buffer[write_buffer_pos++] = '\\';
				write_buffer[write_buffer_pos++] = 't';
				break;
			default:
				write_buffer[write_buffer_pos++] = buffer_ptr[buffer_index];
				break;
			}
			if (write_buffer_pos >= sizeof(write_buffer) - 4)
			{
				write_buffer[write_buffer_pos++] = '\0';
#ifdef WINNT
				DbgPrintEx(0, 0, write_buffer);
#else
				OutputDebugStringA(write_buffer);
#endif
				write_buffer_pos = 0;
			}
		}
		write_buffer[write_buffer_pos++] = '\n';
		write_buffer[write_buffer_pos++] = '\0';
#ifdef WINNT
		DbgPrintEx(0, 0, write_buffer);
#else
		OutputDebugStringA(write_buffer);
#endif
	}
	static ULONG GetSystemBuildNumber() noexcept
	{
		ULONG number = 0;
		RTL_OSVERSIONINFOEXW info = { 0 };
		info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		if (NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&info))) number = info.dwBuildNumber;
		return number;
	}
	static PVOID GetSystemModuleBase(PCSTR ImageName, ULONG* pImageSize) noexcept
	{
		PVOID imageBase = NULL;
		UCHAR buf[4] = { 0 };
		PRTL_PROCESS_MODULES buffer = (PRTL_PROCESS_MODULES)buf;
		ULONG bufferSize = sizeof(buf);
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			buffer = (PRTL_PROCESS_MODULES)Malloc(bufferSize);
			if (buffer != NULL) {
				status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
				if (NT_SUCCESS(status)) {
					for (ULONG i = 0; i < buffer->NumberOfModules; i++) {
						PCSTR fullPathName = (PCSTR)buffer->Modules[i].FullPathName;
						if (strstr(fullPathName, ImageName) != NULL) {
							imageBase = buffer->Modules[i].ImageBase;
							if (pImageSize != NULL)
								*pImageSize = buffer->Modules[i].ImageSize;
							break;
						}
					}
				}
				Free(buffer);
			}
		}
		return imageBase;
	}
	static ULONG GetProcessIdByProcessName(PCWSTR ImageName) noexcept
	{
		ULONG processId = 0;
		UCHAR buf[4] = { 0 };
		PRTL_PROCESS_MODULES buffer = (PRTL_PROCESS_MODULES)buf;
		ULONG bufferSize = sizeof(buf);
		NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			buffer = (PRTL_PROCESS_MODULES)Malloc(bufferSize);
			if (buffer != NULL) {
				status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
				if (NT_SUCCESS(status)) {
					PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
					UNICODE_STRING uStr;
					RtlInitUnicodeString(&uStr, ImageName);
					while (TRUE) {

						if (RtlCompareUnicodeString(&pProcessInfo->ImageName, &uStr, true) == 0) {
							processId = (ULONG)(ULONG_PTR)pProcessInfo->UniqueProcessId;
							break;
						}
						else if (pProcessInfo->NextEntryOffset == 0)
							break;
						else
							pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
					}
				}
				Free(buffer);
			}
		}
		return processId;
	}
	template<typename FUN>//[&]()->ULONG_PTR
	static ULONG_PTR SingleProcessorExecute(FUN fun) noexcept
	{
		ULONG_PTR result = 0;
#ifdef WINNT
		struct IPI_PARAM {
			DWORD64 LockSign;
			DWORD64 execProcessorIndex;
			FUN* fun;
		};
		IPI_PARAM param = { 0 };
		param.fun = &fun;
		param.execProcessorIndex = KeGetCurrentProcessorIndex();
		param.LockSign = 0;
		result = KeIpiGenericCall([](ULONG_PTR Argument)-> ULONG_PTR {
			IPI_PARAM* pParam = (IPI_PARAM*)Argument;
			ULONG_PTR result = 0;
			if (pParam->execProcessorIndex == KeGetCurrentProcessorIndex())
			{
				result = (*pParam->fun)();
				pParam->LockSign = 1;
			}
			else
			{
				while (pParam->LockSign == 0)
					_mm_pause();
			}
			return result;
			}, (ULONG_PTR)&param);
#else
		HANDLE ThreadHandles[1000] = { NULL };
		int ThreadHandleIndex = 0;
		bool success = false;
		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap != INVALID_HANDLE_VALUE)
		{
			THREADENTRY32 te32 = { 0 };
			te32.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(hThreadSnap, &te32))
			{
				while (1)
				{
					if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
					{
						ThreadHandles[ThreadHandleIndex] = OpenThread(THREAD_SUSPEND_RESUME, false, te32.th32ThreadID);
						if (ThreadHandles[ThreadHandleIndex] == NULL)
						{
							for (int i = ThreadHandleIndex - 1; i >= 0; i--)
							{
								ResumeThread(ThreadHandles[i]);
								CloseHandle(ThreadHandles);
								break;
							}
						}
						else
						{
							SuspendThread(ThreadHandles[ThreadHandleIndex]);
							ThreadHandleIndex++;
						}
					}
					if (!Thread32Next(hThreadSnap, &te32))
					{
						success = true;
						break;
					}
				}
			}
			CloseHandle(hThreadSnap);
		}
		if (success)
		{
			result = fun();
			for (int i = ThreadHandleIndex - 1; i >= 0; i--)
			{
				ResumeThread(ThreadHandles[i]);
				CloseHandle(ThreadHandles[i]);
			}
		}
#endif // WINNT
		return result;
	}
	static bool ModifyInstruct(PVOID Address, PVOID Buffer, ULONG Size) noexcept
	{
		bool result = false;
#ifdef WINNT
		PMDL pMdl = IoAllocateMdl(Address, Size, false, false, NULL);
		if (pMdl)
		{
			MmBuildMdlForNonPagedPool(pMdl);
			PVOID newDst = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, 0);
			if (newDst)
			{
				bool LockSig = false;
				ULONG_PTR Param[5] = { (ULONG_PTR)newDst ,(ULONG_PTR)Buffer ,(ULONG_PTR)Size ,KeGetCurrentProcessorNumber() ,(ULONG_PTR)&LockSig };
				KeIpiGenericCall([](ULONG_PTR Argument)->ULONG_PTR {
					PVOID Address = (PVOID)((ULONG_PTR*)Argument)[0];
					PVOID Buffer = (PVOID)((ULONG_PTR*)Argument)[1];
					ULONG Size = (ULONG)((ULONG_PTR*)Argument)[2];
					ULONG SourceProcessorNumber = (ULONG)((ULONG_PTR*)Argument)[3];
					bool* pLockSig = (bool*)((ULONG_PTR*)Argument)[4];
					if (KeGetCurrentProcessorNumber() == SourceProcessorNumber)
					{
						memcpy(Address, Buffer, Size);
						*pLockSig = true;
					}
					else
					{
						while (!*pLockSig)
							_mm_pause();
					}
					return true;
					}, (ULONG_PTR)&Param);
				memcpy(newDst, Buffer, Size);
				result = true;
				MmUnmapLockedPages(newDst, pMdl);
			}
			IoFreeMdl(pMdl);
		}
#else
		HANDLE ThreadHandles[1000] = { NULL };
		int ThreadHandleIndex = 0;
		bool success = false;
		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap != INVALID_HANDLE_VALUE)
		{
			THREADENTRY32 te32 = { 0 };
			te32.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(hThreadSnap, &te32))
			{
				while (1)
				{
					if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != GetCurrentThreadId())
					{
						ThreadHandles[ThreadHandleIndex] = OpenThread(THREAD_SUSPEND_RESUME, false, te32.th32ThreadID);
						if (ThreadHandles[ThreadHandleIndex] == NULL)
						{
							for (int i = ThreadHandleIndex - 1; i >= 0; i--)
							{
								ResumeThread(ThreadHandles[i]);
								CloseHandle(ThreadHandles);
								break;
							}
						}
						else
						{
							SuspendThread(ThreadHandles[ThreadHandleIndex]);
							ThreadHandleIndex++;
						}
					}
					if (!Thread32Next(hThreadSnap, &te32))
					{
						success = true;
						break;
					}
				}
			}
			CloseHandle(hThreadSnap);
		}
		if (success)
		{
			DWORD flOldProtect = 0;
			if (VirtualProtect(Address, Size, PAGE_EXECUTE_READWRITE, &flOldProtect))
			{
				memcpy(Address, Buffer, Size);
				VirtualProtect(Address, Size, flOldProtect, &flOldProtect);
				result = true;
			}
			for (int i = ThreadHandleIndex - 1; i >= 0; i--)
			{
				ResumeThread(ThreadHandles[i]);
				CloseHandle(ThreadHandles[i]);
			}
		}
#endif // WINNT
		return result;
	}
#ifdef WINNT
private:
	union wpdata_t
	{
		struct
		{
			KIRQL IRQL;
			unsigned IRQLF : 1;
			unsigned IF : 1;
			unsigned WP : 1;
			unsigned CET : 1;
		};
		unsigned __int64 value;
	};
public:
	static DWORD64 DisableWP() noexcept
	{
		wpdata_t Data = { 0 };
		if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
			Data.IRQLF = 1;
			Data.IRQL = KeRaiseIrqlToDpcLevel();
		}
		UINT64 cr4 = __readcr4();
		if (cr4 & 0x800000)
		{
			Data.CET = 1;
			cr4 &= 0xffffffffff7fffff;
			__writecr4(cr4);
		}
		UINT64 cr0 = __readcr0();
		if (cr0 & 0x10000) {
			Data.WP = 1;
			cr0 &= 0xfffffffffffeffff;
			__writecr0(cr0);
		}
		UINT64 eflags = __readeflags();
		if (eflags & 0x200) {
			Data.IF = 1;
			_disable();
		}
		return Data.value;
	}
	static VOID RestoreWP(DWORD64 value) noexcept
	{
		wpdata_t Data = { 0 };
		Data.value = value;
		if (Data.IF)
			_enable();
		if (Data.WP) {
			UINT64 cr0 = __readcr0();
			cr0 |= 0x10000;
			__writecr0(cr0);
		}
		if (Data.CET)
		{
			UINT64 cr4 = __readcr4();
			cr4 |= 0x800000;
			__writecr4(cr4);
		}
		if (Data.IRQLF)
			KeLowerIrql(Data.IRQL);
	}
	static VOID ExSetPreviousMode(KPROCESSOR_MODE previousMode) noexcept
	{
		static ULONG previousMode_offset = 0;
		if (previousMode_offset == 0)
		{
			UNICODE_STRING uStr;
			RtlInitUnicodeString(&uStr, L"ExGetPreviousMode");
			PVOID ExSetPreviousMode_addr = MmGetSystemRoutineAddress(&uStr);
			if (ExSetPreviousMode_addr != NULL)
				previousMode_offset = *(ULONG*)((PUCHAR)ExSetPreviousMode_addr + 0xC);
		}
		if (previousMode_offset != 0)
		{
			DWORD64 theThread = __readgsqword(0x188);
			*(UCHAR*)(theThread + previousMode_offset) = previousMode;
		}
	}
	static bool WritePhysicalMemory(ULONG64 PhysicalAddress, PVOID Buffer, SIZE_T Size) noexcept
	{
		bool result = false;
		SIZE_T AllocateSize = Size + PAGE_SIZE;
		PVOID VirtualAddress = MmAllocateMappingAddress(AllocateSize, 'MAPP');
		if (VirtualAddress)
		{
			for (SIZE_T Offset = 0; Offset < AllocateSize; Offset += PAGE_SIZE)
			{
				FYLIB::ADDRESS AddressValue(VirtualAddress);
				AddressValue.PtPtr()->page_frame_number = ((PhysicalAddress & ~(PAGE_SIZE - 1)) + Offset) >> 12;
				AddressValue.PtPtr()->present = 1;
				AddressValue.PtPtr()->write = 1;
			}
			__invlpg(VirtualAddress);
			memcpy((PUCHAR)VirtualAddress + (PhysicalAddress & 0xFFF), Buffer, Size);
			for (SIZE_T Offset = 0; Offset < AllocateSize; Offset += PAGE_SIZE)
			{
				FYLIB::ADDRESS AddressValue(VirtualAddress);
				AddressValue.PtPtr()->flags = 0;
			}
			__invlpg(VirtualAddress);
			MmFreeMappingAddress(VirtualAddress, 'MAPP');
			result = true;
		}
		return result;
	}
	static bool ReadPhysicalMemory(ULONG64 PhysicalAddress, PVOID Buffer, SIZE_T Size) noexcept
	{
		bool result = false;
		SIZE_T AllocateSize = Size + PAGE_SIZE;
		PVOID VirtualAddress = MmAllocateMappingAddress(AllocateSize, 'MAPP');
		if (VirtualAddress)
		{
			for (SIZE_T Offset = 0; Offset < AllocateSize; Offset += PAGE_SIZE)
			{
				FYLIB::ADDRESS AddressValue(VirtualAddress);
				AddressValue.PtPtr()->page_frame_number = ((PhysicalAddress & ~(PAGE_SIZE - 1)) + Offset) >> 12;
				AddressValue.PtPtr()->present = 1;
				AddressValue.PtPtr()->write = 1;
			}
			__invlpg(VirtualAddress);
			memcpy(Buffer, (PUCHAR)VirtualAddress + (PhysicalAddress & 0xFFF), Size);
			for (SIZE_T Offset = 0; Offset < AllocateSize; Offset += PAGE_SIZE)
			{
				FYLIB::ADDRESS AddressValue(VirtualAddress);
				AddressValue.PtPtr()->flags = 0;
			}
			__invlpg(VirtualAddress);
			MmFreeMappingAddress(VirtualAddress, 'MAPP');
			result = true;
		}
		return result;
	}
	static PVOID ShellCode_GetNtoskrnlBase() noexcept
	{
		static PVOID _NtoskrnlBase = NULL;
		if (!_NtoskrnlBase)
		{
			ULONG64 MsrLStar = 0;
			MsrLStar = __readmsr(0xc0000082);	//IA32_LSTAR
			//ULONG64 BaseAddress = MsrLStar & 0xFFFFFFFFFFFFF000ULL;
			//while (((DWORD64*)BaseAddress)[0] != 0x0000000300905A4DULL || ((DWORD64*)BaseAddress)[1] != 0x0000FFFF00000004ULL)
			//    BaseAddress -= 0x1000;
			ULONG64 BaseAddress = MsrLStar & (~0x1FFFFFULL);
			while (((DWORD64*)BaseAddress)[0] != 0x0000000300905A4DULL || ((DWORD64*)BaseAddress)[1] != 0x0000FFFF00000004ULL)
				BaseAddress -= 0x200000ULL;
			_NtoskrnlBase = (PVOID)BaseAddress;
		}
		return _NtoskrnlBase;
	}
	static INT GetSelfMappingIndex() noexcept
	{
		static INT selfMapIndex = -1;
		if (selfMapIndex < 0)
		{
			DWORD64 cr3 = __readcr3();
			PHYSICAL_ADDRESS cr3_ap = { 0 };
			cr3_ap.QuadPart = cr3 & 0x0000FFFFFFFFF000;
			PVOID cr3_va = MmGetVirtualForPhysical(cr3_ap);
			if (cr3_va != NULL)
			{
				for (INT i = 0; i < 512; i++)
				{
					if ((((DWORD64*)cr3_va)[i] & 0x0000FFFFFFFFF000) == (cr3 & 0x0000FFFFFFFFF000))
					{
						selfMapIndex = i;
						break;
					}
				}
			}
		}
		return selfMapIndex;
	}
	static ULONG64 GetIdtProcAddress(UCHAR Index) noexcept
	{
#pragma pack(1)
		typedef struct _IDTR
		{
			USHORT limit;
			ULONG64 Base;
		}IDTR, * PIDTR;

		typedef union _IDT_ENTRY
		{
			struct kidt
			{
				USHORT OffsetLow;
				USHORT Selector;
				USHORT IstIndex : 3;
				USHORT Reserved0 : 5;
				USHORT Type : 5;
				USHORT Dpl : 2;
				USHORT Present : 1;
				USHORT OffsetMiddle;
				ULONG OffsetHigh;
				ULONG Reserved1;
			}idt;
			UINT64 Alignment;
		}IDT_ENTRY, * PIDT_ENTRY;
#pragma pack()
		IDTR Idtr;
		__sidt(&Idtr);


		PIDT_ENTRY Pidt = (PIDT_ENTRY)(Idtr.Base);
		Pidt = Pidt + Index;
		ULONG64 OffsetHigh, OffsetMiddle, OffsetLow, result;

		OffsetHigh = Pidt->idt.OffsetHigh;
		OffsetHigh = OffsetHigh << 32;

		OffsetMiddle = Pidt->idt.OffsetMiddle;
		OffsetMiddle = OffsetMiddle << 16;

		OffsetLow = Pidt->idt.OffsetLow;
		result = OffsetHigh + OffsetMiddle + OffsetLow;
		return result;
	}
	struct PME
	{
		union
		{
			unsigned __int64 flags;
			struct
			{
				unsigned __int64 present : 1;
				unsigned __int64 write : 1;
				unsigned __int64 user : 1;
				unsigned __int64 write_through : 1;
				unsigned __int64 cache_disable : 1;
				unsigned __int64 accessed : 1;
				unsigned __int64 dirty : 1;
				unsigned __int64 large_page : 1;
				unsigned __int64 global : 1;
				unsigned __int64 reserved1 : 2;
				unsigned __int64 r : 1;
				unsigned __int64 page_frame_number : 40;
				unsigned __int64 avl : 11;
				unsigned __int64 execute_disable : 1;
			};
		};
	};
	struct ADDRESS
	{
		static constexpr unsigned __int64 PT_SIZE = 0x1000;
		static constexpr unsigned __int64 PD_SIZE = PT_SIZE * 0x200;
		static constexpr unsigned __int64 PDPT_SIZE = PD_SIZE * 0x200;
		static constexpr unsigned __int64 PML4_SIZE = PDPT_SIZE * 0x200;
		union
		{
			//xx_index:在上一级的序号
			//xx_number:总序号
			UINT64 flags;
			PVOID address;
			struct
			{
				ULONG64 offset : 12;
				ULONG64 pt_index : 9;
				ULONG64 pd_index : 9;
				ULONG64 pdpt_index : 9;
				ULONG64 pml4_index : 9;
				ULONG64 reserved : 16;
			};
			struct
			{
				ULONG64 pt_offset : 12;
				ULONG64 pt_number : 36;
			};
			struct
			{
				ULONG64 pd_offset : 21;
				ULONG64 pd_number : 27;
			};
			struct
			{
				ULONG64 pdpt_offset : 30;
				ULONG64 pdpt_number : 18;
			};
			struct
			{
				ULONG64 pml4_offset : 39;
				ULONG64 pml4_number : 9;
			};
		};
		inline ADDRESS(PVOID _address = nullptr)noexcept :address(_address) {}
		inline ADDRESS(ULONG64 _flags) : flags(_flags) {}
		inline ADDRESS(int pml4, int pdpt, int pd, int pt, unsigned long long _pt_offset)noexcept : reserved(pml4 & 0x100 ? 0xFFFF : 0), pml4_index(pml4), pdpt_index(pdpt), pd_index(pd), pt_index(pt) { pt_offset = _pt_offset; }
		inline ADDRESS(int pml4, int pdpt, int pd, unsigned long long _pd_offset)noexcept : reserved(pml4 & 0x100 ? 0xFFFF : 0), pml4_index(pml4), pdpt_index(pdpt), pd_index(pd) { pd_offset = _pd_offset; }
		inline ADDRESS(int pml4, int pdpt, unsigned long long _pdpt_offset)noexcept : reserved(pml4 & 0x100 ? 0xFFFF : 0), pml4_index(pml4), pdpt_index(pdpt) { pdpt_offset = _pdpt_offset; }
		inline ADDRESS(int pml4, unsigned long long _pml4_offset)noexcept : reserved(pml4 & 0x100 ? 0xFFFF : 0), pml4_index(pml4) { pml4_offset = _pml4_offset; }
		inline PME* Pml4Ptr()noexcept{
			int index = GetSelfMappingIndex();
			if (index < 0)
				return nullptr;
			return static_cast<PME*>(ADDRESS(index, index, index, index, this->pml4_index << 3).address);
		}
		inline PME* PdptPtr()noexcept{
			int index = GetSelfMappingIndex();
			if (index < 0)
				return nullptr;
			return static_cast<PME*>(ADDRESS(index, index, index, this->pml4_index, this->pdpt_index << 3).address);
		}
		inline PME* PdPtr()noexcept{
			int index = GetSelfMappingIndex();
			if (index < 0)
				return nullptr;
			return static_cast<PME*>(ADDRESS(index, index, this->pml4_index, this->pdpt_index, this->pd_index << 3).address);
		}
		inline PME* PtPtr()noexcept{
			int index = GetSelfMappingIndex();
			if (index < 0)
				return nullptr;
			return static_cast<PME*>(ADDRESS(index, this->pml4_index, this->pdpt_index, this->pd_index, this->pt_index << 3).address);
		}
		inline bool Valid()noexcept{
			if (!Pml4Ptr()->present)return false;
			else if (!PdptPtr()->present) return false;
			else if (PdptPtr()->large_page)return true;
			else if (!PdPtr()->present)return false;
			else if (PdPtr()->large_page) return true;
			else return PtPtr()->present;
		}
	};
#endif //WINNT
#ifndef WINNT
	static bool AdjustPrivileges(LPCWSTR pPrivilegeName) noexcept
	{
		HANDLE hToken = NULL;
		TOKEN_PRIVILEGES tp = { 0 };
		TOKEN_PRIVILEGES oldtp = { 0 };
		DWORD dwSize = sizeof(TOKEN_PRIVILEGES);
		LUID luid;
		bool result = false;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
		{
			if (LookupPrivilegeValueW(NULL, pPrivilegeName, &luid))
			{
				tp.PrivilegeCount = 1;
				tp.Privileges[0].Luid = luid;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				/* Adjust Token Privileges */
				if (AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwSize))
				{
					result = true;
				}
			}
			CloseHandle(hToken);
		}
		return result;
	}
	static bool LoadDriver(LPCWSTR pServerName, LPCWSTR pdriverFileName) noexcept
	{
		if (GetFileAttributesW(pdriverFileName) == INVALID_FILE_ATTRIBUTES)
		{
			return false;
		}
		bool result = false;
		WCHAR dosPath[MAX_PATH] = { 0 };
		wsprintfW(dosPath, L"\\??\\%s", pdriverFileName);

		WCHAR subKey[100] = { 0 };
		wsprintfW(subKey, L"System\\CurrentControlSet\\Services\\%s", pServerName);
		HKEY hkResult;
		LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, subKey, &hkResult);
		if (status != ERROR_SUCCESS)
			status = RegCreateKeyW(HKEY_LOCAL_MACHINE, subKey, &hkResult);
		if (status == ERROR_SUCCESS)
		{
			//写入注册表
			status = RegSetValueExW(hkResult, L"DisplayName", 0, 1, (const unsigned char*)pServerName, ((ULONG)wcslen(pServerName) + 1) * sizeof(WCHAR));
			DWORD Data = 1;
			if (status == 0)
				status = RegSetValueExW(hkResult, L"Type", 0, 4, (const unsigned char*)&Data, 4);
			if (status == 0)
				status = RegSetValueExW(hkResult, L"ErrorControl", 0, 4, (const unsigned char*)&Data, 4);
			Data = 3;
			if (status == 0)
				status = RegSetValueExW(hkResult, L"Start", 0, 4, (const unsigned char*)&Data, 4);
			if (status == 0)
				status = RegSetValueExW(hkResult, L"ImagePath", 0, 1, (const unsigned char*)dosPath, ((ULONG)wcslen(dosPath) + 1) * sizeof(WCHAR));
			if (status == ERROR_SUCCESS)
			{
				WCHAR driverName[100] = { 0 };
				wsprintfW(driverName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", pServerName);
				UNICODE_STRING uStr;
				RtlInitUnicodeString(&uStr, driverName);
				if (ZwLoadDriver(&uStr) >= 0)
				{
					result = true;
				}
				else
				{
					//删除注册表
					RegDeleteKeyW(hkResult, L"DisplayName");
					RegDeleteKeyW(hkResult, L"Type");
					RegDeleteKeyW(hkResult, L"ErrorControl");
					RegDeleteKeyW(hkResult, L"Start");
					RegDeleteKeyW(hkResult, L"ImagePath");
					RegDeleteKeyW(HKEY_LOCAL_MACHINE, subKey);
				}
			}
			RegCloseKey(hkResult);
		}
		return result;
	}
	static PVOID ShellCode_GetModuleBase(LPCWSTR ImageName, PULONG pImageSize) noexcept
	{
		PVOID Result = NULL;
#ifdef _WIN64
		PEB64* pPeb64 = (PEB64*)__readgsqword(0x60);
		PEB_LDR_DATA64* pLdrData = (PEB_LDR_DATA64*)pPeb64->Ldr;
		PLIST_ENTRY64 pListEntry = (PLIST_ENTRY64)pLdrData->InMemoryOrderModuleList.Flink;
		while (pListEntry != &pLdrData->InMemoryOrderModuleList)
		{
			LDR_DATA_TABLE_ENTRY64* pLdrDataTail = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
			if (pLdrDataTail->BaseDllName.Buffer && pLdrDataTail->BaseDllName.Length > 0)
			{
				if (wcsncmp((PCWSTR)pLdrDataTail->BaseDllName.Buffer, ImageName, pLdrDataTail->BaseDllName.Length / 2) == 0)
				{
					Result = (PVOID)pLdrDataTail->DllBase;
					if (pImageSize)
						*pImageSize = pLdrDataTail->SizeOfImage;
				}
			}
			pListEntry = (PLIST_ENTRY64)pListEntry->Flink;
		}
#else
		PEB32* pPeb32 = (PEB32*)__readfsdword(0x30);
		PEB_LDR_DATA32* pLdrData = (PEB_LDR_DATA32*)pPeb32->Ldr;
		PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)pLdrData->InMemoryOrderModuleList.Flink;
		while (pListEntry != &pLdrData->InMemoryOrderModuleList)
		{
			LDR_DATA_TABLE_ENTRY32* pLdrDataTail = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
			if (pLdrDataTail->BaseDllName.Buffer && pLdrDataTail->BaseDllName.Length > 0)
			{
				if (wcsncmp((PCWSTR)pLdrDataTail->BaseDllName.Buffer, ImageName, pLdrDataTail->BaseDllName.Length / 2) == 0)
				{
					Result = (PVOID)pLdrDataTail->DllBase;
					if (pImageSize)
						*pImageSize = pLdrDataTail->SizeOfImage;
				}
			}
			pListEntry = (PLIST_ENTRY32)pListEntry->Flink;
		}
#endif // _WIN64
		return Result;
	}
	static bool UnLoadDriver(LPCWSTR pServerName) noexcept
	{
		WCHAR driverName[100] = { 0 };
		wsprintfW(driverName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", pServerName);
		UNICODE_STRING uStr;
		RtlInitUnicodeString(&uStr, driverName);
		LSTATUS status = ZwUnloadDriver(&uStr);
		bool result = status >= 0;
		//清理注册表
		WCHAR subKey[100] = { 0 };
		wsprintfW(subKey, L"System\\CurrentControlSet\\Services\\%s", pServerName);
		HKEY hkResult;
		status = RegOpenKeyW(HKEY_LOCAL_MACHINE, subKey, &hkResult);
		if (status == ERROR_SUCCESS)
		{
			RegDeleteKeyW(hkResult, L"DisplayName");
			RegDeleteKeyW(hkResult, L"Type");
			RegDeleteKeyW(hkResult, L"ErrorControl");
			RegDeleteKeyW(hkResult, L"Start");
			RegDeleteKeyW(hkResult, L"ImagePath");
			RegDeleteKeyW(HKEY_LOCAL_MACHINE, subKey);
			RegCloseKey(hkResult);
		}
		return result;
	}
#endif // !WINNT
#pragma endregion

#pragma region Log
public:
	struct LOG
	{
	public:
		enum class LEVEL
		{
			DEBU = 0,
			INFO = 1,
			WARN = 2,
			ERRO = 3
		};
	private:
		static const char* LevelToString(LEVEL Level)
		{
			switch (Level)
			{
			case LEVEL::DEBU:
				return "DEBU";
				break;
			case LEVEL::INFO:
				return "INFO";
				break;
			case LEVEL::WARN:
				return "WARN";
				break;
			case LEVEL::ERRO:
				return "ERRO";
				break;
			default:
				return "NONE";
				break;
			}

		}
		struct static_data_t
		{
			wchar_t FileName[260] = { 0 };
			LEVEL MinLevel = LOG::LEVEL::DEBU;
			ULONG MaxLen = 1024;
#ifdef WINNT
			KEVENT Event;
#else
			CRITICAL_SECTION Cs;
#endif // WINNT
		};
		static inline static_data_t& static_data() noexcept
		{
			static static_data_t data_{};
			return data_;
		}
	public:
		static bool Initialize(PCWSTR FileName, LEVEL MinLevel = LEVEL::DEBU, ULONG MaxLen = 1024)noexcept
		{
			if (wcslen(FileName) >= (sizeof(static_data().FileName) / sizeof(static_data().FileName[0]) - 1))
			{
				return false;
			}
			static_data().MinLevel = MinLevel;
			static_data().MaxLen = MaxLen;
			wcsncpy(static_data().FileName, FileName, sizeof(static_data().FileName) / sizeof(static_data().FileName[0]));
#ifdef WINNT
			KeInitializeEvent(&static_data().Event, NotificationEvent, TRUE);
#else
			InitializeCriticalSection(&static_data().Cs);
#endif
			return true;
		}
		static void Uninitialize() noexcept
		{
#ifndef WINNT
			DeleteCriticalSection(&static_data().Cs);
#endif
		}
		static bool IsPrint(LEVEL Level)
		{
			return Level >= static_data().MinLevel;
		}
		static void WriteLn(LEVEL Level, PCSTR Flag, PCSTR Format, ...) noexcept
		{
			static const char* TimeFormat = "%04d-%02d-%02d %02d:%02d:%02d";
			if (!IsPrint(Level))
			{
				return;
			}
			char stack_buffer[1024] = { 0 };
			char* malloc_buffer = nullptr;

			char* buffer_ptr = stack_buffer;
			ULONG buffer_count = (int)sizeof(stack_buffer);
			ULONG buffer_pos = 0;
			int len;
#ifdef WINNT
			LARGE_INTEGER SystemTime{};
			LARGE_INTEGER LocalTime{};
			KeQuerySystemTime(&SystemTime);
			ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
			TIME_FIELDS timeField = { 0 };
			RtlTimeToTimeFields(&LocalTime, &timeField);
			buffer_pos += _snprintf(buffer_ptr, buffer_count - buffer_pos, TimeFormat, timeField.Year, timeField.Month, timeField.Day, timeField.Hour, timeField.Minute, timeField.Second);
#else
			SYSTEMTIME LocalTime{};
			GetLocalTime(&LocalTime);
			buffer_pos += snprintf(buffer_ptr, buffer_count - buffer_pos, TimeFormat, LocalTime.wYear, LocalTime.wMonth, LocalTime.wDay, LocalTime.wHour, LocalTime.wMinute, LocalTime.wSecond);
#endif
			while (true)
			{
				len = _snprintf(buffer_ptr + buffer_pos, buffer_count - buffer_pos, "    [%s]%s=> ", LevelToString(Level), Flag ? Flag : "NULL");
				if (len >= 0)
				{
					buffer_pos += len;
					break;
				}
				else if (buffer_count >= static_data().MaxLen)
				{
					buffer_pos = buffer_count;
					break;
				}
				buffer_count = buffer_count * 2 <= static_data().MaxLen ? buffer_count * 2 : static_data().MaxLen;
				char* new_malloc_buffer = (char*)Malloc(buffer_count);
				memcpy(new_malloc_buffer, buffer_ptr, buffer_pos);
				if (malloc_buffer)
				{
					Free(malloc_buffer);
				}
				malloc_buffer = new_malloc_buffer;
				buffer_ptr = malloc_buffer;
			}
			va_list ap;
			va_start(ap, Format);
			while (true)
			{
				len = _vsnprintf(buffer_ptr + buffer_pos, buffer_count - buffer_pos, Format, ap);
				if (len >= 0)
				{
					buffer_pos += len;
					break;
				}
				else if (buffer_count >= static_data().MaxLen)
				{
					buffer_pos = buffer_count;
					break;
				}
				buffer_count = buffer_count * 2 <= static_data().MaxLen ? buffer_count * 2 : static_data().MaxLen;
				char* new_malloc_buffer = (char*)Malloc(buffer_count);
				memcpy(new_malloc_buffer, buffer_ptr, buffer_pos);
				if (malloc_buffer)
				{
					Free(malloc_buffer);
				}
				malloc_buffer = new_malloc_buffer;
				buffer_ptr = malloc_buffer;
			}
			va_end(ap);
#ifdef WINNT
			KeWaitForSingleObject(&static_data().Event, Executive, KernelMode, FALSE, NULL);
			{
#else
			EnterCriticalSection(&static_data().Cs);
			{
#endif
				char write_buffer[512] = { 0 };
				ULONG write_buffer_pos = 0;
				HANDLE hFile = OpenFile(static_data().FileName, true);
				if (hFile != INVALID_HANDLE_VALUE)
				{
					for (ULONG buffer_index = 0; buffer_index < buffer_pos; buffer_index++)
					{
						switch (buffer_ptr[buffer_index])
						{
						case '\n':
							write_buffer[write_buffer_pos++] = '\\';
							write_buffer[write_buffer_pos++] = 'n';
							break;
						case '\\':
							write_buffer[write_buffer_pos++] = '\\';
							write_buffer[write_buffer_pos++] = '\\';
							break;
						case '\t':
							write_buffer[write_buffer_pos++] = '\\';
							write_buffer[write_buffer_pos++] = 't';
							break;
						default:
							write_buffer[write_buffer_pos++] = buffer_ptr[buffer_index];
							break;
						}
						if (write_buffer_pos >= sizeof(write_buffer) - 3)
						{
#ifdef WINNT
							IO_STATUS_BLOCK IoStatus;
							LARGE_INTEGER Offset;
							Offset.HighPart = -1;
							Offset.LowPart = FILE_WRITE_TO_END_OF_FILE;
							ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, write_buffer, write_buffer_pos, &Offset, NULL);
#else
							SetFilePointer(hFile, 0, NULL, FILE_END);
							WriteFile(hFile, write_buffer, write_buffer_pos, NULL, NULL);
#endif
							write_buffer_pos = 0;
						}
					}
					write_buffer[write_buffer_pos++] = '\n';
#ifdef WINNT
					IO_STATUS_BLOCK IoStatus;
					LARGE_INTEGER Offset;
					Offset.HighPart = -1;
					Offset.LowPart = FILE_WRITE_TO_END_OF_FILE;
					ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, write_buffer, write_buffer_pos, &Offset, NULL);
#else
					SetFilePointer(hFile, 0, NULL, FILE_END);
					WriteFile(hFile, write_buffer, write_buffer_pos, NULL, NULL);
#endif
					CloseFile(hFile);
				}
#ifdef WINNT
			}
			KeSetEvent(&static_data().Event, IO_NO_INCREMENT, FALSE);
#else
			}
			LeaveCriticalSection(&static_data().Cs);
#endif
			if (malloc_buffer)
			{
				Free(malloc_buffer);
			}
		}
	};
#pragma endregion

#pragma region Image
public:
	struct IMAGE
	{
	public:
		static constexpr ULONG64 RVA_TO_VA(ULONG64 BA, ULONG64 VA) { return BA + VA; }
		static constexpr PVOID RVA_TO_VA(PVOID BA, ULONG64 VA) { return (PVOID)RVA_TO_VA((ULONG64)BA, VA); }
		struct importhook_t
		{
			PCSTR pModuleName;
			PCSTR pSymbolName;
		};
	private:
		struct HOOK_DATA
		{
			PCSTR ImageName;
			PCSTR SymbolName;
			PVOID target;
			unsigned char ShellCode[0x10];
		};
		struct X64_IMPORT_HOOK
		{
			DWORD32 Sign;
			DWORD32 Count;
			PVOID ImageBase;
			UCHAR HookBuffer[1];
		};
		struct HookX64ImageImports_UserData
		{
			ULONG Index;
			ULONG ItemSize;
			PVOID Buffer;
			PVOID CallBack;
		};
		struct IMPORT_HOOK_DATA
		{
			PVOID* pTargetAddress;
			PVOID TargetAddress;
			importhook_t Info;
		};
		static constexpr auto X64HookSize = 0x1000;
	public:
		static bool MapForBuffer(PVOID ImageBuffer, SIZE_T ImageBufferSize, PVOID MapAddress, SIZE_T* pAddressSize, bool isX64) noexcept
		{
			if (!ImageBuffer || !pAddressSize)
			{
				return false;
			}
			bool result = false;
			PIMAGE_DOS_HEADER pImg_DOS_Header = (PIMAGE_DOS_HEADER)ImageBuffer;
			PIMAGE_NT_HEADERS pImg_NT_Header = (PIMAGE_NT_HEADERS)RVA_TO_VA(ImageBuffer, pImg_DOS_Header->e_lfanew);
			if (pImg_DOS_Header->e_magic == IMAGE_DOS_SIGNATURE && pImg_NT_Header->Signature == IMAGE_NT_SIGNATURE)
			{
				//判断DLL类型
				if ((isX64 && pImg_NT_Header->FileHeader.Machine & IMAGE_FILE_MACHINE_AMD64)
					|| (!isX64 && pImg_NT_Header->FileHeader.Machine & IMAGE_FILE_MACHINE_I386))
				{
					ULONG ImageSize = pImg_NT_Header->OptionalHeader.SizeOfImage;
					if (MapAddress == NULL || *pAddressSize < ImageSize)
					{
						*pAddressSize = ImageSize;
					}
					else
					{
						//内存清空
						memset(MapAddress, 0, *pAddressSize);

						if (ImageBufferSize >= pImg_NT_Header->OptionalHeader.SizeOfHeaders)
						{
							memcpy(MapAddress, ImageBuffer, pImg_NT_Header->OptionalHeader.SizeOfHeaders);
							PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)RVA_TO_VA(pImg_NT_Header, sizeof(IMAGE_NT_HEADERS));
							bool isOk = true;
							for (ULONG i = 0; i < pImg_NT_Header->FileHeader.NumberOfSections; i++)
							{
								if ((*pAddressSize < (size_t)pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)
									|| (ImageBufferSize < (size_t)pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData))
								{
									isOk = false;
									break;
								}
								memcpy((PUCHAR)MapAddress + pSectionHeader[i].VirtualAddress, (PVOID)RVA_TO_VA(ImageBuffer, pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData);
							}
							if (isOk)
							{
								*pAddressSize = ImageSize;
								result = true;
							}
						}
					}
				}
			}
			return result;
		}
		static bool MapForFile(PCWSTR fileName, PVOID MapAddress, SIZE_T* MapAddressSize, bool isX64) noexcept
		{
			bool result = false;
#ifdef WINNT
			NTSTATUS status;
			HANDLE fileHandle = NULL;
			IO_STATUS_BLOCK io_status;
			OBJECT_ATTRIBUTES object_attributes = { 0 };
			UNICODE_STRING fileName_uStr;
			RtlInitUnicodeString(&fileName_uStr, fileName);
			InitializeObjectAttributes(&object_attributes, &fileName_uStr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			status = ZwCreateFile(&fileHandle, GENERIC_READ, &object_attributes, &io_status, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
				FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
			if (NT_SUCCESS(status))
			{
				FILE_STANDARD_INFORMATION fileSize = { 0 };
				status = ZwQueryInformationFile(fileHandle, &io_status, &fileSize, sizeof(fileSize), FileStandardInformation);
				if (NT_SUCCESS(status))
				{
					PVOID Buffer = ExAllocatePoolWithTag(PagedPool, fileSize.EndOfFile.LowPart, 'BUF');
					if (Buffer)
					{
						status = ZwReadFile(fileHandle, NULL, NULL, NULL, &io_status, Buffer, fileSize.EndOfFile.LowPart, NULL, NULL);
						if (NT_SUCCESS(status))
						{
							result = MapForBuffer(Buffer, fileSize.EndOfFile.LowPart, MapAddress, MapAddressSize, isX64);
						}
						ExFreePoolWithTag(Buffer, 'BUF');
					}
				}
				ZwClose(fileHandle);
			}
#else
			HANDLE fileHandle = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (fileHandle != INVALID_HANDLE_VALUE)
			{
				HANDLE sectionHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
				if (sectionHandle != NULL)
				{
					LARGE_INTEGER fileSize = { 0 };
					GetFileSizeEx(fileHandle, &fileSize);
					PVOID ImageBuf = MapViewOfFile(sectionHandle, FILE_MAP_READ, 0, 0, 0);
					if (ImageBuf)
					{
						result = MapForBuffer(ImageBuf, fileSize.QuadPart, MapAddress, MapAddressSize, isX64);
						UnmapViewOfFile(ImageBuf);
					}
					CloseHandle(sectionHandle);
				}
				CloseHandle(fileHandle);
			}
#endif // WINNT
			return result;
		}
		static PVOID GetSectionBase(PVOID ImageBase, PCSTR SectionName, ULONG* pSize) noexcept
		{
			PIMAGE_DOS_HEADER pImg_DOS_Header = (PIMAGE_DOS_HEADER)ImageBase;
			if (!pImg_DOS_Header || pImg_DOS_Header->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;
			PIMAGE_NT_HEADERS64 pImg_NT_Header = (PIMAGE_NT_HEADERS64)RVA_TO_VA(ImageBase, pImg_DOS_Header->e_lfanew);
			if (!pImg_NT_Header || pImg_NT_Header->Signature != IMAGE_NT_SIGNATURE)
				return NULL;
			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pImg_NT_Header);
			PVOID result = NULL;
			for (unsigned short i = 0; i < pImg_NT_Header->FileHeader.NumberOfSections; i++)
			{
				PIMAGE_SECTION_HEADER p = &section[i];
				if (!strncmp((PCSTR)p->Name, SectionName, sizeof((PCSTR)p->Name)))
				{
					result = (PCHAR)RVA_TO_VA(ImageBase, p->VirtualAddress);
					if (pSize)
						*pSize = p->SizeOfRawData;
					break;
				}
			}
			return result;
		}
		static PVOID SectionFind(PVOID ImageBase, PCSTR SectionName, PCSTR des_str) noexcept
		{
			ULONG SectionSize = 0;
			PVOID SectionBase = GetSectionBase(ImageBase, SectionName, &SectionSize);
			if (SectionBase)
			{
				return MemFind(SectionBase, SectionSize, des_str);
			}
			return NULL;
		}
		static bool PerformRelocation(PVOID ImageBase, PVOID MapAddress, bool isX64) noexcept
		{
			PIMAGE_DOS_HEADER pDos_header = (PIMAGE_DOS_HEADER)ImageBase;
			PIMAGE_NT_HEADERS pOld_header = (PIMAGE_NT_HEADERS)RVA_TO_VA(ImageBase, pDos_header->e_lfanew);
			DWORD64 locationDelta = ((DWORD64)MapAddress) - pOld_header->OptionalHeader.ImageBase;

			PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(RVA_TO_VA(ImageBase, pOld_header->OptionalHeader.DataDirectory[5].VirtualAddress));
			ULONG relocationSize = pOld_header->OptionalHeader.DataDirectory[5].Size;
			if (relocationSize > 0) {
				for (; pRelocation->VirtualAddress > 0;) {

					PUCHAR dest = (PUCHAR)ImageBase + pRelocation->VirtualAddress;
					PUSHORT relInfo = (PUSHORT)((DWORD64)pRelocation + sizeof(IMAGE_BASE_RELOCATION));

					for (UINT32 j = 0; j < ((pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); j++) {
						// the upper 4 bits define the type of relocation
						int type = (relInfo[j] >> 12) & 0xf;
						// the lower 12 bits define the offset
						int offset = relInfo[j] & 0xfff;
						if (IMAGE_REL_BASED_ABSOLUTE == type)
						{
							// skip relocation
						}
						else if (IMAGE_REL_BASED_HIGHLOW == type)
						{
							// change complete 32 bit address
							ULONG* patchAddrHL = (ULONG*)(dest + offset);
							*patchAddrHL += (ULONG)locationDelta;
						}
						else if (isX64 && IMAGE_REL_BASED_DIR64 == type)
						{
							ULONGLONG* patchAddr64 = (ULONGLONG*)(dest + offset);
							*patchAddr64 += (ULONGLONG)locationDelta;
						}
					}
					pRelocation = (PIMAGE_BASE_RELOCATION)(((char*)pRelocation) + pRelocation->SizeOfBlock);
				}
			}
			return true;
		}
		template<
			typename FGETMODUHANDLEA		//[&](PCSTR ImageName)->PVOID
			, typename FGETPROCADDRESS	//[&](PVOID ImageBase, PCSTR ProcName, DWORD32 serialNo)->PVOID
		>
		static bool BuildImportTable(PVOID ImageBase, bool isX64, FGETMODUHANDLEA GetModuleHandleA, FGETPROCADDRESS GetProcAddress) noexcept
		{
			if (!ImageBase)
			{
				return false;
			}

			PIMAGE_DOS_HEADER pDos_header = (PIMAGE_DOS_HEADER)ImageBase;
			PIMAGE_NT_HEADERS pOld_header = (PIMAGE_NT_HEADERS)RVA_TO_VA(ImageBase, pDos_header->e_lfanew);
			PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RVA_TO_VA(ImageBase, pOld_header->OptionalHeader.DataDirectory[1].VirtualAddress));
			ULONG importSize = pOld_header->OptionalHeader.DataDirectory[1].Size;
			bool result = true;
			for (unsigned int i = 0; i < importSize && pImport[i].Name != 0 && result; i++)
			{
				char* dllName = (PCHAR)RVA_TO_VA(ImageBase, pImport[i].Name);
				PVOID hDll = GetModuleHandleA(dllName);
				if (hDll == NULL)
				{
					result = false;
				}
				else
				{
					uintptr_t* thunkRef = NULL;
					PVOID* funcRef = NULL;
					if (pImport[i].OriginalFirstThunk)
					{
						thunkRef = (uintptr_t*)(RVA_TO_VA(ImageBase, pImport[i].OriginalFirstThunk));
						funcRef = (PVOID*)(RVA_TO_VA(ImageBase, pImport[i].FirstThunk));
					}
					else
					{
						// no hint table
						thunkRef = (uintptr_t*)(RVA_TO_VA(ImageBase, pImport[i].FirstThunk));
						funcRef = (PVOID*)(RVA_TO_VA(ImageBase, pImport[i].FirstThunk));
					}
					for (; *thunkRef; thunkRef++, funcRef++)
					{
						PVOID funAddress = NULL;
						if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
						{
							//序号导入
							funAddress = GetProcAddress(hDll, NULL, IMAGE_ORDINAL(*thunkRef));
						}
						else
						{
							//名称导入
							PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(RVA_TO_VA(ImageBase, (*thunkRef)));
							funAddress = GetProcAddress(hDll, (LPCSTR)&thunkData->Name, 0);
						}
						if (funAddress == NULL)
						{
							result = false;
							break;
						}
						if (isX64)
							*(DWORD64*)funcRef = (DWORD64)funAddress;
						else
							*(DWORD32*)funcRef = (DWORD32)(DWORD64)funAddress;
					}
				}
			}
			return result;
		}
		template<
			typename FUN		//[&](PVOID ImageBase, PCSTR ProcName, PDWORD32 pRVA)->bool->bool	返回true停止枚举
		>
		static bool EnumExport(PVOID ImageBase, FUN Fun) noexcept
		{
			PIMAGE_DOS_HEADER pImg_DOS_Header = (PIMAGE_DOS_HEADER)ImageBase;
			if (!pImg_DOS_Header || pImg_DOS_Header->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return false;
			}
			PIMAGE_NT_HEADERS pImg_NT_Header = (PIMAGE_NT_HEADERS)RVA_TO_VA(ImageBase, pImg_DOS_Header->e_lfanew);
			if (!pImg_NT_Header || pImg_NT_Header->Signature != IMAGE_NT_SIGNATURE)
			{
				return false;
			}
			PIMAGE_EXPORT_DIRECTORY pImg_Export_Dir = (PIMAGE_EXPORT_DIRECTORY)RVA_TO_VA(ImageBase, pImg_NT_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			DWORD32 nNoOfExports = pImg_Export_Dir->NumberOfNames;
			DWORD32* nameRVAs = (DWORD32*)RVA_TO_VA(ImageBase, pImg_Export_Dir->AddressOfNames);
			DWORD32* funRVAs = (DWORD32*)RVA_TO_VA(ImageBase, pImg_Export_Dir->AddressOfFunctions);
			USHORT* OrdinalsRVAs = (USHORT*)RVA_TO_VA(ImageBase, pImg_Export_Dir->AddressOfNameOrdinals);
			for (ULONG i = 0; i < nNoOfExports; i++)
			{
				if (nameRVAs[i] != 0)
				{
					PCSTR name = (PCSTR)RVA_TO_VA(ImageBase, nameRVAs[i]);
					if (Fun(ImageBase, name, &funRVAs[OrdinalsRVAs[i]]))
						break;
				}
			}
			return true;
		}
		template<
			typename FUN		//[&](PVOID ImageBase, PCSTR ModuleName, PCSTR SymbolName, PVOID* pAddress)->bool	返回true停止枚举
		>
		static bool EnumImport(PVOID ImageBase, FUN Fun) noexcept
		{
			PIMAGE_DOS_HEADER pImg_DOS_Header = (PIMAGE_DOS_HEADER)ImageBase;
			if (!pImg_DOS_Header || pImg_DOS_Header->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return false;
			}
			PIMAGE_NT_HEADERS pImg_NT_Header = (PIMAGE_NT_HEADERS)RVA_TO_VA(ImageBase, pImg_DOS_Header->e_lfanew);
			if (!pImg_NT_Header || pImg_NT_Header->Signature != IMAGE_NT_SIGNATURE)
			{
				return false;
			}
			PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RVA_TO_VA(ImageBase, pImg_NT_Header->OptionalHeader.DataDirectory[1].VirtualAddress));
			DWORD32 importSize = pImg_NT_Header->OptionalHeader.DataDirectory[1].Size;
			bool isBreak = false;
			for (ULONG i = 0; i < importSize && pImport[i].Name != 0 && !isBreak; i++)
			{
				PCSTR ImageName = (PCSTR)RVA_TO_VA(ImageBase, pImport[i].Name);

				uintptr_t* thunkRef = NULL;
				PVOID* funcRef = NULL;
				if (pImport[i].OriginalFirstThunk)
				{
					thunkRef = (uintptr_t*)(RVA_TO_VA(ImageBase, pImport[i].OriginalFirstThunk));
					funcRef = (PVOID*)(RVA_TO_VA(ImageBase, pImport[i].FirstThunk));
				}
				else {
					thunkRef = (uintptr_t*)(RVA_TO_VA(ImageBase, pImport[i].FirstThunk));
					funcRef = (PVOID*)(RVA_TO_VA(ImageBase, pImport[i].FirstThunk));
				}
				for (; *thunkRef; thunkRef++, funcRef++)
				{
					PCSTR FunName = NULL;
					if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
						FunName = (LPCSTR)IMAGE_ORDINAL(*thunkRef);
					else
					{
						PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(RVA_TO_VA(ImageBase, (*thunkRef)));
						FunName = (LPCSTR)&thunkData->Name;
					}
					if (Fun(ImageBase, ImageName, FunName, funcRef))
					{
						isBreak = true;
						break;
					}
				}
			}
			return true;
		}
		static PVOID GetExport(PVOID ImageBase, PCSTR ExportName) noexcept
		{
			PVOID Result = NULL;
			EnumExport(ImageBase, [&](PVOID, PCSTR mProcName, PDWORD32 mpRVA) noexcept->bool
				{
					if (!strcmp(mProcName, ExportName))
					{
						Result = (PVOID)RVA_TO_VA(ImageBase, *mpRVA);
						return true;
					}
					return false;
				}
			);
			return Result;
		}
		static bool SetExport(PVOID ImageBase, PCSTR ExportName, PVOID newValue) noexcept
		{
			if (newValue < ImageBase)
			{
				return false;
			}
			DWORD64 Offset = (DWORD64)newValue - (DWORD64)ImageBase;
			if (Offset > 0xFFFFFFFF)
			{
				return false;
			}
			bool Find = false;
			return EnumExport(ImageBase, [&](PVOID, PCSTR mProcName, PDWORD32 mpRVA) noexcept->bool
				{
					if (!strcmp(mProcName, ExportName))
					{
						*mpRVA = (DWORD32)Offset;
						Find = true;
						return true;
					}
					return false;
				}
			) && Find;
		}
		static PVOID GetImport(PVOID ImageBase, PCSTR ModuleName, PCSTR SymbolName, bool isX64) noexcept
		{
			PVOID Result = NULL;
			EnumImport(ImageBase, [&](PVOID, PCSTR mModuleName, PCSTR mSymbolName, PVOID* mpAddress) noexcept->bool
				{
					if ((!ModuleName || !strcmp(ModuleName, mModuleName)) && !strcmp(SymbolName, mSymbolName))
					{
						Result = isX64 ? *mpAddress : (PVOID)(size_t) * (DWORD32*)mpAddress;
						return true;
					}
					return false;
				}
			);
			return Result;
		}
		static bool SetImport(PVOID ImageBase, PCSTR ModuleName, PCSTR SymbolName, PVOID value, bool isX64) noexcept
		{
			bool Find = false;
			return !EnumImport(ImageBase, [&](PVOID, PCSTR mModuleName, PCSTR mSymbolName, PVOID* mpAddress) noexcept->bool
				{
					if ((!ModuleName || !strcmp(mModuleName, ModuleName)) && !strcmp(mSymbolName, SymbolName))
					{
						isX64 ? ModifyInstruct(mpAddress, &value, sizeof(DWORD64)) : ModifyInstruct(mpAddress, &value, sizeof(DWORD32));
						Find = true;
						return true;
					}
					return false;
				}
			) && Find;
		}
		static PVOID HookImportsX64(PVOID ImageBase, void(*CallBack)(context_x64_t* pCpuState, importhook_t* ImportInfo)) noexcept
		{
			static constexpr unsigned char ShellCode_ImportHook_X64[] =
			{
				/*
					nop
					nop
					nop
					call $lab
				*/
				0x90,0x90,0x90,0xe8,0x20,0x00,0x00,0x00,
				/*
					IMPORT_INFO
				*/
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				/*
					pop rax
				*/
				0x58,
			};
			static constexpr unsigned char ShellCode_ImportHook_X64_call[] =
			{
				/*
					lea rdx,[rax+0x10]
					sub rsp,0x20
					call[HookFunction]
					add rsp,0x20
					jmp short offset_0x8
				*/
				0x48,0x8d,0x50,0x10,0x48,0x83,0xec,0x20,0xff,0x15,0x06,0x00,0x00,0x00,0x48,0x83,0xc4,0x20,0xeb,0x08
			};
			static constexpr unsigned char ShellCode_ImportHook_X64_jmp[] =
			{
				0xff,0x25,0x00,0x00,0x00,0x00
			};


			DWORD64 ImportNum = 0;
			if (!EnumImport(ImageBase, [&](PVOID, PCSTR, PCSTR, PVOID*)->bool {
				ImportNum++;
				return false;
				}) || ImportNum <= 0)
				return NULL;

			ULONG BufferSize = (ULONG)sizeof(X64_IMPORT_HOOK) + X64HookSize * (ULONG)ImportNum;
			X64_IMPORT_HOOK* hook = nullptr;
#ifdef WINNT
			hook = (X64_IMPORT_HOOK*)ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'IMHK');
#else
			hook = (X64_IMPORT_HOOK*)VirtualAlloc(NULL, BufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#endif
			if (hook != NULL)
			{
				memset(hook, 0, BufferSize);
				HookX64ImageImports_UserData UserData = { 0 };
				UserData.Buffer = hook->HookBuffer;
				UserData.CallBack = (PVOID)CallBack;
				UserData.ItemSize = X64HookSize;
				UserData.Index = 0;
				if (!EnumImport(ImageBase, [&](PVOID, PCSTR ModuleName, PCSTR SymbolName, PVOID* pImportAddr) noexcept->bool
					{
						PUCHAR TheHook = (PUCHAR)UserData.Buffer + UserData.ItemSize * UserData.Index;
						PUCHAR cursor = TheHook;
						memcpy(cursor, ShellCode_ImportHook_X64, sizeof(ShellCode_ImportHook_X64));
						cursor += sizeof(ShellCode_ImportHook_X64);
						cursor += WriteX64RegisterSaveCode(cursor, X64HookSize - (cursor - TheHook));
						memcpy(cursor, ShellCode_ImportHook_X64_call, sizeof(ShellCode_ImportHook_X64_call));
						cursor += sizeof(ShellCode_ImportHook_X64_call);
						*(ULONG64*)cursor = (ULONG64)UserData.CallBack;
						cursor += sizeof(ULONG64);
						cursor += WriteX64RegisterRestoreCode(cursor, X64HookSize - (cursor - TheHook));
						memcpy(cursor, ShellCode_ImportHook_X64_jmp, sizeof(ShellCode_ImportHook_X64_jmp));
						cursor += sizeof(ShellCode_ImportHook_X64_jmp);
						*(ULONG64*)cursor = (ULONG64)*pImportAddr;
						cursor += sizeof(ULONG64);
						//DataOffset = 8
						IMPORT_HOOK_DATA* pInfo = (IMPORT_HOOK_DATA*)(TheHook + 8);

						pInfo->pTargetAddress = pImportAddr;
						pInfo->TargetAddress = *pImportAddr;
						pInfo->Info.pModuleName = ModuleName;
						pInfo->Info.pSymbolName = SymbolName;

						ModifyInstruct(pImportAddr, &TheHook, sizeof(TheHook));
						UserData.Index++;
						return false;
					}
				))
				{
#ifdef WINNT
					ExFreePoolWithTag(hook, 'IMHK');
#else
					VirtualFree(hook, 0, MEM_RELEASE);
#endif
					hook = NULL;
				}
				else
				{
					hook->Sign = 0x98765432;
					hook->Count = UserData.Index;
					hook->ImageBase = ImageBase;
				}
			}
			return hook;
		}
		static bool ImageUnHookImportsX64(PVOID Hook) noexcept
		{
			X64_IMPORT_HOOK* pHook = (X64_IMPORT_HOOK*)Hook;
#ifdef WINNT
			if (MmIsAddressValid(Hook))
#else
			if (!IsBadCodePtr((FARPROC)Hook) && !IsBadWritePtr(Hook, sizeof(X64_IMPORT_HOOK)))
#endif // WINNT
			{
				for (ULONG i = 0; i < pHook->Count; i++)
				{
					//DataOffset = 8
					IMPORT_HOOK_DATA* pHookData = (IMPORT_HOOK_DATA*)((PUCHAR)pHook->HookBuffer + i * X64HookSize + 8);
					ModifyInstruct(pHookData->pTargetAddress, &pHookData->TargetAddress, sizeof(pHookData->TargetAddress));
				}
#ifdef WINNT
				ExFreePoolWithTag(Hook, 'IMHK');
#else
				VirtualFree(Hook, 0, MEM_RELEASE);
#endif
				return true;
			}
			return false;
		}
	};
#pragma endregion

#pragma region Instruction
public:
	struct INSTRUCTION
	{
		struct HDES
		{
			unsigned char len;
			unsigned char p_rep;
			unsigned char p_lock;
			unsigned char p_seg;
			unsigned char p_66;
			unsigned char p_67;
			unsigned char rex;
			unsigned char rex_w;
			unsigned char rex_r;
			unsigned char rex_x;
			unsigned char rex_b;
			unsigned char opcode;
			unsigned char opcode2;
			unsigned char modrm;
			unsigned char modrm_mod;
			unsigned char modrm_reg;
			unsigned char modrm_rm;
			unsigned char sib;
			unsigned char sib_scale;
			unsigned char sib_index;
			unsigned char sib_base;
			union {
				unsigned char imm8;
				unsigned short imm16;
				unsigned int imm32;
				unsigned __int64 imm64;
			} imm;
			union {
				unsigned char disp8;
				unsigned short disp16;
				unsigned int disp32;
			} disp;
			unsigned int flags;
		};
		class X86
		{
		public:
			static constexpr unsigned int F_MODRM = 0x00000001;
			static constexpr unsigned int F_SIB = 0x00000002;
			static constexpr unsigned int F_IMM8 = 0x00000004;
			static constexpr unsigned int F_IMM16 = 0x00000008;
			static constexpr unsigned int F_IMM32 = 0x00000010;
			static constexpr unsigned int F_DISP8 = 0x00000020;
			static constexpr unsigned int F_DISP16 = 0x00000040;
			static constexpr unsigned int F_DISP32 = 0x00000080;
			static constexpr unsigned int F_RELATIVE = 0x00000100;
			static constexpr unsigned int F_2IMM16 = 0x00000800;
			static constexpr unsigned int F_ERROR = 0x00001000;
			static constexpr unsigned int F_ERROR_OPCODE = 0x00002000;
			static constexpr unsigned int F_ERROR_LENGTH = 0x00004000;
			static constexpr unsigned int F_ERROR_LOCK = 0x00008000;
			static constexpr unsigned int F_ERROR_OPERAND = 0x00010000;
			static constexpr unsigned int F_PREFIX_REPNZ = 0x01000000;
			static constexpr unsigned int F_PREFIX_REPX = 0x02000000;
			static constexpr unsigned int F_PREFIX_REP = 0x03000000;
			static constexpr unsigned int F_PREFIX_66 = 0x04000000;
			static constexpr unsigned int F_PREFIX_67 = 0x08000000;
			static constexpr unsigned int F_PREFIX_LOCK = 0x10000000;
			static constexpr unsigned int F_PREFIX_SEG = 0x20000000;
			static constexpr unsigned int F_PREFIX_ANY = 0x3f000000;

			static constexpr unsigned char PREFIX_SEGMENT_CS = 0x2e;
			static constexpr unsigned char PREFIX_SEGMENT_SS = 0x36;
			static constexpr unsigned char PREFIX_SEGMENT_DS = 0x3e;
			static constexpr unsigned char PREFIX_SEGMENT_ES = 0x26;
			static constexpr unsigned char PREFIX_SEGMENT_FS = 0x64;
			static constexpr unsigned char PREFIX_SEGMENT_GS = 0x65;
			static constexpr unsigned char PREFIX_LOCK = 0xf0;
			static constexpr unsigned char PREFIX_REPNZ = 0xf2;
			static constexpr unsigned char PREFIX_REPX = 0xf3;
			static constexpr unsigned char PREFIX_OPERAND_SIZE = 0x66;
			static constexpr unsigned char PREFIX_ADDRESS_SIZE = 0x67;

			static constexpr unsigned char  C_NONE = 0x00;
			static constexpr unsigned char  C_MODRM = 0x01;
			static constexpr unsigned char  C_IMM8 = 0x02;
			static constexpr unsigned char  C_IMM16 = 0x04;
			static constexpr unsigned char  C_IMM_P66 = 0x10;
			static constexpr unsigned char  C_REL8 = 0x20;
			static constexpr unsigned char  C_REL32 = 0x40;
			static constexpr unsigned char  C_GROUP = 0x80;
			static constexpr unsigned char  C_ERROR = 0xff;

			static constexpr unsigned char  PRE_ANY = 0x00;
			static constexpr unsigned char  PRE_NONE = 0x01;
			static constexpr unsigned char  PRE_F2 = 0x02;
			static constexpr unsigned char  PRE_F3 = 0x04;
			static constexpr unsigned char  PRE_66 = 0x08;
			static constexpr unsigned char  PRE_67 = 0x10;
			static constexpr unsigned char  PRE_LOCK = 0x20;
			static constexpr unsigned char  PRE_SEG = 0x40;
			static constexpr unsigned char  PRE_ALL = 0xff;

			static constexpr unsigned short  DELTA_OPCODES = 0x4a;
			static constexpr unsigned short  DELTA_FPU_REG = 0xf1;
			static constexpr unsigned short  DELTA_FPU_MODRM = 0xf8;
			static constexpr unsigned short  DELTA_PREFIXES = 0x130;
			static constexpr unsigned short  DELTA_OP_LOCK_OK = 0x1a1;
			static constexpr unsigned short  DELTA_OP2_LOCK_OK = 0x1b9;
			static constexpr unsigned short  DELTA_OP_ONLY_MEM = 0x1cb;
			static constexpr unsigned short  DELTA_OP2_ONLY_MEM = 0x1da;
			static unsigned int Disasm(const void* code, HDES* hs) noexcept
			{
				unsigned char x, c = 0, * p = (unsigned char*)code, cflags, opcode, pref = 0;
				const unsigned char* ht = hde32_table;
				unsigned char m_mod, m_reg, m_rm, disp_size = 0;

				for (x = 16; x; x--)
					switch (c = *p++) {
					case 0xf3:
						hs->p_rep = c;
						pref |= PRE_F3;
						break;
					case 0xf2:
						hs->p_rep = c;
						pref |= PRE_F2;
						break;
					case 0xf0:
						hs->p_lock = c;
						pref |= PRE_LOCK;
						break;
					case 0x26: case 0x2e: case 0x36:
					case 0x3e: case 0x64: case 0x65:
						hs->p_seg = c;
						pref |= PRE_SEG;
						break;
					case 0x66:
						hs->p_66 = c;
						pref |= PRE_66;
						break;
					case 0x67:
						hs->p_67 = c;
						pref |= PRE_67;
						break;
					default:
						goto pref_done;
					}
			pref_done:

				hs->flags = (unsigned int)pref << 23;

				if (!pref)
					pref |= PRE_NONE;

				if ((hs->opcode = c) == 0x0f) {
					hs->opcode2 = c = *p++;
					ht += DELTA_OPCODES;
				}
				else if (c >= 0xa0 && c <= 0xa3) {
					if (pref & PRE_67)
						pref |= PRE_66;
					else
						pref &= ~PRE_66;
				}

				opcode = c;
				cflags = ht[ht[opcode / 4] + (opcode % 4)];

				if (cflags == C_ERROR) {
					hs->flags |= F_ERROR | F_ERROR_OPCODE;
					cflags = 0;
					if ((opcode & -3) == 0x24)
						cflags++;
				}

				x = 0;
				if (cflags & C_GROUP) {
					unsigned short t;
					t = *(unsigned short*)(ht + (cflags & 0x7f));
					cflags = (unsigned char)t;
					x = (unsigned char)(t >> 8);
				}

				if (hs->opcode2) {
					ht = hde32_table + DELTA_PREFIXES;
					if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
						hs->flags |= F_ERROR | F_ERROR_OPCODE;
				}

				if (cflags & C_MODRM) {
					hs->flags |= F_MODRM;
					hs->modrm = c = *p++;
					hs->modrm_mod = m_mod = c >> 6;
					hs->modrm_rm = m_rm = c & 7;
					hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

					if (x && ((x << m_reg) & 0x80))
						hs->flags |= F_ERROR | F_ERROR_OPCODE;

					if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
						unsigned char t = opcode - 0xd9;
						if (m_mod == 3) {
							ht = hde32_table + DELTA_FPU_MODRM + t * 8;
							t = ht[m_reg] << m_rm;
						}
						else {
							ht = hde32_table + DELTA_FPU_REG;
							t = ht[t] << m_reg;
						}
						if (t & 0x80)
							hs->flags |= F_ERROR | F_ERROR_OPCODE;
					}

					if (pref & PRE_LOCK) {
						if (m_mod == 3) {
							hs->flags |= F_ERROR | F_ERROR_LOCK;
						}
						else {
							const unsigned char* table_end;
							unsigned char op = opcode;
							if (hs->opcode2) {
								ht = hde32_table + DELTA_OP2_LOCK_OK;
								table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
							}
							else {
								ht = hde32_table + DELTA_OP_LOCK_OK;
								table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
								op &= -2;
							}
							for (; ht != table_end; ht++)
								if (*ht++ == op) {
									if (!((*ht << m_reg) & 0x80))
										goto no_lock_error;
									else
										break;
								}
							hs->flags |= F_ERROR | F_ERROR_LOCK;
						no_lock_error:
							;
						}
					}

					if (hs->opcode2) {
						switch (opcode) {
						case 0x20: case 0x22:
							m_mod = 3;
							if (m_reg > 4 || m_reg == 1)
								goto error_operand;
							else
								goto no_error_operand;
						case 0x21: case 0x23:
							m_mod = 3;
							if (m_reg == 4 || m_reg == 5)
								goto error_operand;
							else
								goto no_error_operand;
						}
					}
					else {
						switch (opcode) {
						case 0x8c:
							if (m_reg > 5)
								goto error_operand;
							else
								goto no_error_operand;
						case 0x8e:
							if (m_reg == 1 || m_reg > 5)
								goto error_operand;
							else
								goto no_error_operand;
						}
					}

					if (m_mod == 3) {
						const unsigned char* table_end;
						if (hs->opcode2) {
							ht = hde32_table + DELTA_OP2_ONLY_MEM;
							table_end = ht + sizeof(hde32_table) - DELTA_OP2_ONLY_MEM;
						}
						else {
							ht = hde32_table + DELTA_OP_ONLY_MEM;
							table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
						}
						for (; ht != table_end; ht += 2)
							if (*ht++ == opcode) {
								if ((*ht++ & pref) && !((*ht << m_reg) & 0x80))
									goto error_operand;
								else
									break;
							}
						goto no_error_operand;
					}
					else if (hs->opcode2) {
						switch (opcode) {
						case 0x50: case 0xd7: case 0xf7:
							if (pref & (PRE_NONE | PRE_66))
								goto error_operand;
							break;
						case 0xd6:
							if (pref & (PRE_F2 | PRE_F3))
								goto error_operand;
							break;
						case 0xc5:
							goto error_operand;
						}
						goto no_error_operand;
					}
					else
						goto no_error_operand;

				error_operand:
					hs->flags |= F_ERROR | F_ERROR_OPERAND;
				no_error_operand:

					c = *p++;
					if (m_reg <= 1) {
						if (opcode == 0xf6)
							cflags |= C_IMM8;
						else if (opcode == 0xf7)
							cflags |= C_IMM_P66;
					}

					switch (m_mod) {
					case 0:
						if (pref & PRE_67) {
							if (m_rm == 6)
								disp_size = 2;
						}
						else
							if (m_rm == 5)
								disp_size = 4;
						break;
					case 1:
						disp_size = 1;
						break;
					case 2:
						disp_size = 2;
						if (!(pref & PRE_67))
							disp_size <<= 1;
						break;
					}

					if (m_mod != 3 && m_rm == 4 && !(pref & PRE_67)) {
						hs->flags |= F_SIB;
						p++;
						hs->sib = c;
						hs->sib_scale = c >> 6;
						hs->sib_index = (c & 0x3f) >> 3;
						if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
							disp_size = 4;
					}

					p--;
					switch (disp_size) {
					case 1:
						hs->flags |= F_DISP8;
						hs->disp.disp8 = *p;
						break;
					case 2:
						hs->flags |= F_DISP16;
						hs->disp.disp16 = *(unsigned short*)p;
						break;
					case 4:
						hs->flags |= F_DISP32;
						hs->disp.disp32 = *(unsigned int*)p;
						break;
					}
					p += disp_size;
				}
				else if (pref & PRE_LOCK)
					hs->flags |= F_ERROR | F_ERROR_LOCK;

				if (cflags & C_IMM_P66) {
					if (cflags & C_REL32) {
						if (pref & PRE_66) {
							hs->flags |= F_IMM16 | F_RELATIVE;
							hs->imm.imm16 = *(unsigned short*)p;
							p += 2;
							goto disasm_done;
						}
						goto rel32_ok;
					}
					if (pref & PRE_66) {
						hs->flags |= F_IMM16;
						hs->imm.imm16 = *(unsigned short*)p;
						p += 2;
					}
					else {
						hs->flags |= F_IMM32;
						hs->imm.imm32 = *(unsigned int*)p;
						p += 4;
					}
				}

				if (cflags & C_IMM16) {
					if (hs->flags & F_IMM32) {
						hs->flags |= F_IMM16;
						hs->disp.disp16 = *(unsigned short*)p;
					}
					else if (hs->flags & F_IMM16) {
						hs->flags |= F_2IMM16;
						hs->disp.disp16 = *(unsigned short*)p;
					}
					else {
						hs->flags |= F_IMM16;
						hs->imm.imm16 = *(unsigned short*)p;
					}
					p += 2;
				}
				if (cflags & C_IMM8) {
					hs->flags |= F_IMM8;
					hs->imm.imm8 = *p++;
				}

				if (cflags & C_REL32) {
				rel32_ok:
					hs->flags |= F_IMM32 | F_RELATIVE;
					hs->imm.imm32 = *(unsigned int*)p;
					p += 4;
				}
				else if (cflags & C_REL8) {
					hs->flags |= F_IMM8 | F_RELATIVE;
					hs->imm.imm8 = *p++;
				}

			disasm_done:

				if ((hs->len = (unsigned char)(p - (unsigned char*)code)) > 15) {
					hs->flags |= F_ERROR | F_ERROR_LENGTH;
					hs->len = 15;
				}

				return (unsigned int)hs->len;
			}

			static int CreateReplaceCode(void* source, unsigned int minSize, void* buf, unsigned int bufSize, unsigned int* bufLen, void* target) noexcept
			{
				if (source == NULL || buf == NULL || bufLen == NULL || minSize == 0 || bufSize < minSize)
					return -1;
				if (target == NULL)
					target = buf;

				//已反编译指令的地址集合
				struct {
					ULONG saddress;
					ULONG taddress;
				}codemap[100] = { 0 };
				UINT32 codemap_index = 0;
				//已修改指令的集合
				DWORD32* codemap2[10] = { NULL };
				UINT32 codemap2_index = 0;

				UCHAR* pSou = (UCHAR*)source;
				UCHAR* pBuf = (UCHAR*)buf;
				UCHAR* pTar = (UCHAR*)target;

				int result = -1;
				while (1)
				{
					HDES hs = { 0 };
					UINT32 oldCodeLen = Disasm(pSou, &hs);
					if (hs.len == 0)
						break;
					void* pNewCode = pSou;
					UINT32 newCodeLen = oldCodeLen;
					UCHAR codeBuf[0x60] = { 0 };
					UCHAR codeBufIndex = 0;
#pragma region 解析代码
					//call rva
					if (hs.opcode == 0xE8)
					{
						//push eax
						codeBuf[codeBufIndex++] = 0x50;
						//mov eax
						codeBuf[codeBufIndex++] = 0xB8;
						if (hs.opcode & 1)
							*(INT32*)(codeBuf + codeBufIndex) = (INT32)((INT64)pSou + oldCodeLen + (INT32)hs.imm.imm32);
						else
							*(INT32*)(codeBuf + codeBufIndex) = (INT32)((INT64)pSou + oldCodeLen + (INT8)hs.imm.imm8);
						codeBufIndex += sizeof(UINT32);
						//添加到待修复表
						if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
						codemap2[codemap2_index++] = (DWORD32*)(pBuf + codeBufIndex);
						//lea esp,[esp-4]
						*(UINT32*)(codeBuf + codeBufIndex) = 0xFC24648D;
						codeBufIndex += sizeof(UINT32);
						//call [esp+4]
						*(UINT32*)(codeBuf + codeBufIndex) = 0x042454FF;
						codeBufIndex += sizeof(UINT32);

						pNewCode = codeBuf;
						newCodeLen = codeBufIndex;
					}
					//jmp rva
					else if ((hs.opcode & 0xFD) == 0xE9)
					{
						//push eax
						codeBuf[codeBufIndex++] = 0x50;
						//mov eax
						codeBuf[codeBufIndex++] = 0xB8;
						if (hs.opcode & 1)
							*(INT32*)(codeBuf + codeBufIndex) = (INT32)((INT64)pSou + oldCodeLen + (INT32)hs.imm.imm32);
						else
							*(INT32*)(codeBuf + codeBufIndex) = (INT32)((INT64)pSou + oldCodeLen + (INT8)hs.imm.imm8);
						codeBufIndex += sizeof(UINT32);
						//添加到待修复表
						if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
						codemap2[codemap2_index++] = (DWORD32*)(pBuf + codeBufIndex);
						//xchg eax,[esp]
						//result
						*(UINT32*)(codeBuf + codeBufIndex) = 0xC3240487;
						codeBufIndex += sizeof(UINT32);

						pNewCode = codeBuf;
						newCodeLen = codeBufIndex;
					}
					//jcc rva
					else if ((hs.opcode & 0xFC) == 0xE0 || (hs.opcode & 0xF0) == 0x70 || (hs.opcode2 & 0xF0) == 0x80)
					{
						//jcc 0xA
						codeBuf[codeBufIndex++] = hs.opcode;
						if (hs.opcode == 0x0F)
							codeBuf[codeBufIndex++] = hs.opcode2;
						UCHAR opcode = codeBuf[codeBufIndex - 1];
						//确定立即数大小
						if (opcode & 1)
						{
							*(UINT32*)(codeBuf + codeBufIndex) = 0x2;                 //dword offset;
							codeBufIndex += sizeof(UINT32);
						}
						else
						{
							codeBuf[codeBufIndex++] = 0x2;                              //byte offset;
						}
						//跳转不成立时
						//jmp 0xA
						codeBuf[codeBufIndex++] = 0xEB;
						codeBuf[codeBufIndex++] = 0xA;
						//跳转成立时
						//push eax
						codeBuf[codeBufIndex++] = 0x50;
						//mov eax
						codeBuf[codeBufIndex++] = 0xB8;
						//确定操作数大小
						if (opcode & 1)
							*(INT32*)(codeBuf + codeBufIndex) = (INT32)((INT64)pSou + oldCodeLen + (INT32)hs.imm.imm32);
						else
							*(INT32*)(codeBuf + codeBufIndex) = (INT32)((INT64)pSou + oldCodeLen + (INT8)hs.imm.imm8);
						codeBufIndex += sizeof(UINT32);
						//添加到待修复表
						if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
						codemap2[codemap2_index++] = (DWORD32*)(pBuf + codeBufIndex);
						//跳转不成立的真实入口
						//xchg eax,[esp];result
						*(UINT32*)(codeBuf + codeBufIndex) = 0xC3240487;
						codeBufIndex += sizeof(UINT32);

						pNewCode = codeBuf;
						newCodeLen = codeBufIndex;
					}
#pragma endregion
					if (pNewCode == NULL || newCodeLen == 0)
						break;
					//判断缓冲区是否够
					if (pBuf - (UCHAR*)buf + newCodeLen > bufSize)
						break;
					memcpy(pBuf, pNewCode, newCodeLen);

					//保存到表
					if (codemap_index >= sizeof(codemap) / sizeof(codemap[0]))
						break;
					codemap[codemap_index].saddress = (ULONG)(ULONG_PTR)pSou;
					codemap[codemap_index].taddress = (ULONG)(ULONG_PTR)pTar;
					codemap_index++;

					pBuf += newCodeLen;
					pSou += oldCodeLen;
					pTar += newCodeLen;
					//判断是否完成
					if (pSou - (UCHAR*)source >= minSize)
					{
						*bufLen = (UINT32)(pBuf - (UCHAR*)buf);
						result = (INT32)(pSou - (UCHAR*)source);
						break;
					}
				}
				//匹配地址修复表
				if (result > 0)
				{
					for (UINT32 i = 0; i < codemap2_index; i++)
					{
						for (UINT32 j = 0; j < codemap_index; j++)
						{
							if (*codemap2[i] == codemap[j].saddress)
							{
								*(codemap2[i]) = codemap[j].taddress;
								break;
							}
						}
					}
				}
				return result;
			}
		private:
			static constexpr unsigned char hde32_table[] = {
				0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,
				0xa8,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xac,0xaa,0xb2,0xaa,0x9f,0x9f,
				0x9f,0x9f,0xb5,0xa3,0xa3,0xa4,0xaa,0xaa,0xba,0xaa,0x96,0xaa,0xa8,0xaa,0xc3,
				0xc3,0x96,0x96,0xb7,0xae,0xd6,0xbd,0xa3,0xc5,0xa3,0xa3,0x9f,0xc3,0x9c,0xaa,
				0xaa,0xac,0xaa,0xbf,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0x90,
				0x82,0x7d,0x97,0x59,0x59,0x59,0x59,0x59,0x7f,0x59,0x59,0x60,0x7d,0x7f,0x7f,
				0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x9a,0x88,0x7d,
				0x59,0x50,0x50,0x50,0x50,0x59,0x59,0x59,0x59,0x61,0x94,0x61,0x9e,0x59,0x59,
				0x85,0x59,0x92,0xa3,0x60,0x60,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,
				0x59,0x59,0x9f,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xcc,0x01,0xbc,0x03,0xf0,
				0x10,0x10,0x10,0x10,0x50,0x50,0x50,0x50,0x14,0x20,0x20,0x20,0x20,0x01,0x01,
				0x01,0x01,0xc4,0x02,0x10,0x00,0x00,0x00,0x00,0x01,0x01,0xc0,0xc2,0x10,0x11,
				0x02,0x03,0x11,0x03,0x03,0x04,0x00,0x00,0x14,0x00,0x02,0x00,0x00,0xc6,0xc8,
				0x02,0x02,0x02,0x02,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0xca,
				0x01,0x01,0x01,0x00,0x06,0x00,0x04,0x00,0xc0,0xc2,0x01,0x01,0x03,0x01,0xff,
				0xff,0x01,0x00,0x03,0xc4,0xc4,0xc6,0x03,0x01,0x01,0x01,0xff,0x03,0x03,0x03,
				0xc8,0x40,0x00,0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,
				0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0xff,0xff,0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x7f,0x00,0x00,0xff,0x4a,0x4a,0x4a,0x4a,0x4b,0x52,0x4a,0x4a,0x4a,0x4a,0x4f,
				0x4c,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x55,0x45,0x40,0x4a,0x4a,0x4a,
				0x45,0x59,0x4d,0x46,0x4a,0x5d,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,
				0x4a,0x4a,0x4a,0x4a,0x4a,0x61,0x63,0x67,0x4e,0x4a,0x4a,0x6b,0x6d,0x4a,0x4a,
				0x45,0x6d,0x4a,0x4a,0x44,0x45,0x4a,0x4a,0x00,0x00,0x00,0x02,0x0d,0x06,0x06,
				0x06,0x06,0x0e,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x00,0x06,0x06,0x02,0x06,
				0x00,0x0a,0x0a,0x07,0x07,0x06,0x02,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
				0x04,0x04,0x00,0x00,0x00,0x0e,0x05,0x06,0x06,0x06,0x01,0x06,0x00,0x00,0x08,
				0x00,0x10,0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,
				0x86,0x00,0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,
				0xf8,0xbb,0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,
				0xc4,0xff,0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,
				0x13,0x09,0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,
				0xb2,0xff,0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,
				0xe7,0x08,0x00,0xf0,0x02,0x00
			};
		};
		class X64
		{
		public:
			static constexpr unsigned int F_MODRM = 0x00000001;
			static constexpr unsigned int F_SIB = 0x00000002;
			static constexpr unsigned int F_IMM8 = 0x00000004;
			static constexpr unsigned int F_IMM16 = 0x00000008;
			static constexpr unsigned int F_IMM32 = 0x00000010;
			static constexpr unsigned int F_IMM64 = 0x00000020;
			static constexpr unsigned int F_DISP8 = 0x00000040;
			static constexpr unsigned int F_DISP16 = 0x00000080;
			static constexpr unsigned int F_DISP32 = 0x00000100;
			static constexpr unsigned int F_RELATIVE = 0x00000200;
			static constexpr unsigned int F_ERROR = 0x00001000;
			static constexpr unsigned int F_ERROR_OPCODE = 0x00002000;
			static constexpr unsigned int F_ERROR_LENGTH = 0x00004000;
			static constexpr unsigned int F_ERROR_LOCK = 0x00008000;
			static constexpr unsigned int F_ERROR_OPERAND = 0x00010000;
			static constexpr unsigned int F_PREFIX_REPNZ = 0x01000000;
			static constexpr unsigned int F_PREFIX_REPX = 0x02000000;
			static constexpr unsigned int F_PREFIX_REP = 0x03000000;
			static constexpr unsigned int F_PREFIX_66 = 0x04000000;
			static constexpr unsigned int F_PREFIX_67 = 0x08000000;
			static constexpr unsigned int F_PREFIX_LOCK = 0x10000000;
			static constexpr unsigned int F_PREFIX_SEG = 0x20000000;
			static constexpr unsigned int F_PREFIX_REX = 0x40000000;
			static constexpr unsigned int F_PREFIX_ANY = 0x7f000000;

			static constexpr unsigned int PREFIX_SEGMENT_CS = 0x2e;
			static constexpr unsigned int PREFIX_SEGMENT_SS = 0x36;
			static constexpr unsigned int PREFIX_SEGMENT_DS = 0x3e;
			static constexpr unsigned int PREFIX_SEGMENT_ES = 0x26;
			static constexpr unsigned int PREFIX_SEGMENT_FS = 0x64;
			static constexpr unsigned int PREFIX_SEGMENT_GS = 0x65;
			static constexpr unsigned int PREFIX_LOCK = 0xf0;
			static constexpr unsigned int PREFIX_REPNZ = 0xf2;
			static constexpr unsigned int PREFIX_REPX = 0xf3;
			static constexpr unsigned int PREFIX_OPERAND_SIZE = 0x66;
			static constexpr unsigned int PREFIX_ADDRESS_SIZE = 0x67;

			static constexpr unsigned char C_NONE = 0x00;
			static constexpr unsigned char C_MODRM = 0x01;
			static constexpr unsigned char C_IMM8 = 0x02;
			static constexpr unsigned char C_IMM16 = 0x04;
			static constexpr unsigned char C_IMM_P66 = 0x10;
			static constexpr unsigned char C_REL8 = 0x20;
			static constexpr unsigned char C_REL32 = 0x40;
			static constexpr unsigned char C_GROUP = 0x80;
			static constexpr unsigned char C_ERROR = 0xff;

			static constexpr unsigned char PRE_ANY = 0x00;
			static constexpr unsigned char PRE_NONE = 0x01;
			static constexpr unsigned char PRE_F2 = 0x02;
			static constexpr unsigned char PRE_F3 = 0x04;
			static constexpr unsigned char PRE_66 = 0x08;
			static constexpr unsigned char PRE_67 = 0x10;
			static constexpr unsigned char PRE_LOCK = 0x20;
			static constexpr unsigned char PRE_SEG = 0x40;
			static constexpr unsigned char PRE_ALL = 0xff;

			static constexpr unsigned short DELTA_OPCODES = 0x4a;
			static constexpr unsigned short DELTA_FPU_REG = 0xfd;
			static constexpr unsigned short DELTA_FPU_MODRM = 0x104;
			static constexpr unsigned short DELTA_PREFIXES = 0x13c;
			static constexpr unsigned short DELTA_OP_LOCK_OK = 0x1ae;
			static constexpr unsigned short DELTA_OP2_LOCK_OK = 0x1c6;
			static constexpr unsigned short DELTA_OP_ONLY_MEM = 0x1d8;
			static constexpr unsigned short DELTA_OP2_ONLY_MEM = 0x1e7;
			static unsigned int Disasm(const void* code, HDES* hs) noexcept
			{
				unsigned char x, c = 0, * p = (unsigned char*)code, cflags, opcode, pref = 0;
				const unsigned char* ht = hde64_table;
				unsigned char m_mod, m_reg, m_rm, disp_size = 0;
				unsigned char op64 = 0;

				/*
					// Avoid using memset to reduce the footprint.
				#ifndef _MSC_VER
					memset((LPBYTE)hs, 0, sizeof(hde64s));
				#else
					__stosb((unsigned char*)hs, 0, sizeof(hde64s));
				#endif
				*/
				for (int i = 0; i < sizeof(hs); i++) {
					((unsigned char*)hs)[i] = 0;
				}

				for (x = 16; x; x--)
					switch (c = *p++) {
					case 0xf3:
						hs->p_rep = c;
						pref |= PRE_F3;
						break;
					case 0xf2:
						hs->p_rep = c;
						pref |= PRE_F2;
						break;
					case 0xf0:
						hs->p_lock = c;
						pref |= PRE_LOCK;
						break;
					case 0x26: case 0x2e: case 0x36:
					case 0x3e: case 0x64: case 0x65:
						hs->p_seg = c;
						pref |= PRE_SEG;
						break;
					case 0x66:
						hs->p_66 = c;
						pref |= PRE_66;
						break;
					case 0x67:
						hs->p_67 = c;
						pref |= PRE_67;
						break;
					default:
						goto pref_done;
					}
			pref_done:

				hs->flags = (unsigned int)pref << 23;

				if (!pref)
					pref |= PRE_NONE;

				if ((c & 0xf0) == 0x40) {
					hs->flags |= F_PREFIX_REX;
					if ((hs->rex_w = (c & 0xf) >> 3) != 0 && (*p & 0xf8) == 0xb8)
						op64++;
					hs->rex_r = (c & 7) >> 2;
					hs->rex_x = (c & 3) >> 1;
					hs->rex_b = c & 1;
					if (((c = *p++) & 0xf0) == 0x40) {
						opcode = c;
						goto error_opcode;
					}
				}

				if ((hs->opcode = c) == 0x0f) {
					hs->opcode2 = c = *p++;
					ht += DELTA_OPCODES;
				}
				else if (c >= 0xa0 && c <= 0xa3) {
					op64++;
					if (pref & PRE_67)
						pref |= PRE_66;
					else
						pref &= ~PRE_66;
				}

				opcode = c;
				cflags = ht[ht[opcode / 4] + (opcode % 4)];

				if (cflags == C_ERROR) {
				error_opcode:
					hs->flags |= F_ERROR | F_ERROR_OPCODE;
					cflags = 0;
					if ((opcode & -3) == 0x24)
						cflags++;
				}

				x = 0;
				if (cflags & C_GROUP) {
					unsigned short t;
					t = *(unsigned short*)(ht + (cflags & 0x7f));
					cflags = (unsigned char)t;
					x = (unsigned char)(t >> 8);
				}

				if (hs->opcode2) {
					ht = hde64_table + DELTA_PREFIXES;
					if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
						hs->flags |= F_ERROR | F_ERROR_OPCODE;
				}

				if (cflags & C_MODRM) {
					hs->flags |= F_MODRM;
					hs->modrm = c = *p++;
					hs->modrm_mod = m_mod = c >> 6;
					hs->modrm_rm = m_rm = c & 7;
					hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

					if (x && ((x << m_reg) & 0x80))
						hs->flags |= F_ERROR | F_ERROR_OPCODE;

					if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
						unsigned char t = opcode - 0xd9;
						if (m_mod == 3) {
							ht = hde64_table + DELTA_FPU_MODRM + t * 8;
							t = ht[m_reg] << m_rm;
						}
						else {
							ht = hde64_table + DELTA_FPU_REG;
							t = ht[t] << m_reg;
						}
						if (t & 0x80)
							hs->flags |= F_ERROR | F_ERROR_OPCODE;
					}

					if (pref & PRE_LOCK) {
						if (m_mod == 3) {
							hs->flags |= F_ERROR | F_ERROR_LOCK;
						}
						else {
							const unsigned char* table_end;
							unsigned char op = opcode;
							if (hs->opcode2) {
								ht = hde64_table + DELTA_OP2_LOCK_OK;
								table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
							}
							else {
								ht = hde64_table + DELTA_OP_LOCK_OK;
								table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
								op &= -2;
							}
							for (; ht != table_end; ht++)
								if (*ht++ == op) {
									if (!((*ht << m_reg) & 0x80))
										goto no_lock_error;
									else
										break;
								}
							hs->flags |= F_ERROR | F_ERROR_LOCK;
						no_lock_error:
							;
						}
					}

					if (hs->opcode2) {
						switch (opcode) {
						case 0x20: case 0x22:
							m_mod = 3;
							if (m_reg > 4 || m_reg == 1)
								goto error_operand;
							else
								goto no_error_operand;
						case 0x21: case 0x23:
							m_mod = 3;
							if (m_reg == 4 || m_reg == 5)
								goto error_operand;
							else
								goto no_error_operand;
						}
					}
					else {
						switch (opcode) {
						case 0x8c:
							if (m_reg > 5)
								goto error_operand;
							else
								goto no_error_operand;
						case 0x8e:
							if (m_reg == 1 || m_reg > 5)
								goto error_operand;
							else
								goto no_error_operand;
						}
					}

					if (m_mod == 3) {
						const unsigned char* table_end;
						if (hs->opcode2) {
							ht = hde64_table + DELTA_OP2_ONLY_MEM;
							table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
						}
						else {
							ht = hde64_table + DELTA_OP_ONLY_MEM;
							table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
						}
						for (; ht != table_end; ht += 2)
							if (*ht++ == opcode) {
								if (*ht++ & pref && !((*ht << m_reg) & 0x80))
									goto error_operand;
								else
									break;
							}
						goto no_error_operand;
					}
					else if (hs->opcode2) {
						switch (opcode) {
						case 0x50: case 0xd7: case 0xf7:
							if (pref & (PRE_NONE | PRE_66))
								goto error_operand;
							break;
						case 0xd6:
							if (pref & (PRE_F2 | PRE_F3))
								goto error_operand;
							break;
						case 0xc5:
							goto error_operand;
						}
						goto no_error_operand;
					}
					else
						goto no_error_operand;

				error_operand:
					hs->flags |= F_ERROR | F_ERROR_OPERAND;
				no_error_operand:

					c = *p++;
					if (m_reg <= 1) {
						if (opcode == 0xf6)
							cflags |= C_IMM8;
						else if (opcode == 0xf7)
							cflags |= C_IMM_P66;
					}

					switch (m_mod) {
					case 0:
						if (pref & PRE_67) {
							if (m_rm == 6)
								disp_size = 2;
						}
						else
							if (m_rm == 5)
								disp_size = 4;
						break;
					case 1:
						disp_size = 1;
						break;
					case 2:
						disp_size = 2;
						if (!(pref & PRE_67))
							disp_size <<= 1;
					}

					if (m_mod != 3 && m_rm == 4) {
						hs->flags |= F_SIB;
						p++;
						hs->sib = c;
						hs->sib_scale = c >> 6;
						hs->sib_index = (c & 0x3f) >> 3;
						if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
							disp_size = 4;
					}

					p--;
					switch (disp_size) {
					case 1:
						hs->flags |= F_DISP8;
						hs->disp.disp8 = *p;
						break;
					case 2:
						hs->flags |= F_DISP16;
						hs->disp.disp16 = *(unsigned short*)p;
						break;
					case 4:
						hs->flags |= F_DISP32;
						hs->disp.disp32 = *(unsigned int*)p;
					}
					p += disp_size;
				}
				else if (pref & PRE_LOCK)
					hs->flags |= F_ERROR | F_ERROR_LOCK;

				if (cflags & C_IMM_P66) {
					if (cflags & C_REL32) {
						if (pref & PRE_66) {
							hs->flags |= F_IMM16 | F_RELATIVE;
							hs->imm.imm16 = *(unsigned short*)p;
							p += 2;
							goto disasm_done;
						}
						goto rel32_ok;
					}
					if (op64) {
						hs->flags |= F_IMM64;
						hs->imm.imm64 = *(unsigned __int64*)p;
						p += 8;
					}
					else if (!(pref & PRE_66)) {
						hs->flags |= F_IMM32;
						hs->imm.imm32 = *(unsigned int*)p;
						p += 4;
					}
					else
						goto imm16_ok;
				}


				if (cflags & C_IMM16) {
				imm16_ok:
					hs->flags |= F_IMM16;
					hs->imm.imm16 = *(unsigned short*)p;
					p += 2;
				}
				if (cflags & C_IMM8) {
					hs->flags |= F_IMM8;
					hs->imm.imm8 = *p++;
				}

				if (cflags & C_REL32) {
				rel32_ok:
					hs->flags |= F_IMM32 | F_RELATIVE;
					hs->imm.imm32 = *(unsigned int*)p;
					p += 4;
				}
				else if (cflags & C_REL8) {
					hs->flags |= F_IMM8 | F_RELATIVE;
					hs->imm.imm8 = *p++;
				}

			disasm_done:

				if ((hs->len = (unsigned char)(p - (unsigned char*)code)) > 15) {
					hs->flags |= F_ERROR | F_ERROR_LENGTH;
					hs->len = 15;
				}

				return (unsigned int)hs->len;
			}
			static int CreateReplaceCode(void* source, unsigned int minSize, void* buf, unsigned int bufSize, unsigned int* bufLen, void* target) noexcept
			{
				if (source == NULL || buf == NULL || bufLen == NULL || minSize == 0 || bufSize < minSize)
					return -1;
				if (target == NULL)
					target = buf;

				//已反编译指令的地址集合
				struct {
					void* saddress;
					void* taddress;
				}codemap[100] = { NULL };
				UINT32 codemap_index = 0;
				//已修改指令的集合
				void** codemap2[10] = { NULL };
				UINT32 codemap2_index = 0;

				UCHAR* pSou = (UCHAR*)source;
				UCHAR* pBuf = (UCHAR*)buf;
				UCHAR* pTar = (UCHAR*)target;

				int result = -1;
				while (1)
				{
					HDES hs = { 0 };
					UINT32 oldCodeLen = Disasm(pSou, &hs);
					if (hs.len == 0)
						break;
					void* pNewCode = pSou;
					UINT32 newCodeLen = oldCodeLen;
					UCHAR codeBuf[0x60] = { 0 };
					UCHAR codeBufIndex = 0;
#pragma region 解析代码
					//rip 相对寻址
					if ((hs.modrm & 0xC7) == 0x05)
					{
						//mov reg,[rva]
						if ((hs.opcode & 0xFE) == 0x8A)
						{
							//mov reg,address
							codeBuf[codeBufIndex++] = 0x48 | hs.rex_x;
							codeBuf[codeBufIndex++] = 0xB8 | hs.modrm_reg;
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
							codeBufIndex += sizeof(INT64);
							//mov reg,[reg]
							for (int k = 0; pSou[k] != hs.opcode; k++) codeBuf[codeBufIndex++] = pSou[k];
							codeBuf[codeBufIndex++] = hs.opcode;
							codeBuf[codeBufIndex++] = (hs.modrm_reg << 3) + hs.modrm_reg;

							pNewCode = codeBuf;
							newCodeLen = codeBufIndex;
						}
						//mov [rva],const
						else if ((hs.opcode & 0xFE) == 0xC6)
						{
							//push rax
							codeBuf[codeBufIndex++] = 0x50;
							//mov rax,[****]
							*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
							codeBufIndex += sizeof(UINT16);
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
							codeBufIndex += sizeof(INT64);
							//mov [rax],const
							for (int k = 0; pSou[k] != hs.opcode; k++) codeBuf[codeBufIndex++] = pSou[k];
							codeBuf[codeBufIndex++] = hs.opcode;
							codeBuf[codeBufIndex++] = 0x0;
							if (hs.p_66)
							{
								*(UINT16*)(codeBuf + codeBufIndex) = hs.imm.imm16;
								codeBufIndex += sizeof(UINT16);
							}
							else if (hs.opcode & 1)
							{
								*(UINT32*)(codeBuf + codeBufIndex) = hs.imm.imm32;
								codeBufIndex += sizeof(UINT32);
							}
							else
							{
								codeBuf[codeBufIndex++] = hs.imm.imm8;
							}
							//pop rax
							codeBuf[codeBufIndex++] = 0x58;

							pNewCode = codeBuf;
							newCodeLen = codeBufIndex;
						}
						//mov [rva],reg
						else if ((hs.opcode & 0xFE) == 0x88)
						{
							UCHAR tmpreg = (hs.modrm_reg + 1) % 8;
							if (tmpreg == 4) tmpreg = 5;
							//push tmpreg
							codeBuf[codeBufIndex++] = 0x50 | tmpreg;
							codeBuf[codeBufIndex++] = 0x48;
							//mov tmpreg,vaule
							codeBuf[codeBufIndex++] = 0xB8 | tmpreg;
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
							codeBufIndex += sizeof(INT64);
							for (int k = 0; pSou[k] != hs.opcode; k++) codeBuf[codeBufIndex++] = pSou[k];
							//mov [tmpreg],reg
							codeBuf[codeBufIndex++] = hs.opcode;
							codeBuf[codeBufIndex++] = hs.modrm_reg << 3 | tmpreg;
							//pop tmpreg
							codeBuf[codeBufIndex++] = 0x58 | tmpreg;

							pNewCode = codeBuf;
							newCodeLen = codeBufIndex;
						}
						//lea reg,[rva]
						else if (hs.opcode == 0x8d)
						{
							//mov reg,address
							for (int k = 0; pSou[k] != hs.opcode; k++) codeBuf[codeBufIndex++] = pSou[k];
							codeBuf[codeBufIndex++] = 0xB8 | hs.modrm_reg;
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
							codeBufIndex += sizeof(INT64);

							pNewCode = codeBuf;
							newCodeLen = codeBufIndex;
						}
						//cmp|test byte ptr[rva],const
						else if ((hs.opcode & 0xFC) == 0x80 || (hs.opcode & 0xFE) == 0xF6)
						{
							//push rax
							codeBuf[codeBufIndex++] = 0x50;
							//mov rax,vaule
							*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
							codeBufIndex += sizeof(UINT16);
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
							codeBufIndex += sizeof(INT64);
							//cmp|test byte ptr[rax],const
							for (int k = 0; pSou[k] != hs.opcode; k++) codeBuf[codeBufIndex++] = pSou[k];
							codeBuf[codeBufIndex++] = hs.opcode;
							codeBuf[codeBufIndex++] = hs.modrm & 0xF8;
							if (hs.p_66)
							{
								*(INT16*)(codeBuf + codeBufIndex) = hs.imm.imm16;
								codeBufIndex += sizeof(INT16);
							}
							else if (hs.opcode == 0x83 || hs.opcode == 0x80 || hs.opcode == 0xF6)
							{
								codeBuf[codeBufIndex++] = hs.imm.imm8;
							}
							else
							{
								*(UINT32*)(codeBuf + codeBufIndex) = hs.imm.imm32;
								codeBufIndex += sizeof(UINT32);
							}
							//pop rax
							codeBuf[codeBufIndex++] = 0x58;

							pNewCode = codeBuf;
							newCodeLen = codeBufIndex;
						}
						//cmp|test [rva],reg
						else if ((hs.opcode & 0xFE) == 0x38 || (hs.opcode & 0xFE) == 0x84)
						{
							UCHAR tmpreg = (hs.modrm_reg + 1) % 8;
							if (tmpreg == 4) tmpreg = 5;
							//push tmpreg
							codeBuf[codeBufIndex++] = 0x50 | tmpreg;
							codeBuf[codeBufIndex++] = 0x48;
							//mov tmpreg,vaule
							codeBuf[codeBufIndex++] = 0xB8 | tmpreg;
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
							codeBufIndex += sizeof(INT64);
							for (int k = 0; pSou[k] != hs.opcode; k++) codeBuf[codeBufIndex++] = pSou[k];
							//cmp|test [tmpreg],reg
							//这里好像没有cmp [reg],reg指令
							//只能使用 cmp [reg+0],reg
							codeBuf[codeBufIndex++] = hs.opcode;
							codeBuf[codeBufIndex++] = 0b01000000 | hs.modrm_reg << 3 | tmpreg;
							codeBuf[codeBufIndex++] = 0;
							//pop tmpreg
							codeBuf[codeBufIndex++] = 0x58 | tmpreg;

							pNewCode = codeBuf;
							newCodeLen = codeBufIndex;
						}
						//cmpxchg [rva],reg
						else if (hs.opcode == 0x0F && hs.opcode2 == 0xB1)
						{
							UCHAR tmpreg = (hs.modrm_reg + 1) % 8;
							if (tmpreg == 4) tmpreg = 5;
							//push tmpreg
							codeBuf[codeBufIndex++] = 0x50 | tmpreg;
							codeBuf[codeBufIndex++] = 0x48;
							//mov tmpreg,vaule
							codeBuf[codeBufIndex++] = 0xB8 | tmpreg;
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
							codeBufIndex += sizeof(INT64);
							//cmpxchg [tmpreg],reg
							for (int k = 0; pSou[k] != hs.opcode; k++) codeBuf[codeBufIndex++] = pSou[k];
							codeBuf[codeBufIndex++] = hs.opcode;
							codeBuf[codeBufIndex++] = hs.opcode2;
							codeBuf[codeBufIndex++] = hs.modrm_reg << 3 | tmpreg;
							//pop tmpreg
							codeBuf[codeBufIndex++] = 0x58 | tmpreg;

							pNewCode = codeBuf;
							newCodeLen = codeBufIndex;
						}
						//call|jmp [rva]
						else if (hs.opcode == 0xFF)
						{
							//call [rva]
							if (hs.modrm == 0x15)
							{
								//push rax
								codeBuf[codeBufIndex++] = 0x50;
								//mov rax,****
								*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
								codeBufIndex += sizeof(UINT16);
								*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
								codeBufIndex += sizeof(INT64);
								//添加到待修复表
								if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
								codemap2[codemap2_index++] = (void**)((INT64)pBuf + codeBufIndex);
								//mov rax,[rax]
								codeBuf[codeBufIndex++] = 0x48;
								codeBuf[codeBufIndex++] = 0x8B;
								codeBuf[codeBufIndex++] = 0x00;
								//xchg rax,[rsp]
								*(UINT32*)(codeBuf + codeBufIndex) = 0x24048748;
								codeBufIndex += sizeof(UINT32);
								//lea rsp,[rsp-8]
								*(UINT32*)(codeBuf + codeBufIndex) = 0x24648D48;
								codeBufIndex += sizeof(UINT32);
								codeBuf[codeBufIndex++] = 0x08;
								//call [rsp+8]
								*(UINT32*)(codeBuf + codeBufIndex) = 0xF82454FF;
								codeBufIndex += sizeof(UINT32);

								pNewCode = codeBuf;
								newCodeLen = codeBufIndex;
							}
							//jmp [rva]
							else if (hs.modrm == 0x25)
							{
								//push rax
								codeBuf[codeBufIndex++] = 0x50;
								//mov rax,[****]
								*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
								codeBufIndex += sizeof(UINT16);
								*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
								codeBufIndex += sizeof(INT64);
								//添加到待修复表
								if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
								codemap2[codemap2_index++] = (void**)((INT64)pBuf + codeBufIndex);
								//mov rax,[rax]
								codeBuf[codeBufIndex++] = 0x48;
								codeBuf[codeBufIndex++] = 0x8B;
								codeBuf[codeBufIndex++] = 0x00;
								//xchg rax,[rsp]
								*(UINT32*)(codeBuf + codeBufIndex) = 0x24048748;
								codeBufIndex += sizeof(UINT32);
								//result
								codeBuf[codeBufIndex++] = 0xC3;

								pNewCode = codeBuf;
								newCodeLen = codeBufIndex;
							}
							//push [rva]
							else if (hs.modrm == 0x35)
							{
								//push rax
								codeBuf[codeBufIndex++] = 0x50;
								//mov rax,****
								*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
								codeBufIndex += sizeof(UINT16);
								*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
								codeBufIndex += sizeof(INT64);
								//添加到待修复表
								if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
								codemap2[codemap2_index++] = (void**)((INT64)pBuf + codeBufIndex);
								//mov rax,[rax]
								codeBuf[codeBufIndex++] = 0x48;
								codeBuf[codeBufIndex++] = 0x8B;
								codeBuf[codeBufIndex++] = 0x00;
								//xchg rax,[rsp]
								*(UINT32*)(codeBuf + codeBufIndex) = 0x24048748;
								codeBufIndex += sizeof(UINT32);

								pNewCode = codeBuf;
								newCodeLen = codeBufIndex;
							}
							else
							{
								__debugbreak();
								break;
							}
						}
						//movdqa xmm*,[rva]
						else if (hs.opcode == 0x0F && hs.opcode2 == 0x6F)
						{
							//push rax
							codeBuf[codeBufIndex++] = 0x50;
							//mov rax,***
							*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
							codeBufIndex += sizeof(UINT16);
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.disp.disp32;
							codeBufIndex += sizeof(INT64);
							//拷贝指令前缀
							for (int k = 0; pSou[k] != hs.opcode; k++) codeBuf[codeBufIndex++] = pSou[k];
							//movdqa xmm*,[rax]
							codeBuf[codeBufIndex++] = hs.opcode;
							codeBuf[codeBufIndex++] = hs.opcode2;
							codeBuf[codeBufIndex++] = hs.modrm_reg << 3;
							//pop rax
							codeBuf[codeBufIndex++] = 0x58;

							pNewCode = codeBuf;
							newCodeLen = codeBufIndex;
						}
						else
						{
							__debugbreak();
							break;
						}
					}
					//call rva
					else if (hs.opcode == 0xE8)
					{
						//push rax
						codeBuf[codeBufIndex++] = 0x50;
						//mov rax,[****]
						*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
						codeBufIndex += sizeof(UINT16);
						*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.imm.imm32;
						codeBufIndex += sizeof(INT64);
						//添加到待修复表
						if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
						codemap2[codemap2_index++] = (void**)((INT64)pBuf + codeBufIndex);
						//xchg rax,[rsp]
						*(UINT32*)(codeBuf + codeBufIndex) = 0x24048748;
						codeBufIndex += sizeof(UINT32);
						//lea rsp,[rsp-8]
						*(UINT32*)(codeBuf + codeBufIndex) = 0x24648D48;
						codeBufIndex += sizeof(UINT32);
						codeBuf[codeBufIndex++] = 0x08;
						//call [rsp+8]
						*(UINT32*)(codeBuf + codeBufIndex) = 0xF82454FF;
						codeBufIndex += sizeof(UINT32);

						pNewCode = codeBuf;
						newCodeLen = codeBufIndex;
					}
					//jmp rva
					else if ((hs.opcode & 0xFD) == 0xE9)
					{
						//push rax
						codeBuf[codeBufIndex++] = 0x50;
						//mov rax
						*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
						codeBufIndex += sizeof(UINT16);
						if (hs.opcode & 2)
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.imm.imm32;
						else
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT8)hs.imm.imm8;
						codeBufIndex += sizeof(INT64);
						//添加到待修复表
						if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
						codemap2[codemap2_index++] = (void**)((INT64)pBuf + codeBufIndex);
						//xchg rax,[rsp]
						*(UINT32*)(codeBuf + codeBufIndex) = 0x24048748;
						codeBufIndex += sizeof(UINT32);
						//result
						codeBuf[codeBufIndex++] = 0xC3;

						pNewCode = codeBuf;
						newCodeLen = codeBufIndex;
					}
					//jcc rva
					else if (((hs.opcode & 0xFC) == 0xE0 || (hs.opcode & 0xF0) == 0x70 || (hs.opcode2 & 0xF0) == 0x80)
						|| (hs.opcode == 0x0F && ((hs.opcode2 & 0xFC) == 0xE0 || (hs.opcode2 & 0xF0) == 0x70 || (hs.opcode2 & 0xF0) == 0x80)))
					{
						//jcc 0x10
						codeBuf[codeBufIndex++] = hs.opcode;
						if (hs.opcode == 0x0F)
							codeBuf[codeBufIndex++] = hs.opcode2;
						//确定立即数大小
						if (hs.opcode == 0x0F)
						{
							*(UINT32*)(codeBuf + codeBufIndex) = 0x2;                 //dword offset;
							codeBufIndex += sizeof(UINT32);
						}
						else
						{
							codeBuf[codeBufIndex++] = 0x2;                              //byte offset;
						}
						//跳转不成立时
						//jmp 0x10
						codeBuf[codeBufIndex++] = 0xEB;
						codeBuf[codeBufIndex++] = 0x10;
						//跳转成立时
						//push rax
						codeBuf[codeBufIndex++] = 0x50;
						//mov rax,[****]
						*(UINT16*)(codeBuf + codeBufIndex) = 0xB848;
						codeBufIndex += sizeof(UINT16);
						//确定操作数大小
						if (hs.opcode == 0x0F)
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT32)hs.imm.imm32;
						else
							*(INT64*)(codeBuf + codeBufIndex) = (INT64)pSou + oldCodeLen + (INT8)hs.imm.imm8;
						codeBufIndex += sizeof(INT64);
						//添加到待修复表
						if (codemap2_index >= sizeof(codemap2) / sizeof(codemap2[0])) break;
						codemap2[codemap2_index++] = (void**)((INT64)pBuf + codeBufIndex);
						//跳转不成立时的真实入口
						//xchg rax,[rsp]
						*(UINT32*)(codeBuf + codeBufIndex) = 0x24048748;
						codeBufIndex += sizeof(UINT32);
						//result
						codeBuf[codeBufIndex++] = 0xC3;

						pNewCode = codeBuf;
						newCodeLen = codeBufIndex;
					}
#pragma endregion
					if (pNewCode == NULL || newCodeLen == 0)
						break;
					//判断缓冲区是否够
					if (pBuf - (UCHAR*)buf + newCodeLen > bufSize)
						break;
					memcpy(pBuf, pNewCode, newCodeLen);
					//保存到表
					if (codemap_index >= sizeof(codemap) / sizeof(codemap[0]))
						break;
					codemap[codemap_index].saddress = pSou;
					codemap[codemap_index].taddress = pTar;
					codemap_index++;

					pBuf += newCodeLen;
					pSou += oldCodeLen;
					pTar += newCodeLen;
					//判断是否完成
					if (pSou - (UCHAR*)source >= minSize)
					{
						*bufLen = (UINT32)(pBuf - (UCHAR*)buf);
						result = (INT32)(pSou - (UCHAR*)source);
						break;
					}
				}
				//匹配地址修复表
				if (result > 0)
				{
					for (UINT32 i = 0; i < codemap2_index; i++)
					{
						for (UINT32 j = 0; j < codemap_index; j++)
						{
							if (*codemap2[i] == codemap[j].saddress)
							{
								*(codemap2[i]) = codemap[j].taddress;
								break;
							}
						}
					}
				}
				return result;
			}
		private:
			static constexpr unsigned char hde64_table[] = {
			  0xa5,0xaa,0xa5,0xb8,0xa5,0xaa,0xa5,0xaa,0xa5,0xb8,0xa5,0xb8,0xa5,0xb8,0xa5,
			  0xb8,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xac,0xc0,0xcc,0xc0,0xa1,0xa1,
			  0xa1,0xa1,0xb1,0xa5,0xa5,0xa6,0xc0,0xc0,0xd7,0xda,0xe0,0xc0,0xe4,0xc0,0xea,
			  0xea,0xe0,0xe0,0x98,0xc8,0xee,0xf1,0xa5,0xd3,0xa5,0xa5,0xa1,0xea,0x9e,0xc0,
			  0xc0,0xc2,0xc0,0xe6,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0xab,
			  0x8b,0x90,0x64,0x5b,0x5b,0x5b,0x5b,0x5b,0x92,0x5b,0x5b,0x76,0x90,0x92,0x92,
			  0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x6a,0x73,0x90,
			  0x5b,0x52,0x52,0x52,0x52,0x5b,0x5b,0x5b,0x5b,0x77,0x7c,0x77,0x85,0x5b,0x5b,
			  0x70,0x5b,0x7a,0xaf,0x76,0x76,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,
			  0x5b,0x5b,0x86,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xd5,0x03,0xcc,0x01,0xbc,
			  0x03,0xf0,0x03,0x03,0x04,0x00,0x50,0x50,0x50,0x50,0xff,0x20,0x20,0x20,0x20,
			  0x01,0x01,0x01,0x01,0xc4,0x02,0x10,0xff,0xff,0xff,0x01,0x00,0x03,0x11,0xff,
			  0x03,0xc4,0xc6,0xc8,0x02,0x10,0x00,0xff,0xcc,0x01,0x01,0x01,0x00,0x00,0x00,
			  0x00,0x01,0x01,0x03,0x01,0xff,0xff,0xc0,0xc2,0x10,0x11,0x02,0x03,0x01,0x01,
			  0x01,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0x00,0x00,0xff,0xff,0xff,0xff,0x10,
			  0x10,0x10,0x10,0x02,0x10,0x00,0x00,0xc6,0xc8,0x02,0x02,0x02,0x02,0x06,0x00,
			  0x04,0x00,0x02,0xff,0x00,0xc0,0xc2,0x01,0x01,0x03,0x03,0x03,0xca,0x40,0x00,
			  0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,0x00,0x00,0x00,
			  0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0xff,0x00,
			  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
			  0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7f,0x00,0x00,
			  0xff,0x40,0x40,0x40,0x40,0x41,0x49,0x40,0x40,0x40,0x40,0x4c,0x42,0x40,0x40,
			  0x40,0x40,0x40,0x40,0x40,0x40,0x4f,0x44,0x53,0x40,0x40,0x40,0x44,0x57,0x43,
			  0x5c,0x40,0x60,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
			  0x40,0x40,0x64,0x66,0x6e,0x6b,0x40,0x40,0x6a,0x46,0x40,0x40,0x44,0x46,0x40,
			  0x40,0x5b,0x44,0x40,0x40,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x01,0x06,
			  0x06,0x02,0x06,0x06,0x00,0x06,0x00,0x0a,0x0a,0x00,0x00,0x00,0x02,0x07,0x07,
			  0x06,0x02,0x0d,0x06,0x06,0x06,0x0e,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
			  0x04,0x04,0x05,0x06,0x06,0x06,0x00,0x00,0x00,0x0e,0x00,0x00,0x08,0x00,0x10,
			  0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,0x86,0x00,
			  0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,0xf8,0xbb,
			  0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,0xc4,0xff,
			  0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,0x13,0x09,
			  0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,0xb2,0xff,
			  0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,0xe7,0x08,
			  0x00,0xf0,0x02,0x00
			};
		};
	};
#pragma endregion

#pragma region InlineHook
public:
	struct INLINEHOOK
	{
	private:
		struct static_data_t
		{
			bool(*WriteMemory)(PVOID _Des, PVOID _Src, size_t _Size) = nullptr;
		};
		static inline static_data_t& static_data() noexcept
		{
			static static_data_t data_{};
			return data_;
		}
#pragma pack(push, 1)
		struct X64RET_ABS
		{
			UCHAR push_rax;
			USHORT mov_rax;
			DWORD64 address;
			DWORD32 xchg_rax_rsp0;
			UCHAR ret;
		};
		struct X86JMP_ABS
		{
			UCHAR jmp;
			LONG abs;
		};
		struct HOOK_STR
		{
			UCHAR newAsm[0x100];			//汇编代码
			UCHAR backAsm[max(sizeof(X86JMP_ABS), sizeof(X64RET_ABS))];
			PVOID pTarget;					//原函数地址
			PVOID pDetour;					//新函数地址
			LONG RefCount;                  //引用计数
			bool isEnable;				//是否启用
			bool isX86;                  //是否X86
		};
#pragma pack(pop)
	public:
		static void Initialize(bool(*WriteMemory)(PVOID _Des, PVOID _Src, size_t _Size)) noexcept
		{
			static_data().WriteMemory = WriteMemory;
		}
		static PVOID CreateFunction(PVOID pTarget, PVOID pDetour, bool isX86) noexcept
		{
			HOOK_STR* result = NULL;
			if (pTarget && pDetour)
			{
#ifdef WINNT
				result = (HOOK_STR*)ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_STR), 'ILHK');
#else
				result = (HOOK_STR*)VirtualAlloc(NULL, sizeof(HOOK_STR), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#endif
				if (result != NULL)
				{
					memset(result, 0, sizeof(HOOK_STR));
					unsigned int newCodeLen = 0;
					int len = 0;
					if (isX86)
					{
						len = INSTRUCTION::X86::CreateReplaceCode(pTarget, sizeof(result->backAsm), result->newAsm, sizeof(result->newAsm), &newCodeLen, NULL);
					}
					else
					{
						len = INSTRUCTION::X64::CreateReplaceCode(pTarget, sizeof(result->backAsm), result->newAsm, sizeof(result->newAsm), &newCodeLen, NULL);
					}
					if (len <= 0)
					{
#ifdef WINNT
						ExFreePoolWithTag(result, 'ILHK');
#else
						VirtualFree(result, 0, MEM_RELEASE);
#endif
						result = NULL;
					}
					else
					{
						if (isX86)
						{
							//目的地址-当前地址-5
							LONG offset = ((LONG)(LONG64)pTarget + len) - ((LONG)(LONG64)result->newAsm + newCodeLen) - 5;
							X86JMP_ABS jmpAbs = { 0xE9,offset };
							memcpy(result->newAsm + newCodeLen, &jmpAbs, sizeof(jmpAbs));
						}
						else
						{
							X64RET_ABS retAbs = { 0x50,0xB848,(DWORD64)pTarget + len,0x24048748,0xC3 };
							memcpy(result->newAsm + newCodeLen, &retAbs, sizeof(retAbs));
						}
						result->pTarget = pTarget;
						result->pDetour = pDetour;
						result->RefCount = 0;
						result->isX86 = isX86;
					}
				}
			}
			return result;
		}
		static PVOID Create(PVOID pTarget, void(*CallBack)(PVOID CpuState, PVOID pTarget), bool isX86) noexcept
		{
			HOOK_STR* result = NULL;
#ifdef WINNT
			result = (HOOK_STR*)ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'INHK');
#else
			result = (HOOK_STR*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#endif // WINNT
			if (result != NULL)
			{
				memset(result, 0, 0x1000);
				PUCHAR pDetour = (PUCHAR)result + sizeof(HOOK_STR);
				PUCHAR cursor = pDetour;
				if (!isX86)
				{
					cursor += WriteX64RegisterSaveCode(cursor, 0x1000 - (cursor - pDetour));
					//mov rdx,[tag]
					*(cursor++) = 0x48;
					*(cursor++) = 0xBA;
					*(ULONG64*)cursor = (ULONG64)pTarget;
					cursor += sizeof(ULONG64);
					UCHAR code1[] = { 0x48,0x83,0xEC,0x20,0xFF,0x15,0x06,0x00,0x00,0x00,0x48,0x83,0xC4,0x20,0xEB,0x08 };
					memcpy(cursor, code1, sizeof(code1));
					cursor += sizeof(code1);
					*(ULONG64*)cursor = (ULONG64)CallBack;
					cursor += sizeof(ULONG64);
					cursor += WriteX64RegisterRestoreCode(cursor, 0x1000 - (cursor - pDetour));
					unsigned int newCodeLen = 0;
					int len = INSTRUCTION::X64::CreateReplaceCode(pTarget, sizeof(result->backAsm), cursor, (int)(sizeof(result->newAsm) - ((ULONG64)cursor - (ULONG64)&result->newAsm)), &newCodeLen, NULL);
					if (len <= 0)
					{
#ifdef WINNT
						ExFreePoolWithTag(result, 'INHK');
#else
						VirtualFree(result, 0, MEM_RELEASE);
#endif // WINNT
						result = NULL;
					}
					else
					{
						X64RET_ABS retAbs = { 0x50,0xB848,(DWORD64)pTarget + len,0x24048748,0xC3 };
						memcpy(cursor + newCodeLen, &retAbs, sizeof(retAbs));
						result->pTarget = pTarget;
						result->pDetour = pDetour;
						result->RefCount = 0;
						result->isX86 = false;
					}
				}
				else
				{
					cursor += WriteX86RegisterSaveCode(cursor, 0x1000 - (cursor - pDetour));
					//push ecx
					*(cursor++) = 0x51;
					//push Target
					*(cursor++) = 0x68;
					*(DWORD32*)cursor = (DWORD32)(ULONG_PTR)pTarget;
					cursor += sizeof(DWORD32);
					//mov eax,callback
					*(cursor++) = 0xB8;
					*(DWORD32*)cursor = (DWORD32)(ULONG_PTR)CallBack;
					cursor += sizeof(DWORD32);
					//call eax
					*(cursor++) = 0xFF;
					*(cursor++) = 0xD0;
					cursor += WriteX86RegisterRestoreCode(cursor, 0x1000 - (cursor - pDetour));
					unsigned int newCodeLen = 0;
					int len = INSTRUCTION::X86::CreateReplaceCode(pTarget, sizeof(result->backAsm), cursor, (int)(sizeof(result->newAsm) - ((ULONG64)cursor - (ULONG64)&result->newAsm)), &newCodeLen, NULL);

					if (len <= 0)
					{
#ifdef WINNT
						ExFreePoolWithTag(result, 'INHK');
#else
						VirtualFree(result, 0, MEM_RELEASE);
#endif // WINNT
						result = NULL;
					}
					else
					{
						//目的地址-当前地址-5
						LONG offset = ((LONG)(LONG64)pTarget + len) - ((LONG)(LONG64)cursor + newCodeLen) - 5;
						X86JMP_ABS jmpAbs = { 0xE9,offset };
						memcpy(cursor + newCodeLen, &jmpAbs, sizeof(jmpAbs));
						result->pTarget = pTarget;
						result->pDetour = pDetour;
						result->RefCount = 0;
						result->isX86 = true;
					}
				}
			}
			return result;
		}
		static bool Enable(PVOID hook) noexcept
		{
			bool result = false;
			if (hook != NULL)
			{
				HOOK_STR* pHook = (HOOK_STR*)hook;
				if (pHook->isEnable)
				{
					result = true;
				}
				else
				{
					X86JMP_ABS jmpAbs = { 0xE9,0 };
					X64RET_ABS retAbs = { 0x50,0xB848,(DWORD64)pHook->pDetour,0x24048748,0xC3 };
					PVOID pWriteCode;
					ULONG WriteSize;
					if (pHook->isX86)
					{
						//目的地址-当前地址-5
						jmpAbs.abs = (LONG)(LONG64)pHook->newAsm - (LONG)(LONG64)pHook->pDetour - 5;
						pWriteCode = &jmpAbs;
						WriteSize = sizeof(X86JMP_ABS);
					}
					else
					{
						retAbs.address = (DWORD64)pHook->pDetour;
						pWriteCode = &retAbs;
						WriteSize = sizeof(X64RET_ABS);
					}
					//备份代码
					memcpy(&pHook->backAsm, pHook->pTarget, WriteSize);
					result = static_data().WriteMemory
						? static_data().WriteMemory(pHook->pTarget, pWriteCode, WriteSize)
						: ModifyInstruct(pHook->pTarget, pWriteCode, WriteSize);
					if (result)
					{
						pHook->isEnable = true;
					}
				}
			}
			return result;
		}
		static inline bool Disable(PVOID hook) noexcept
		{
			bool result = false;
			if (hook != NULL)
			{
				HOOK_STR* pHook = (HOOK_STR*)hook;
				if (!pHook->isEnable)
				{
					result = true;
				}
				else
				{
					ULONG WriteSize;
					if (pHook->isX86)
					{
						WriteSize = sizeof(X86JMP_ABS);
					}
					else
					{
						WriteSize = sizeof(X64RET_ABS);
					}
					result = static_data().WriteMemory
						? static_data().WriteMemory(pHook->pTarget, pHook->backAsm, WriteSize)
						: ModifyInstruct(pHook->pTarget, pHook->backAsm, WriteSize);
					if (result)
					{
						pHook->isEnable = false;
					}
				}
			}
			return result;
		}
		static inline void Remove(PVOID hook) noexcept
		{
			if (hook != NULL)
			{
				HOOK_STR* pHook = (HOOK_STR*)hook;
				if (!pHook->isEnable)
				{
					while (true)
					{
						if (pHook->RefCount == 0)
						{
#ifdef WINNT
							ExFreePoolWithTag(pHook, 'IMHK');
#else
							VirtualFree(pHook, 0, MEM_RELEASE);
#endif
							break;
						}
#ifdef WINNT
						LARGE_INTEGER Timeout = { 0 };
						Timeout.QuadPart = -10000LL * 100;	//100ms
						KeDelayExecutionThread(KernelMode, false, &Timeout);
#else
						Sleep(100);
#endif // WINNT
					}
				}
			}
		}
		static inline void DetoutFunctionBegin(PVOID hook) noexcept
		{
			InterlockedAdd(&(((HOOK_STR*)hook)->RefCount), 1);
		}
		static inline void DetoutFunctionEnd(PVOID hook) noexcept
		{
			InterlockedAdd(&(((HOOK_STR*)hook))->RefCount, -1);
		}
	};
#pragma endregion

#pragma region SSDT
public:
#ifdef WINNT
	struct SSDT
	{
	public:
		struct SYSTEM_SERVICE_TABLE
		{
			PLONG ServiceTableBase;                         // SSDT基址，8字节大小
			PVOID ServiceCounterTableBase;                  // SSDT中服务被调用次数计数器，8字节大小
			DWORD64 NumberOfService;                        // SSDT服务函数的个数，8字节大小
			PVOID ParamTableBase;                           // 系统服务参数表基址，8字节大小。实际指向的数组是以字节为单位的记录着对应服务函数的参数个数
		};
	private:
		struct static_data_t
		{
			SYSTEM_SERVICE_TABLE* pSSDTTable = nullptr;
			SYSTEM_SERVICE_TABLE* pSSDTShadowTable = nullptr;
			char SSDTName[0x200][0x40] = { 0 };
			char SSDTShadowName[0x600][0x40] = { 0 };
		};
		static inline static_data_t& static_data() noexcept
		{
			static static_data_t data_{};
			return data_;
		}

		static constexpr ULONG SSDT_OFFSET(ULONG v) { return v >> 4; }
		static constexpr ULONG SSDT_PARAMCOUNT(ULONG v) { return v & 0xF; }
		static constexpr auto SYSCALL_KEY0 = 0xB8D18B4C;
		static constexpr auto SYSCALL_KEY2 = 0x082504F6;
		static constexpr auto SYSCALL_KEY3 = 0x017FFE03;
		static constexpr auto SYSCALL_KEY4 = 0x050F0375;
		static constexpr auto SYSCALL_KEY5 = 0xC32ECDC3;
		static inline PVOID GetKiServiceInternalAddress() noexcept
		{
			UNICODE_STRING uStr;
			RtlInitUnicodeString(&uStr, L"ZwOpenFile");
			PVOID funZwOpenThread = MmGetSystemRoutineAddress(&uStr);
			if (funZwOpenThread == NULL)
				return NULL;
			//find KiServiceInternal
			PVOID  funKiServiceInternal = NULL;
			PCHAR tmp = (PCHAR)funZwOpenThread;
			INSTRUCTION::HDES hde_info = { 0 };
			//他就在不远处
			for (int i = 0; i < 20; i++) {
				if (!INSTRUCTION::X64::Disasm(tmp, &hde_info))
					break;
				//E9 42 28 01 00                jmp     KiServiceInternal
				if (hde_info.len == 5 && hde_info.opcode == 0xE9)
				{
					funKiServiceInternal = tmp + hde_info.len + *((DWORD32*)(tmp + 1));
					break;
				}
				tmp += hde_info.len;
			}
			return funKiServiceInternal;
		}
	public:
		static bool Initialize() noexcept
		{
			static bool _init = false;
			if (!_init)
			{
				do
				{
					PVOID funKiServiceInternal = GetKiServiceInternalAddress();
					if (!funKiServiceInternal)
						break;
					//find KiSystemServiceStart
					INSTRUCTION::HDES hde_info = { 0 };
					PVOID funKiSystemServiceStart = nullptr;
					PCHAR tmp = (PCHAR)funKiServiceInternal;
					for (int i = 0; i < 20; i++)
					{
						if (!INSTRUCTION::X64::Disasm(tmp, &hde_info))
							break;
						if (hde_info.len == 7 && hde_info.opcode == 0x8D &&
							hde_info.modrm == 0x1D) //4C 8D 1D 5F 03 00 00          lea     r11, KiSystemServiceStart
						{
							funKiSystemServiceStart = tmp + hde_info.len + *((INT32*)(tmp + 3));
							break;
						}
						tmp += hde_info.len;
					}
					if (!funKiSystemServiceStart)
						break;
					//find SSDT
					tmp = (PCHAR)funKiSystemServiceStart;
					for (int i = 0; i < 20; i++) {
						if (!INSTRUCTION::X64::Disasm(tmp, &hde_info))
							break;
						if (hde_info.len == 7 && hde_info.opcode == 0x8D) {
							if (hde_info.modrm == 0x15) {   //4C 8D 15 E5 8D 3B 00          lea     r10, KeServiceDescriptorTable
								static_data().pSSDTTable = (SYSTEM_SERVICE_TABLE*)(tmp + hde_info.len + *((INT32*)(tmp + 3)));
							}
							else if (hde_info.modrm == 0x1D) {
								static_data().pSSDTShadowTable = (SYSTEM_SERVICE_TABLE*)(tmp + hde_info.len + *((INT32*)(tmp + 3))) + 1;
							}
							if (static_data().pSSDTTable && static_data().pSSDTShadowTable)
								break;
						}
						tmp += hde_info.len;
					}
					//读取Index
					PVOID Buffer = NULL;
					SIZE_T BufferSize = 0;
					IMAGE::MapForFile(L"\\??\\C:\\Windows\\System32\\ntdll.dll", NULL, &BufferSize, true);
					if (BufferSize == 0)
						break;
					Buffer = ExAllocatePoolWithTag(PagedPool, BufferSize, 'BUF');
					if (Buffer == NULL)
						break;
					{
						memset(static_data().SSDTName, 0, sizeof(static_data().SSDTName));
						bool success = IMAGE::MapForFile(L"\\??\\C:\\Windows\\System32\\ntdll.dll", Buffer, &BufferSize, true);
						if (success)
						{
							success = IMAGE::EnumExport(Buffer, [&](PVOID ImageBase, PCSTR ProcName, PDWORD32 pRVA)->bool
								{
									PVOID procAddress = IMAGE::RVA_TO_VA(ImageBase, *pRVA);
									if (((DWORD32*)procAddress)[0] == SYSCALL_KEY0 && ((DWORD32*)procAddress)[2] == SYSCALL_KEY2 &&
										((DWORD32*)procAddress)[3] == SYSCALL_KEY3 && ((DWORD32*)procAddress)[4] == SYSCALL_KEY4)
									{
										ULONG sysCallIndex = ((DWORD32*)procAddress)[1] & 0xEFFF;
										if (sysCallIndex < sizeof(static_data().SSDTName) / sizeof(static_data().SSDTName[0])) {
											if (((USHORT*)(static_data().SSDTName[sysCallIndex]))[0] != 'tN')
												strcpy_s(static_data().SSDTName[sysCallIndex], sizeof(static_data().SSDTName[0]), ProcName);
										}
									}
									return false;
								}
							);
						}
						ExFreePoolWithTag(Buffer, 'BUF');
						if (!success)
							break;
					}
					Buffer = NULL;
					BufferSize = 0;
					IMAGE::MapForFile(L"\\??\\C:\\Windows\\System32\\win32u.dll", NULL, &BufferSize, true);
					if (BufferSize == 0)
						break;
					Buffer = ExAllocatePoolWithTag(PagedPool, BufferSize, 'BUF');
					if (Buffer == NULL)
						break;
					{
						memset(static_data().SSDTShadowName, 0, sizeof(static_data().SSDTShadowName));
						bool success = IMAGE::MapForFile(L"\\??\\C:\\Windows\\System32\\win32u.dll", Buffer, &BufferSize, true);
						if (success)
						{
							success = IMAGE::EnumExport(Buffer, [&](PVOID ImageBase, PCSTR ProcName, PDWORD32 pRVA)->bool 
								{
									PVOID procAddress = IMAGE::RVA_TO_VA(ImageBase, *pRVA);
									if (((DWORD32*)procAddress)[0] == SYSCALL_KEY0 && ((DWORD32*)procAddress)[2] == SYSCALL_KEY2 &&
										((DWORD32*)procAddress)[3] == SYSCALL_KEY3 && ((DWORD32*)procAddress)[4] == SYSCALL_KEY4)
									{
										ULONG sysCallIndex = ((DWORD32*)procAddress)[1] & 0xEFFF;
										if (sysCallIndex < sizeof(static_data().SSDTShadowName) / sizeof(static_data().SSDTShadowName[0])) {
											if (((USHORT*)(static_data().SSDTShadowName[sysCallIndex]))[0] != 'tN')
												strcpy_s(static_data().SSDTShadowName[sysCallIndex], sizeof(static_data().SSDTShadowName[0]), ProcName);
										}
									}
									return false;
								}
							);
						}
						ExFreePoolWithTag(Buffer, 'BUF');
						if (!success)
							break;
					}
					_init = true;
				} while (false);
			}
			return _init;
		}
		static PCSTR IndexToName(ULONG Index) noexcept
		{
			PCSTR result = NULL;
			if (Initialize())
			{
				bool IsShadow = (Index & 0x1000) != 0;
				ULONG TableIndex = Index & 0xFFF;
				if (!IsShadow && TableIndex < static_data().pSSDTTable->NumberOfService && TableIndex < sizeof(static_data().SSDTName) / sizeof(static_data().SSDTName[0]))
					result = static_data().SSDTName[TableIndex];
				else if (TableIndex < static_data().pSSDTTable->NumberOfService && TableIndex < sizeof(static_data().SSDTShadowName) / sizeof(static_data().SSDTShadowName[0]))
					result = static_data().SSDTShadowName[TableIndex];
			}
			return result;
		}
		static PVOID IndexToAddress(ULONG Index, PULONG pArgCount) noexcept
		{
			PVOID result = NULL;
			if (Initialize())
			{
				bool IsShadow = (Index & 0x1000) != 0;
				ULONG TableIndex = Index & 0xFFF;
				if (!IsShadow && TableIndex < static_data().pSSDTTable->NumberOfService)
				{
					if (pArgCount) *pArgCount = SSDT_PARAMCOUNT(static_data().pSSDTTable->ServiceTableBase[TableIndex]);
					result = (PCHAR)static_data().pSSDTTable->ServiceTableBase + SSDT_OFFSET(static_data().pSSDTTable->ServiceTableBase[TableIndex]);
				}
				else if (TableIndex < static_data().pSSDTShadowTable->NumberOfService)
				{
					PEPROCESS explorerPEPROCESS = NULL;
					KAPC_STATE ks = { 0 };
					if (!MmIsAddressValid(static_data().pSSDTShadowTable->ServiceTableBase))
					{
						ULONG64 pid = GetProcessIdByProcessName(L"explorer.exe");
						if (pid != 0 && NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &explorerPEPROCESS)))
							KeStackAttachProcess(explorerPEPROCESS, &ks);
					}
					if (pArgCount) *pArgCount = SSDT_PARAMCOUNT(static_data().pSSDTShadowTable->ServiceTableBase[TableIndex]);
					result = (PCHAR)static_data().pSSDTShadowTable->ServiceTableBase + SSDT_OFFSET(static_data().pSSDTShadowTable->ServiceTableBase[TableIndex]);
					if (explorerPEPROCESS)
					{
						KeUnstackDetachProcess(&ks);
						ObDereferenceObject(explorerPEPROCESS);
					}
				}
			}
			return result;
		}
		static PCSTR AddressToName(PVOID address) noexcept
		{
			PCSTR result = NULL;
			if (Initialize())
			{
				for (ULONG i = 0; i < min(static_data().pSSDTTable->NumberOfService, sizeof(static_data().SSDTName) / sizeof(static_data().SSDTName[0])); i++)
				{
					if (address == ((PCHAR)static_data().pSSDTTable->ServiceTableBase + SSDT_OFFSET(static_data().pSSDTTable->ServiceTableBase[i])))
					{
						result = static_data().SSDTName[i];
						break;
					}
				}
				if (result == NULL && MmIsAddressValid(static_data().pSSDTShadowTable->ServiceTableBase))
				{
					for (ULONG i = 0; i < min(static_data().pSSDTShadowTable->NumberOfService, sizeof(static_data().SSDTShadowName) / sizeof(static_data().SSDTShadowName[0])); i++)
					{
						if (address == ((PCHAR)static_data().pSSDTShadowTable->ServiceTableBase + SSDT_OFFSET(static_data().pSSDTShadowTable->ServiceTableBase[i])))
						{
							result = static_data().SSDTShadowName[i];
							break;
						}
					}
				}
			}
			return result;
		}
		static ULONG AddressToIndex(PVOID address) noexcept
		{
			ULONG result = 0xFFFFFFFF;
			if (Initialize())
			{
				for (ULONG i = 0; i < min(static_data().pSSDTTable->NumberOfService, sizeof(static_data().SSDTName) / sizeof(static_data().SSDTName[0])); i++)
				{
					if (address == ((PCHAR)static_data().pSSDTTable->ServiceTableBase + SSDT_OFFSET(static_data().pSSDTTable->ServiceTableBase[i])))
					{
						result = i;
						break;
					}
				}

				if (result == 0xFFFFFFFF && MmIsAddressValid(static_data().pSSDTShadowTable->ServiceTableBase))
				{
					for (ULONG i = 0; i < min(static_data().pSSDTShadowTable->NumberOfService, sizeof(static_data().SSDTShadowName) / sizeof(static_data().SSDTShadowName[0])); i++)
					{
						if (address == ((PCHAR)static_data().pSSDTShadowTable->ServiceTableBase + SSDT_OFFSET(static_data().pSSDTShadowTable->ServiceTableBase[i])))
						{
							result = i | 0x1000;
							break;
						}
					}
				}
			}
			return result;
		}
		static PVOID NameToAddress(PCSTR name, PULONG pPNum) noexcept
		{
			PVOID result = NULL;
			if (Initialize())
			{
				for (ULONG i = 0; i < min(static_data().pSSDTTable->NumberOfService, sizeof(static_data().SSDTName) / sizeof(static_data().SSDTName[0])); i++)
				{
					if (strcmp(name, static_data().SSDTName[i]) == 0)
					{
						if (pPNum) *pPNum = SSDT_PARAMCOUNT(static_data().pSSDTTable->ServiceTableBase[i]);
						result = (PCHAR)static_data().pSSDTTable->ServiceTableBase + SSDT_OFFSET(static_data().pSSDTTable->ServiceTableBase[i]);
						break;
					}
				}
				if (!result)
				{
					for (ULONG i = 0; i < min(static_data().pSSDTShadowTable->NumberOfService, sizeof(static_data().SSDTShadowName) / sizeof(static_data().SSDTShadowName[0])); i++)
					{
						if (strcmp(name, static_data().SSDTShadowName[i]) == 0)
						{
							PEPROCESS explorerPEPROCESS = NULL;
							KAPC_STATE ks = { 0 };
							if (!MmIsAddressValid(static_data().pSSDTShadowTable->ServiceTableBase))
							{
								ULONG64 pid = GetProcessIdByProcessName(L"explorer.exe");
								if (pid != 0 && NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &explorerPEPROCESS)))
									KeStackAttachProcess(explorerPEPROCESS, &ks);
							}
							if (pPNum) *pPNum = SSDT_PARAMCOUNT(static_data().pSSDTShadowTable->ServiceTableBase[i]);
							result = (PCHAR)static_data().pSSDTShadowTable->ServiceTableBase + SSDT_OFFSET(static_data().pSSDTShadowTable->ServiceTableBase[i]);
							if (explorerPEPROCESS)
							{
								KeUnstackDetachProcess(&ks);
								ObDereferenceObject(explorerPEPROCESS);
							}
							break;
						}
					}
				}
			}
			return result;
		}
		static ULONG NameToIndex(PCSTR name) noexcept
		{
			ULONG result = 0xFFFFFFFF;
			if (Initialize())
			{
				for (ULONG i = 0; i < min(static_data().pSSDTTable->NumberOfService, sizeof(static_data().SSDTName) / sizeof(static_data().SSDTName[0])); i++)
				{
					if (strcmp(name, static_data().SSDTName[i]) == 0)
					{
						result = i;
						break;
					}
				}
				if (result == 0xFFFFFFFF)
				{
					for (ULONG i = 0; i < min(static_data().pSSDTShadowTable->NumberOfService, sizeof(static_data().SSDTShadowName) / sizeof(static_data().SSDTShadowName[0])); i++)
					{
						if (strcmp(name, static_data().SSDTShadowName[i]) == 0)
						{
							result = i | 0x1000;
							break;
						}
					}
				}
			}
			return result;
		}
	};
public:
	struct SYSCALLHOOK
	{
	private:
		struct static_data_t
		{
			PVOID Hooks[100][2] = { NULL };
			PVOID SystemCallHook = NULL;
		};
		static inline static_data_t& static_data() noexcept
		{
			static static_data_t data_{};
			return data_;
		}
		static constexpr auto MAX_THREADID = 0x10000;
		//HOOK使用
		static inline VOID MySysCall(PVOID pCpuState, void* pTarget)noexcept {
			context_x64_t* CpuState = (context_x64_t*)pCpuState;
			INLINEHOOK::DetoutFunctionBegin(static_data().SystemCallHook);
			UNREFERENCED_PARAMETER(pTarget);
			PVOID target = (PVOID)CpuState->r10;
			if (ExGetPreviousMode() == UserMode)
			{
				for (ULONG i = 0; i < sizeof(static_data().Hooks) / sizeof(static_data().Hooks[0]); i++)
				{
					if (static_data().Hooks[i][0] == target && MmIsAddressValid(static_data().Hooks[i][1]))
					{
						CpuState->r10 = (ULONG64)static_data().Hooks[i][1];
						break;
					}
				}
			}
			INLINEHOOK::DetoutFunctionEnd(static_data().SystemCallHook);
		}
		static inline PVOID GetRealSyscallEntry()noexcept {
			PVOID ntosBase = GetSystemModuleBase("ntoskrnl.exe", NULL);
			if (!MmIsAddressValid(ntosBase))
				return NULL;

			PVOID syscall_entry = (PVOID)__readmsr(0xC0000082);
			ULONG KVASCODE_size = 0;
			PVOID KVASCODE_base = IMAGE::GetSectionBase(ntosBase, "KVASCODE", &KVASCODE_size);
			if (!KVASCODE_base)
				return syscall_entry;
			//不在KVASCODE节
			if (syscall_entry < KVASCODE_base || syscall_entry >(PVOID)((DWORD64)KVASCODE_base + KVASCODE_size))
				return syscall_entry;
			PVOID result = NULL;
			INSTRUCTION::HDES hde_info = { 0 };
			for (char* ki_system_service_user = (char*)syscall_entry; ; ki_system_service_user += hde_info.len)
			{
				// 反汇编
				if (!INSTRUCTION::X64::Disasm(ki_system_service_user, &hde_info)) break;

				// 我们要查找jmp
				if (hde_info.opcode != 0xE9)
					continue;

				// 忽略在KVASCODE节区内的jmp指令
				PVOID possible_syscall_entry = (PVOID)((long long)ki_system_service_user + (int)hde_info.len + (int)hde_info.imm.imm32);
				if (possible_syscall_entry >= KVASCODE_base && possible_syscall_entry < (PVOID)((DWORD64)KVASCODE_base + KVASCODE_size))
					continue;

				// 发现KiSystemServiceUser
				result = possible_syscall_entry;
				break;
			}
			return result;
		}
	public:
		static inline bool Initialize() noexcept {
			bool result = false;
			do
			{
				if (static_data().SystemCallHook != NULL)
				{
					break;
				}
				PVOID ntosBase = GetSystemModuleBase("ntoskrnl.exe", NULL);
				if (!MmIsAddressValid(ntosBase))
				{
					break;
				}
				memset(static_data().Hooks, 0, sizeof(static_data().Hooks));
				const char* mask = "488b461048894710488b460848894708";
				PUCHAR gKiSystemServiceCopyEndAddr = (PUCHAR)IMAGE::SectionFind(ntosBase, ".text", mask);
				if (gKiSystemServiceCopyEndAddr == NULL)
				{
					break;
				}
				PVOID HookEntryPoint = gKiSystemServiceCopyEndAddr + strlen(mask) / 2;
				static_data().SystemCallHook = INLINEHOOK::Create(HookEntryPoint, MySysCall, false);
				if (static_data().SystemCallHook == NULL)
				{
					break;
				}
				result = true;
			} while (FALSE);
			return result;
		}
		static inline void Uninitialize() noexcept{
			if (static_data().SystemCallHook == NULL)
			{
				return;
			}
			INLINEHOOK::Disable(static_data().SystemCallHook);
			INLINEHOOK::Remove(static_data().SystemCallHook);
			static_data().SystemCallHook = NULL;
		}
		static inline bool SysCallHookEnable()noexcept {
			if (static_data().SystemCallHook == NULL)
			{
				return false;
			}
			return INLINEHOOK::Enable(static_data().SystemCallHook);
		}
		static inline bool SysCallHookDisable()noexcept {
			if (static_data().SystemCallHook == NULL)
			{
				return false;
			}
			return INLINEHOOK::Disable(static_data().SystemCallHook);
		}
		static inline bool SysCallHookAppend(PVOID pTarget, PVOID pDetour) noexcept {
			//已初始化
			if (static_data().SystemCallHook == NULL)
			{
				return false;
			}
			bool result = false;
			for (ULONG i = 0; i < sizeof(static_data().Hooks) / sizeof(static_data().Hooks[0]); i++)
			{
				if (static_data().Hooks[i][0] == NULL)
				{
					static_data().Hooks[i][1] = pDetour;
					static_data().Hooks[i][0] = pTarget;
					result = true;
					break;
				}
			}
			return result;
		}
		static inline bool SysCallHookRemove(PVOID pTarget) noexcept {
			//已初始化
			if (static_data().SystemCallHook == NULL)
			{
				return false;
			}
			bool result = false;
			for (ULONG i = 0; i < sizeof(static_data().Hooks) / sizeof(static_data().Hooks[0]); i++)
			{
				if (static_data().Hooks[i][0] == pTarget)
				{
					static_data().Hooks[i][0] = NULL;
					static_data().Hooks[i][1] = NULL;
					result = true;
					break;
				}
			}
			return result;
		}
	};
#endif // WINNT
#pragma endregion

public:
	struct PROCESS
	{
#pragma region MemoryOperate
	public:
		static PVOID AllocMemory(HANDLE hProcess, SIZE_T Size, ULONG Protect) noexcept
		{
			PVOID BaseAddress = NULL;
			SIZE_T RegionSize = Size;
			if (NT_SUCCESS(ZwAllocateVirtualMemory(hProcess, &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, Protect)))
			{
				return BaseAddress;
			}
			return NULL;
		}
		static VOID FreeMemory(HANDLE hProcess, PVOID Address) noexcept
		{
			PVOID BaseAddress = Address;
			SIZE_T RegionSize = 0;
			ZwFreeVirtualMemory(hProcess, &BaseAddress, &RegionSize, MEM_RELEASE);
		}
		static bool ProtectMemory(HANDLE hProcess, PVOID Address, SIZE_T Size, ULONG NewProtect, PULONG OldProtect) noexcept
		{
			PVOID BaseAddress = Address;
			SIZE_T RegionSize = Size;
			return (NT_SUCCESS(ZwProtectVirtualMemory(hProcess, &BaseAddress, &RegionSize, NewProtect, OldProtect)));
		}
		static bool QueryMemory(HANDLE hProcess, PVOID Address, PMEMORY_BASIC_INFORMATION pMemoryBasicInfo) noexcept
		{
			SIZE_T MemoryInformationLength = sizeof(MEMORY_BASIC_INFORMATION);
			SIZE_T ReturnLength = 0;
			return (NT_SUCCESS(ZwQueryVirtualMemory(hProcess, Address, MemoryBasicInformation, pMemoryBasicInfo, MemoryInformationLength, &ReturnLength))
				&& ReturnLength == MemoryInformationLength);
		}
		static bool ReadMemory(HANDLE hProcess, PVOID address, SIZE_T size, PVOID pBuf) noexcept
		{
			static NtReadVirtualMemory_TYPE funNtReadVirtualMemory = NULL;
			if (funNtReadVirtualMemory == NULL)
			{
#ifdef WINNT
				funNtReadVirtualMemory = (NtReadVirtualMemory_TYPE)SSDT::NameToAddress("NtReadVirtualMemory", NULL);
#else
				HMODULE ntdllHModule = GetModuleHandleA("ntdll.dll");
				if (ntdllHModule)
					funNtReadVirtualMemory = (NtReadVirtualMemory_TYPE)GetProcAddress(ntdllHModule, "NtReadVirtualMemory");
#endif // WINNT
			}
			if (funNtReadVirtualMemory == NULL)
			{
				return false;
			}
			if ((DWORD64)address >= 0x8000000000000000 || (DWORD64)address + size >= 0x8000000000000000)
			{
				return false;
			}
			else
			{
				SIZE_T ReadSize = 0;
#ifdef WINNT
				KPROCESSOR_MODE OldMode = ExGetPreviousMode();
				if (OldMode != KernelMode)
					ExSetPreviousMode(KernelMode);
#endif // WINNT

				NTSTATUS Status = funNtReadVirtualMemory(hProcess, address, pBuf, size, &ReadSize);

#ifdef WINNT		
				if (OldMode != KernelMode)
					ExSetPreviousMode(OldMode);
#endif // WINNT

				return (NT_SUCCESS(Status) && ReadSize == size);
			}
		}
		static bool WriteMemory(HANDLE hProcess, PVOID address, SIZE_T size, PVOID pBuf) noexcept
		{
			static NtWriteVirtualMemory_TYPE funNtWriteVirtualMemory = NULL;
			if (funNtWriteVirtualMemory == NULL)
			{
#ifdef WINNT
				funNtWriteVirtualMemory = (NtWriteVirtualMemory_TYPE)SSDT::NameToAddress("NtWriteVirtualMemory", NULL);
#else
				HMODULE ntdllHModule = GetModuleHandleA("ntdll.dll");
				if (ntdllHModule)
					funNtWriteVirtualMemory = (NtWriteVirtualMemory_TYPE)GetProcAddress(ntdllHModule, "NtWriteVirtualMemory");
#endif // WINNT
			}
			if (funNtWriteVirtualMemory == NULL)
			{
				return false;
			}
			if ((DWORD64)address >= 0x8000000000000000 || (DWORD64)address + size >= 0x8000000000000000)
			{
				return false;
			}
			else
			{
				SIZE_T ReadSize = 0;

#ifdef WINNT
				KPROCESSOR_MODE OldMode = ExGetPreviousMode();
				if (OldMode != KernelMode)
					ExSetPreviousMode(KernelMode);
#endif // WINNT

				NTSTATUS Status = funNtWriteVirtualMemory(hProcess, address, pBuf, size, &ReadSize);

#ifdef WINNT		
				if (OldMode != KernelMode)
					ExSetPreviousMode(OldMode);
#endif // WINNT

				return (NT_SUCCESS(Status) && ReadSize == size);
			}
		}
#pragma endregion

#pragma region Query
	public:
		static DWORD32 GetMainThreadId(HANDLE hProcess)
		{
			DWORD32 result = 0;
			PROCESS_BASIC_INFORMATION BasicInformation{};
			if (NT_SUCCESS(ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInformation, sizeof(BasicInformation), NULL)))
			{
				ULONG_PTR Wow64 = NULL;
				if (NT_SUCCESS(ZwQueryInformationProcess(hProcess, ProcessWow64Information, &BasicInformation, sizeof(BasicInformation), NULL)
					&& Wow64 != NULL))
				{
					if (BasicInformation.PebBaseAddress)
					{
						TEB32* pTeb = (TEB32*)((PUCHAR)BasicInformation.PebBaseAddress + 0x1000);
						CLIENT_ID32 ClientId = { NULL };
						if (ReadMemory(hProcess, &pTeb->ClientId, sizeof(ClientId), &ClientId))
						{
							result = ClientId.UniqueThread;
						}
					}
				}
				else
				{
					TEB64* pTeb = (TEB64*)((PUCHAR)BasicInformation.PebBaseAddress + 0x1000);
					CLIENT_ID64 ClientId = { NULL };
					if (ReadMemory(hProcess, &pTeb->ClientId, sizeof(ClientId), &ClientId))
					{
						result = (DWORD32)ClientId.UniqueThread;
					}
				}
			}
			return result;
		}
#ifndef WINNT
		template<typename FUNCTION>
		static bool SwitchUIThreadExecute(HWND hwnd, FUNCTION function)
		{
			const int WM_EXECUTE_PROC = WM_USER + 1213;
			bool result = false;
			DWORD ProcessId = 0;
			DWORD ThreadId = GetWindowThreadProcessId(hwnd, &ProcessId);
			HHOOK hHook = NULL;
			do
			{
				if (ProcessId != GetCurrentProcessId())break;

				hHook = SetWindowsHookExW(WH_CALLWNDPROC, [](int code, WPARAM wParam, LPARAM lParam)->LRESULT {
					LPCWPSTRUCT pCWPStruct = (LPCWPSTRUCT)lParam;
					if (WM_EXECUTE_PROC == pCWPStruct->message)
					{
						(*(FUNCTION*)pCWPStruct->wParam)();
						return 0;
					}
					else
					{
						return CallNextHookEx(NULL, code, wParam, lParam);
					}
				}, NULL, ThreadId);
				if (!hHook)break;

				SendMessageW(hwnd, WM_EXECUTE_PROC, &function, NULL);

				result = true;
			} while (false);

			if (hHook)
			{
				UnhookWindowsHookEx(hHook);
			}
			return result;
		}
#endif // !WINNT
#pragma endregion

#pragma region UserCall
	public:
		static bool X64CallUseThreadContext(HANDLE hProcess, HANDLE hThread, PVOID UserFun, ULONG64* pRetCode, PULONG64 pArgs, ULONG ArgNum) noexcept
		{
			static NtSuspendThread_TYPE funNtSuspendThread = NULL;
			static NtResumeThread_TYPE funNtResumeThread = NULL;
#ifdef WINNT
			PETHREAD targetPEThread2 = NULL;
			if (NT_SUCCESS(ObReferenceObjectByHandle(hThread, PROCESS_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&targetPEThread2, NULL)))
			{
				ObReferenceObject(targetPEThread2);
			}
			if (!targetPEThread2 || PsGetThreadId(targetPEThread2) == PsGetCurrentThreadId())
#else
			if (GetThreadId(hThread) == GetCurrentThreadId())
#endif // WINNT
			{
				return false;
			}
			if (!funNtSuspendThread || !funNtResumeThread)
			{
#ifdef WINNT
				funNtSuspendThread = (NtSuspendThread_TYPE)SSDT::NameToAddress("NtSuspendThread", NULL);
				funNtResumeThread = (NtResumeThread_TYPE)SSDT::NameToAddress("NtResumeThread", NULL);
#else
				HMODULE ntdllHModule = GetModuleHandleA("ntdll.dll");
				if (ntdllHModule)
				{
					funNtSuspendThread = (NtSuspendThread_TYPE)GetProcAddress(ntdllHModule, "NtSuspendThread");
					funNtResumeThread = (NtResumeThread_TYPE)GetProcAddress(ntdllHModule, "NtResumeThread");
				}
#endif // WINNT
			}
			if (!funNtSuspendThread || !funNtResumeThread)
			{
				return false;
			}
#pragma pack(push, 1)
			typedef struct _SHELLCODE_DATA {
				ULONG64 param[0x10];		//最大16个参数
				ULONG64 UserFun;
				ULONG64 ret;
				ULONG64 EventHandle;
				ULONG64 funNtSetEvent;
				ULONG64 oldRip;
			} SHELLCODE_DATA, * PSHELLCODE_DATA;
#pragma pack(pop, 1)
			const UCHAR ShellCode[] = {
				/*
					nop
					nop
					push rsi
					call $start;offset 0xB0
				*/
				0x90,0x90,0x56,0xE8,0xB0,0x00,0x00,0x00,
				/*
				$data:
				*/
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				/*
				$start:
					pop rsi
					push rax
					push rcx
					push rdx
					push r8
					push r9
					push r10
					push r11
					pushfq
					push rbp
					mov rbp,rsp
					lea rsp,[rsp-100h]
					and rsp,0FFFFFFFFFFFFFFF0h
					movups [rsp+000h],xmm0
					movups [rsp+010h],xmm1
					movups [rsp+020h],xmm2
					movups [rsp+030h],xmm3
					movups [rsp+040h],xmm4
					movups [rsp+050h],xmm5
					push [rsi+078h]
					push [rsi+070h]
					push [rsi+068h]
					push [rsi+060h]
					push [rsi+058h]
					push [rsi+050h]
					push [rsi+048h]
					push [rsi+040h]
					push [rsi+038h]
					push [rsi+030h]
					push [rsi+028h]
					push [rsi+020h]
					mov r9,[rsi+018h]
					mov r8,[rsi+010h]
					mov rdx,[rsi+008h]
					mov rcx,[rsi+000h]
					sub rsp,20h
					call qword ptr[rsi+080h]
					mov [rsi+088h],rax
					mov rcx,[rsi+090h]
					lea rdx,[rsp+030h]
					call qword ptr[rsi+098h]
					movups xmm0,[rsp+000h]
					movups xmm1,[rsp+010h]
					movups xmm2,[rsp+020h]
					movups xmm3,[rsp+030h]
					movups xmm4,[rsp+040h]
					movups xmm5,[rsp+050h]
					mov rsp,rbp
					pop rbp
					popfq
					pop r11
					pop r10
					pop r9
					pop r8
					pop rdx
					pop rcx
					pop rax
					mov rsi,[rsi+0A0h]
					xchg rsi,[rsp]
					ret
				*/
				0x5e,0x50,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x9c,0x55,0x48,0x89,0xe5,0x48,0x8d,0xa4,0x24,0x00,0xff,0xff,0xff,0x48,0x83,0xe4,0xf0,0x0f,0x11,0x04,0x24,0x0f,0x11,0x4c,0x24,0x10,0x0f,0x11,0x54,0x24,0x20,0x0f,0x11,0x5c,0x24,0x30,0x0f,0x11,0x64,0x24,0x40,0x0f,0x11,0x6c,0x24,0x50,0xff,0x76,0x78,0xff,0x76,0x70,0xff,0x76,0x68,0xff,0x76,0x60,0xff,0x76,0x58,0xff,0x76,0x50,0xff,0x76,0x48,0xff,0x76,0x40,0xff,0x76,0x38,0xff,0x76,0x30,0xff,0x76,0x28,0xff,0x76,0x20,0x4c,0x8b,0x4e,0x18,0x4c,0x8b,0x46,0x10,0x48,0x8b,0x56,0x08,0x48,0x8b,0x0e,0x48,0x83,0xec,0x20,0xff,0x96,0x80,0x00,0x00,0x00,0x48,0x89,0x86,0x88,0x00,0x00,0x00,0x48,0x8b,0x8e,0x90,0x00,0x00,0x00,0x48,0x8d,0x54,0x24,0x30,0xff,0x96,0x98,0x00,0x00,0x00,0x0f,0x10,0x04,0x24,0x0f,0x10,0x4c,0x24,0x10,0x0f,0x10,0x54,0x24,0x20,0x0f,0x10,0x5c,0x24,0x30,0x0f,0x10,0x64,0x24,0x40,0x0f,0x10,0x6c,0x24,0x50,0x48,0x89,0xec,0x5d,0x9d,0x41,0x5b,0x41,0x5a,0x41,0x59,0x41,0x58,0x5a,0x59,0x58,0x48,0x8b,0xb6,0xa0,0x00,0x00,0x00,0x48,0x87,0x34,0x24,0xc3
			};
			const UCHAR ShellCode_DataOffset = 8;
			PVOID ntdllBase = GetModuleHandleX64W(hProcess, L"ntdll.dll");
			if (!ntdllBase)
			{
				return false;
			}
			NtSetEvent_TYPE user_NtSetEvent = (NtSetEvent_TYPE)GetProcAddressX64(hProcess, ntdllBase, "NtSetEvent", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum)->bool
				{
					return X64CallUseThreadContext(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
				}
			);
			if (!user_NtSetEvent)
			{
				return false;
			}
			bool result = false;

			//申请内存
			PVOID pShellCode = AllocMemory(hProcess, 0x1000, PAGE_EXECUTE_READWRITE);
			if (pShellCode)
			{
				CONTEXT LocalContext = { 0 };
				//创建Event
				HANDLE eventHandle = NULL;
				if (NT_SUCCESS(ZwCreateEvent(&eventHandle, EVENT_ALL_ACCESS, NULL, EVENT_TYPE::NotificationEvent, false)) && eventHandle != NULL)
				{
					//将Event复制到目标进程
					HANDLE targetEventHandle = NULL;
					if (NT_SUCCESS(ZwDuplicateObject((HANDLE)-1, eventHandle, hProcess, &targetEventHandle, 0, 0,
						4/*DUPLICATE_SAME_ATTRIBUTES*/ | DUPLICATE_SAME_ACCESS)))
					{
						UCHAR LocalShellCode[sizeof(ShellCode)];
						memcpy(&LocalShellCode, ShellCode, sizeof(ShellCode));
						PSHELLCODE_DATA pLocalShellCodeData = (PSHELLCODE_DATA)(LocalShellCode + ShellCode_DataOffset);
						bool success;
#ifdef WINNT
						success = false;
						PETHREAD targetPEThread = NULL;
						typedef NTSTATUS(*PspxxxContextThreadInternal_TYPE)(PETHREAD, PCONTEXT, KPROCESSOR_MODE, KPROCESSOR_MODE, UCHAR);
						static PspxxxContextThreadInternal_TYPE funPspSetContextThreadInternal = NULL;
						static PspxxxContextThreadInternal_TYPE funPspGetContextThreadInternal = NULL;
						if (NT_SUCCESS(ObReferenceObjectByHandle(hThread, PROCESS_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&targetPEThread, NULL))
							&& targetPEThread != NULL)
						{
							//获取函数地址
							if (!funPspSetContextThreadInternal)
							{
								UNICODE_STRING uStr;
								RtlInitUnicodeString(&uStr, L"PsSetContextThread");
								PUCHAR funPsSetContextThread = (PUCHAR)MmGetSystemRoutineAddress(&uStr);
								if (funPsSetContextThread)
								{
									for (int i = 0; i < 10; i++)
									{
										INSTRUCTION::HDES hde = { 0 };
										int len = INSTRUCTION::X64::Disasm(funPsSetContextThread, &hde);
										if (len <= 0)
										{
											break;
										}
										else if (hde.opcode == 0xE8 && len == 5)
										{
											funPspSetContextThreadInternal = (PspxxxContextThreadInternal_TYPE)(funPsSetContextThread + len + (int)(hde.imm.imm32));
											break;
										}
										else
										{
											funPsSetContextThread += len;
										}
									}
								}
							}
							if (!funPspGetContextThreadInternal)
							{
								UNICODE_STRING uStr;
								RtlInitUnicodeString(&uStr, L"PsGetContextThread");
								PUCHAR funPsGetContextThread = (PUCHAR)MmGetSystemRoutineAddress(&uStr);
								for (int i = 0; i < 10; i++)
								{
									INSTRUCTION::HDES hde = { 0 };
									int len = INSTRUCTION::X64::Disasm(funPsGetContextThread, &hde);
									if (len <= 0)
									{
										break;
									}
									else if (hde.opcode == 0xE8 && len == 5)
									{
										funPspGetContextThreadInternal = (PspxxxContextThreadInternal_TYPE)(funPsGetContextThread + len + (int)(hde.imm.imm32));
										break;
									}
									else
									{
										funPsGetContextThread += len;
									}
								}
							}
							//检查函数地址是否获取成功
							if (funPspSetContextThreadInternal && funPspGetContextThreadInternal)
							{
								success = true;
							}
						}
#else
						success = true;
#endif
						if (success)
						{
							do
							{
								ULONG previousSuspendCount = 0;
								if (!NT_SUCCESS(funNtSuspendThread(hThread, &previousSuspendCount)))
								{
									break;
								}
								success = false;
								LocalContext.ContextFlags = CONTEXT_ALL;
#ifdef WINNT
								success = NT_SUCCESS(funPspGetContextThreadInternal(targetPEThread, &LocalContext, KernelMode, UserMode, 1));
#else
								success = NT_SUCCESS(NtGetContextThread(hThread, &LocalContext));
#endif // WINNT
								if (!success)
								{
									funNtResumeThread(hThread, &previousSuspendCount);
									break;
								}
								//填充参数
								pLocalShellCodeData->oldRip = LocalContext.Rip;
								LocalContext.Rip = (ULONG64)pShellCode;
								pLocalShellCodeData->UserFun = (ULONG64)UserFun;
								pLocalShellCodeData->EventHandle = (ULONG64)targetEventHandle;
								pLocalShellCodeData->funNtSetEvent = (ULONG64)user_NtSetEvent;

								memcpy(pLocalShellCodeData->param, pArgs, ArgNum * sizeof(pArgs[0]));
								//复制shellcode到目标进程
								if (!WriteMemory(hProcess, pShellCode, sizeof(LocalShellCode), &LocalShellCode))
								{
									funNtResumeThread(hThread, &previousSuspendCount);
									break;
								}
								success = false;
#ifdef WINNT
								success = NT_SUCCESS(funPspSetContextThreadInternal(targetPEThread, &LocalContext, KernelMode, UserMode, 1));
#else
								success = NT_SUCCESS(NtSetContextThread(hThread, &LocalContext));
#endif // WINNT
								if (!success)
								{
									funNtResumeThread(hThread, &previousSuspendCount);
									break;
								}
								//恢复目标线程
								if (!NT_SUCCESS(funNtResumeThread(hThread, &previousSuspendCount)))
								{
									break;
								}
								//两种结果，要么执行成功，要么目标线程挂掉
								HANDLE handles[2] = { eventHandle,hThread };
								if (NT_SUCCESS(ZwWaitForMultipleObjects(sizeof(handles) / sizeof(handles[0]), handles, WaitAny, false, NULL)))
								{
									LARGE_INTEGER Timeout = { 0 };
									if (ZwWaitForSingleObject(eventHandle, false, &Timeout) != STATUS_SUCCESS)
									{
										break;
									}
									if (!pRetCode)
									{
										result = true;
									}
									else if (ReadMemory(hProcess, pShellCode, sizeof(LocalShellCode), &LocalShellCode))
									{
										*pRetCode = pLocalShellCodeData->ret;
										result = true;
									}
#ifdef WINNT
									Timeout.QuadPart = -10LL * 1000 * 20;	//20ms
									KeDelayExecutionThread(KernelMode, false, &Timeout);
#else
									Sleep(20);
#endif
								}
							} while (FALSE);
#ifdef WINNT
							ObReferenceObject(targetPEThread);
#endif
						}
						//删除远程句柄
						HANDLE tmpEventHandle = NULL;
						if (NT_SUCCESS(ZwDuplicateObject(hProcess, targetEventHandle, (HANDLE)-1, &tmpEventHandle, 0, 0,
							4/*DUPLICATE_SAME_ATTRIBUTES*/ | DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)))
						{
							ZwClose(tmpEventHandle);
						}
					}
					ZwClose(eventHandle);
				}
				FreeMemory(hProcess, pShellCode);
			}
			return result;
		}
		static bool X64CallUseThreadContext(HANDLE hProcess, PVOID UserFun, ULONG64* pRetCode, PULONG64 pArgs, ULONG ArgNum) noexcept
		{
			HANDLE ProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					ProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			ProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!ProcessId)
			{
				return false;
			}
			DWORD32 MainThreadId = GetMainThreadId(hProcess);
			if (!MainThreadId)
			{
				return false;
			}
			HANDLE hThread = NULL;
			CLIENT_ID ClientId = { 0 };
			OBJECT_ATTRIBUTES oa = { 0 };
			ClientId.UniqueThread = (HANDLE)(ULONG_PTR)MainThreadId;
			if (!NT_SUCCESS(ZwOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &ClientId)) && hThread != NULL)
			{
				return false;
			}
			bool result = X64CallUseThreadContext(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
			ZwClose(hThread);
			return result;
		}
		static bool X64CallUseCreateThread(HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum) noexcept
		{
#pragma pack(push, 1)
			typedef struct _SHELLCODE_DATA {
				ULONG64 param[0x10];		//最大16个参数
				ULONG64 UserFun;
				ULONG64 ret;
				ULONG64 funNtTerminateThread;
			} SHELLCODE_DATA, * PSHELLCODE_DATA;
#pragma pack(pop, 1)
			const UCHAR ShellCode[] = {
				/*
					nop
					nop
					push rsi
					call $start;offset 0xB0
				*/
				0x90,0x90,0x56,0xE8,0xB0,0x00,0x00,0x00,
				/*
				$data:
				*/
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				/*
				$start:
					pop rsi
					push [rsi+078h]
					push [rsi+070h]
					push [rsi+068h]
					push [rsi+060h]
					push [rsi+058h]
					push [rsi+050h]
					push [rsi+048h]
					push [rsi+040h]
					push [rsi+038h]
					push [rsi+030h]
					push [rsi+028h]
					push [rsi+020h]
					mov r9,[rsi+018h]
					mov r8,[rsi+010h]
					mov rdx,[rsi+008h]
					mov rcx,[rsi+000h]
					sub rsp,20h
					call qword ptr[rsi+080h]
					mov [rsi+088h],rax
					mov rcx,-2
					mov rdx,0
					call qword ptr[rsi+090h]
					add rsp,20h
					pop rsi
					ret
				*/
				0x5e,0xff,0x76,0x78,0xff,0x76,0x70,0xff,0x76,0x68,0xff,0x76,0x60,0xff,0x76,0x58,0xff,0x76,0x50,0xff,0x76,0x48,0xff,0x76,0x40,0xff,0x76,0x38,0xff,0x76,0x30,0xff,0x76,0x28,0xff,0x76,0x20,0x4c,0x8b,0x4e,0x18,0x4c,0x8b,0x46,0x10,0x48,0x8b,0x56,0x08,0x48,0x8b,0x0e,0x48,0x83,0xec,0x20,0xff,0x96,0x80,0x00,0x00,0x00,0x48,0x89,0x86,0x88,0x00,0x00,0x00,0x48,0xc7,0xc1,0xfe,0xff,0xff,0xff,0x48,0xc7,0xc2,0x00,0x00,0x00,0x00,0xff,0x96,0x90,0x00,0x00,0x00,0x48,0x83,0xc4,0x20,0x5e,0xc3
			};
			const UCHAR ShellCode_DataOffset = 8;
			static NtCreateThreadEx_TYPE funNtCreateThreadEx = NULL;
			if (funNtCreateThreadEx == NULL)
			{
#ifdef WINNT
				funNtCreateThreadEx = (NtCreateThreadEx_TYPE)SSDT::NameToAddress("NtCreateThreadEx", NULL);
#else
				HMODULE ntdllHModule = GetModuleHandleA("ntdll.dll");
				if (ntdllHModule)
					funNtCreateThreadEx = (NtCreateThreadEx_TYPE)GetProcAddress(ntdllHModule, "NtCreateThreadEx");
#endif // WINNT
			}
			if (!funNtCreateThreadEx)
			{
				return false;
			}
			UCHAR LocalShellCode[sizeof(ShellCode)] = { 0xCC };
			memcpy(LocalShellCode, ShellCode, sizeof(LocalShellCode));
			PSHELLCODE_DATA pLocalShellCodeData = (PSHELLCODE_DATA)(LocalShellCode + ShellCode_DataOffset);
			pLocalShellCodeData->UserFun = (ULONG64)UserFun;
			memcpy(pLocalShellCodeData->param, pArgs, ArgNum * sizeof(pArgs[0]));

			PVOID ntdllBase = GetModuleHandleX64W(hProcess, L"ntdll.dll");
			if (ntdllBase == NULL)
			{
				return false;
			}
			pLocalShellCodeData->funNtTerminateThread = (ULONG64)GetProcAddressX64(hProcess, ntdllBase, "NtTerminateThread", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum)->bool
				{
					return X64CallUseCreateThread(hProcess, UserFun, pRetCode, pArgs, ArgNum);
				}
			);
			if (pLocalShellCodeData->funNtTerminateThread == 0)
			{
				return false;
			}
			PVOID pShellCode = AllocMemory(hProcess, 0x1000, PAGE_EXECUTE_READWRITE);
			if (pShellCode == NULL)
			{
				return false;
			}
			bool result = false;
			do
			{
				//写入ShellCode
				if (!WriteMemory(hProcess, pShellCode, sizeof(LocalShellCode), LocalShellCode))
				{
					break;
				}
				HANDLE hThread = NULL;
				if (!NT_SUCCESS(funNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pShellCode, NULL, false, 0, 0, 0, NULL)))
				{
					break;
				}
				if (NT_SUCCESS(ZwWaitForSingleObject(hThread, false, NULL)))
				{
					if (ReadMemory(hProcess, pShellCode, sizeof(LocalShellCode), LocalShellCode))
					{
						if (pRetCode)
						{
							*pRetCode = pLocalShellCodeData->ret;
						}
						result = true;
					}
				}
				ZwClose(hThread);
			} while (FALSE);
			FreeMemory(hProcess, pShellCode);
			return result;
		}
		static bool X64CallUseApc(HANDLE hProcess, HANDLE hThread, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum) noexcept
		{
#pragma pack(push, 1)
			typedef struct _SHELLCODE_DATA {
				ULONG64 param[0x10];		//最大16个参数
				ULONG64 UserFun;
				ULONG64 ret;
				ULONG64 EventHandle;
				ULONG64 funNtSetEvent;
			} SHELLCODE_DATA, * PSHELLCODE_DATA;
#pragma pack(pop, 1)
			const UCHAR ShellCode[] = {
				/*
					nop
					nop
					push rsi
					call $start;offset 0xB0
				*/
				0x90,0x90,0x56,0xE8,0xB0,0x00,0x00,0x00,
				/*
				$data:
				*/
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				/*
				$start:
					pop rsi
					mov rbp,rsp
					push [rsi+078h]
					push [rsi+070h]
					push [rsi+068h]
					push [rsi+060h]
					push [rsi+058h]
					push [rsi+050h]
					push [rsi+048h]
					push [rsi+040h]
					push [rsi+038h]
					push [rsi+030h]
					push [rsi+028h]
					push [rsi+020h]
					mov r9,[rsi+018h]
					mov r8,[rsi+010h]
					mov rdx,[rsi+008h]
					mov rcx,[rsi+000h]
					sub rsp,20h
					call qword ptr[rsi+080h]
					mov [rsi+0x88],rax
					mov rcx,[rsi+090h]
					lea rdx,[rsp+030h]
					call qword ptr[rsi+098h]
					mov rsp,rbp
					pop rsi
					ret
				*/
				0x5e,0x48,0x89,0xe5,0xff,0x76,0x78,0xff,0x76,0x70,0xff,0x76,0x68,0xff,0x76,0x60,0xff,0x76,0x58,0xff,0x76,0x50,0xff,0x76,0x48,0xff,0x76,0x40,0xff,0x76,0x38,0xff,0x76,0x30,0xff,0x76,0x28,0xff,0x76,0x20,0x4c,0x8b,0x4e,0x18,0x4c,0x8b,0x46,0x10,0x48,0x8b,0x56,0x08,0x48,0x8b,0x0e,0x48,0x83,0xec,0x20,0xff,0x96,0x80,0x00,0x00,0x00,0x48,0x89,0x86,0x88,0x00,0x00,0x00,0x48,0x8b,0x8e,0x90,0x00,0x00,0x00,0x48,0x8d,0x54,0x24,0x30,0xff,0x96,0x98,0x00,0x00,0x00,0x48,0x89,0xec,0x5e,0xc3
			};
			const UCHAR ShellCode_DataOffset = 8;

			static NtQueueApcThread_TYPE funNtQueueApcThread = NULL;
			if (funNtQueueApcThread == NULL)
			{
#ifdef WINNT
				funNtQueueApcThread = (NtQueueApcThread_TYPE)SSDT::NameToAddress("NtQueueApcThread", NULL);
#else
				HMODULE ntdllHModule = GetModuleHandleA("ntdll.dll");
				if (ntdllHModule)
					funNtQueueApcThread = (NtQueueApcThread_TYPE)GetProcAddress(ntdllHModule, "NtQueueApcThread");
#endif // WINNT
			}
			if (funNtQueueApcThread == NULL)
			{
				return false;
			}

			UCHAR LocalShellCode[sizeof(ShellCode)] = { 0xCC };
			memcpy(LocalShellCode, ShellCode, sizeof(LocalShellCode));
			PSHELLCODE_DATA pLocalShellCodeData = (PSHELLCODE_DATA)(LocalShellCode + ShellCode_DataOffset);
			pLocalShellCodeData->UserFun = (ULONG64)UserFun;
			memcpy(pLocalShellCodeData->param, pArgs, ArgNum * sizeof(pArgs[0]));
			PVOID ntdllBase = GetModuleHandleX64W(hProcess, L"ntdll.dll");
			if (ntdllBase == NULL)
			{
				return false;
			}
			pLocalShellCodeData->funNtSetEvent = (ULONG64)GetProcAddressX64(hProcess, ntdllBase, "NtSetEvent", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum)->bool
				{
					return X64CallUseApc(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
				}
			);
			if (pLocalShellCodeData->funNtSetEvent == 0)
			{
				return false;
			}
			HANDLE tagProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					tagProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			tagProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!tagProcessId)
			{
				return false;
			}
			bool result = false;

			HANDLE eventHandle = NULL;
			if (NT_SUCCESS(ZwCreateEvent(&eventHandle, EVENT_ALL_ACCESS, NULL, EVENT_TYPE::NotificationEvent, false)))
			{
				//将Event复制到目标进程
				HANDLE targetEventHandle = NULL;
				if (NT_SUCCESS(ZwDuplicateObject((HANDLE)-1, eventHandle, hProcess, &targetEventHandle, 0, 0,
					4/*DUPLICATE_SAME_ATTRIBUTES*/ | DUPLICATE_SAME_ACCESS)))
				{
					pLocalShellCodeData->EventHandle = (ULONG64)targetEventHandle;
					PVOID pBuffer = AllocMemory(hProcess, 0x1000, PAGE_EXECUTE_READWRITE);
					if (pBuffer != NULL)
					{
						do
						{
							if (!WriteMemory(hProcess, pBuffer, sizeof(LocalShellCode), LocalShellCode))
							{
								break;
							}
							if (!NT_SUCCESS(funNtQueueApcThread(hThread, pBuffer, NULL, NULL, (PVOID)-1)))
							{
								break;
							}
#ifdef WINNT
							PETHREAD pEThread = NULL;
							if (NT_SUCCESS(ObReferenceObjectByHandle(hThread, NULL, *PsThreadType, KernelMode, (PVOID*)&pEThread, NULL)))
							{
								//ETHREAD.ApcState.UserApcPendingAll.UserApcPending = 1
								*((PUCHAR)pEThread + 0xC2) |= 2;
								ObReferenceObject(pEThread);
							}
#endif // WINNT

							//两种结果，要么执行成功，要么目标线程挂掉
							HANDLE handles[2] = { eventHandle,hThread };
							if (NT_SUCCESS(ZwWaitForMultipleObjects(sizeof(handles) / sizeof(handles[0]), handles, WaitAny, false, NULL)))
							{
								LARGE_INTEGER Timeout = { 0 };
								if (ZwWaitForSingleObject(eventHandle, false, &Timeout) != STATUS_SUCCESS)
								{
									break;
								}
								if (!pRetCode)
								{
									result = true;
								}
								else if (ReadMemory(hProcess, pBuffer, sizeof(LocalShellCode), &LocalShellCode))
								{
									*pRetCode = pLocalShellCodeData->ret;
									result = true;
								}
#ifdef WINNT
								Timeout.QuadPart = -10LL * 1000 * 20;	//20ms
								KeDelayExecutionThread(KernelMode, false, &Timeout);
#else
								Sleep(20);
#endif
							}
						} while (FALSE);
						FreeMemory(hProcess, pBuffer);
					}
					//删除远程句柄
					HANDLE tmpEventHandle = NULL;
					if (NT_SUCCESS(ZwDuplicateObject(hProcess, targetEventHandle, (HANDLE)-1, &tmpEventHandle, 0, 0,
						4/*DUPLICATE_SAME_ATTRIBUTES*/ | DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)))
					{
						ZwClose(tmpEventHandle);
					}
				}
				ZwClose(eventHandle);
			}
			return result;
		}
		static bool X64CallUseApc(HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum) noexcept
		{
			HANDLE ProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					ProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			ProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!ProcessId)
			{
				return false;
			}

			UCHAR BufferData[4] = { 0 };
			ULONG BufferSize = 4;
			PVOID Buffer = BufferData;
			if (ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize) != STATUS_INFO_LENGTH_MISMATCH
				|| BufferSize == sizeof(SYSTEM_PROCESS_INFORMATION))
			{
				return false;
			}
			HANDLE ThreadId = NULL;
			Buffer = Malloc(BufferSize);
			if (Buffer)
			{
				if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize)))
				{
					PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;
					while (TRUE)
					{
						if (pProcessInfo->UniqueProcessId == ProcessId)
						{
							if (pProcessInfo->NumberOfThreads > 0)
							{
								for (ULONG threadIndex = 0; threadIndex < pProcessInfo->NumberOfThreads; threadIndex++) {
									//确定为用户线程
									if (pProcessInfo->Threads[threadIndex].UserTime.QuadPart > 0) {
										//定位正在等待的线程
										if (pProcessInfo->Threads[threadIndex].ThreadState == Waiting &&
											(pProcessInfo->Threads[threadIndex].WaitReason == UserRequest || pProcessInfo->Threads[threadIndex].WaitReason == WrUserRequest))
										{
											ThreadId = pProcessInfo->Threads[threadIndex].ClientId.UniqueThread;
											break;
										}
									}
								}
								if (ThreadId == NULL)
								{
									ThreadId = pProcessInfo->Threads[0].ClientId.UniqueThread;
								}
							}
							break;
						}
						else if (pProcessInfo->NextEntryOffset == 0)
							break;
						else
							pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
					}
				}
				Free(Buffer);
			}
			if (!ThreadId)
			{
				return false;
			}
			HANDLE hThread = NULL;
			CLIENT_ID ClientId = { 0 };
			OBJECT_ATTRIBUTES oa = { 0 };
			ClientId.UniqueThread = ThreadId;
			if (!NT_SUCCESS(ZwOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &ClientId)) && hThread != NULL)
			{
				return false;
			}
			bool result = X64CallUseApc(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
			ZwClose(hThread);
			return result;
		}
#ifdef WINNT
		static bool X64CallUseNtCallBackReturn(HANDLE hProcess, HANDLE hThread, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum) noexcept
		{
			struct KernelAPC_Args
			{
				ULONG ApiNumber;
				PVOID InputBuffer;
				ULONG InputLength;
				PVOID* OutputBuffer;
				PULONG OutputLength;
				NTSTATUS* ReturnCode;
				HANDLE WaitEvent;
			};
#pragma pack(push,8)
			typedef struct _SHELLCODE_PARAM {
				ULONG64 Args[0x10];		//最大16个参数
				ULONG64 EntryPoint;
				ULONG64 funNtCallbackReturn;
			} SHELLCODE_PARAM;
#pragma pack(pop)
			//不行 执行内核APC时会临时清除掉KTHREAD.TrapFrame
			const UCHAR ShellCode[] = {
				/*
				push rbp
				push rdi
				push 0
				mov rbp,rsp
				mov rdi,rcx
				push [rdi+078h]
				push [rdi+070h]
				push [rdi+068h]
				push [rdi+060h]
				push [rdi+058h]
				push [rdi+050h]
				push [rdi+048h]
				push [rdi+040h]
				push [rdi+038h]
				push [rdi+030h]
				push [rdi+028h]
				push [rdi+020h]
				mov r9,[rdi+018h]
				mov r8,[rdi+010h]
				mov rdx,[rdi+008h]
				mov rcx,[rdi]
				sub rsp,020h
				call qword ptr[rdi+080h]
				mov rcx,rbp
				mov [rcx],rax
				mov edx,8
				mov r8d,0
				call qword ptr[rdi+088h]
				mov rsp,rbp
				pop rdi
				pop rdi
				pop rbp
				ret
				*/
				0x55,0x57,0x6a,0x00,0x48,0x89,0xe5,0x48,0x89,0xcf,0xff,0x77,0x78,0xff,0x77,0x70,0xff,0x77,0x68,0xff,0x77,0x60,0xff,0x77,0x58,0xff,0x77,0x50,0xff,0x77,0x48,0xff,0x77,0x40,0xff,0x77,0x38,0xff,0x77,0x30,0xff,0x77,0x28,0xff,0x77,0x20,0x4c,0x8b,0x4f,0x18,0x4c,0x8b,0x47,0x10,0x48,0x8b,0x57,0x08,0x48,0x8b,0x0f,0x48,0x83,0xec,0x20,0xff,0x97,0x80,0x00,0x00,0x00,0x48,0x89,0xe9,0x48,0x89,0x01,0xba,0x08,0x00,0x00,0x00,0x41,0xb8,0x00,0x00,0x00,0x00,0xff,0x97,0x88,0x00,0x00,0x00,0x48,0x89,0xec,0x5f,0x5f,0x5d,0xc3
			};
			PEPROCESS pEProcess = NULL;
			if (!NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL))
				|| pEProcess == NULL)
			{
				return false;
			}
			ObReferenceObject(pEProcess);
			//获取peb64地址
			PEB64* ppeb = (PEB64*)PsGetProcessPeb(pEProcess);
			if (ppeb == NULL)
			{
				return false;
			}
			//读取PEB64内容
			PEB64 LocalPeb = { 0 };
			if (!ReadMemory(hProcess, ppeb, sizeof(LocalPeb), &LocalPeb))
			{
				return false;
			}
			//获取NtCallbackReturn并构建参数
			PVOID ntdllBase = GetModuleHandleX64W(hProcess, L"ntdll.dll");
			if (ntdllBase == NULL)
			{
				return false;
			}
			SHELLCODE_PARAM inputArg = { 0 };
			inputArg.funNtCallbackReturn = (ULONG64)GetProcAddressX64(hProcess, ntdllBase, "NtCallbackReturn", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum)->bool
				{
					return X64CallUseNtCallBackReturn(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
				}
			);
			inputArg.EntryPoint = (ULONG64)UserFun;

			memcpy(inputArg.Args, pArgs, ArgNum * sizeof(pArgs[0]));

			if (inputArg.funNtCallbackReturn == 0)
			{
				return false;
			}

			PVOID pBuffer = NULL;
			//申请内存，计算callBackIndex(如果进程本身的UserSharedInfoPtr不为空，需要在UserSharedInfoPtr往上8*4G内申请到内存,因为callBackIndex只有4位)
			if (LocalPeb.UserSharedInfoPtr)
			{
				//如果已经有UserSharedInfoPtr了只能在这附近找
				DWORD64 Address = (LocalPeb.UserSharedInfoPtr & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
				DWORD64 MaxAddress = Address + (ULONG64)MAXULONG * sizeof(ULONG64);
				//限制在用户层申请
				if (MaxAddress > 0x00007FFFFFFFF000)
					MaxAddress = 0x00007FFFFFFFF000;
				while (Address > 0 && Address < MaxAddress, Address += PAGE_SIZE)
				{
					PVOID TmpAddress = (PVOID)Address;
					SIZE_T userMemorySize = PAGE_SIZE;
					if (NT_SUCCESS(ZwAllocateVirtualMemory(hProcess, &TmpAddress, 0, &userMemorySize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
					{
						pBuffer = TmpAddress;
						break;
					}
				}
			}
			else
			{
				pBuffer = AllocMemory(hProcess, PAGE_SIZE, PAGE_EXECUTE_READWRITE);
			}
			if (pBuffer == NULL)
			{
				return false;
			}
			HANDLE eventHandle = NULL;
			if (!NT_SUCCESS(ZwCreateEvent(&eventHandle, EVENT_ALL_ACCESS, NULL, EVENT_TYPE::NotificationEvent, false)) && eventHandle != NULL)
			{
				FreeMemory(hProcess, pBuffer);
				return false;
			}
			bool result = false;
			ULONG callBackIndex;
			do
			{
				//计算index
				if (LocalPeb.UserSharedInfoPtr)
				{
					callBackIndex = (DWORD32)(((DWORD64)pBuffer - LocalPeb.UserSharedInfoPtr) / sizeof(ULONG64));
				}
				else
				{
					callBackIndex = 0;
					if (!WriteMemory(hProcess, (PUCHAR)ppeb + (ULONG64)(&(((PEB64*)0)->UserSharedInfoPtr)), sizeof(ULONG64), &pBuffer))
					{
						break;
					}
				}
				//生成本地ShellCode
				UCHAR LocalShellCode[PAGE_SIZE] = { 0xCC };
				*(ULONG64*)LocalShellCode = (ULONG64)pBuffer;
				memcpy(LocalShellCode + sizeof(ULONG64), ShellCode, sizeof(ShellCode));
				//拷贝ShellCode到远程
				if (!WriteMemory(hProcess, pBuffer, PAGE_SIZE, &LocalShellCode))
				{
					break;
				}

				//给hThread插入APC
				PETHREAD pEThread = NULL;
				KAPC SuspendApc = { 0 };
				if (!NT_SUCCESS(ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pEThread, NULL))
					|| pEThread == NULL)
				{
					return false;
				}
				ObReferenceObject(pEThread);

				NTSTATUS KeUserModeCallback_Ret = 0;
				PVOID userRetPoint = NULL;
				ULONG userRetSize = 0;
				KernelAPC_Args args = { 0 };
				args.ApiNumber = callBackIndex;
				args.InputBuffer = &inputArg;
				args.InputLength = sizeof(inputArg);
				args.OutputBuffer = &userRetPoint;
				args.OutputLength = &userRetSize;
				args.ReturnCode = &KeUserModeCallback_Ret;
				args.WaitEvent = eventHandle;
				KeInitializeApc(&SuspendApc, pEThread, OriginalApcEnvironment, [](
					_In_ struct _KAPC*,
					_Inout_ PKNORMAL_ROUTINE*,
					_Inout_ PVOID*,
					_Inout_ PVOID*,
					_Inout_ PVOID*
					)->void {

					}, (PKRUNDOWN_ROUTINE)NULL
						, [](PVOID, PVOID arg2, PVOID)->void {
						KernelAPC_Args* args = (KernelAPC_Args*)arg2;
						*args->ReturnCode = KeUserModeCallback(args->ApiNumber, args->InputBuffer, args->InputLength, args->OutputBuffer, args->OutputLength);
						ZwSetEvent(args->WaitEvent, NULL);
						}
					, KernelMode, &args);
				if (KeInsertQueueApc(&SuspendApc, &args, &args, 0))
				{
					if (NT_SUCCESS(ZwWaitForSingleObject(eventHandle, false, NULL)))
					{
						if (userRetPoint != NULL && userRetSize >= sizeof(ULONG64))
						{
							result = true;
							if (pRetCode)
							{
								*pRetCode = *(PULONG64)userRetPoint;
							}
						}
					}
				}
			} while (FALSE);
			if (callBackIndex == 0)
			{
				ULONG64 Tmp = 0;
				WriteMemory(hProcess, (PUCHAR)ppeb + (ULONG64)(&(((PEB64*)0)->UserSharedInfoPtr)), sizeof(ULONG64), &Tmp);
			}
			NtClose(eventHandle);
			FreeMemory(hProcess, pBuffer);
			return result;
		}
		static bool X64CallUseNtCallBackReturn(HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum) noexcept
		{
			HANDLE ProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					ProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			ProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!ProcessId)
			{
				return false;
			}

			UCHAR BufferData[4] = { 0 };
			ULONG BufferSize = 4;
			PVOID Buffer = BufferData;
			if (ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize) != STATUS_INFO_LENGTH_MISMATCH
				|| BufferSize == sizeof(SYSTEM_PROCESS_INFORMATION))
			{
				return false;
			}
			HANDLE ThreadId = NULL;
			Buffer = Malloc(BufferSize);
			if (Buffer)
			{
				if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize)))
				{
					PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;
					while (TRUE)
					{
						if (pProcessInfo->UniqueProcessId == ProcessId) {
							if (pProcessInfo->NumberOfThreads > 0)
							{
								LONG64 UserTimeMax = 0;
								for (int threadIndex = pProcessInfo->NumberOfThreads - 1; threadIndex >= 0; threadIndex--)
								{
									//找UserTime最大的线程
									if (pProcessInfo->Threads[threadIndex].UserTime.QuadPart > UserTimeMax)
									{
										UserTimeMax = pProcessInfo->Threads[threadIndex].UserTime.QuadPart;
										ThreadId = pProcessInfo->Threads[threadIndex].ClientId.UniqueThread;
									}
								}
								if (ThreadId == NULL)
								{
									ThreadId = pProcessInfo->Threads[0].ClientId.UniqueThread;
								}
							}
							break;
						}
						else if (pProcessInfo->NextEntryOffset == 0)
							break;
						else
							pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
					}
				}
				Free(Buffer);
			}
			if (!ThreadId)
			{
				return false;
			}
			HANDLE hThread = NULL;
			CLIENT_ID ClientId = { 0 };
			OBJECT_ATTRIBUTES oa = { 0 };
			ClientId.UniqueThread = ThreadId;
			if (!NT_SUCCESS(ZwOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &ClientId)) && hThread != NULL)
			{
				return false;
			}
			bool result = X64CallUseNtCallBackReturn(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
			ZwClose(hThread);
			return result;
		}
#endif // WINNT
		static bool X86CallUseThreadContext(HANDLE hProcess, HANDLE hThread, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum) noexcept
		{
			static NtSuspendThread_TYPE funNtSuspendThread = NULL;
			static NtResumeThread_TYPE funNtResumeThread = NULL;

			if (!funNtSuspendThread || !funNtResumeThread)
			{
#ifdef WINNT
				funNtSuspendThread = (NtSuspendThread_TYPE)SSDT::NameToAddress("NtSuspendThread", NULL);
				funNtResumeThread = (NtResumeThread_TYPE)SSDT::NameToAddress("NtResumeThread", NULL);
#else
				HMODULE ntdllHModule = GetModuleHandleA("ntdll.dll");
				if (ntdllHModule)
				{
					funNtSuspendThread = (NtSuspendThread_TYPE)GetProcAddress(ntdllHModule, "NtSuspendThread");
					funNtResumeThread = (NtResumeThread_TYPE)GetProcAddress(ntdllHModule, "NtResumeThread");
				}
#endif // WINNT
			}
			if (!funNtSuspendThread || !funNtResumeThread)
			{
				return false;
			}
#pragma pack(push, 1)
			typedef struct _SHELLCODE_DATA {
				ULONG param[0x10];		//最大16个参数
				ULONG UserFun;
				ULONG ret;
				ULONG EventHandle;
				ULONG funNtSetEvent;
				ULONG oldEip;
			} SHELLCODE_DATA, * PSHELLCODE_DATA;
#pragma pack(pop, 1)
			const UCHAR ShellCode[] = {
				/*
					nop
					nop
					push rsi
					call $start;offset 0xB0
				*/
				0x90,0x90,0x56,0xE8,0xB0,0x00,0x00,0x00,
				/*
				$data:
				*/
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				/*
				$start:
					pop esi
					pushad
					pushfd
					mov ebp,esp
					push [esi+0x3C]
					push [esi+0x38]
					push [esi+0x34]
					push [esi+0x30]
					push [esi+0x2C]
					push [esi+0x28]
					push [esi+0x24]
					push [esi+0x20]
					push [esi+0x1C]
					push [esi+0x18]
					push [esi+0x14]
					push [esi+0x10]
					push [esi+0x0C]
					push [esi+0x08]
					push [esi+0x04]
					push [esi+0x00]
					call [esi+0x40]
					mov [esi+0x44],eax
					lea eax,[esp+0x10]
					push eax
					push [esi+0x48]
					call [esi+0x4C]
					mov esp,ebp
					popfd
					popad
					mov esi,[esi+0x50]
					xchg esi,[esp]
					ret
				*/
				0x5e,0x60,0x9c,0x89,0xe5,0xff,0x76,0x3c,0xff,0x76,0x38,0xff,0x76,0x34,0xff,0x76,0x30,0xff,0x76,0x2c,0xff,0x76,0x28,0xff,0x76,0x24,0xff,0x76,0x20,0xff,0x76,0x1c,0xff,0x76,0x18,0xff,0x76,0x14,0xff,0x76,0x10,0xff,0x76,0x0c,0xff,0x76,0x08,0xff,0x76,0x04,0xff,0x36,0xff,0x56,0x40,0x89,0x46,0x44,0x8d,0x44,0x24,0x10,0x50,0xff,0x76,0x48,0xff,0x56,0x4c,0x89,0xec,0x9d,0x61,0x8b,0x76,0x50,0x87,0x34,0x24,0xc3
			};
			const UCHAR ShellCode_DataOffset = 8;

			HANDLE tagProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					tagProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			tagProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!tagProcessId)
			{
				return false;
			}
			PVOID ntdllBase = GetModuleHandleX86W(hProcess, L"ntdll.dll");
			if (!ntdllBase)
			{
				return false;
			}
			NtSetEvent_TYPE user_NtSetEvent = (NtSetEvent_TYPE)GetProcAddressX86(hProcess, ntdllBase, "NtSetEvent", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)->bool
				{
					return X86CallUseThreadContext(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
				}
			);
			if (!user_NtSetEvent)
			{
				return false;
			}
			bool result = false;

			//申请内存
			PVOID pShellCode = AllocMemory(hProcess, 0x1000, PAGE_EXECUTE_READWRITE);
			if (pShellCode)
			{
				WOW64_CONTEXT LocalContext = { 0 };
				//创建Event
				HANDLE eventHandle = NULL;
				if (NT_SUCCESS(ZwCreateEvent(&eventHandle, EVENT_ALL_ACCESS, NULL, EVENT_TYPE::NotificationEvent, false)) && eventHandle != NULL)
				{
					//将Event复制到目标进程
					HANDLE targetEventHandle = NULL;
					if (NT_SUCCESS(ZwDuplicateObject((HANDLE)-1, eventHandle, hProcess, &targetEventHandle, 0, 0,
						4/*DUPLICATE_SAME_ATTRIBUTES*/ | DUPLICATE_SAME_ACCESS)))
					{
						UCHAR LocalShellCode[sizeof(ShellCode)];
						memcpy(&LocalShellCode, ShellCode, sizeof(ShellCode));
						PSHELLCODE_DATA pLocalShellCodeData = (PSHELLCODE_DATA)(LocalShellCode + ShellCode_DataOffset);
						do
						{
							ULONG previousSuspendCount = 0;
							if (!NT_SUCCESS(funNtSuspendThread(hThread, &previousSuspendCount)))
							{
								break;
							}
							LocalContext.ContextFlags = CONTEXT_ALL;
							if (!NT_SUCCESS(ZwQueryInformationThread(hThread, 29/*ThreadWow64Context*/, &LocalContext, sizeof(LocalContext), NULL)))
							{
								funNtResumeThread(hThread, &previousSuspendCount);
								break;
							}
							//填充参数
							pLocalShellCodeData->oldEip = (ULONG)LocalContext.Eip;
							LocalContext.Eip = (ULONG)(ULONG_PTR)pShellCode;
							pLocalShellCodeData->UserFun = (ULONG)(ULONG_PTR)UserFun;
							pLocalShellCodeData->EventHandle = (ULONG)(ULONG_PTR)targetEventHandle;
							pLocalShellCodeData->funNtSetEvent = (ULONG)(ULONG_PTR)user_NtSetEvent;

							memcpy(pLocalShellCodeData->param, pArgs, ArgNum * sizeof(pArgs[0]));
							//复制shellcode到目标进程
							if (!WriteMemory(hProcess, pShellCode, sizeof(LocalShellCode), &LocalShellCode))
							{
								funNtResumeThread(hThread, &previousSuspendCount);
								break;
							}
							if (!NT_SUCCESS(ZwSetInformationThread(hThread, (THREADINFOCLASS)29/*ThreadWow64Context*/, &LocalContext, sizeof(LocalContext))))
							{
								funNtResumeThread(hThread, &previousSuspendCount);
								break;
							}
							//恢复目标线程
							if (!NT_SUCCESS(funNtResumeThread(hThread, &previousSuspendCount)))
							{
								break;
							}
							//两种结果，要么执行成功，要么目标线程挂掉
							HANDLE handles[2] = { eventHandle,hThread };
							if (NT_SUCCESS(ZwWaitForMultipleObjects(sizeof(handles) / sizeof(handles[0]), handles, WaitAny, false, NULL)))
							{
								LARGE_INTEGER Timeout = { 0 };
								if (ZwWaitForSingleObject(eventHandle, false, &Timeout) != STATUS_SUCCESS)
								{
									break;
								}
								if (!pRetCode)
								{
									result = true;
								}
								else if (ReadMemory(hProcess, pShellCode, sizeof(LocalShellCode), &LocalShellCode))
								{
									*pRetCode = pLocalShellCodeData->ret;
									result = true;
								}
#ifdef WINNT
								Timeout.QuadPart = -10LL * 1000 * 20;	//20ms
								KeDelayExecutionThread(KernelMode, false, &Timeout);
#else
								Sleep(20);
#endif
							}
						} while (FALSE);
					}
					//删除远程句柄
					HANDLE tmpEventHandle = NULL;
					if (NT_SUCCESS(ZwDuplicateObject(hProcess, targetEventHandle, (HANDLE)-1, &tmpEventHandle, 0, 0,
						4/*DUPLICATE_SAME_ATTRIBUTES*/ | DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)))
					{
						ZwClose(tmpEventHandle);
					}
					ZwClose(eventHandle);
				}
				FreeMemory(hProcess, pShellCode);
			}
			return result;
		}
		static bool X86CallUseThreadContext(HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum) noexcept
		{
			HANDLE ProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					ProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			ProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!ProcessId)
			{
				return false;
			}
			DWORD32 MainThreadId = GetMainThreadId(hProcess);
			if (!MainThreadId)
			{
				return false;
			}
			HANDLE hThread = NULL;
			CLIENT_ID ClientId = { 0 };
			OBJECT_ATTRIBUTES oa = { 0 };
			ClientId.UniqueThread = (HANDLE)(ULONG_PTR)MainThreadId;
			if (!NT_SUCCESS(ZwOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &ClientId)) && hThread != NULL)
			{
				return false;
			}
			bool result = X86CallUseThreadContext(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
			ZwClose(hThread);
			return result;
		}
		static bool X86CallUseCreateThread(HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum) noexcept
		{
#pragma pack(push, 1)
			typedef struct _SHELLCODE_DATA {
				ULONG param[0x10];		//最大16个参数
				ULONG UserFun;
				ULONG ret;
				ULONG funNtTerminateThread;
			} SHELLCODE_DATA, * PSHELLCODE_DATA;
#pragma pack(pop, 1)
			const UCHAR ShellCode[] = {
				/*
					nop
					nop
					push esi
					call $start;offset 0xB0
				*/
				0x90,0x90,0x56,0xE8,0xB0,0x00,0x00,0x00,
				/*
				$data:
				*/
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				/*
				$start:
					pop esi
					mov ebp,esp
					push [esi+0x3C]
					push [esi+0x38]
					push [esi+0x34]
					push [esi+0x30]
					push [esi+0x2C]
					push [esi+0x28]
					push [esi+0x24]
					push [esi+0x20]
					push [esi+0x1C]
					push [esi+0x18]
					push [esi+0x14]
					push [esi+0x10]
					push [esi+0x0C]
					push [esi+0x08]
					push [esi+0x04]
					push [esi+0x00]
					call [esi+0x40]
					mov esp,ebp
					mov [esi+0x44],eax
					push 0
					push -2
					call [esi+0x48]
					pop esi
					ret 0x4
				*/
				0x5e,0x89,0xe5,0xff,0x76,0x3c,0xff,0x76,0x38,0xff,0x76,0x34,0xff,0x76,0x30,0xff,0x76,0x2c,0xff,0x76,0x28,0xff,0x76,0x24,0xff,0x76,0x20,0xff,0x76,0x1c,0xff,0x76,0x18,0xff,0x76,0x14,0xff,0x76,0x10,0xff,0x76,0x0c,0xff,0x76,0x08,0xff,0x76,0x04,0xff,0x36,0xff,0x56,0x40,0x89,0xec,0x89,0x46,0x44,0x6a,0x00,0x6a,0xfe,0xff,0x56,0x48,0x5e,0xC2,0x04,0x00
			};
			const UCHAR ShellCode_DataOffset = 8;
			static NtCreateThreadEx_TYPE funNtCreateThreadEx = NULL;
			if (funNtCreateThreadEx == NULL)
			{
#ifdef WINNT
				funNtCreateThreadEx = (NtCreateThreadEx_TYPE)SSDT::NameToAddress("NtCreateThreadEx", NULL);
#else
				HMODULE ntdllHModule = GetModuleHandleA("ntdll.dll");
				if (ntdllHModule)
					funNtCreateThreadEx = (NtCreateThreadEx_TYPE)GetProcAddress(ntdllHModule, "NtCreateThreadEx");
#endif // WINNT
			}
			if (!funNtCreateThreadEx)
			{
				return false;
			}
			UCHAR LocalShellCode[sizeof(ShellCode)] = { 0xCC };
			memcpy(LocalShellCode, ShellCode, sizeof(LocalShellCode));
			PSHELLCODE_DATA pLocalShellCodeData = (PSHELLCODE_DATA)(LocalShellCode + ShellCode_DataOffset);
			pLocalShellCodeData->UserFun = (ULONG)(ULONG_PTR)UserFun;

			memcpy(pLocalShellCodeData->param, pArgs, ArgNum * sizeof(pArgs[0]));

			PVOID ntdllBase = GetModuleHandleX86W(hProcess, L"ntdll.dll");
			if (ntdllBase == NULL)
			{
				return false;
			}
			pLocalShellCodeData->funNtTerminateThread = (ULONG)(ULONG_PTR)GetProcAddressX86(hProcess, ntdllBase, "NtTerminateThread", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)->bool
				{
					return X86CallUseCreateThread(hProcess, UserFun, pRetCode, pArgs, ArgNum);
				}
			);
			if (pLocalShellCodeData->funNtTerminateThread == 0)
			{
				return false;
			}
			PVOID pShellCode = AllocMemory(hProcess, 0x1000, PAGE_EXECUTE_READWRITE);
			if (pShellCode == NULL)
			{
				return false;
			}
			bool result = false;
			do
			{
				//写入ShellCode
				if (!WriteMemory(hProcess, pShellCode, sizeof(LocalShellCode), LocalShellCode))
				{
					break;
				}
				HANDLE hThread = NULL;
				if (!NT_SUCCESS(funNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pShellCode, NULL, 0, 0, 0, 0, NULL)))
				{
					break;
				}
				if (NT_SUCCESS(ZwWaitForSingleObject(hThread, false, NULL)))
				{
					if (ReadMemory(hProcess, pShellCode, sizeof(LocalShellCode), LocalShellCode))
					{
						if (pRetCode)
						{
							*pRetCode = pLocalShellCodeData->ret;
						}
						result = true;
					}
				}
				ZwClose(hThread);
			} while (FALSE);
			FreeMemory(hProcess, pShellCode);
			return result;
		}
		static bool X86CallUseApc(HANDLE hProcess, HANDLE hThread, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum) noexcept
		{
#pragma pack(push, 1)
			typedef struct _SHELLCODE_DATA {
				ULONG param[0x10];		//最大16个参数
				ULONG UserFun;
				ULONG ret;
				ULONG EventHandle;
				ULONG funNtSetEvent;
			} SHELLCODE_DATA, * PSHELLCODE_DATA;
#pragma pack(pop, 1)
			const UCHAR ShellCode[] = {
				/*
					nop
					nop
					push esi
					call $start;offset 0xB0
				*/
				0x90,0x90,0x56,0xE8,0xB0,0x00,0x00,0x00,
				/*
				$data:
				*/
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				/*
				$start:
					pop esi
					mov ebp,esp
					push [esi+0x3C]
					push [esi+0x38]
					push [esi+0x34]
					push [esi+0x30]
					push [esi+0x2C]
					push [esi+0x28]
					push [esi+0x24]
					push [esi+0x20]
					push [esi+0x1C]
					push [esi+0x18]
					push [esi+0x14]
					push [esi+0x10]
					push [esi+0x0C]
					push [esi+0x08]
					push [esi+0x04]
					push [esi+0x00]
					call [esi+0x40]
					mov [esi+0x44],eax
					lea eax,[esp+0x10]
					push eax
					push [esi+0x48]
					call [esi+0x4C]
					mov esp,ebp
					pop esi
					ret 0xC
				*/
				0x5e,0x89,0xe5,0xff,0x76,0x3c,0xff,0x76,0x38,0xff,0x76,0x34,0xff,0x76,0x30,0xff,0x76,0x2c,0xff,0x76,0x28,0xff,0x76,0x24,0xff,0x76,0x20,0xff,0x76,0x1c,0xff,0x76,0x18,0xff,0x76,0x14,0xff,0x76,0x10,0xff,0x76,0x0c,0xff,0x76,0x08,0xff,0x76,0x04,0xff,0x36,0xff,0x56,0x40,0x89,0x46,0x44,0x8d,0x44,0x24,0x10,0x50,0xff,0x76,0x48,0xff,0x56,0x4c,0x89,0xec,0x5e,0xc2,0x0c,0x00
			};
			const UCHAR ShellCode_DataOffset = 8;

			static NtQueueApcThread_TYPE funNtQueueApcThread = NULL;
			if (funNtQueueApcThread == NULL)
			{
#ifdef WINNT
				funNtQueueApcThread = (NtQueueApcThread_TYPE)SSDT::NameToAddress("NtQueueApcThread", NULL);
#else
				HMODULE ntdllHModule = GetModuleHandleA("ntdll.dll");
				if (ntdllHModule)
					funNtQueueApcThread = (NtQueueApcThread_TYPE)GetProcAddress(ntdllHModule, "NtQueueApcThread");
#endif // WINNT
			}
			if (funNtQueueApcThread == NULL)
			{
				return false;
			}

			UCHAR LocalShellCode[sizeof(ShellCode)] = { 0xCC };
			memcpy(LocalShellCode, ShellCode, sizeof(LocalShellCode));
			PSHELLCODE_DATA pLocalShellCodeData = (PSHELLCODE_DATA)(LocalShellCode + ShellCode_DataOffset);
			pLocalShellCodeData->UserFun = (ULONG)(ULONG_PTR)UserFun;

			memcpy(pLocalShellCodeData->param, pArgs, ArgNum * sizeof(pArgs[0]));

			PVOID ntdllBase = GetModuleHandleX86W(hProcess, L"ntdll.dll");
			if (ntdllBase == NULL)
			{
				return false;
			}
			pLocalShellCodeData->funNtSetEvent = (ULONG)(ULONG_PTR)GetProcAddressX86(hProcess, ntdllBase, "NtSetEvent", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)->bool
				{
					return X86CallUseApc(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
				}
			);
			if (pLocalShellCodeData->funNtSetEvent == 0)
			{
				return false;
			}
			HANDLE tagProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					tagProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			tagProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!tagProcessId)
			{
				return false;
			}

			bool result = false;

			//打开目标线程
			HANDLE eventHandle = NULL;
			if (NT_SUCCESS(ZwCreateEvent(&eventHandle, EVENT_ALL_ACCESS, NULL, EVENT_TYPE::NotificationEvent, false)))
			{
				//将Event复制到目标进程
				HANDLE targetEventHandle = NULL;
				if (NT_SUCCESS(ZwDuplicateObject((HANDLE)-1, eventHandle, hProcess, &targetEventHandle, 0, 0,
					4/*DUPLICATE_SAME_ATTRIBUTES*/ | DUPLICATE_SAME_ACCESS)))
				{
					pLocalShellCodeData->EventHandle = (ULONG)(ULONG_PTR)targetEventHandle;
					PVOID pBuffer = AllocMemory(hProcess, 0x1000, PAGE_EXECUTE_READWRITE);
					if (pBuffer != NULL)
					{
						do
						{
							if (!WriteMemory(hProcess, pBuffer, sizeof(LocalShellCode), LocalShellCode))
							{
								break;
							}
							LONG64 ApcProc = (LONG64)pBuffer * -4;
							if (!NT_SUCCESS(funNtQueueApcThread(hThread, (PVOID)ApcProc, NULL, NULL, (PVOID)-1)))
							{
								break;
							}
							//两种结果，要么执行成功，要么目标线程挂掉
							HANDLE handles[2] = { eventHandle,hThread };
							if (NT_SUCCESS(ZwWaitForMultipleObjects(sizeof(handles) / sizeof(handles[0]), handles, WaitAny, false, NULL)))
							{
								LARGE_INTEGER Timeout = { 0 };
								if (ZwWaitForSingleObject(eventHandle, false, &Timeout) != STATUS_SUCCESS)
								{
									break;
								}
								if (!pRetCode)
								{
									result = true;
								}
								else if (ReadMemory(hProcess, pBuffer, sizeof(LocalShellCode), &LocalShellCode))
								{
									*pRetCode = pLocalShellCodeData->ret;
									result = true;
								}
#ifdef WINNT
								Timeout.QuadPart = -10LL * 1000 * 20;	//20ms
								KeDelayExecutionThread(KernelMode, false, &Timeout);
#else
								Sleep(20);
#endif
							}
						} while (FALSE);
						FreeMemory(hProcess, pBuffer);
					}
					//删除远程句柄
					HANDLE tmpEventHandle = NULL;
					if (NT_SUCCESS(ZwDuplicateObject(hProcess, targetEventHandle, (HANDLE)-1, &tmpEventHandle, 0, 0,
						4/*DUPLICATE_SAME_ATTRIBUTES*/ | DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)))
					{
						ZwClose(tmpEventHandle);
					}
				}
				ZwClose(eventHandle);
			}
			return result;
		}
		static bool X86CallUseApc(HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum) noexcept
		{
			HANDLE ProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					ProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			ProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!ProcessId)
			{
				return false;
			}

			UCHAR BufferData[4] = { 0 };
			ULONG BufferSize = 4;
			PVOID Buffer = BufferData;
			if (ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize) != STATUS_INFO_LENGTH_MISMATCH
				|| BufferSize == sizeof(SYSTEM_PROCESS_INFORMATION))
			{
				return false;
			}
			HANDLE ThreadId = NULL;
			Buffer = Malloc(BufferSize);
			if (Buffer)
			{
				if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize)))
				{
					PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;
					while (TRUE)
					{
						if (pProcessInfo->UniqueProcessId == ProcessId)
						{
							if (pProcessInfo->NumberOfThreads > 0)
							{
								for (ULONG threadIndex = 0; threadIndex < pProcessInfo->NumberOfThreads; threadIndex++) {
									//确定为用户线程
									if (pProcessInfo->Threads[threadIndex].UserTime.QuadPart > 0) {
										//定位正在等待的线程
										if (pProcessInfo->Threads[threadIndex].ThreadState == Waiting &&
											(pProcessInfo->Threads[threadIndex].WaitReason == UserRequest
												|| pProcessInfo->Threads[threadIndex].WaitReason == WrUserRequest))
										{
											ThreadId = pProcessInfo->Threads[threadIndex].ClientId.UniqueThread;
											break;
										}
									}
								}
								if (ThreadId == NULL)
								{
									ThreadId = pProcessInfo->Threads[0].ClientId.UniqueThread;
								}
							}
							break;
						}
						else if (pProcessInfo->NextEntryOffset == 0)
							break;
						else
							pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
					}
				}
				Free(Buffer);
			}
			if (!ThreadId)
			{
				return false;
			}
			HANDLE hThread = NULL;
			CLIENT_ID ClientId = { 0 };
			OBJECT_ATTRIBUTES oa = { 0 };
			ClientId.UniqueThread = ThreadId;
			if (!NT_SUCCESS(ZwOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &ClientId)) && hThread != NULL)
			{
				return false;
			}
			bool result = X86CallUseApc(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
			ZwClose(hThread);
			return result;
		}
#ifdef WINNT
		static bool X86CallUseNtCallBackReturn(HANDLE hProcess, HANDLE hThread, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum) noexcept
		{
#pragma pack(push,4)
			typedef struct _SHELL_CODE_PARAM {
				ULONG Args[0x10];		//最大16个参数
				ULONG EntryPoint;
				ULONG funNtCallbackReturn;
			} SHELL_CODE_PARAM;
#pragma pack(pop)
			const UCHAR ShellCode[] = {
				/*
				push ebp
				push edi
				mov ebp,esp
				mov edi,dword ptr ss:[ebp+C]
				push dword ptr ds:[edi+3C]
				push dword ptr ds:[edi+38]
				push dword ptr ds:[edi+34]
				push dword ptr ds:[edi+30]
				push dword ptr ds:[edi+2C]
				push dword ptr ds:[edi+28]
				push dword ptr ds:[edi+24]
				push dword ptr ds:[edi+20]
				push dword ptr ds:[edi+1C]
				push dword ptr ds:[edi+18]
				push dword ptr ds:[edi+14]
				push dword ptr ds:[edi+10]
				push dword ptr ds:[edi+C]
				push dword ptr ds:[edi+8]
				push dword ptr ds:[edi+4]
				push dword ptr ds:[edi]
				call dword ptr ds:[edi+40]
				push eax
				mov eax,esp
				push 0
				push 4
				push eax
				call dword ptr ds:[edi+44]
				mov esp,ebp
				pop edi
				pop ebp
				ret 4
				*/
				0x55,0x57,0x8B,0xEC,0x8B,0x7D,0x0C,0xFF,0x77,0x3C,0xFF,0x77,0x38,0xFF,0x77,0x34,0xFF,0x77,0x30,0xFF,0x77,0x2C,0xFF,0x77,0x28,0xFF,0x77,0x24,0xFF,0x77,0x20,0xFF,0x77,0x1C,0xFF,0x77,0x18,0xFF,0x77,0x14,0xFF,0x77,0x10,0xFF,0x77,0x0C,0xFF,0x77,0x08,0xFF,0x77,0x04,0xFF,0x37,0xFF,0x57,0x40,0x50,0x8B,0xC4,0x6A,0x00,0x6A,0x04,0x50,0xFF,0x57,0x44,0x8B,0xE5,0x5F,0x5D,0xC2,0x04,0x00
			};
			//获取线程PEB32地址
			PEPROCESS pEProcess = NULL;
			if (!NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL))
				|| pEProcess == NULL)
			{
				return false;
			}
			//只有当前进程才能使用
			if (PsGetCurrentProcess() != pEProcess || PsGetThreadProcess(PsGetCurrentThread()) != pEProcess)
			{
				ObDereferenceObject(pEProcess);
				return false;
			}
			PEB32* ppeb = (PEB32*)PsGetProcessWow64Process(pEProcess);
			ObDereferenceObject(pEProcess);
			pEProcess = NULL;
			//读取线程PEB32
			PEB32 LocalPeb = { 0 };
			if (!ReadMemory(hProcess, ppeb, sizeof(LocalPeb), &LocalPeb))
			{
				return false;
			}
			//获取NtCallbackReturn地址
			PVOID ntdllBase = GetModuleHandleX86W(hProcess, L"ntdll.dll");
			if (ntdllBase == NULL)
			{
				return false;
			}
			//构建参数
			SHELL_CODE_PARAM inputArg = { 0 };
			inputArg.funNtCallbackReturn = (ULONG)(ULONG_PTR)GetProcAddressX86(hProcess, ntdllBase, "NtCallbackReturn", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)->bool
				{
					X86CallUseNtCallBackReturn(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
				}
			);
			if (inputArg.funNtCallbackReturn == 0)
			{
				return false;
			}
			inputArg.EntryPoint = (ULONG)(ULONG_PTR)UserFun;

			memcpy(inputArg.Args, pArgs, ArgNum * sizeof(pArgs[0]));

			bool result = false;
			//shellCode地址
			PVOID pBuffer = AllocMemory(hProcess, PAGE_SIZE, PAGE_EXECUTE_READWRITE);
			if (pBuffer)
			{
				UCHAR LocalBuffer[PAGE_SIZE] = { 0 };
				//复制参数到Buffer
				memcpy(&LocalBuffer, &inputArg, sizeof(inputArg));
				//填入函数指针
				*(DWORD32*)LocalBuffer = (DWORD32)(DWORD64)pBuffer + 4;
				//填入函数体
				memcpy(LocalBuffer + sizeof(DWORD32), ShellCode, sizeof(ShellCode));
				//跳转到X86时的临时Context与X86参数
				PVOID pContext = (PUCHAR)pBuffer + (PAGE_SIZE - sizeof(CONTEXT));
				PVOID pWow64Argument = (PUCHAR)pContext - sizeof(inputArg);

				//计算Index
				ULONG callBackIndex;
				if (LocalPeb.UserSharedInfoPtr == 0)
				{
					callBackIndex = 0;
					ULONG new_UserSharedInfoPtr = (ULONG)(ULONG_PTR)pBuffer;
					WriteMemory(hProcess, (PUCHAR)ppeb + (ULONG64)(&(((PEB32*)0)->UserSharedInfoPtr)), sizeof(DWORD32), &new_UserSharedInfoPtr);
				}
				else
				{
					callBackIndex = (DWORD32)(((DWORD64)pBuffer - (DWORD64)LocalPeb.UserSharedInfoPtr) / 4);
				}
				//开始UserModeCall
				do {
					PVOID wow64Base = GetModuleHandleX64W(hProcess, L"wow64.dll");
					if (wow64Base == NULL)
					{
						break;
					}
					PVOID funWow64KiUserCallbackDispatcher = GetProcAddressX64(hProcess, wow64Base, "Wow64KiUserCallbackDispatcher", 0, [&](HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum)->bool
						{
							return X64CallUseNtCallBackReturn(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
						}
					);
					if (funWow64KiUserCallbackDispatcher == NULL)
					{
						break;
					}
					ULONG64 x64CallArg[] = {
						(ULONG)(ULONG_PTR)pContext,
						callBackIndex,
						(ULONG)(ULONG_PTR)pWow64Argument,
						sizeof(SHELL_CODE_PARAM)
					};
					ULONG64 CallRetCode = 0;
					result = X64CallUseNtCallBackReturn(hProcess, hThread, funWow64KiUserCallbackDispatcher, &CallRetCode, x64CallArg, sizeof(x64CallArg) / sizeof(*x64CallArg));
					if (result && pRetCode)
					{
						*pRetCode = (ULONG)CallRetCode;
					}
					//如果线程本身没有UserSharedInfoPtr,还原
					if (callBackIndex == 0)
					{
						ULONG new_UserSharedInfoPtr = 0;
						WriteMemory(hProcess, (PUCHAR)ppeb + (ULONG)(ULONG_PTR)(&(((PEB32*)0)->UserSharedInfoPtr)), sizeof(DWORD32), &new_UserSharedInfoPtr);
					}
				} while (FALSE);
				FreeMemory(hProcess, pBuffer);
			}
			return result;
			return false;
		}
		static bool X86CallUseNtCallBackReturn(HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum) noexcept
		{

			HANDLE ProcessId = NULL;
#ifdef WINNT
			{
				PEPROCESS pEProcess = NULL;
				if (NT_SUCCESS(ObReferenceObjectByHandle(hProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&pEProcess, NULL)))
				{
					ProcessId = PsGetProcessId(pEProcess);
					ObReferenceObject(pEProcess);
				}
			}
#else
			ProcessId = (HANDLE)(DWORD64)GetProcessId(hProcess);
#endif //WINNT
			if (!ProcessId)
			{
				return false;
			}

			UCHAR BufferData[4] = { 0 };
			ULONG BufferSize = 4;
			PVOID Buffer = BufferData;
			if (ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize) != STATUS_INFO_LENGTH_MISMATCH
				|| BufferSize == sizeof(SYSTEM_PROCESS_INFORMATION))
			{
				return false;
			}
			HANDLE ThreadId = NULL;
			Buffer = Malloc(BufferSize);
			if (Buffer)
			{
				if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize)))
				{
					PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;
					while (TRUE)
					{
						if (pProcessInfo->UniqueProcessId == ProcessId) {
							if (pProcessInfo->NumberOfThreads > 0)
							{
								LONG64 UserTimeMax = 0;
								for (int threadIndex = pProcessInfo->NumberOfThreads - 1; threadIndex >= 0; threadIndex--)
								{
									//找UserTime最大的线程
									if (pProcessInfo->Threads[threadIndex].UserTime.QuadPart > UserTimeMax)
									{
										UserTimeMax = pProcessInfo->Threads[threadIndex].UserTime.QuadPart;
										ThreadId = pProcessInfo->Threads[threadIndex].ClientId.UniqueThread;
									}
								}
								if (ThreadId == NULL)
								{
									ThreadId = pProcessInfo->Threads[0].ClientId.UniqueThread;
								}
							}
							break;
						}
						else if (pProcessInfo->NextEntryOffset == 0)
							break;
						else
							pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
					}
				}
				Free(Buffer);
			}
			if (!ThreadId)
			{
				return false;
			}
			HANDLE hThread = NULL;
			CLIENT_ID ClientId = { 0 };
			OBJECT_ATTRIBUTES oa = { 0 };
			ClientId.UniqueThread = ThreadId;
			if (!NT_SUCCESS(ZwOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &ClientId)) && hThread != NULL)
			{
				return false;
			}
			bool result = X86CallUseNtCallBackReturn(hProcess, hThread, UserFun, pRetCode, pArgs, ArgNum);
			ZwClose(hThread);
			return result;
		}
#endif // WINNT
#pragma endregion

#pragma region ModuleOperate
	public:

		static PVOID GetModuleHandleX64W(HANDLE hProcess, PCWSTR ModuleName) noexcept
		{
			PROCESS_BASIC_INFORMATION BaseInfo = { 0 };
			ULONG RetSize = 0;
			if (!NT_SUCCESS(ZwQueryInformationProcess(hProcess, 0/*ProcessBasicInformation*/, &BaseInfo, sizeof(BaseInfo), &RetSize))
				|| RetSize != sizeof(BaseInfo))
			{
				return NULL;
			}
			PEB64 Peb = { 0 };
			PVOID result = NULL;
			if (ReadMemory(hProcess, BaseInfo.PebBaseAddress, sizeof(Peb), &Peb))
			{
				PEB_LDR_DATA64 LdrData = { 0 };
				if (ReadMemory(hProcess, (PVOID)Peb.Ldr, sizeof(LdrData), &LdrData))
				{
					UNICODE_STRING ModuleNameUStr;
					RtlInitUnicodeString(&ModuleNameUStr, ModuleName);

					PLIST_ENTRY64 pListEntry = (PLIST_ENTRY64)LdrData.InLoadOrderModuleList.Flink;
					while ((ULONG64)pListEntry != Peb.Ldr + (ULONG64)(&((PEB_LDR_DATA64*)(nullptr))->InLoadOrderModuleList))
					{
						LDR_DATA_TABLE_ENTRY64* pLdrDataTail = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
						LDR_DATA_TABLE_ENTRY64 LdrDataTable = { 0 };
						if (!ReadMemory(hProcess, pLdrDataTail, sizeof(LdrDataTable), &LdrDataTable))
						{
							break;
						}
						if (LdrDataTable.BaseDllName.Buffer && LdrDataTable.BaseDllName.Length > 0)
						{
							wchar_t NameBuffer[0x100] = { 0 };
							ULONG NameLength = LdrDataTable.BaseDllName.Length < sizeof(NameBuffer) - 2 ? LdrDataTable.BaseDllName.Length : sizeof(NameBuffer) - 2;
							if (!ReadMemory(hProcess, (PVOID)LdrDataTable.BaseDllName.Buffer, NameLength, &NameBuffer))
							{
								continue;
							}
							UNICODE_STRING BaseDllNameStr;
							RtlInitUnicodeString(&BaseDllNameStr, NameBuffer);
							if (RtlCompareUnicodeString(&BaseDllNameStr, &ModuleNameUStr, true) == 0)
							{
								result = (PVOID)LdrDataTable.DllBase;
								break;
							}
						}
						pListEntry = (PLIST_ENTRY64)LdrDataTable.InLoadOrderLinks.Flink;
					}
				}
			}
			return result;
		}
		static PVOID GetModuleHandleX64A(HANDLE hProcess, PCSTR ModuleName) noexcept
		{
			wchar_t uModuleName[0x100] = { 0 };
			LONG BufferLen = sizeof(uModuleName);
			PCWSTR wModuleName = AscllStrToUnicodeStr(ModuleName, uModuleName, &BufferLen);
			if (wModuleName == NULL)
			{
				return NULL;
			}
			else
			{
				return GetModuleHandleX64W(hProcess, wModuleName);
			}
		}
		static PVOID GetModuleHandleX86W(HANDLE hProcess, PCWSTR ModuleName) noexcept
		{
			ULONG RetSize = 0;
			ULONG64 pPeb32 = 0;
			if (!NT_SUCCESS(ZwQueryInformationProcess(hProcess, 26/*ProcessWow64Information*/, &pPeb32, sizeof(pPeb32), &RetSize))
				|| RetSize != sizeof(pPeb32))
			{
				return NULL;
			}
			PEB32 Peb = { 0 };
			PVOID result = NULL;
			if (ReadMemory(hProcess, (PVOID)pPeb32, sizeof(Peb), &Peb))
			{
				PEB_LDR_DATA32 LdrData = { 0 };
				if (ReadMemory(hProcess, (PVOID)(ULONG_PTR)Peb.Ldr, sizeof(LdrData), &LdrData))
				{
					UNICODE_STRING ModuleNameUStr;
					RtlInitUnicodeString(&ModuleNameUStr, ModuleName);

					PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)(ULONG64)LdrData.InLoadOrderModuleList.Flink;
					while ((ULONG64)pListEntry != Peb.Ldr + (ULONG64) & ((PEB_LDR_DATA32*)(nullptr))->InLoadOrderModuleList)
					{
						LDR_DATA_TABLE_ENTRY32* pLdrDataTail = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
						LDR_DATA_TABLE_ENTRY32 LdrDataTable = { 0 };
						if (!ReadMemory(hProcess, pLdrDataTail, sizeof(LdrDataTable), &LdrDataTable))
						{
							break;
						}
						if (LdrDataTable.BaseDllName.Buffer && LdrDataTable.BaseDllName.Length > 0)
						{
							wchar_t NameBuffer[0x100] = { 0 };
							ULONG NameLength = LdrDataTable.BaseDllName.Length < sizeof(NameBuffer) - 2 ? LdrDataTable.BaseDllName.Length : sizeof(NameBuffer) - 2;
							if (!ReadMemory(hProcess, (PVOID)(ULONG64)LdrDataTable.BaseDllName.Buffer, NameLength, &NameBuffer))
							{
								continue;
							}
							UNICODE_STRING BaseDllNameStr;
							RtlInitUnicodeString(&BaseDllNameStr, NameBuffer);
							if (RtlCompareUnicodeString(&BaseDllNameStr, &ModuleNameUStr, true) == 0)
							{
								result = (PVOID)(ULONG64)LdrDataTable.DllBase;
								break;
							}
						}
						pListEntry = (PLIST_ENTRY32)(ULONG_PTR)LdrDataTable.InLoadOrderLinks.Flink;
					}
				}
			}
			return result;
		}
		static PVOID GetModuleHandleX86A(HANDLE hProcess, PCSTR ModuleName) noexcept
		{
			wchar_t uModuleName[0x100] = { 0 };
			LONG BufferLen = sizeof(uModuleName);
			PCWSTR wModuleName = AscllStrToUnicodeStr(ModuleName, uModuleName, &BufferLen);
			if (wModuleName == NULL)
			{
				return NULL;
			}
			else
			{
				return GetModuleHandleX86W(hProcess, wModuleName);
			}
		}
		template<typename FX64CALL>	//[&](HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum)->bool
		static PVOID GetProcAddressX64(HANDLE hProcess, PVOID ModuleBase, PCSTR ProcName, ULONG serialNo, FX64CALL X64Call) noexcept
		{
			//读取DOS头
			IMAGE_DOS_HEADER Img_DOS_Header = { 0 };
			if (!ReadMemory(hProcess, ModuleBase, sizeof(Img_DOS_Header), &Img_DOS_Header) || Img_DOS_Header.e_magic != IMAGE_DOS_SIGNATURE)
			{
				return NULL;
			}
			ULONG64 pImg_NT_Header = (ULONG64)IMAGE::RVA_TO_VA(ModuleBase, Img_DOS_Header.e_lfanew);
			IMAGE_NT_HEADERS64 Img_NT_Header = { 0 };
			//读取NT头
			if (!ReadMemory(hProcess, (PVOID)pImg_NT_Header, sizeof(Img_NT_Header), &Img_NT_Header) || Img_NT_Header.Signature != IMAGE_NT_SIGNATURE)
			{
				return NULL;
			}
			ULONG64 pImg_Export_Dir = (ULONG64)IMAGE::RVA_TO_VA(ModuleBase, Img_NT_Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			ULONG Img_Export_Size = Img_NT_Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			if (Img_Export_Size < sizeof(IMAGE_EXPORT_DIRECTORY))
			{
				return NULL;
			}
			IMAGE_EXPORT_DIRECTORY Img_Export_Dir = { 0 };
			//读取导出表
			if (!ReadMemory(hProcess, (PVOID)pImg_Export_Dir, sizeof(Img_Export_Dir), &Img_Export_Dir))
			{
				return NULL;
			}
			PVOID result = NULL;

			DWORD32* nameRVAs = (DWORD32*)IMAGE::RVA_TO_VA(ModuleBase, Img_Export_Dir.AddressOfNames);
			DWORD32* funRVAs = (DWORD32*)IMAGE::RVA_TO_VA(ModuleBase, Img_Export_Dir.AddressOfFunctions);
			USHORT* OrdinalsRVAs = (USHORT*)IMAGE::RVA_TO_VA(ModuleBase, Img_Export_Dir.AddressOfNameOrdinals);
			//循环遍历所有导出表
			for (ULONG ExportIndex = 0; ExportIndex < Img_Export_Dir.NumberOfNames; ExportIndex++)
			{
				char name[0x100] = { 0 };
				DWORD32 nameOffset = 0;
				DWORD32 funOffset = 0;
				USHORT funOrdinal = 0;
				//读取序号
				if (!ReadMemory(hProcess, OrdinalsRVAs + ExportIndex, sizeof(funOrdinal), &funOrdinal))
				{
					continue;
				}
				bool IsThis = false;
				//名字为空且序号相等 序号=(Img_Export_Dir.Base + funOrdinal)
				if (ProcName == NULL && serialNo == Img_Export_Dir.Base + funOrdinal)
				{
					IsThis = true;
				}
				//名字相等
				else if (ProcName != NULL
					&& ReadMemory(hProcess, nameRVAs + ExportIndex, sizeof(nameOffset), &nameOffset)
					&& ReadMemory(hProcess, (PUCHAR)ModuleBase + nameOffset, sizeof(name) - 1, name)
					&& strcmp(ProcName, name) == 0)
				{
					IsThis = true;
				}
				//已经找到函数
				if (IsThis)
				{
					//读取函数RVA偏移
					if (ReadMemory(hProcess, funRVAs + funOrdinal, sizeof(funOffset), &funOffset))
					{
						result = (PVOID)IMAGE::RVA_TO_VA(ModuleBase, funOffset);
					}
					break;
				}
			}
			//处理函数转发
			if ((ULONG64)result >= pImg_Export_Dir && (ULONG64)result < pImg_Export_Dir + Img_Export_Size)
			{
				PVOID forward_info = result;
				result = NULL;
				char forward_dll[0x100] = { 0 };
				char forward_func[0x100] = { 0 };
				if (ReadMemory(hProcess, forward_info, sizeof(forward_dll) - 1, forward_dll))
				{
					char* pos = strchr(forward_dll, '.');
					if (pos != NULL)
					{
						strncpy(forward_func, pos + 1, sizeof(forward_func));
						strncpy(pos, ".dll", sizeof(forward_dll) - (pos - forward_dll));
						if (strlen(forward_dll) > 0 && strlen(forward_func) > 0)
						{
							PVOID forwardDllBase = GetModuleHandleX64A(hProcess, forward_dll);
							if (forwardDllBase == NULL)
							{
								//如果转发目标DLL未加载，先加载目标DLL
								forwardDllBase = LoadLibraryX64A(hProcess, forward_dll, X64Call);
							}
							if (forwardDllBase != NULL)
							{
								if (forward_func[0] == '@')
								{
									//转发时使用的序号导入
									DWORD32 serialNo1 = 0;
									for (int j = 1; forward_func[j] != 0; j++)
									{
										serialNo1 = serialNo1 * 10 + (forward_func[j] - '0');
									}
									result = GetProcAddressX64(hProcess, forwardDllBase, NULL, serialNo1, X64Call);
								}
								else
								{
									result = GetProcAddressX64(hProcess, forwardDllBase, forward_func, 0, X64Call);
								}
							}
						}
					}
				}
			}
			return result;
		}
		static PVOID GetProcAddressX64(HANDLE hProcess, PVOID ModuleBase, PCSTR ProcName, ULONG serialNo)
		{
			return GetProcAddressX64(hProcess, ModuleBase, ProcName, serialNo, [](HANDLE, PVOID, PULONG64, PULONG64, ULONG)->bool
				{
					return false;
				}
			);
		}
		template<typename FX86CALL>	//[&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)->bool
		static PVOID GetProcAddressX86(HANDLE hProcess, PVOID ModuleBase, PCSTR ProcName, ULONG serialNo, FX86CALL X86Call) noexcept
		{
			//读取DOS头
			IMAGE_DOS_HEADER Img_DOS_Header = { 0 };
			if (!ReadMemory(hProcess, ModuleBase, sizeof(Img_DOS_Header), &Img_DOS_Header) || Img_DOS_Header.e_magic != IMAGE_DOS_SIGNATURE)
			{
				return NULL;
			}
			ULONG64 pImg_NT_Header = (ULONG64)IMAGE::RVA_TO_VA(ModuleBase, Img_DOS_Header.e_lfanew);
			IMAGE_NT_HEADERS32 Img_NT_Header = { 0 };
			//读取NT头
			if (!ReadMemory(hProcess, (PVOID)pImg_NT_Header, sizeof(Img_NT_Header), &Img_NT_Header) || Img_NT_Header.Signature != IMAGE_NT_SIGNATURE)
			{
				return NULL;
			}
			ULONG64 pImg_Export_Dir = (ULONG64)IMAGE::RVA_TO_VA(ModuleBase, Img_NT_Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			ULONG Img_Export_Size = Img_NT_Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			if (Img_Export_Size < sizeof(IMAGE_EXPORT_DIRECTORY))
			{
				return NULL;
			}
			IMAGE_EXPORT_DIRECTORY Img_Export_Dir = { 0 };
			//读取导出表
			if (!ReadMemory(hProcess, (PVOID)pImg_Export_Dir, sizeof(Img_Export_Dir), &Img_Export_Dir))
			{
				return NULL;
			}
			PVOID result = NULL;

			DWORD32* nameRVAs = (DWORD32*)IMAGE::RVA_TO_VA(ModuleBase, Img_Export_Dir.AddressOfNames);
			DWORD32* funRVAs = (DWORD32*)IMAGE::RVA_TO_VA(ModuleBase, Img_Export_Dir.AddressOfFunctions);
			USHORT* OrdinalsRVAs = (USHORT*)IMAGE::RVA_TO_VA(ModuleBase, Img_Export_Dir.AddressOfNameOrdinals);
			//循环遍历所有导出表
			for (ULONG ExportIndex = 0; ExportIndex < Img_Export_Dir.NumberOfNames; ExportIndex++)
			{
				char name[0x100] = { 0 };
				DWORD32 nameOffset = 0;
				DWORD32 funOffset = 0;
				USHORT funOrdinal = 0;
				//读取序号
				if (!ReadMemory(hProcess, OrdinalsRVAs + ExportIndex, sizeof(funOrdinal), &funOrdinal))
				{
					continue;
				}
				bool IsThis = false;
				//名字为空且序号相等 序号=(Img_Export_Dir.Base + funOrdinal)
				if (ProcName == NULL && serialNo == Img_Export_Dir.Base + funOrdinal)
				{
					IsThis = true;
				}
				//名字相等
				else if (ProcName != NULL
					&& ReadMemory(hProcess, nameRVAs + ExportIndex, sizeof(nameOffset), &nameOffset)
					&& ReadMemory(hProcess, (PUCHAR)ModuleBase + nameOffset, sizeof(name) - 1, name)
					&& strcmp(ProcName, name) == 0)
				{
					IsThis = true;
				}
				//已经找到函数
				if (IsThis)
				{
					//读取函数RVA偏移
					if (ReadMemory(hProcess, funRVAs + funOrdinal, sizeof(funOffset), &funOffset))
					{
						result = IMAGE::RVA_TO_VA(ModuleBase, funOffset);
					}
					break;
				}
			}
			//处理函数转发
			if ((ULONG64)result >= pImg_Export_Dir && (ULONG64)result < pImg_Export_Dir + Img_Export_Size)
			{
				PVOID forward_info = result;
				result = NULL;
				char forward_dll[0x100] = { 0 };
				char forward_func[0x100] = { 0 };
				if (ReadMemory(hProcess, forward_info, sizeof(forward_dll) - 1, forward_dll))
				{
					char* pos = strchr(forward_dll, '.');
					if (pos != NULL)
					{
						strncpy(forward_func, pos + 1, sizeof(forward_func));
						strncpy(pos, ".dll", sizeof(forward_dll) - (pos - forward_dll));
						if (strlen(forward_dll) > 0 && strlen(forward_func) > 0)
						{
							PVOID forwardDllBase = GetModuleHandleX86A(hProcess, forward_dll);
							if (forwardDllBase == NULL)
							{
								//如果转发目标DLL未加载，先加载目标DLL
								forwardDllBase = LoadLibraryX86A(hProcess, forward_dll, X86Call);
							}
							if (forwardDllBase != NULL)
							{
								if (forward_func[0] == '@')
								{
									//转发时使用的序号导入
									DWORD32 serialNo1 = 0;
									for (int j = 1; forward_func[j] != 0; j++)
									{
										serialNo1 = serialNo1 * 10 + (forward_func[j] - '0');
									}
									result = GetProcAddressX86(hProcess, forwardDllBase, NULL, serialNo1, X86Call);
								}
								else
								{
									result = GetProcAddressX86(hProcess, forwardDllBase, forward_func, 0, X86Call);
								}
							}
						}
					}
				}
			}
			return result;
		}
		static PVOID GetProcAddressX86(HANDLE hProcess, PVOID ModuleBase, PCSTR ProcName, ULONG serialNo)
		{
			return GetProcAddressX86(hProcess, ModuleBase, ProcName, serialNo, [](HANDLE, PVOID, PULONG, PULONG, ULONG)->bool
				{
					return false;
				}
			);
		}
		template<typename FX64CALL>	//[&](HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum)->bool
		static PVOID LoadLibraryX64W(HANDLE hProcess, PCWSTR DllName, FX64CALL X64Call)
		{
			ULONG DllNameSize = (ULONG)wcslen(DllName) * sizeof(DllName[0]);
			if (DllName == NULL || DllNameSize > 0x900)
			{
				return NULL;
			}
			PVOID ntdllBase = GetModuleHandleX64W(hProcess, L"ntdll.dll");
			if (ntdllBase == NULL)
			{
				return NULL;
			}
			PVOID funLdrLoadDll = GetProcAddressX64(hProcess, ntdllBase, "LdrLoadDll", 0, X64Call);
			if (funLdrLoadDll == NULL)
			{
				return NULL;
			}
			PVOID result = NULL;
			PVOID ProcessMemory = AllocMemory(hProcess, 0x1000, PAGE_READWRITE);
			if (ProcessMemory != NULL)
			{
				UNICODE_STRING uStr = { 0 };
				uStr.Buffer = (PWSTR)((PCHAR)ProcessMemory + 0x100);
				uStr.MaximumLength = (USHORT)DllNameSize;
				uStr.Length = (USHORT)DllNameSize;
				if (WriteMemory(hProcess, ProcessMemory, sizeof(uStr), &uStr) &&
					WriteMemory(hProcess, uStr.Buffer, DllNameSize, (PVOID)DllName))
				{
					ULONG64 CallResult;
					ULONG64 Args[] = {
						NULL,
						NULL,
						(ULONG_PTR)ProcessMemory,
						(ULONG_PTR)((PCHAR)ProcessMemory + 0x20)
					};
					if (X64Call(hProcess, funLdrLoadDll, &CallResult, Args, sizeof(Args) / sizeof(Args[0])) && NT_SUCCESS((NTSTATUS)CallResult))
					{
						ReadMemory(hProcess, (PCHAR)ProcessMemory + 0x20, sizeof(result), &result);
					}
				}
				FreeMemory(hProcess, ProcessMemory);
			}
			return result;
		}
		template<typename FX64CALL>	//[&](HANDLE hProcess, PVOID UserFun, PULONG64 pRetCode, PULONG64 pArgs, ULONG ArgNum)->bool
		static PVOID LoadLibraryX64A(HANDLE hProcess, PCSTR DllName, FX64CALL X64Call)
		{
			wchar_t uModuleName[260] = { 0 };
			LONG BufferLen = sizeof(uModuleName);
			PCWSTR wDllName = AscllStrToUnicodeStr(DllName, uModuleName, &BufferLen);
			if (wDllName == NULL)
			{
				return NULL;
			}
			else
			{
				return LoadLibraryX64W(hProcess, wDllName, X64Call);
			}
		}
		template<typename FX86CALL>	//[&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)->bool
		static PVOID LoadLibraryX86W(HANDLE hProcess, PCWSTR DllName, FX86CALL X86Call)
		{
			ULONG DllNameSize = (ULONG)wcslen(DllName) * sizeof(DllName[0]);
			if (DllName == NULL || DllNameSize > 0x900)
			{
				return NULL;
			}
			PVOID ntdllBase = GetModuleHandleX86W(hProcess, L"ntdll.dll");
			if (ntdllBase == NULL)
			{
				return NULL;
			}
			PVOID funLdrLoadDll = GetProcAddressX86(hProcess, ntdllBase, "LdrLoadDll", 0, X86Call);
			if (funLdrLoadDll == NULL)
			{
				return NULL;
			}
			PVOID result = NULL;
			PVOID ProcessMemory = AllocMemory(hProcess, 0x1000, PAGE_READWRITE);
			if (ProcessMemory != NULL)
			{
				UNICODE_STRING uStr = { 0 };
				uStr.Buffer = (PWSTR)((PCHAR)ProcessMemory + 0x100);
				uStr.MaximumLength = (USHORT)DllNameSize;
				uStr.Length = (USHORT)DllNameSize;
				if (WriteMemory(hProcess, ProcessMemory, sizeof(uStr), &uStr) &&
					WriteMemory(hProcess, uStr.Buffer, DllNameSize, (PVOID)DllName))
				{
					ULONG CallResult;
					ULONG Args[] = {
						0,
						0,
						(ULONG)(ULONG_PTR)ProcessMemory,
						(ULONG)(ULONG_PTR)((PCHAR)ProcessMemory + 0x20)
					};
					if (X86Call(hProcess, funLdrLoadDll, &CallResult, Args, sizeof(Args) / sizeof(Args[0])) && NT_SUCCESS((NTSTATUS)CallResult))
					{
						ReadMemory(hProcess, (PCHAR)ProcessMemory + 0x20, sizeof(result), &result);
					}
				}
				FreeMemory(hProcess, ProcessMemory);
			}
			return result;
		}
		template<typename FX86CALL>	//[&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)->bool
		static PVOID LoadLibraryX86A(HANDLE hProcess, PCSTR DllName, FX86CALL X86Call)
		{
			wchar_t uModuleName[260] = { 0 };
			LONG BufferLen = sizeof(uModuleName);
			PCWSTR wDllName = AscllStrToUnicodeStr(DllName, uModuleName, &BufferLen);
			if (wDllName == NULL)
			{
				return NULL;
			}
			else
			{
				return LoadLibraryX86W(hProcess, wDllName, X86Call);
			}
		}
		template<typename FX64CALL>	//[&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)->bool
		static PVOID LoadMemoryLibraryX64(HANDLE hProcess, PVOID ImageBuffer, ULONG ImageSize, FX64CALL X64Call)
		{
			SIZE_T MapSize = 0;
			IMAGE::MapForBuffer(ImageBuffer, ImageSize, NULL, &MapSize, true);
			if (MapSize == 0)
			{
				return NULL;
			}
			PVOID LocalBuffer = NULL;
#ifdef WINNT
			LocalBuffer = ExAllocatePoolWithTag(PagedPool, MapSize, 'PRO');
#else
			LocalBuffer = VirtualAlloc(NULL, MapSize, MEM_COMMIT, PAGE_READWRITE);
#endif // WINNT
			PVOID result = NULL;
			if (LocalBuffer != NULL)
			{
				//先Map到本地
				if (IMAGE::MapForBuffer(ImageBuffer, ImageSize, LocalBuffer, &MapSize, true))
				{
					PVOID RemoteBuffer = AllocMemory(hProcess, MapSize, PAGE_EXECUTE_READWRITE);
					if (RemoteBuffer != NULL)
					{
						do
						{
							//修复重定位表
							if (!IMAGE::PerformRelocation(LocalBuffer, RemoteBuffer, true))
								break;
							//修复导入表
							if (!IMAGE::BuildImportTable(LocalBuffer, true, [&](PCSTR ImageName)->PVOID {
								PVOID result = GetModuleHandleX64A(hProcess, ImageName);
								if (!result)result = LoadLibraryX64A(hProcess, ImageName, X64Call);
								return result;
								}, [&](PVOID ImageBase, PCSTR ProcName, DWORD32 serialNo)->PVOID {
									return GetProcAddressX64(hProcess, ImageBase, ProcName, serialNo, X64Call);
									}))
								break;
							//复制到进程
							if (!WriteMemory(hProcess, RemoteBuffer, MapSize, LocalBuffer))
								break;
							PIMAGE_DOS_HEADER pDos_header = (PIMAGE_DOS_HEADER)LocalBuffer;
							PIMAGE_NT_HEADERS pOld_header = (PIMAGE_NT_HEADERS)IMAGE::RVA_TO_VA(LocalBuffer, pDos_header->e_lfanew);

							result = RemoteBuffer;

							ULONG64 CallArgs[] = {
								(ULONG64)RemoteBuffer,
								(ULONG64)1/*DLL_PROCESS_ATTACH*/,
								(ULONG64)NULL
							};
							//获取TLS并调用
							DWORD32 TlsOffset = pOld_header->OptionalHeader.DataDirectory[9].VirtualAddress;
							DWORD32 TlsSize = pOld_header->OptionalHeader.DataDirectory[9].Size;
							if (TlsOffset != 0 && TlsSize > 0)
							{
								PIMAGE_TLS_DIRECTORY64 pTls = (PIMAGE_TLS_DIRECTORY64)IMAGE::RVA_TO_VA(LocalBuffer, TlsOffset);
								int tlsNum = TlsSize / sizeof(IMAGE_TLS_DIRECTORY64);
								for (int tlsIndex = 0; tlsIndex < tlsNum; tlsIndex++)
								{
									PVOID* CallBacks = (PVOID*)pTls[tlsIndex].AddressOfCallBacks;
									for (ULONG CallBackIndex = 0; ; CallBackIndex++)
									{
										PVOID CallBack = NULL;
										if (!ReadMemory(hProcess, CallBacks + CallBackIndex, sizeof(CallBack), &CallBack) || !CallBack)
										{
											break;
										}
										X64Call(hProcess, CallBack, NULL, CallArgs, sizeof(CallArgs) / sizeof(CallArgs[0]));
									}
								}
							}
							//调用DLLMain
							PVOID EntryPoint = (PVOID)IMAGE::RVA_TO_VA(RemoteBuffer, pOld_header->OptionalHeader.AddressOfEntryPoint);
							ULONG64 callRet = 0;
							if (X64Call(hProcess, EntryPoint, &callRet, CallArgs, sizeof(CallArgs) / sizeof(CallArgs[0])) && callRet != 0)
							{
								result = RemoteBuffer;
							}

						} while (FALSE);
						if (result == NULL)
						{
							FreeMemory(hProcess, RemoteBuffer);
						}
					}
				}
#ifdef WINNT
				ExFreePoolWithTag(LocalBuffer, 'PRO');
#else
				VirtualFree(LocalBuffer, 0, MEM_RELEASE);
#endif // WINNT
			}
			return result;
		}
		template<typename FX86CALL>	//[&](HANDLE hProcess, PVOID UserFun, PULONG pRetCode, PULONG pArgs, ULONG ArgNum)
		static PVOID LoadMemoryLibraryX86(HANDLE hProcess, PVOID ImageBuffer, ULONG ImageSize, FX86CALL X86Call)
		{
			SIZE_T MapSize = 0;
			IMAGE::MapForBuffer(ImageBuffer, ImageSize, NULL, &MapSize, false);
			if (MapSize == 0)
			{
				return NULL;
			}
			PVOID LocalBuffer = NULL;
#ifdef WINNT
			LocalBuffer = ExAllocatePoolWithTag(PagedPool, MapSize, 'PRO');
#else
			LocalBuffer = VirtualAlloc(NULL, MapSize, MEM_COMMIT, PAGE_READWRITE);
#endif // WINNT
			PVOID result = NULL;
			if (LocalBuffer != NULL)
			{
				//先Map到本地
				if (IMAGE::MapForBuffer(ImageBuffer, ImageSize, LocalBuffer, &MapSize, false))
				{
					PVOID RemoteBuffer = AllocMemory(hProcess, MapSize, PAGE_EXECUTE_READWRITE);
					if (RemoteBuffer != NULL)
					{
						do
						{
							//修复重定位表
							if (!IMAGE::PerformRelocation(LocalBuffer, RemoteBuffer, false))
								break;
							//修复导入表
							if (!IMAGE::BuildImportTable(LocalBuffer, false, [&](PCSTR ImageName)->PVOID {
								PVOID result = GetModuleHandleX86A(hProcess, ImageName);
								if (!result)result = LoadLibraryX86A(hProcess, ImageName, X86Call);
								return result;
								}, [&](PVOID ImageBase, PCSTR ProcName, DWORD32 serialNo)->PVOID {
									return GetProcAddressX86(hProcess, ImageBase, ProcName, serialNo, X86Call);
									}))
								break;
							//复制到进程
							if (!WriteMemory(hProcess, RemoteBuffer, MapSize, LocalBuffer))
								break;
							PIMAGE_DOS_HEADER pDos_header = (PIMAGE_DOS_HEADER)LocalBuffer;
							PIMAGE_NT_HEADERS pOld_header = (PIMAGE_NT_HEADERS)IMAGE::RVA_TO_VA(LocalBuffer, pDos_header->e_lfanew);

							//获取TLS并调用
							ULONG CallArgs[] = {
								(ULONG)RemoteBuffer
								, (ULONG)1/*DLL_PROCESS_ATTACH*/
								, (ULONG)NULL
							};
							DWORD32 TlsOffset = pOld_header->OptionalHeader.DataDirectory[9].VirtualAddress;
							DWORD32 TlsSize = pOld_header->OptionalHeader.DataDirectory[9].Size;
							if (TlsOffset != 0 && TlsSize > 0)
							{
								PIMAGE_TLS_DIRECTORY32 pTls = (PIMAGE_TLS_DIRECTORY32)IMAGE::RVA_TO_VA(LocalBuffer, TlsOffset);
								int tlsNum = TlsSize / sizeof(IMAGE_TLS_DIRECTORY32);
								for (int tlsIndex = 0; tlsIndex < tlsNum; tlsIndex++)
								{
									DWORD32* CallBacks = (DWORD32*)(ULONG_PTR)pTls[tlsIndex].AddressOfCallBacks;
									for (ULONG CallBackIndex = 0; ; CallBackIndex++)
									{
										DWORD32 CallBack = NULL;
										if (!ReadMemory(hProcess, CallBacks + CallBackIndex, sizeof(CallBack), &CallBack) || !CallBack)
										{
											break;
										}
										X86Call(hProcess, (PVOID)(ULONG_PTR)CallBack, NULL, CallArgs, sizeof(CallArgs) / sizeof(CallArgs[0]));
									}
								}
							}
							//调用DLLMain
							PVOID EntryPoint = (PVOID)IMAGE::RVA_TO_VA(RemoteBuffer, pOld_header->OptionalHeader.AddressOfEntryPoint);
							ULONG callRet = 0;
							if (X86Call(hProcess, EntryPoint, &callRet, CallArgs, sizeof(CallArgs) / sizeof(CallArgs[0])) && callRet != 0)
							{
								result = RemoteBuffer;
							}

						} while (FALSE);
						if (result == NULL)
						{
							FreeMemory(hProcess, RemoteBuffer);
						}
					}
				}
#ifdef WINNT
				ExFreePoolWithTag(LocalBuffer, 'PRO');
#else
				VirtualFree(LocalBuffer, 0, MEM_RELEASE);
#endif // WINNT
			}
			return result;
		}
#pragma endregion
	};
};

#pragma warning(pop)