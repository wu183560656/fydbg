#include <ntifs.h>
#include <fylib\fylib.hpp>
#include <iocode.h>

namespace patch
{
	static PVOID _NtdllBase = NULL;
#pragma pack(push, 1)
	/*
	90 90 90 E8 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48 B8 88 77 66 55 44 33 22 11 FF E0 90 90 90 90 48 87 2C 24 48 83 EC 70 48 89 4C 24 58 48 89 54 24 60 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 48 C7 44 24 30 18 00 00 00 48 8D 44 24 58 48 89 44 24 28 48 C7 44 24 20 78 56 34 12 4C 8D 4C 24 48 4D 31 C0 48 31 D2 48 8B 4D 00 48 8B 45 08 48 C7 44 24 68 01 00 00 00 FF D0 85 C0 B0 01 74 3A 48 8B 4C 24 58 48 8B 54 24 60 48 8D 45 10 FF D0 84 C0 75 26 4C 8D 4C 24 48 4D 31 C0 48 31 D2 48 8B 4D 00 48 8B 45 08 48 C7 44 24 68 00 00 00 00 FF D0 85 C0 B0 01 74 02 30 C0 48 83 C4 70 5D C3
	*/
	struct
	{
		/*
		0000017E8DFF0000 | 90                         | nop                                     |
		0000017E8DFF0001 | 90                         | nop                                     |
		0000017E8DFF0002 | 90                         | nop                                     |
		0000017E8DFF0003 | E8 30000000                | call 17E8DFF0038                        | CALL 0
		*/
		UCHAR const_code_1[0x8] = { 0x90,0x90,0x90,0xe8,0x30,0x00,0x00,0x00 };
		ULONG64 DeviceHandle = 0;
		ULONG64 NtDeviceIoControlFile = 0;
//offset=0x18
		UCHAR RtlDispatchExceptionOldCode[0x10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
		/*
		mov rax,0x1122334455667788
		*/
		UCHAR const_code_2[0x2] = { 0x48,0xb8/*,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11*/ };

		ULONG64 RtlDispatchExceptionJmpAddress = 0;
		/*
		jmp rax
		*/
		UCHAR const_code_3[0x6] = { 0xFF,0xE0,0x90,0x90,0x90,0x90 };
//offset=0x38
		/*
		* 
		0000017E8DFF0038 | 48:872C24                  | xchg qword ptr ss:[rsp],rbp             |
		0000017E8DFF003C | 48:83EC 70                 | sub rsp,70                              |
		0000017E8DFF0040 | 48:894C24 58               | mov qword ptr ss:[rsp+58],rcx           |	FORWARD_EXCEPTION_PARAM.ExceptionRecord
		0000017E8DFF0045 | 48:895424 60               | mov qword ptr ss:[rsp+60],rdx           |	FORWARD_EXCEPTION_PARAM.pContext
		0000017E8DFF004A | 48:C74424 40 00000000      | mov qword ptr ss:[rsp+40],0             |	OutputBufferLength
		0000017E8DFF0053 | 48:C74424 38 00000000      | mov qword ptr ss:[rsp+38],0             |	OutputBuffer
		0000017E8DFF005C | 48:C74424 30 18000000      | mov qword ptr ss:[rsp+30],18            |	InputBufferLength
		0000017E8DFF0065 | 48:8D4424 58               | lea rax,qword ptr ss:[rsp+58]           |
		0000017E8DFF006A | 48:894424 28               | mov qword ptr ss:[rsp+28],rax           |	InputBuffer
		0000017E8DFF006F | 48:C74424 20 78563412      | mov qword ptr ss:[rsp+20],12345678      |	IoControlCode
		*/
		UCHAR const_code_4[0x3C] = { 0x48,0x87,0x2c,0x24,0x48,0x83,0xec,0x70,0x48,0x89,0x4c,0x24,0x58,0x48,0x89,0x54,0x24,0x60,0x48,0xc7,0x44,0x24,0x40,0x00,0x00,0x00,0x00,0x48,0xc7,0x44,0x24,0x38,0x00,0x00,0x00,0x00,0x48,0xc7,0x44,0x24,0x30,0x18,0x00,0x00,0x00,0x48,0x8d,0x44,0x24,0x58,0x48,0x89,0x44,0x24,0x28,0x48,0xc7,0x44,0x24,0x20/*,0x78,0x56,0x34,0x12*/ };
		ULONG32 IoCode = IO_CODE_FORWARD_EXCEPTION;
		/*
		0000017E8DFF0078 | 4C:8D4C24 48               | lea r9,qword ptr ss:[rsp+48]            |	IoStatusBlock
		0000017E8DFF007D | 4D:31C0                    | xor r8,r8                               |	ApcContext
		0000017E8DFF0080 | 48:31D2                    | xor rdx,rdx                             |	ApcRoutine
		0000017E8DFF0083 | 48:8B4D 00                 | mov rcx,qword ptr ss:[rbp]              |	DeviceHandle
		0000017E8DFF0087 | 48:8B45 08                 | mov rax,qword ptr ss:[rbp+8]            |
		0000017E8DFF008B | 48:C74424 68 01000000      | mov qword ptr ss:[rsp+68],1             |	FORWARD_EXCEPTION_PARAM.First = TRUE
		0000017E8DFF0094 | FFD0                       | call rax                                |	call NtDeviceIoControlFile
		0000017E8DFF0096 | 85C0                       | test eax,eax                            |
		0000017E8DFF0098 | B0 01                      | mov al,1                                |
		0000017E8DFF009A | 74 3A                      | je 17E8DFF00D6                          |
		0000017E8DFF009C | 48:8B4C24 58               | mov rcx,qword ptr ss:[rsp+58]           |	ExceptionRecord
		0000017E8DFF00A1 | 48:8B5424 60               | mov rdx,qword ptr ss:[rsp+60]           |	pContext
		0000017E8DFF00A6 | 48:8D45 10                 | lea rax,qword ptr ss:[rbp+10]           |
		0000017E8DFF00AA | FFD0                       | call rax                                |	call OldRtlDispatchExceptionNewCode
		0000017E8DFF00AC | 84C0                       | test al,al                              |
		0000017E8DFF00AE | 75 26                      | jne 17E8DFF00D6                         |
		0000017E8DFF00B0 | 4C:8D4C24 48               | lea r9,qword ptr ss:[rsp+48]            |	IoStatusBlock
		0000017E8DFF00B5 | 4D:31C0                    | xor r8,r8                               |	ApcContext
		0000017E8DFF00B8 | 48:31D2                    | xor rdx,rdx                             |	ApcRoutine
		0000017E8DFF00BB | 48:8B4D 00                 | mov rcx,qword ptr ss:[rbp]              |	DeviceHandle
		0000017E8DFF00BF | 48:8B45 08                 | mov rax,qword ptr ss:[rbp+8]            |
		0000017E8DFF00C3 | 48:C74424 68 00000000      | mov qword ptr ss:[rsp+68],0             |	FORWARD_EXCEPTION_PARAM.First = FALSE
		0000017E8DFF00CC | FFD0                       | call rax                                |	call NtDeviceIoControlFile
		0000017E8DFF00CE | 85C0                       | test eax,eax                            |
		0000017E8DFF00D0 | B0 01                      | mov al,1                                |
		0000017E8DFF00D2 | 74 02                      | je 17E8DFF00D6                          |
		0000017E8DFF00D4 | 30C0                       | xor al,al                               |
		0000017E8DFF00D6 | 48:83C4 70                 | add rsp,70                              |
		0000017E8DFF00DA | 5D                         | pop rbp                                 |
		0000017E8DFF00DB | C3                         | ret                                     |
		*/
		UCHAR const_code_5[0x64] = { 0x4c,0x8d,0x4c,0x24,0x48,0x4d,0x31,0xc0,0x48,0x31,0xd2,0x48,0x8b,0x4d,0x00,0x48,0x8b,0x45,0x08,0x48,0xc7,0x44,0x24,0x68,0x01,0x00,0x00,0x00,0xff,0xd0,0x85,0xc0,0xb0,0x01,0x74,0x3a,0x48,0x8b,0x4c,0x24,0x58,0x48,0x8b,0x54,0x24,0x60,0x48,0x8d,0x45,0x10,0xff,0xd0,0x84,0xc0,0x75,0x26,0x4c,0x8d,0x4c,0x24,0x48,0x4d,0x31,0xc0,0x48,0x31,0xd2,0x48,0x8b,0x4d,0x00,0x48,0x8b,0x45,0x08,0x48,0xc7,0x44,0x24,0x68,0x00,0x00,0x00,0x00,0xff,0xd0,0x85,0xc0,0xb0,0x01,0x74,0x02,0x30,0xc0,0x48,0x83,0xc4,0x70,0x5d,0xc3 };
	}RtlDispatchExceptionNewCode;

	/*
	90 90 90 E8 18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 B8 44 33 22 11 FF E0 90 87 2C 24 83 EC 40 8B 44 24 48 89 44 24 20 C7 44 24 24 00 00 00 00 8B 44 24 4C 89 44 24 28 C7 44 24 2C 00 00 00 00 C7 44 24 30 00 00 00 00 C7 44 24 34 00 00 00 00 6A 00 6A 00 6A 18 8D 44 24 20 50 68 44 33 22 11 8D 44 24 10 50 6A 00 6A 00 8B 45 00 50 8B 45 08 C7 44 24 30 01 00 00 00 FF D0 85 C0 B0 01 74 45 8B 44 24 20 50 8B 44 24 28 50 8D 45 10 FF D0 84 C0 75 32 6A 00 6A 00 6A 18 8D 44 24 20 50 68 44 33 22 11 8D 44 24 10 50 6A 00 6A 00 8B 45 00 50 8B 45 08 C7 44 24 30 00 00 00 00 FF D0 85 C0 B0 01 74 02 30 C0 83 C4 40 5D C2 08 00
	*/
	struct
	{
		/*
			01400000 | 90                       | nop                           |
			01400001 | 90                       | nop                           |
			01400002 | 90                       | nop                           |
			01400003 | E8 18000000              | call 1400020                  | call 0
		*/
		UCHAR const_code_1[8] = { 0x90,0x90,0x90,0xe8,0x30,0x00,0x00,0x00 };
		ULONG64 DeviceHandle = 0;
		ULONG64 NtDeviceIoControlFile = 0;
		//offset=0x18
		UCHAR RtlDispatchExceptionOldCode[0x10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
		/*
		mov eax,0x11223344
		*/
		UCHAR const_code_2[0x1] = { 0xb8/*,0x44,0x33,0x22,0x11*/ };

		ULONG32 RtlDispatchExceptionJmpAddress = 0;
		/*
		jmp eax
		*/
		UCHAR const_code_3[0x3] = { 0xFF,0xE0,0x90 };
		//offset=0x30
		/*
		01400030 | 872C24                   | xchg dword ptr ss:[esp],ebp                |
		01400033 | 83EC 40                  | sub esp,40                                 |
		01400036 | 8B4424 48                | mov eax,dword ptr ss:[esp+48]              |
		0140003A | 894424 20                | mov dword ptr ss:[esp+20],eax              |	FORWARD_EXCEPTION_PARAM.ExceptionRecord
		0140003E | C74424 24 00000000       | mov dword ptr ss:[esp+24],0                |
		01400046 | 8B4424 4C                | mov eax,dword ptr ss:[esp+4C]              |
		0140004A | 894424 28                | mov dword ptr ss:[esp+28],eax              |	FORWARD_EXCEPTION_PARAM.pContext
		0140004E | C74424 2C 00000000       | mov dword ptr ss:[esp+2C],0                |
		01400056 | C74424 30 00000000       | mov dword ptr ss:[esp+30],0                |
		0140005E | C74424 34 00000000       | mov dword ptr ss:[esp+34],0                |
		01400066 | C74424 38 44332211       | mov dword ptr ss:[esp+38],11223344         |
		*/
		UCHAR const_code_4[0x3A] = { 0x87,0x2c,0x24,0x83,0xec,0x40,0x8b,0x44,0x24,0x48,0x89,0x44,0x24,0x20,0xc7,0x44,0x24,0x24,0x00,0x00,0x00,0x00,0x8b,0x44,0x24,0x4c,0x89,0x44,0x24,0x28,0xc7,0x44,0x24,0x2c,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x30,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x34,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x38/*,0x44,0x33,0x22,0x11 */ };
		ULONG32 IoCode = IO_CODE_FORWARD_EXCEPTION;
		/*
		0140006E | 6A 00                    | push 0                                     |	OutputBufferLength
		01400070 | 6A 00                    | push 0                                     |	OutputBuffer
		01400072 | 6A 18                    | push 18                                    |	InputBufferLength
		01400074 | 8D4424 20                | lea eax,dword ptr ss:[esp+20]              |
		01400078 | 50                       | push eax                                   |	InputBuffer
		01400079 | 8B4424 38                | mov eax,dword ptr ss:[esp+38]              |
		0140007D | 50                       | push eax                                   |	IoControlCode
		0140007E | 8D4424 10                | lea eax,dword ptr ss:[esp+10]              |
		01400082 | 50                       | push eax                                   |	IoStatusBlock
		01400083 | 6A 00                    | push 0                                     |	ApcContext
		01400085 | 6A 00                    | push 0                                     |	ApcRoutine
		01400087 | 8B45 00                  | mov eax,dword ptr ss:[ebp]                 |
		0140008A | 50                       | push eax                                   |	DeviceHandle
		0140008B | 8B45 08                  | mov eax,dword ptr ss:[ebp+8]               |
		0140008E | C74424 30 01000000       | mov dword ptr ss:[esp+30],1                |	FORWARD_EXCEPTION_PARAM.First = TRUE
		01400096 | FFD0                     | call eax                                   |	call NtDeviceIoControlFile
		01400098 | 85C0                     | test eax,eax                               |
		0140009A | B0 01                    | mov al,1                                   |
		0140009C | 74 45                    | je 14000E3                                 |
		0140009E | 8B4424 20                | mov eax,dword ptr ss:[esp+20]              |
		014000A2 | 50                       | push eax                                   |	ExceptionRecord
		014000A3 | 8B4424 28                | mov eax,dword ptr ss:[esp+28]              |
		014000A7 | 50                       | push eax                                   |	pContext
		014000A8 | 8D45 10                  | lea eax,dword ptr ss:[ebp+10]              |
		014000AB | FFD0                     | call eax                                   |	call OldRtlDispatchExceptionNewCode
		014000AD | 84C0                     | test al,al                                 |
		014000AF | 75 32                    | jne 14000E3                                |
		014000B1 | 6A 00                    | push 0                                     |	OutputBufferLength
		014000B3 | 6A 00                    | push 0                                     |	OutputBuffer
		014000B5 | 6A 18                    | push 18                                    |	InputBufferLength
		014000B7 | 8D4424 20                | lea eax,dword ptr ss:[esp+20]              |
		014000BB | 50                       | push eax                                   |	InputBuffer
		014000BC | 8B4424 38                | mov eax,dword ptr ss:[esp+38]              |
		014000C0 | 50                       | push eax                                   |	IoControlCode
		014000C1 | 8D4424 10                | lea eax,dword ptr ss:[esp+10]              |
		014000C5 | 50                       | push eax                                   |	IoStatusBlock
		014000C6 | 6A 00                    | push 0                                     |	ApcContext
		014000C8 | 6A 00                    | push 0                                     |	ApcRoutine
		014000CA | 8B45 00                  | mov eax,dword ptr ss:[ebp]                 |
		014000CD | 50                       | push eax                                   |	DeviceHandle
		014000CE | 8B45 08                  | mov eax,dword ptr ss:[ebp+8]               |
		014000D1 | C74424 30 00000000       | mov dword ptr ss:[esp+30],0                |	FORWARD_EXCEPTION_PARAM.First = FALSE
		014000D9 | FFD0                     | call eax                                   |	call NtDeviceIoControlFile
		014000DB | 85C0                     | test eax,eax                               |
		014000DD | B0 01                    | mov al,1                                   |
		014000DF | 74 02                    | je 14000E3                                 |
		014000E1 | 30C0                     | xor al,al                                  |
		014000E3 | 83C4 40                  | add esp,40                                 |
		014000E6 | 5D                       | pop ebp                                    |
		014000E7 | C2 0800                  | ret 8                                      |
		*/
		UCHAR const_code_5[0x7C] = { 0x6a,0x00,0x6a,0x00,0x6a,0x18,0x8d,0x44,0x24,0x20,0x50,0x8b,0x44,0x24,0x38,0x50,0x8d,0x44,0x24,0x10,0x50,0x6a,0x00,0x6a,0x00,0x8b,0x45,0x00,0x50,0x8b,0x45,0x08,0xc7,0x44,0x24,0x30,0x01,0x00,0x00,0x00,0xff,0xd0,0x85,0xc0,0xb0,0x01,0x74,0x45,0x8b,0x44,0x24,0x20,0x50,0x8b,0x44,0x24,0x28,0x50,0x8d,0x45,0x10,0xff,0xd0,0x84,0xc0,0x75,0x32,0x6a,0x00,0x6a,0x00,0x6a,0x18,0x8d,0x44,0x24,0x20,0x50,0x8b,0x44,0x24,0x38,0x50,0x8d,0x44,0x24,0x10,0x50,0x6a,0x00,0x6a,0x00,0x8b,0x45,0x00,0x50,0x8b,0x45,0x08,0xc7,0x44,0x24,0x30,0x00,0x00,0x00,0x00,0xff,0xd0,0x85,0xc0,0xb0,0x01,0x74,0x02,0x30,0xc0,0x83,0xc4,0x40,0x5d,0xc2,0x08,0x00 };
	}Wow64RtlDispatchExceptionNewCode;
#pragma pack(pop)

	BOOLEAN RtlDispatchExceptionPatch(PEPROCESS Process)
	{
		UNREFERENCED_PARAMETER(Process);
		return FALSE;
	}
	BOOLEAN RtlDispatchExceptionRestore(PEPROCESS Process)
	{
		UNREFERENCED_PARAMETER(Process);
		return FALSE;
	}

	BOOLEAN RtlWow64DispatchExceptionPatch(PEPROCESS Process)
	{
		UNREFERENCED_PARAMETER(Process);
		return FALSE;
	}
	BOOLEAN RtlWow64DispatchExceptionRestore(PEPROCESS Process)
	{
		UNREFERENCED_PARAMETER(Process);
		return FALSE;
	}
}
