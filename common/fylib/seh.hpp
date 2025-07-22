#pragma once
#ifdef WINNT
#include <ntifs.h>
#include <ntimage.h>
#else
#include <Windows.h>
#include <TlHelp32.h>
#endif

struct SEH
{
private:
	struct RtlpxLookupFunctionTableInfo
	{
		PVOID ExceptionDirectoryEntry;
		PVOID ImageBase;
		DWORD32 ImageSize;
		DWORD32 ExceptionDirectorySize;
	};
	struct static_data_t
	{
		RtlpxLookupFunctionTableInfo ExceptionTables[10] = { 0 };
		PVOID RtlpxLookupFunctionTable_Hook = NULL;
	};
	inline static static_data_t& static_data() noexcept
	{
		static static_data_t data_;
		return data_;
	}
private:
	static PVOID My_RtlpxLookupFunctionTable(ULONG64 Pc, RtlpxLookupFunctionTableInfo* pOutInfo) noexcept
	{
		PVOID result = NULL;
		FYLIB::INLINEHOOK::DetoutFunctionBegin(static_data().RtlpxLookupFunctionTable_Hook);
		for (int i = 0; i < sizeof(static_data().ExceptionTables) / sizeof(*static_data().ExceptionTables); i++)
		{
			if (Pc >= (DWORD64)static_data().ExceptionTables[i].ImageBase && Pc < ((DWORD64)static_data().ExceptionTables[i].ImageBase) + static_data().ExceptionTables[i].ImageSize)
			{
				pOutInfo->ExceptionDirectoryEntry = static_data().ExceptionTables[i].ExceptionDirectoryEntry;
				pOutInfo->ImageBase = static_data().ExceptionTables[i].ImageBase;
				pOutInfo->ImageSize = static_data().ExceptionTables[i].ImageSize;
				pOutInfo->ExceptionDirectorySize = static_data().ExceptionTables[i].ExceptionDirectorySize;
				result = pOutInfo->ExceptionDirectoryEntry;
				break;
			}
		}
		if (!result)
		{
			result = ((PVOID(*)(ULONG64, RtlpxLookupFunctionTableInfo*))static_data().RtlpxLookupFunctionTable_Hook)(Pc, pOutInfo);
		}
		FYLIB::INLINEHOOK::DetoutFunctionEnd(static_data().RtlpxLookupFunctionTable_Hook);
		return result;
	}
public:

	static bool Append(PVOID ImageBase, PVOID ExceptionDirectoryEntry, DWORD32 ImageSize, DWORD32 ExceptionDirectorySize) noexcept
	{
		if (ImageBase == NULL || ExceptionDirectoryEntry == NULL || ImageSize == 0 || ExceptionDirectorySize == 0)
		{
			return false;
		}
		if (static_data().RtlpxLookupFunctionTable_Hook == NULL)
		{
			PVOID RtlPcToFileHeader_Address = NULL;
#ifdef WINNT
			UNICODE_STRING uStr = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
			RtlPcToFileHeader_Address = MmGetSystemRoutineAddress(&uStr);
#else
			HMODULE ntdllBase = GetModuleHandleA("ntdll");
			if (ntdllBase)
			{
				RtlPcToFileHeader_Address = GetProcAddress(ntdllBase, "RtlPcToFileHeader");
			}
#endif // WINNT
			if (RtlPcToFileHeader_Address == NULL)
			{
				return false;
			}
			PVOID RtlpxLookupFunctionTable_Address = NULL;
			PUCHAR pos = (PUCHAR)RtlPcToFileHeader_Address;
			for (int i = 0; i < 40; i++)
			{
				FYLIB::INSTRUCTION::HDES hde = { 0 };
				if (!FYLIB::INSTRUCTION::X64::Disasm(pos, &hde))
				{
					break;
				}
				else if (hde.len == 5 && hde.opcode == 0xE8)
				{
					RtlpxLookupFunctionTable_Address = pos + (int)hde.imm.imm32 + hde.len;
				}
				pos += hde.len;
			}
			if (RtlpxLookupFunctionTable_Address == NULL)
			{
				return false;
			}
			static_data().RtlpxLookupFunctionTable_Hook = FYLIB::INLINEHOOK::CreateFunction(RtlpxLookupFunctionTable_Address, My_RtlpxLookupFunctionTable, FALSE);
			if (!FYLIB::INLINEHOOK::Enable(static_data().RtlpxLookupFunctionTable_Hook))
			{
				FYLIB::INLINEHOOK::Remove(static_data().RtlpxLookupFunctionTable_Hook);
				static_data().RtlpxLookupFunctionTable_Hook = NULL;
				return false;
			}
			memset(static_data().ExceptionTables, 0, sizeof(static_data().ExceptionTables));
		}
		for (int i = 0; i < sizeof(static_data().ExceptionTables) / sizeof(*static_data().ExceptionTables); i++)
		{
			if (static_data().ExceptionTables[i].ExceptionDirectoryEntry == NULL)
			{
				static_data().ExceptionTables[i].ImageBase = ImageBase;
				static_data().ExceptionTables[i].ExceptionDirectoryEntry = ExceptionDirectoryEntry;
				static_data().ExceptionTables[i].ImageSize = ImageSize;
				static_data().ExceptionTables[i].ExceptionDirectorySize = ExceptionDirectorySize;
				return true;
			}
		}
		return false;
	}
	static void Remove(PVOID ExceptionDirectoryEntry) noexcept
	{
		if (static_data().RtlpxLookupFunctionTable_Hook)
		{
			bool IsAllEmpty = true;
			for (int i = 0; i < sizeof(static_data().ExceptionTables) / sizeof(*static_data().ExceptionTables); i++)
			{
				if (static_data().ExceptionTables[i].ExceptionDirectoryEntry == ExceptionDirectoryEntry)
				{
					static_data().ExceptionTables[i].ImageBase = NULL;
					static_data().ExceptionTables[i].ExceptionDirectoryEntry = NULL;
					static_data().ExceptionTables[i].ImageSize = 0;
					static_data().ExceptionTables[i].ExceptionDirectorySize = 0;
				}
				else if (static_data().ExceptionTables[i].ExceptionDirectoryEntry != NULL)
				{
					IsAllEmpty = false;
				}
			}
			if (IsAllEmpty)
			{
				FYLIB::INLINEHOOK::Disable(static_data().RtlpxLookupFunctionTable_Hook);
				FYLIB::INLINEHOOK::Remove(static_data().RtlpxLookupFunctionTable_Hook);
				static_data().RtlpxLookupFunctionTable_Hook = NULL;
			}
		}
	}
};