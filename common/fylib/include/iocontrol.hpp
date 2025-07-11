#pragma once
#include "fylib.hpp"

class IOCONTROL
{
private:
	static constexpr auto IOCONTROL_KEY1 = 0x76543210;
	static constexpr auto IOCONTROL_KEY2 = 0xFEDCBA98;
	static constexpr auto IOCONTROL_KEY3 = 0x12349876;
	static constexpr auto IOCONTROL_SUCCESS = 0xbbbb0000;
	static constexpr auto IOCONTROL_FAIL = 0xbbbb0001;
	static constexpr auto HOOK_FUN_NAME = "NtGdiDdDDIDestroyKeyedMutex";
	using NtGdiDdDDIDestroyKeyedMutex_TYPE = LONG(*)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
	using IoControlProc_TYPE = ULONG_PTR(*)(DWORD32 IoCode, PVOID pData, DWORD32 DataSize);
	struct IOCONTROL_ARG
	{
		DWORD32 IoCode;
		DWORD32 DataSize;
		DWORD64 Return;
	};
	struct STATIC_DATA_STR
	{
		NtGdiDdDDIDestroyKeyedMutex_TYPE oldNtGdiDdDDIDestroyKeyedMutex = NULL;
		IoControlProc_TYPE IoControlProc = NULL;
	};
	static STATIC_DATA_STR& STATIC_DATA()
	{
		static STATIC_DATA_STR Data;
		return Data;
	}
#ifdef WINNT
	static NTSTATUS MyNtGdiDdDDIDestroyKeyedMutex(ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3, ULONG_PTR arg4)
	{
		if (arg2 != IOCONTROL_KEY1 || arg3 != IOCONTROL_KEY2 || arg4 != IOCONTROL_KEY3)
		{
			return STATIC_DATA().oldNtGdiDdDDIDestroyKeyedMutex(arg1, arg2, arg3, arg4);
		}
		if (!MmIsAddressValid((PVOID)arg1))
		{
			return IOCONTROL_FAIL;
		}
		else
		{
			IOCONTROL_ARG* pArg = (IOCONTROL_ARG*)arg1;
			PVOID pData = NULL;
			if (pArg->DataSize > 0)
			{
				pData = (PVOID)(arg1 + sizeof(IOCONTROL_ARG));
			}
			pArg->Return = STATIC_DATA().IoControlProc(pArg->IoCode, pData, pArg->DataSize);
			return IOCONTROL_SUCCESS;
		}
	}
#endif
public:
#ifdef WINNT
	static bool SetIoControlProc(ULONG_PTR(*Proc)(DWORD32 IoCode, PVOID pData, DWORD32 DataSize))
	{
		if (STATIC_DATA().IoControlProc != NULL)
		{
			return false;
		}
		bool result = false;
		STATIC_DATA().IoControlProc = Proc;
		ULONG64 explorerPID = FYLIB::GetProcessIdByProcessName(L"explorer.exe");
		if (explorerPID)
		{
			PEPROCESS explorerPEP = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)explorerPID, &explorerPEP)))
			{
				KAPC_STATE apcState{};
				KeStackAttachProcess(explorerPEP, &apcState);
				PVOID win32kBase = FYLIB::GetSystemModuleBase("win32k.sys", NULL);
				if (win32kBase)
				{
					STATIC_DATA().oldNtGdiDdDDIDestroyKeyedMutex = (NtGdiDdDDIDestroyKeyedMutex_TYPE)FYLIB::IMAGE::GetImport(win32kBase, NULL, HOOK_FUN_NAME, TRUE);
					if (STATIC_DATA().oldNtGdiDdDDIDestroyKeyedMutex)
					{
						if (FYLIB::IMAGE::SetImport(win32kBase, NULL, HOOK_FUN_NAME, MyNtGdiDdDDIDestroyKeyedMutex, TRUE))
						{
							result = true;
						}
					}
				}
				KeUnstackDetachProcess(&apcState);
				ObReferenceObject(explorerPEP);
			}
		}
		if (!result)
		{
			STATIC_DATA().oldNtGdiDdDDIDestroyKeyedMutex = NULL;
			STATIC_DATA().IoControlProc = NULL;
		}
		return result;
	}
	static void RemoveIoControlProc()
	{
		if (STATIC_DATA().IoControlProc)
		{
			if (STATIC_DATA().oldNtGdiDdDDIDestroyKeyedMutex)
			{
				ULONG64 explorerPID = FYLIB::GetProcessIdByProcessName(L"explorer.exe");
				if (explorerPID)
				{
					PEPROCESS explorerPEP = NULL;
					if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)explorerPID, &explorerPEP)))
					{
						KAPC_STATE apcState{};
						KeStackAttachProcess(explorerPEP, &apcState);
						PVOID win32kBase = FYLIB::GetSystemModuleBase("win32k.sys", NULL);
						if (win32kBase)
						{
							FYLIB::IMAGE::SetImport(win32kBase, NULL, HOOK_FUN_NAME, STATIC_DATA().oldNtGdiDdDDIDestroyKeyedMutex, TRUE);
						}
						KeUnstackDetachProcess(&apcState);
						ObReferenceObject(explorerPEP);
					}
				}
				STATIC_DATA().oldNtGdiDdDDIDestroyKeyedMutex = NULL;
			}
			STATIC_DATA().IoControlProc = NULL;
		}
	}

#else

	static NtGdiDdDDIDestroyKeyedMutex_TYPE GetFunAddress()
	{
		static NtGdiDdDDIDestroyKeyedMutex_TYPE NtGdiDdDDIDestroyKeyedMutex_Proc = NULL;
		if (NtGdiDdDDIDestroyKeyedMutex_Proc == NULL)
		{
			HMODULE win32uBase = GetModuleHandleA("win32u.dll");
			if (win32uBase)
			{
				NtGdiDdDDIDestroyKeyedMutex_Proc = (NtGdiDdDDIDestroyKeyedMutex_TYPE)GetProcAddress(win32uBase, HOOK_FUN_NAME);
			}
		}
		return NtGdiDdDDIDestroyKeyedMutex_Proc;
	}

	bool IoControlCheck()
	{
		NtGdiDdDDIDestroyKeyedMutex_TYPE NtGdiDdDDIDestroyKeyedMutex_Proc = GetFunAddress();
		if (!NtGdiDdDDIDestroyKeyedMutex_Proc)
		{
			return false;
		}
#ifdef _WIN64
		return NtGdiDdDDIDestroyKeyedMutex_Proc(0xFFFFFFFFFFFFFFFFULL, IOCONTROL_KEY1, IOCONTROL_KEY2, IOCONTROL_KEY3) == IOCONTROL_FAIL;
#else
		return NtGdiDdDDIDestroyKeyedMutex_Proc(0xFFFFFFFFU, IOCONTROL_KEY1, IOCONTROL_KEY2, IOCONTROL_KEY3) == IOCONTROL_FAIL;
#endif // _WIN64

	}

	ULONG_PTR IoControl(DWORD IoCode, PVOID pData, DWORD DataSize)
	{
		NtGdiDdDDIDestroyKeyedMutex_TYPE NtGdiDdDDIDestroyKeyedMutex_Proc = GetFunAddress();
		if (!NtGdiDdDDIDestroyKeyedMutex_Proc)
		{
			return false;
		}
		IOCONTROL_ARG* pParam = (IOCONTROL_ARG*)malloc(sizeof(IOCONTROL_ARG) + DataSize);
		if (!pParam)
		{
			return false;
		}
		ULONG_PTR result = 0;
		pParam->IoCode = IoCode;
		pParam->DataSize = DataSize;
		if (pData && DataSize > 0)
		{
			memcpy(pParam + 1, pData, DataSize);
		}
		if (NtGdiDdDDIDestroyKeyedMutex_Proc((ULONG_PTR)pParam, IOCONTROL_KEY1, IOCONTROL_KEY2, IOCONTROL_KEY3) == IOCONTROL_SUCCESS)
		{
			result = pParam->Return;
			if (pData && DataSize > 0)
			{
				memcpy(pData, pParam + 1, DataSize);
			}
		}
		free(pParam);
		return result;
	}

#endif // WINNT
};
