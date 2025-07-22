#pragma once
#include <Windows.h>
#include <vector>
#include <regex>
#include <TlHelp32.h>

namespace COMMON
{
#pragma region STRING
	//utf8 转 Unicode
	static std::wstring Utf82Unicode(const std::string& utf8string)
	{
		int widesize = ::MultiByteToWideChar(CP_UTF8, 0, utf8string.c_str(), -1, NULL, 0);
		if (widesize == ERROR_NO_UNICODE_TRANSLATION)
		{
			throw std::exception("Invalid UTF-8 sequence.");
		}
		if (widesize == 0)
		{
			throw std::exception("Error in conversion.");
		}

		std::vector<wchar_t> resultstring(widesize);

		int convresult = ::MultiByteToWideChar(CP_UTF8, 0, utf8string.c_str(), -1, &resultstring[0], widesize);

		if (convresult != widesize)
		{
			throw std::exception("La falla!");
		}
		return std::wstring(&resultstring[0]);
	}
	//unicode 转为 ascii
	static std::string Unicode2Acsii(const std::wstring& wstrcode)
	{
		int asciisize = ::WideCharToMultiByte(CP_OEMCP, 0, wstrcode.c_str(), -1, NULL, 0, NULL, NULL);
		if (asciisize == ERROR_NO_UNICODE_TRANSLATION)
		{
			throw std::exception("Invalid UTF-8 sequence.");
		}
		if (asciisize == 0)
		{
			throw std::exception("Error in conversion.");
		}
		std::vector<char> resultstring(asciisize);
		int convresult = ::WideCharToMultiByte(CP_OEMCP, 0, wstrcode.c_str(), -1, &resultstring[0], asciisize, NULL, NULL);

		if (convresult != asciisize)
		{
			throw std::exception("La falla!");
		}

		return std::string(&resultstring[0]);
	}
	//utf-8 转 ascii
	static std::string Utf82Ascii(const std::string& strUtf8Code)
	{
		std::string strRet("");
		//先把 utf8 转为 unicode
		std::wstring wstr = Utf82Unicode(strUtf8Code);
		//最后把 unicode 转为 ascii
		strRet = Unicode2Acsii(wstr);
		return strRet;
	}
	//ascii 转 Unicode
	static std::wstring Acsii2Unicode(const std::string& strascii)
	{
		int widesize = MultiByteToWideChar(CP_ACP, 0, (char*)strascii.c_str(), -1, NULL, 0);
		if (widesize == ERROR_NO_UNICODE_TRANSLATION)
		{
			throw std::exception("Invalid UTF-8 sequence.");
		}
		if (widesize == 0)
		{
			throw std::exception("Error in conversion.");
		}
		std::vector<wchar_t> resultstring(widesize);
		int convresult = MultiByteToWideChar(CP_ACP, 0, (char*)strascii.c_str(), -1, &resultstring[0], widesize);


		if (convresult != widesize)
		{
			throw std::exception("La falla!");
		}

		return std::wstring(&resultstring[0]);
	}
	//Unicode 转 Utf8
	static std::string Unicode2Utf8(const std::wstring& widestring)
	{
		int utf8size = ::WideCharToMultiByte(CP_UTF8, 0, widestring.c_str(), -1, NULL, 0, NULL, NULL);
		if (utf8size == 0)
		{
			throw std::exception("Error in conversion.");
		}

		std::vector<char> resultstring(utf8size);

		int convresult = ::WideCharToMultiByte(CP_UTF8, 0, widestring.c_str(), -1, &resultstring[0], utf8size, NULL, NULL);

		if (convresult != utf8size)
		{
			throw std::exception("La falla!");
		}

		return std::string(&resultstring[0]);
	}
	//ascii 转 Utf8
	static std::string Ascii2Utf8(const std::string& strAsciiCode)
	{
		std::string strRet("");
		//先把 ascii 转为 unicode
		std::wstring wstr = Acsii2Unicode(strAsciiCode);
		//最后把 unicode 转为 utf8
		strRet = Unicode2Utf8(wstr);
		return strRet;
	}
#pragma endregion
#pragma region PROCESS
	static PVOID GetProcessModuleBase(DWORD uPid, const wchar_t* pModuleName)
	{
		PVOID Result = NULL;
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32W moduleEntry = { 0 };
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, uPid);
		if (hModuleSnap == INVALID_HANDLE_VALUE) {
			return NULL;
		}
		moduleEntry.dwSize = sizeof(moduleEntry);
		if (Module32First(hModuleSnap, &moduleEntry)) {
			do {
				if (_wcsicmp(moduleEntry.szModule, pModuleName) == 0) {
					Result = moduleEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hModuleSnap, &moduleEntry));
		}
		CloseHandle(hModuleSnap);
		return Result;
	}

	//[[[[[[WXWork.exe+0x079D12E8]+0x0]+0x44]+0x104]+0x5C]+0x0]
	static bool ReadProcessMemoryByFormat(HANDLE hProcess, const char* format, PVOID Buffer, size_t Size)
	{
		std::regex reg("^\\[?(.*)\\+(.*?)\\]?$");
		std::cmatch m;
		if (!std::regex_match(format, m, reg) || m.size() == 0)
		{
			return false;
		}
		std::string sub_format = m[1].str();
		PVOID BaseAddress = 0;
		DWORD Offset = 0;
		//计算Offset base
		if (sub_format != "")
		{
			if (std::regex_match(sub_format, reg))
			{
				if (!ReadProcessMemoryByFormat(hProcess, sub_format.c_str(), &BaseAddress, sizeof(BaseAddress)))
				{
					return false;
				}
			}
			else
			{
				if (hProcess == GetCurrentProcess())
				{
					BaseAddress = GetModuleHandleA(sub_format.c_str());
				}
				else
				{
					BaseAddress = GetProcessModuleBase(GetProcessId(hProcess), Acsii2Unicode(sub_format).c_str());
				}
				if (BaseAddress == NULL)
				{
					return false;

				}
			}
		}
		//计算Offset
		if (m[2].str() != "")
		{
			char* str;
			Offset = (DWORD)strtol(m[2].str().c_str(), &str, 16);
		}
		PVOID ReadAddress = (PVOID)((SIZE_T)BaseAddress + Offset);
		if (ReadAddress == NULL)
		{
			return false;
		}
		if (hProcess == GetCurrentProcess())
		{
			if (IsBadReadPtr(ReadAddress, Size))
			{
				return false;
			}
			else
			{
				memcpy(Buffer, ReadAddress, Size);
				return true;
			}
		}
		else
		{
			SIZE_T ReadSize = 0;
			if (!ReadProcessMemory(hProcess, ReadAddress, Buffer, Size, &ReadSize) || Size != ReadSize)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}

#pragma endregion

#pragma region WINDOW
	//一级窗口类>二级窗口类>三级窗口类....
	template<typename FUN> //[&](HWND hwnd)->bool 返回true停止枚举
	static void EnumWindowsByFormat(LPCSTR Format, FUN fun)
	{
		std::smatch match;
		std::regex rgx("([^><]+)<?([^><]*)>?");
		std::string text_str(Format);

		auto pWndParents = new std::vector<HWND>();
		auto pWndChildAfters = new std::vector<HWND>();
		pWndChildAfters->push_back(NULL);
		while (std::regex_search(text_str, match, rgx))
		{
			std::swap(pWndParents, pWndChildAfters);
			pWndChildAfters->clear();

			std::string szClass_str = match[1].str();
			std::string szWindow_str = match[2].str();
			for (HWND hWndParent : *pWndParents)
			{
				HWND hWndChildAfter = NULL;
				while (hWndChildAfter = FindWindowExA(hWndParent, hWndChildAfter, szClass_str.c_str(), NULL))
				{
					if (szWindow_str != "")
					{
						char szWindow_buffer[512] = { 0 };
						GetWindowTextA(hWndChildAfter, szWindow_buffer, sizeof(szWindow_buffer) - 1);
						if (std::string(szWindow_buffer).find(szWindow_str) == std::string::npos)
						{
							continue;
						}
					}
					pWndChildAfters->push_back(hWndChildAfter);
				}
			}
			if (pWndChildAfters->size() == 0)
			{
				break;
			}
			text_str = match.suffix().str();
		}
		for (HWND hWnd : *pWndChildAfters)
		{
			if (fun(hWnd))
			{
				break;
			}
		}
		delete pWndParents;
		delete pWndChildAfters;
	}

	static HWND FindWindowByCurrentProcess(LPCWSTR lpClassName, LPCWSTR lpWindowName)
	{
		HWND hWndChildAfter = NULL;
		hWndChildAfter = FindWindowExW(NULL, hWndChildAfter, lpClassName, lpWindowName);
		while (hWndChildAfter)
		{
			DWORD dWndPid = 0;
			GetWindowThreadProcessId(hWndChildAfter, &dWndPid);
			if (dWndPid == GetCurrentProcessId())
			{
				return hWndChildAfter;
			}
		}
		return NULL;
	}

	template<typename FUN>
	static bool ToWindowThreadCall(HWND hWnd, FUN fun) noexcept
	{
		const int WM_EXECUTE_PROC = WM_USER + 1213;
		DWORD WndProcessId = 0;
		DWORD WndThreadId = GetWindowThreadProcessId(hWnd, &WndProcessId);
		if (WndThreadId == GetCurrentThreadId())
		{
			fun();
			return true;
		}
		if (WndProcessId != GetCurrentProcessId())
		{
			return false;
		}
		bool result = false;
		HHOOK hHook = SetWindowsHookExW(WH_CALLWNDPROC, [](int code, WPARAM wParam, LPARAM lParam)
			{
				LPCWPSTRUCT pCWPStruct = (LPCWPSTRUCT)lParam;
				if (WM_EXECUTE_PROC == pCWPStruct->message)
				{
					(*(FUN*)pCWPStruct->wParam)();
					return 0;
				}
				else
				{
					return CallNextHookEx(NULL, code, wParam, lParam);
				}
			}, NULL, WndThreadId);
		if (hHook)
		{
			SendMessage(hWnd, WM_EXECUTE_PROC, (WPARAM)&fun, NULL);
			result = true;
			UnhookWindowsHookEx(hHook);
		}
	}
#pragma endregion
}