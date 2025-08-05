#include "kdmapperHelper.h"
#include <iostream>
#include <intel_driver.hpp>
#include <fylib\fylib.hpp>

namespace kdmapperHelper
{
	static HANDLE intel_driver_handle = INVALID_HANDLE_VALUE;
	static ULONG64  g_CiOptions_Address = 0;
	static DWORD32 g_CiOptions_Back = 0;
	bool CancelCiOptions(ULONG g_CiOptions_Offset)
	{
		bool result = false;
		do
		{
			ULONG64 ci = (ULONG64)FYLIB::GetSystemModuleBase("ci.dll", NULL);
			if (!ci)
			{
				std::cout << "ci.dll not found!" << std::endl;
				break;
			}
			g_CiOptions_Address = ci + g_CiOptions_Offset;
			HANDLE intel_driver_handle = intel_driver::Load();
			if (intel_driver_handle == INVALID_HANDLE_VALUE)
			{
				std::cout << "Failed to load intel_driver!" << std::endl;
				break;
			}
			if (!intel_driver::ReadMemory(intel_driver_handle, g_CiOptions_Address, &g_CiOptions_Back, sizeof(g_CiOptions_Back)))
			{
				std::cout << "Failed to read g_CiOptions_Address!" << std::endl;
				break;
			}
			DWORD32 g_CiOptions_Value = 0x00000000;
			if (!intel_driver::WriteMemory(intel_driver_handle, g_CiOptions_Address, &g_CiOptions_Value, sizeof(g_CiOptions_Value)))
			{
				std::cout << "Failed to write g_CiOptions_Address!" << std::endl;
				break;
			}

			result = true;
		} while (false);
		if (!result)
		{
			if (intel_driver_handle != INVALID_HANDLE_VALUE)
			{
				intel_driver::Unload(intel_driver_handle);
				intel_driver_handle = INVALID_HANDLE_VALUE;
			}
			g_CiOptions_Address = 0;
		}
		return result;
	}

	void RestoreCiOptions()
	{
		if (intel_driver_handle == INVALID_HANDLE_VALUE || !g_CiOptions_Address)
		{
			return;
		}
		intel_driver::WriteMemory(intel_driver_handle, g_CiOptions_Address, &g_CiOptions_Back, sizeof(g_CiOptions_Back));
		intel_driver::Unload(intel_driver_handle);
		intel_driver_handle = INVALID_HANDLE_VALUE;
		g_CiOptions_Address = 0;
	}
};
