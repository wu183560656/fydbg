#include "killpg.h"
#include "../fylib.hpp"
#include "../type.hpp"

#pragma warning(disable:4996)

#define PGCONTEXT_MINSIZE 0x40000
struct PGCONTEXT
{
	ULONG64 Address;
	SIZE_T Size;
	bool DisableExecuteAttr;
};
TYPE::FIXEDARRAY<PGCONTEXT, 400, false> g_PGContextArray;

PDRIVER_OBJECT g_DriverObject = NULL;
PDRIVER_UNLOAD g_OldDriverUnload = NULL;
extern"C" PVOID hookKiPageFault = NULL;
extern"C" void AsmKiPageFault();

static PVOID GetKiPageFaultAddress()
{
	PVOID KiPageFault = NULL;
	ULONG64 KiPageFaultShadow = FYLIB::GetIdtProcAddress(0xE);
	PVOID kernelBase = FYLIB::GetSystemModuleBase("ntoskrnl.exe", NULL);
	ULONG TextSectionSize = 0;
	PVOID TextSectionBase = FYLIB::IMAGE::GetSectionBase(kernelBase, ".text", &TextSectionSize);
	if (KiPageFaultShadow >= (ULONG64)TextSectionBase && KiPageFaultShadow < (ULONG64)TextSectionBase + TextSectionSize)
		KiPageFault = (PVOID)KiPageFaultShadow;
	else
	{
		//找一条跳转到.text段的jmp
		for (ULONG i = 0; i < 40; i++)
		{
			FYLIB::INSTRUCTION::HDES hde;
			FYLIB::INSTRUCTION::X64::Disasm((PVOID)KiPageFaultShadow, &hde);
			if (hde.len == 0)
				break;
			if (hde.opcode == 0xE9)
			{
				ULONG64 JmpAddress = KiPageFaultShadow + hde.len + (int)hde.imm.imm32;
				if (JmpAddress >= (ULONG64)TextSectionBase && JmpAddress < (ULONG64)TextSectionBase + TextSectionSize)
				{
					KiPageFault = (PVOID)JmpAddress;
					break;
				}
			}
			KiPageFaultShadow += hde.len;
		}
	}
	return KiPageFault;
}

static bool EnumPGContext(TYPE::FIXEDARRAY<PGCONTEXT, 0x100, false>& Array)
{
	NTSTATUS status;
	PRTL_PROCESS_MODULES pModules = NULL;
	PSYSTEM_BIGPOOL_INFORMATION pBigPool = NULL;
	ULONG BufferSize;
	PGCONTEXT TmpPGContext = { 0 };
	bool result = false;
	do
	{
		//查询所有系统模块
		BufferSize = sizeof(RTL_PROCESS_MODULES);
		pModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'BUF');
		if (!pModules) {
			break;
		}
		status = ZwQuerySystemInformation(SystemModuleInformation, pModules, BufferSize, &BufferSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePoolWithTag(pModules, 'BUF');
			BufferSize += 0x100000;
			pModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'BUF');
			if (pModules)
			{
				status = ZwQuerySystemInformation(SystemModuleInformation, pModules, BufferSize, &BufferSize);
			}
		}
		if (!NT_SUCCESS(status)) {
			break;
		}
		//查询系统所有内存pool
		BufferSize = sizeof(PSYSTEM_BIGPOOL_INFORMATION);
		pBigPool = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'BUF');
		if (!pBigPool) {
			break;
		}
		status = ZwQuerySystemInformation(SystemBigPoolInformation, pBigPool, BufferSize, &BufferSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePoolWithTag(pBigPool, 'BUF');
			BufferSize += 0x100000;
			pBigPool = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'BUF');
			if (pBigPool)
			{
				status = ZwQuerySystemInformation(SystemBigPoolInformation, pBigPool, BufferSize, &BufferSize);
			}
		}
		if (!NT_SUCCESS(status)) {
			break;
		}
		//从BigPool里面找Context
		for (ULONG i = 0; i < pBigPool->Count; i++)
		{
			//大小过滤
			if (!pBigPool->AllocatedInfo[i].NonPaged || pBigPool->AllocatedInfo[i].SizeInBytes < PGCONTEXT_MINSIZE)
				continue;
			ULONG64 BaseAddress = (ULONG64)pBigPool->AllocatedInfo[i].VirtualAddress & 0xfffffffffffff000ULL;
			//去除自己申请的两个内存块
			if (BaseAddress == (ULONG64)pBigPool || BaseAddress == (ULONG64)pModules)
				continue;
			//去除当前模块
			if (((ULONG64)AsmKiPageFault) >= BaseAddress && ((ULONG64)AsmKiPageFault) < BaseAddress + pBigPool->AllocatedInfo[i].SizeInBytes)
				continue;
			//去除系统模块
			bool isModule = false;
			for (ULONG j = 0; j < pModules->NumberOfModules; j++) {
				if (BaseAddress < (ULONG64)pModules->Modules[j].ImageBase + pModules->Modules[j].ImageSize
					&& (ULONG64)pModules->Modules[j].ImageBase < BaseAddress + pBigPool->AllocatedInfo[i].SizeInBytes) {
					isModule = true;
					break;
				}
			}
			if (isModule)
				continue;
			//页表检测
			FYLIB::ADDRESS address = BaseAddress;
			if (!address.Pml4Ptr()->present || address.Pml4Ptr()->execute_disable || !address.Pml4Ptr()->write)
				continue;
			if (!address.PdptPtr()->present || address.PdptPtr()->execute_disable || !address.PdptPtr()->write)
				continue;
			if (!address.PdptPtr()->large_page) {
				if (!address.PdPtr()->present || address.PdPtr()->execute_disable || !address.PdPtr()->write)
					continue;
				if (!address.PdPtr()->large_page) {
					if (!address.PtPtr()->present || address.PtPtr()->execute_disable || !address.PtPtr()->write)
						continue;
				}
			}
			TmpPGContext.Address = BaseAddress;
			TmpPGContext.Size = pBigPool->AllocatedInfo[i].SizeInBytes;
			TmpPGContext.DisableExecuteAttr = false;
			Array.PushBack(TmpPGContext);
		}
		//从非分页内存中找PGCONTEXT
		TmpPGContext = { 0 };

		ULONG64 LastBaseAddress = 0;
		ULONG64 LastSize = 0;
		bool LastWriteExecute = false;
		FYLIB::ADDRESS Address(0x100, 0);
		while (Address.pml4_index >= 0x100)
		{
			ULONG64 CurrentSize;
			bool CurrentWriteExecute;
			do
			{
				//PML4
				if (!Address.Pml4Ptr()->present
					|| !Address.Pml4Ptr()->write || Address.Pml4Ptr()->execute_disable) {
					CurrentSize = FYLIB::ADDRESS::PML4_SIZE;
					CurrentWriteExecute = false;
					break;
				}
				//PDPT
				if (!Address.PdptPtr()->present
					|| !Address.PdptPtr()->write || Address.PdptPtr()->execute_disable) {
					CurrentSize = FYLIB::ADDRESS::PDPT_SIZE;
					CurrentWriteExecute = false;
					break;
				}
				if (Address.PdptPtr()->large_page) {
					CurrentSize = FYLIB::ADDRESS::PDPT_SIZE;
					CurrentWriteExecute = true;
					break;
				}
				//PD
				if (!Address.PdPtr()->present
					|| !Address.PdPtr()->write || Address.PdPtr()->execute_disable) {
					CurrentSize = FYLIB::ADDRESS::PD_SIZE;
					CurrentWriteExecute = false;
					break;
				}
				if (Address.PdPtr()->large_page) {
					CurrentSize = FYLIB::ADDRESS::PD_SIZE;
					CurrentWriteExecute = true;
					break;
				}
				//PT
				if (!Address.PtPtr()->present
					|| !Address.PtPtr()->write || Address.PtPtr()->execute_disable) {
					CurrentSize = FYLIB::ADDRESS::PT_SIZE;
					CurrentWriteExecute = false;
					break;
				}
				CurrentSize = FYLIB::ADDRESS::PT_SIZE;
				CurrentWriteExecute = true;
			} while (false);
			if (LastWriteExecute == CurrentWriteExecute) {
				LastSize += CurrentSize;
			}
			else {
				do
				{
					if (!LastWriteExecute)
						break;
					if (LastSize < PGCONTEXT_MINSIZE)
						break;
					//去除系统模块
					bool isFind = false;
					for (ULONG j = 0; j < pModules->NumberOfModules; j++) {
						if (LastBaseAddress < (ULONG64)pModules->Modules[j].ImageBase + pModules->Modules[j].ImageSize
							&& (ULONG64)pModules->Modules[j].ImageBase < LastBaseAddress + LastSize) {
							isFind = true;
							break;
						}
					}
					if (isFind)
						continue;
					//去除POOL内存
					for (ULONG j = 0; j < pBigPool->Count; j++) {
						ULONG64 BigPoolBaseAddress = (ULONG64)pBigPool->AllocatedInfo[j].VirtualAddress & 0xfffffffffffff000ULL;
						if (LastBaseAddress < BigPoolBaseAddress + pBigPool->AllocatedInfo[j].SizeInBytes
							&& BigPoolBaseAddress < LastBaseAddress + LastSize) {
							isFind = true;
							break;
						}
					}
					if (isFind)
						continue;

					TmpPGContext.Address = LastBaseAddress;
					TmpPGContext.Size = LastSize;
					TmpPGContext.DisableExecuteAttr = false;
					Array.PushBack(TmpPGContext);

				} while (false);
			}
			Address.flags += CurrentSize;
		}
		result = true;
	} while (false);
	if (pModules) {
		ExFreePoolWithTag(pModules, 'BUF');
	}
	if (pBigPool) {
		ExFreePoolWithTag(pBigPool, 'BUF');
	}
	return result;
}

static bool DisableContextExecuteAttr(PGCONTEXT& Context)
{
	bool result = FYLIB::SingleProcessorExecute([&]()
		{
			bool result = true;
			ULONG64 Offset = 0;
			for (; Offset < Context.Size;)
			{
				FYLIB::ADDRESS address(Context.Address + Offset);
				if (!address.Pml4Ptr()->present || !address.PdptPtr()->present)
				{
					result = false;
					break;
				}
				if (address.PdptPtr()->large_page)
				{
					address.PdptPtr()->execute_disable = 1;
					Offset += (512ULL * 512 * PAGE_SIZE) - address.pdpt_offset;
					continue;
				}
				if (!address.PdPtr()->present)
				{
					result = false;
					break;
				}
				if (address.PdPtr()->large_page)
				{
					address.PdPtr()->execute_disable = 1;
					Offset += (512ULL * PAGE_SIZE) - address.pd_offset;
					continue;
				}
				if (!address.PtPtr()->present)
				{
					result = false;
					break;
				}
				address.PtPtr()->execute_disable = 1;
				Offset += (1ULL * PAGE_SIZE) - address.pt_offset;
			}
			return result;
		}
	);
	Context.DisableExecuteAttr = true;
	FYLIB::DebugPrint("KillPatchGuard", "Disable Context Execute Attr(Base:%p,Size:%X) %s.\n",
		Context.Address, Context.Size, result ? "success" : "fail");
	return result;
}
static void RestoreContextExecuteAttr(PGCONTEXT& Context)
{
	FYLIB::SingleProcessorExecute([&]()
		{
			if (Context.DisableExecuteAttr)
			{
				ULONG64 Offset = 0;
				for (; Offset < Context.Size;)
				{
					FYLIB::ADDRESS address(Context.Address + Offset);
					if (!address.Pml4Ptr()->present)
					{
						Offset += (512ULL * 512 * 512 * PAGE_SIZE) - address.pml4_offset;
						continue;
					}
					if (!address.PdptPtr()->present)
					{
						Offset += (512ULL * 512 * PAGE_SIZE) - address.pdpt_offset;
						continue;
					}
					if (address.PdptPtr()->large_page)
					{
						address.PdptPtr()->execute_disable = 0;
						Offset += (512ULL * 512 * PAGE_SIZE) - address.pdpt_offset;
						continue;
					}
					if (!address.PdPtr()->present)
					{
						Offset += (512ULL * PAGE_SIZE) - address.pd_offset;
						continue;
					}
					if (address.PdPtr()->large_page)
					{
						address.PdPtr()->execute_disable = 0;
						Offset += (512ULL * PAGE_SIZE) - address.pd_offset;
						continue;
					}
					if (address.PtPtr()->present)
					{
						address.PtPtr()->execute_disable = 0;
					}
					Offset += (1ULL * PAGE_SIZE) - address.pt_offset;
				}
				Context.DisableExecuteAttr = false;
				FYLIB::DebugPrint("KillPatchGuard", "Enable Context Execute Attr(Base:%p,Size:%X) succsee.\n", Context.Address, Context.Size);
			}
			return 0;
		}
	);
}

extern"C" bool MyKiPageFault(DWORD64 Code, DWORD64* Rip, DWORD64* Rsp)
{
	UNREFERENCED_PARAMETER(Rsp);
	if (Code != 0x11 || *Rip < 0x800000000000)
	{
		return false;
	}
	bool result = false;
	for (auto& Item : g_PGContextArray)
	{
		if (*Rip >= Item.Address && *Rip < Item.Address + Item.Size)
		{
			RestoreContextExecuteAttr(Item);
			FYLIB::INSTRUCTION::HDES hde;
			FYLIB::INSTRUCTION::X64::Disasm((PVOID)*Rip, &hde);
			//xor [rcx],rdx
			if (hde.modrm == 0x11 && hde.opcode == 0x31)
			{
				FYLIB::DebugPrint("KillPatchGuard", "The is a PatchGuard Context\n");
				*Rip = *(DWORD64*)*Rsp;
				*Rsp += 8;
			}
			result = true;
			break;
		}
	}
	return result;
}

static void KStartRoutine(PVOID StartContext) {
#define TIME_INTERVAL 30
	LARGE_INTEGER Timeout = { 0 };
	int EnumEmptyCount = 0;
	Timeout.QuadPart = -10000LL * 1000 * TIME_INTERVAL;
	while (true)
	{
		TYPE::FIXEDARRAY<PGCONTEXT, 0x100, false> Array;
		EnumPGContext(Array);
		FYLIB::DebugPrint("KillPatchGuard", "EnumPGContext Count:%d\n", Array.Size());
		bool IsNew = false;
		for (auto& Item : Array) {
			bool IsNewPGContext = true;
			for (auto& gItem : g_PGContextArray)
			{
				if (gItem.Address < Item.Address + Item.Size
					&& Item.Address < gItem.Address + gItem.Size) {
					//重复
					IsNewPGContext = false;
					break;
				}
			}
			if (IsNewPGContext) {
				FYLIB::DebugPrint("KillPatchGuard", "Scan to new memory Address:%p,Size:%x\n", Item.Address, Item.Size);
				DisableContextExecuteAttr(Item);
				g_PGContextArray.PushBack(Item);
				IsNew = true;
			}
		}
		EnumEmptyCount = IsNew ? 0 : EnumEmptyCount + 1;
		if (EnumEmptyCount > 5) {
			break;
		}
		KeDelayExecutionThread(KernelMode, false, &Timeout);
	}
	FYLIB::DebugPrint("KillPatchGuard", "Success\n");
	FYLIB::INLINEHOOK::Disable(hookKiPageFault);
	FYLIB::INLINEHOOK::Remove(hookKiPageFault);
	hookKiPageFault = NULL;
	while (!g_PGContextArray.Empty())
	{
		auto Item = g_PGContextArray.PopBack();
		RestoreContextExecuteAttr(Item);
	}
	ZwSetEvent((HANDLE)StartContext, NULL);
	if (g_DriverObject && !g_DriverObject->DriverUnload)
	{
		//现在可以卸载了
		g_DriverObject->DriverUnload = g_OldDriverUnload;
	}
	PsTerminateSystemThread(0);
}

#define EVENT_NAME L"\\BaseNamedObjects\\KillPG_Event"
NTSTATUS KillPatchGuard(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	HANDLE EventHandle = NULL;
	UNICODE_STRING EventNameStr;
	RtlInitUnicodeString(&EventNameStr, EVENT_NAME);
	OBJECT_ATTRIBUTES EventAttr = { 0 };
	InitializeObjectAttributes(&EventAttr, &EventNameStr, OBJ_KERNEL_HANDLE, NULL, 0);
	status = ZwOpenEvent(&EventHandle, EVENT_ALL_ACCESS, &EventAttr);
	if (NT_SUCCESS(status))
	{
		//已经存在
		FYLIB::DebugPrint("KillPatchGuard", "\"\\BaseNamedObjects\\KillPG_Event\" Already exists.\n");
		LARGE_INTEGER Integer = { 0 };
		status = ZwWaitForSingleObject(EventHandle, false, &Integer);
		if (status == STATUS_TIMEOUT)
		{
			FYLIB::DebugPrint("KillPatchGuard", "KillPatchGuard Running...\n");
			status = STATUS_PENDING;
		}
		ZwClose(EventHandle);
		return status;
	}

	status = ZwCreateEvent(&EventHandle, EVENT_ALL_ACCESS, &EventAttr, NotificationEvent, false);
	if (!NT_SUCCESS(status))
	{
		FYLIB::DebugPrint("KillPatchGuard", "\"\\BaseNamedObjects\\KillPG_Event\" Create Failed,status:%x\n", status);
		return status;
	}
	//挂载KiPageFault HOOK
	PVOID KiPageFault = GetKiPageFaultAddress();
	if (!KiPageFault)
	{
		FYLIB::DebugPrint("KillPatchGuard", "Get KiPageFault Address failed.\n");
		return STATUS_INVALID_ADDRESS;
	}
	hookKiPageFault = FYLIB::INLINEHOOK::CreateFunction((PVOID)KiPageFault, (PVOID)&AsmKiPageFault, false);
	if (!hookKiPageFault || !FYLIB::INLINEHOOK::Enable(hookKiPageFault))
	{
		FYLIB::DebugPrint("KillPatchGuard", "HOOK KiPageFault Failed.\n");
		if (!hookKiPageFault)
		{
			FYLIB::INLINEHOOK::Remove(hookKiPageFault);
		}
		hookKiPageFault = NULL;
		return STATUS_FAIL_FAST_EXCEPTION;
	}

	FYLIB::DebugPrint("KillPatchGuard", "HOOK KiPageFault succsee.\n");
	g_DriverObject = DriverObject;
	if (g_DriverObject)
	{
		g_OldDriverUnload = g_DriverObject->DriverUnload;
		//临时不允许卸载
		g_DriverObject->DriverUnload = NULL;
	}

	//创建系统线程
	HANDLE ThreadHandle = NULL;
	status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, KStartRoutine, EventHandle);
	if (!NT_SUCCESS(status))
	{
		FYLIB::DebugPrint("KillPatchGuard", "PsCreateSystemThread Failed.\n");
		FYLIB::INLINEHOOK::Disable(hookKiPageFault);
		FYLIB::INLINEHOOK::Remove(hookKiPageFault);
		hookKiPageFault = NULL;
		ZwClose(EventHandle);
		return status;
	}
	FYLIB::DebugPrint("KillPatchGuard", "PsCreateSystemThread success.\n");

	return STATUS_SUCCESS;
}