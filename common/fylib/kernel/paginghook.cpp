#include <ntifs.h>
#include "../fylib.hpp"
#include "paginghook.h"
#pragma warning(disable:4996)
#pragma warning(disable:4201)

namespace paginghook
{
	typedef struct _CR3
	{
		union
		{
			unsigned __int64 Value;
			struct
			{
				unsigned __int64 Pcid : 12;
				unsigned __int64 PageFrameNumber : 36;
				unsigned __int64 Reserved1 : 12;
				unsigned __int64 Reserved2 : 3;
				unsigned __int64 PcidInvalidate : 1;
			};
		};
	}CR3;

	static PVOID ntoskrnl_base_ = nullptr;
	static ULONG ntoskrnl_size_ = 0;
	static PVOID new_ntoskrnl_base_ = nullptr;

	//1 pdpt,512 pd
	static FYLIB::PME* new_pdpt_table_ = nullptr;
	static FYLIB::PME* new_pd_tables_ = nullptr;
	static FYLIB::PME* new_pt_tables_ = nullptr;

	static FYLIB::PME pml4_value_{};
	static FYLIB::PME new_pml4_value_{};

	static PEPROCESS process_list_[0x200] = { nullptr };

	bool Initialize()
	{
		PHYSICAL_ADDRESS PhysicalAddress{};
		if (!new_ntoskrnl_base_)
		{
			bool success = false;
			do
			{
				ntoskrnl_base_ = FYLIB::GetSystemModuleBase("ntoskrnl.exe", &ntoskrnl_size_);
				if (!ntoskrnl_base_)
					break;

				FYLIB::ADDRESS ntoskrnl_begin_address(ntoskrnl_base_);
				FYLIB::ADDRESS ntoskrnl_end_address((ULONG64)ntoskrnl_base_ + ntoskrnl_size_);
				//申请页表内存
				ULONG64 pd_number = ntoskrnl_end_address.pd_number - ntoskrnl_begin_address.pd_number + 1;
				new_pdpt_table_ = (FYLIB::PME*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'PME');
				new_pd_tables_ = (FYLIB::PME*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'PME');
				new_pt_tables_ = (FYLIB::PME*)ExAllocatePoolWithTag(NonPagedPool, pd_number * PAGE_SIZE, 'PME');
				if (!new_pdpt_table_ || !new_pd_tables_ || !new_pt_tables_)
					break;

				pml4_value_ = *ntoskrnl_begin_address.Pml4Ptr();
				new_pml4_value_ = pml4_value_;
				new_pml4_value_.page_frame_number = MmGetPhysicalAddress(new_pdpt_table_).QuadPart >> 12;

				//复制原pdpt_table
				PhysicalAddress.QuadPart = ntoskrnl_begin_address.Pml4Ptr()->page_frame_number << 12;
				FYLIB::PME* sou_pdpt_table = (FYLIB::PME*)MmGetVirtualForPhysical(PhysicalAddress);
				if (!sou_pdpt_table)
					break;
				memcpy(new_pdpt_table_, sou_pdpt_table, PAGE_SIZE);
				new_pdpt_table_[ntoskrnl_begin_address.pdpt_index].page_frame_number = MmGetPhysicalAddress(new_pd_tables_).QuadPart >> 12;
				//复制原pd_table
				PhysicalAddress.QuadPart = sou_pdpt_table[ntoskrnl_begin_address.pdpt_index].page_frame_number << 12;
				FYLIB::PME* sou_pd_table = (FYLIB::PME*)MmGetVirtualForPhysical(PhysicalAddress);
				if (!sou_pd_table)
					break;
				memcpy(new_pd_tables_, sou_pd_table, PAGE_SIZE);

				for (ULONG64 pd_index = 0; pd_index < pd_number; pd_index++)
				{
					new_pd_tables_[ntoskrnl_begin_address.pd_index + pd_index] = sou_pd_table[ntoskrnl_begin_address.pd_index + pd_index];
					if (sou_pd_table[ntoskrnl_begin_address.pd_index + pd_index].present)
					{
						FYLIB::PME* new_pt_table = new_pt_tables_ + pd_index * 512;
						if (!sou_pd_table[ntoskrnl_begin_address.pd_index + pd_index].large_page)
						{
							PhysicalAddress.QuadPart = sou_pd_table[ntoskrnl_begin_address.pd_index + pd_index].page_frame_number << 12;
							FYLIB::PME* sou_pt_table = (FYLIB::PME*)MmGetVirtualForPhysical(PhysicalAddress);
							memcpy(new_pt_table, sou_pt_table, PAGE_SIZE);
						}
						else
						{
							for (ULONG64 pt_index = 0; pt_index < 512; pt_index++)
							{
								new_pt_table[pt_index] = sou_pd_table[ntoskrnl_begin_address.pd_index + pd_index];
								new_pt_table[pt_index].large_page = 0;
								new_pt_table[pt_index].page_frame_number += pt_index;
							}
						}
					}
				}
				//申请与ntoskrnl相同大小内存
				new_ntoskrnl_base_ = ExAllocatePoolWithTag(NonPagedPool, ntoskrnl_size_, 'PME');
				if (!new_ntoskrnl_base_)
					break;
				memcpy(new_ntoskrnl_base_, ntoskrnl_base_, ntoskrnl_size_);

				ULONG64 map_begin_address = (ULONG64)ntoskrnl_base_ & ~(FYLIB::ADDRESS::PD_SIZE - 1);
				PVOID section_base;
				ULONG section_size;
				ULONG64 section_pt_count;
				ULONG64 begin_pt_index;
				PUCHAR new_section_base;
				//重新map ntoskrnl .text段
				section_base = FYLIB::IMAGE::GetSectionBase(ntoskrnl_base_, ".text", &section_size);
				section_pt_count = section_size / PAGE_SIZE + (section_size % PAGE_SIZE ? 1 : 0);
				new_section_base = (PUCHAR)new_ntoskrnl_base_ + ((ULONG64)section_base - (ULONG64)ntoskrnl_base_);
				begin_pt_index = ((ULONG64)section_base - map_begin_address) / PAGE_SIZE;

				for (ULONG64 pt_index = 0; pt_index < section_pt_count; pt_index++)
				{
					new_pt_tables_[begin_pt_index + pt_index].page_frame_number = MmGetPhysicalAddress(new_section_base + pt_index * PAGE_SIZE).QuadPart >> 12;
				}
				//重新map ntoskrnl PAGE段
				section_base = FYLIB::IMAGE::GetSectionBase(ntoskrnl_base_, "PAGE", &section_size);
				section_pt_count = section_size / PAGE_SIZE + (section_size % PAGE_SIZE ? 1 : 0);
				new_section_base = (PUCHAR)new_ntoskrnl_base_ + ((ULONG64)section_base - (ULONG64)ntoskrnl_base_);
				begin_pt_index = ((ULONG64)section_base - map_begin_address) / PAGE_SIZE;
				for (ULONG64 pt_index = 0; pt_index < section_pt_count; pt_index++)
				{
					new_pt_tables_[begin_pt_index + pt_index].page_frame_number = MmGetPhysicalAddress(new_section_base + pt_index * PAGE_SIZE).QuadPart >> 12;
				}

				FYLIB::INLINEHOOK::Initialize([](PVOID _Des, PVOID _Src, size_t _Size)->bool
					{
						if (_Des >= ntoskrnl_base_ && (ULONG64)_Des + _Size <= (ULONG64)ntoskrnl_base_ + ntoskrnl_size_)
						{
							PVOID newDes = (PUCHAR)new_ntoskrnl_base_ + ((ULONG64)_Des - (ULONG64)ntoskrnl_base_);
							memcpy(newDes, _Src, _Size);
							return true;
						}
						return false;
					}
				);
				success = true;
			} while (false);
			if (!success)
			{
				if (new_pdpt_table_)
				{
					ExFreePoolWithTag(new_pdpt_table_, 'PME');
					new_pdpt_table_ = nullptr;
				}
				if (new_pd_tables_)
				{
					ExFreePoolWithTag(new_pd_tables_, 'PME');
					new_pd_tables_ = nullptr;
				}
				if (new_pt_tables_)
				{
					ExFreePoolWithTag(new_pt_tables_, 'PME');
					new_pt_tables_ = nullptr;
				}
				if (new_ntoskrnl_base_)
				{
					ExFreePoolWithTag(new_ntoskrnl_base_, 'PME');
					new_ntoskrnl_base_ = nullptr;
				}
			}
		}
		return new_ntoskrnl_base_ != nullptr;
	}
	void Unitialize()
	{
		for (ULONG index = 0; index < sizeof(process_list_) / sizeof(process_list_[0]); index++)
		{
			if (process_list_[index])
			{
				ReplaceMap(process_list_[index]);
			}
		}
		if (new_pdpt_table_)
		{
			ExFreePoolWithTag(new_pdpt_table_, 'PME');
			new_pdpt_table_ = nullptr;
		}
		if (new_pd_tables_)
		{
			ExFreePoolWithTag(new_pd_tables_, 'PME');
			new_pd_tables_ = nullptr;
		}
		if (new_pt_tables_)
		{
			ExFreePoolWithTag(new_pt_tables_, 'PME');
			new_pt_tables_ = nullptr;
		}
		if (new_ntoskrnl_base_)
		{
			ExFreePoolWithTag(new_ntoskrnl_base_, 'PME');
			new_ntoskrnl_base_ = nullptr;
		}
	}
	bool ReplaceMap(PEPROCESS peprocess)
	{
		bool result = false;
		CR3 cr3{};
		cr3.Value = *(ULONG64*)((PUCHAR)peprocess + 0x28);
		DbgBreakPoint();
		FYLIB::WritePhysicalMemory((cr3.PageFrameNumber << 12) + FYLIB::ADDRESS(ntoskrnl_base_).pml4_index * 8, &new_pml4_value_, 8);
		result = true;
		return result;
	}
	void RestoreMap(PEPROCESS peprocess)
	{
		CR3 cr3{};
		cr3.Value = *(ULONG64*)((PUCHAR)peprocess + 0x28);
		FYLIB::WritePhysicalMemory((cr3.PageFrameNumber << 12) + FYLIB::ADDRESS(ntoskrnl_base_).pml4_index * 8, &pml4_value_, 8);
	}
};