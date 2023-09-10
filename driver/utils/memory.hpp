#pragma once
#include "../Standard/base.h"
#include "../pdb/analysis.h"

namespace memory
{
	struct HideRecord
	{
		void* address;
		size_t size;
		size_t index;
		MMPFN* pfnbase;
		uint64_t pfn[512];
		uint32_t attribute[512];
		PEPROCESS process;
	};

	class PageTableUtils
	{
	public:
		PageTableUtils()
		{
			cr3 system_cr3{ .flags = __readcr3() };
			PHYSICAL_ADDRESS physical_address{ .QuadPart = static_cast<LONGLONG>(system_cr3.address_of_page_directory << 12) };
			pt_entry_64* pml4t = reinterpret_cast<pt_entry_64*>(MmGetVirtualForPhysical(physical_address));

			for (uint64_t i = 0; i < PML4E_ENTRY_COUNT_64; i++) {
				if (pml4t[i].page_frame_number == system_cr3.address_of_page_directory) {
					m_pte_base = (i + 0x1FFFE00ui64) << 39ui64;
					m_pde_base = (i << 30ui64) + m_pte_base;
					m_ppe_base = (i << 30ui64) + m_pte_base + (i << 21ui64);
					m_pxe_base = (i << 12ui64) + m_ppe_base;
					break;
				}
			}
		}

		pml4e_64* GetPml4eAddress(uint64_t address)
		{
			uint64_t pml4e_index = (address >> 39) & 0x1FF;
			return reinterpret_cast<pml4e_64*>((pml4e_index * 8) + m_pxe_base);
		}

		pdpte_64* GetPdpteAddress(uint64_t address)
		{
			auto pdpte_index = (address >> 30) & 0x3FFFF;
			return reinterpret_cast<pdpte_64*>((pdpte_index * 8) + m_ppe_base);
		}

		pde_64* GetPdeAddress(uint64_t address)
		{
			uint64_t pde_index = (address >> 21) & 0x7FFFFFF;
			return reinterpret_cast<pde_64*>((pde_index * 8) + m_pde_base);
		}

		pte_64* GetPteAddress(uint64_t address)
		{
			uint64_t pte_index = (address >> 12) & 0xFFFFFFFFF;
			return reinterpret_cast<pte_64*>((pte_index * 8) + m_pte_base);
		}

		pt_entry_64* CreatePageTable()
		{
			PHYSICAL_ADDRESS low_physical_address{ .QuadPart = 0 };
			PHYSICAL_ADDRESS hight_physical_address{ .QuadPart = -1 };
			PHYSICAL_ADDRESS boundary_physical_address{ .QuadPart = 0 };
			void* page_table = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low_physical_address, hight_physical_address, boundary_physical_address, MmCached);
			if (page_table) {
				RtlZeroMemory(page_table, PAGE_SIZE);
			}
			else {
				LOG_ERROR("failed");
			}
			return reinterpret_cast<pt_entry_64*>(page_table);
		}

		pt_entry_64* GetPageTable(uint64_t page_number)
		{
			PHYSICAL_ADDRESS physical_address{ .QuadPart = static_cast<LONGLONG>(page_number << 12) };
			return reinterpret_cast<pt_entry_64*>(MmGetVirtualForPhysical(physical_address));
		}

		uint64_t GetPageNumber(void* address)
		{
			return MmGetPhysicalAddress(address).QuadPart >> 12;
		}

		void FreePageTable(void* pointer)
		{
			MmFreeContiguousMemorySpecifyCache(pointer, PAGE_SIZE, MmCached);
			pointer = nullptr;
			return;
		}

		void CopyPageTable(pt_entry_64* destination, pt_entry_64* source)
		{
			for (uint64_t i = 0; i < 512; i++) {
				destination[i] = source[i];
			}
			return;
		}

		void SplitLargePage(pde_64* pde, pt_entry_64* page_table)
		{
			uint64_t start_pfn = pde->page_frame_number;
			for (uint64_t i = 0; i < 512; i++) {
				page_table[i].flags = pde->flags;
				page_table[i].large_page = 0;
				page_table[i].page_frame_number = start_pfn + i;
			}
			return;
		}

	private:
		uint64_t m_pte_base;
		uint64_t m_pde_base;
		uint64_t m_ppe_base;
		uint64_t m_pxe_base;
	};

	class MemoryUtils : public Singleton<MemoryUtils>
	{
	public:

		MemoryUtils()
		{
			NOTHING;
		}

		~MemoryUtils()
		{
			NOTHING;
		}

		template<typename _VA> NTSTATUS HideMemory(_VA temp, size_t size)
		{
			//参数校验
			void* virtual_address = (void*)temp;
			if (virtual_address == 0 || !MmIsAddressValid(virtual_address)) {
				LOG_WARN("invalid address");
				return STATUS_INVALID_ADDRESS;
			}

			//获取MmGetVirtualForPhysical
			UNICODE_STRING name{};
			RtlInitUnicodeString(&name, L"MmGetVirtualForPhysical");
			uint8_t* address = static_cast<uint8_t*>(MmGetSystemRoutineAddress(&name));
			if (address == 0) {
				LOG_WARN("get MmGetVirtualForPhysical failed");
				return STATUS_UNSUCCESSFUL;
			}

			//获取mmpfndatabase
			MMPFN* pfnbase = 0;
			for (int i = 0; address[i] != 0xc3; i++) {
				if (address[i] == 0x48 && address[i + 1] == 0xb8 && address[i + 2] == 0x08) {
					pfnbase = reinterpret_cast<MMPFN*>(((*reinterpret_cast<uint64_t*>(address + i + 2)) - 8));
					break;
				}
			}

			if (pfnbase == 0) {
				LOG_WARN("get MmPfnDataBase failed");
				return STATUS_UNSUCCESSFUL;
			}

			HideRecord record{};
			record.address = virtual_address;
			record.size = size;
			record.pfnbase = pfnbase;
			record.process = PsGetCurrentProcess();
			uint64_t start = reinterpret_cast<uint64_t>(PAGE_ALIGN(virtual_address));
			uint64_t end = reinterpret_cast<uint64_t>(PAGE_ALIGN(start + size));
			int i = 0;
			while (end > start) {
				//修改原始pte
				uint64_t pfn = MmGetPhysicalAddress(reinterpret_cast<void*>(start)).QuadPart >> 12;
				record.pfn[i] = pfn;

				uint32_t attribute = pfnbase[pfn].OriginalPte.u.Soft.Protection;
				record.attribute[i] = attribute;

				pfnbase[pfn].OriginalPte.u.Soft.Protection = MM_NOACCESS;

				LOG_INFO("base: %llx address: %llx, pfn: %llx, i: %d", pfnbase, start, pfn, i);
				start += PAGE_SIZE;
				i++;
			}
			record.index = i;
			this->m_record.push_back(record);
			return STATUS_SUCCESS;
		}

		template<typename _VA> NTSTATUS HideMemory(HANDLE pid, _VA temp, size_t size)
		{
			//获取进程
			PEPROCESS process = nullptr;
			auto status = PsLookupProcessByProcessId(pid, &process);
			if (!NT_SUCCESS(status)) {
				LOG_WARN("get PsLookupProcessByProcessId failed status: %llx", status);
				return status;
			}

			if (PsGetProcessExitStatus(process) == 0x103) {
				LOG_WARN("process is termination");
				ObDereferenceObject(process);
				return STATUS_PROCESS_IS_TERMINATING;
			}

			//参数校验
			void* virtual_address = (void*)temp;
			if (virtual_address == 0 || !MmIsAddressValid(virtual_address)) {
				LOG_WARN("invalid address");
				return STATUS_INVALID_ADDRESS;
			}

			//获取MmGetVirtualForPhysical
			UNICODE_STRING name{};
			RtlInitUnicodeString(&name, L"MmGetVirtualForPhysical");
			uint8_t* address = static_cast<uint8_t*>(MmGetSystemRoutineAddress(&name));
			if (address == 0 || !MmIsAddressValid(address)) {
				LOG_WARN("get MmGetVirtualForPhysical failed");
				return STATUS_UNSUCCESSFUL;
			}

			//获取mmpfndatabase
			MMPFN* pfnbase = 0;
			for (int i = 0; address[i] != 0xc3; i++) {
				if (address[i] == 0x48 && address[i + 1] == 0xb8 && address[i + 2] == 0x08) {
					pfnbase = reinterpret_cast<MMPFN*>(((*reinterpret_cast<uint64_t*>(address + i + 2)) - 8));
					break;
				}
			}

			if (pfnbase == 0) {
				LOG_WARN("get MmPfnDataBase failed");
				return STATUS_UNSUCCESSFUL;
			}

			//附加
			KAPC_STATE apc{};
			KeStackAttachProcess(process, &apc);

			HideRecord record{};
			record.address = virtual_address;
			record.size = size;
			record.pfnbase = pfnbase;
			record.process = process;
			uint64_t start = reinterpret_cast<uint64_t>(PAGE_ALIGN(virtual_address));
			uint64_t end = reinterpret_cast<uint64_t>(PAGE_ALIGN(start + size));
			int i = 0;
			while (end > start) {
				//修改原始pte
				uint64_t pfn = MmGetPhysicalAddress(reinterpret_cast<void*>(start)).QuadPart >> 12;
				record.pfn[i] = pfn;

				uint32_t attribute = pfnbase[pfn].OriginalPte.u.Soft.Protection;
				record.attribute[i] = attribute;
				pfnbase[pfn].OriginalPte.u.Soft.Protection = MM_NOACCESS;

				LOG_INFO("MmPfnDataBase: %llx VritualAddress: %llx, pfn: %llx, i: %d", pfnbase, start, pfn, i);
				start += PAGE_SIZE;
				i++;
			}
			record.index = i;
			this->m_record.push_back(record);

			KeUnstackDetachProcess(&apc);
			ObDereferenceObject(process);
			return status;
		}

		template<typename _VA> NTSTATUS RecovreMemory(_VA temp)
		{
			void* virtual_address = (void*)temp;
			if (virtual_address == 0) {
				LOG_WARN("invalid address");
				return STATUS_INVALID_ADDRESS;
			}

			for (auto it = this->m_record.begin(); it != this->m_record.end();) {
				HideRecord record = *it;
				if (record.address == virtual_address) {
					KAPC_STATE apc{};
					KeStackAttachProcess(record.process, &apc);
					for (int i = 0; i < record.index; i++) {
						record.pfnbase[record.pfn[i]].OriginalPte.u.Soft.Protection = record.attribute[i];
						LOG_INFO("base: %llx, pfn: %llx, i: %d", record.pfnbase, record.pfn[i], i);
					}
					KeUnstackDetachProcess(&apc);
					it = this->m_record.erase(it);
					break;
				}
				else {
					it++;
				}
			}
			return STATUS_SUCCESS;
		}
	private:
		std::list<HideRecord> m_record;
	};
}