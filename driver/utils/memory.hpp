#pragma once
#include "../Standard/base.h"
#include "../pdb/oxygenPdb.h"

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
			LOG_ERROR("CreatePageTable failed");
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

class MemoryUtils
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

	template<typename _VA> NTSTATUS HideMemory(HANDLE pid, _VA temp)
	{
		void* virtual_address = (void*)temp;
		if (pid == 0 || virtual_address == 0) {
			LOG_WARN("invalid pid or address");
			return STATUS_INVALID_ADDRESS;
		}

		UNICODE_STRING name{};
		RtlInitUnicodeString(&name, L"MmGetVirtualForPhysical");
		uint8_t* address = static_cast<uint8_t*>(MmGetSystemRoutineAddress(&name));
		if (address == 0) {
			LOG_WARN("get MmGetVirtualForPhysical failed");
			return STATUS_UNSUCCESSFUL;
		}

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

		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			LOG_WARN("get PsLookupProcessByProcessId failed status: %llx", status);
			return status;
		}

		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);

		LOG_INFO("MmPfnDataBase: %llx VritualAddress: %llx", pfnbase, virtual_address);
		uint64_t pfn = MmGetPhysicalAddress(PAGE_ALIGN(virtual_address)).QuadPart >> 12;
		pfnbase[pfn].OriginalPte.u.Soft.Protection = MM_NOACCESS;

		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		return status;
	}

	NTSTATUS ReadMemory()
	{
		NOTHING;
	}

	NTSTATUS WriteMemory()
	{
		NOTHING;
	}
};