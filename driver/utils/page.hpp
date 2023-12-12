#include "../standard/base.h"
#include "../define/ia32.hpp"

namespace utils
{
	class page_table
	{
	public:
		page_table()
		{
			cr3 system_cr3{ .flags = __readcr3() };
			PHYSICAL_ADDRESS physical_address{ .QuadPart = static_cast<long long>(system_cr3.address_of_page_directory << 12) };
			pt_entry_64* pml4t = reinterpret_cast<pt_entry_64*>(MmGetVirtualForPhysical(physical_address));

			for (unsigned __int64 i = 0; i < PML4E_ENTRY_COUNT_64; i++) {
				if (pml4t[i].page_frame_number == system_cr3.address_of_page_directory) {
					m_pte_base = (i + 0x1FFFE00ui64) << 39ui64;
					m_pde_base = (i << 30ui64) + m_pte_base;
					m_ppe_base = (i << 30ui64) + m_pte_base + (i << 21ui64);
					m_pxe_base = (i << 12ui64) + m_ppe_base;
					break;
				}
			}
		}

		/// @brief 获取pml4e
		/// @param address
		/// @return
		pml4e_64* get_pml4e(unsigned __int64 address)
		{
			uint64_t pml4e_index = (address >> 39) & 0x1FF;
			return reinterpret_cast<pml4e_64*>((pml4e_index * 8) + m_pxe_base);
		}

		/// @brief 获取pdpte
		/// @param address
		/// @return
		pdpte_64* get_pdpte(unsigned __int64 address)
		{
			auto pdpte_index = (address >> 30) & 0x3FFFF;
			return reinterpret_cast<pdpte_64*>((pdpte_index * 8) + m_ppe_base);
		}

		/// @brief 获取pte
		/// @param address
		/// @return
		pde_64* get_pde(unsigned __int64 address)
		{
			uint64_t pde_index = (address >> 21) & 0x7FFFFFF;
			return reinterpret_cast<pde_64*>((pde_index * 8) + m_pde_base);
		}

		/// @brief 获取pte
		/// @param address
		/// @return
		pte_64* get_pte(unsigned __int64 address)
		{
			uint64_t pte_index = (address >> 12) & 0xFFFFFFFFF;
			return reinterpret_cast<pte_64*>((pte_index * 8) + m_pte_base);
		}

		/// @brief 创建页表
		/// @return
		pt_entry_64* create_page()
		{
			PHYSICAL_ADDRESS low_physical_address{ .QuadPart = 0 };
			PHYSICAL_ADDRESS hight_physical_address{ .QuadPart = -1 };
			PHYSICAL_ADDRESS boundary_physical_address{ .QuadPart = 0 };
			void* page = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low_physical_address, hight_physical_address, boundary_physical_address, MmCached);
			if (page) {
				RtlZeroMemory(page, PAGE_SIZE);
			}
			return reinterpret_cast<pt_entry_64*>(page);
		}

		/// @brief 释放页表
		/// @param address
		void free_page(void* address)
		{
			MmFreeContiguousMemorySpecifyCache(address, PAGE_SIZE, MmCached);
			address = nullptr;
			return;
		}

		/// @brief 获取页表
		/// @param page_number 页帧
		/// @return
		pt_entry_64* get_page_table(unsigned __int64 page_number)
		{
			PHYSICAL_ADDRESS physical_address{ .QuadPart = static_cast<long long>(page_number << 12) };
			return reinterpret_cast<pt_entry_64*>(MmGetVirtualForPhysical(physical_address));
		}

		/// @brief 获取页帧
		/// @param address 地址
		/// @return
		unsigned __int64 get_page_number(void* address)
		{
			return MmGetPhysicalAddress(address).QuadPart >> 12;
		}

		/// @brief 复制页表
		/// @param destination 目标
		/// @param source 原始
		void copy_page(pt_entry_64* destination, pt_entry_64* source)
		{
			for (uint64_t i = 0; i < 512; i++) {
				destination[i] = source[i];
			}
			return;
		}

		/// @brief 分割大页
		/// @param pde
		/// @param table
		void split_page(pde_64* pde, pt_entry_64* table)
		{
			unsigned __int64 start_pfn = pde->page_frame_number;
			for (unsigned __int64 i = 0; i < 512; i++) {
				table[i].flags = pde->flags;
				table[i].large_page = 0;
				table[i].page_frame_number = start_pfn + i;
			}
			return;
		}

	private:
		unsigned __int64 m_pte_base;
		unsigned __int64 m_pde_base;
		unsigned __int64 m_ppe_base;
		unsigned __int64 m_pxe_base;
	};
}