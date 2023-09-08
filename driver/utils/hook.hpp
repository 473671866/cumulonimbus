#pragma once
#include "../Standard/base.h"
#include "../hde/hde.h"
#include "./memory.hpp"

#define HOOK_FLAG 'hook'
#define POOL_FLAG 'rest'

namespace hook_engine
{
	struct HookRecord
	{
		char* srcbyte[28];					//保存原有字节
		uint64_t bytesize;					//保存字节的长度
		uint64_t forword;					//原函数的CALL
		uint64_t address;					//原函数地址
		uint64_t handler;					//新函数地址
		uint64_t recover;					//没有被破坏的地址
		uint64_t success;					//是否HOOK成功
	};

	struct PteHookRecord
	{
		void* pdpt;
		void* pd;
		void* pt;
		void* page;
		void* trampline;
		uint64_t pml4e_page_number;
		uint64_t address;
		PEPROCESS process;
	};

	union VirtualAddressHelper
	{
		struct
		{
			uint64_t reserved : 12;
			uint64_t pte : 9;
			uint64_t pde : 9;
			uint64_t pdpte : 9;
			uint64_t pml4e : 9;
		};
		uint64_t flags;
	};

	constexpr uint8_t jmp_code[] =
	{
		0x68, 0x00, 0x00, 0x00, 0x00,					//push low 32bit +1
		0xC7, 0x44 ,0x24 ,0x04, 0x00, 0x00, 0x00, 0x00, //mov dword[rsp + 4] +9
		0xC3											//ret
	};

	class InlineHook :public Singleton<InlineHook>
	{
	public:
		InlineHook()
		{
			ExInitializeResourceLite(&this->m_mutex);
			ExInitializeNPagedLookasideList(&this->m_lookaside, NULL, NULL, NULL, sizeof(HookRecord), HOOK_FLAG, NULL);
		}

		~InlineHook()
		{
			KeEnterCriticalRegion();
			ExAcquireResourceExclusiveLite(&this->m_mutex, true);

			for (auto it = this->m_record_list.begin(); it != this->m_record_list.end(); it++) {
				HookRecord* record = *it;
				if (record->success) {
					void* p = MmMapIoSpace(MmGetPhysicalAddress((void*)record->address), 0x40, MmNonCached);
					if (p != nullptr) {
						RtlCopyMemory(p, record->srcbyte, record->bytesize);
						ExFreePoolWithTag((void*)record->forword, POOL_FLAG);
						ExFreeToNPagedLookasideList(&this->m_lookaside, record);
						MmUnmapIoSpace(p, 0x40);
						record = nullptr;
						LOG_INFO("Inline Hook: delete hook success address: %llx", record->address);
					}
				}
				it = this->m_record_list.erase(it);
			}

			KeLeaveCriticalRegion();
			ExReleaseResourceLite(&this->m_mutex);
			ExDeleteResourceLite(&this->m_mutex);
			ExDeleteNPagedLookasideList(&this->m_lookaside);
			return;
		}

		template<typename _Fn, typename _Or> boolean Install(_Fn function, void* handler, _Or original)
		{
			uint64_t address = (uint64_t)function;
			if (address == 0 || handler == nullptr || original == nullptr) {
				LOG_INFO("Inline Hook: invalid address: %llx, handle: %llx", address, handler);
				return false;
			}

			if (this->LookupRecord(address) != nullptr) {
				LOG_WARN("Inline Hook: installed address: %llx, handle: %llx", address, handler);
				return false;
			}

			HookRecord* record = static_cast<HookRecord*>(ExAllocateFromNPagedLookasideList(&this->m_lookaside));
			if (record == nullptr) {
				LOG_WARN("Inline Hook: builder record failed\n");
				return false;
			}

			char* trampline = static_cast<char*>(ExAllocatePoolWithTag(NonPagedPool, 60, POOL_FLAG));
			if (trampline == nullptr) {
				LOG_WARN("Inline Hook: builder trampline failed\n");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				return false;
			}

			void* p = MmMapIoSpace(MmGetPhysicalAddress((void*)address), 0x40, MmNonCached);
			if (p == nullptr) {
				LOG_WARN("Inline Hook: map address: %llx failed\n", address);
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				return false;
			}

			KeEnterCriticalRegion();
			ExAcquireResourceExclusiveLite(&this->m_mutex, true);

			int32_t length = 0;
			uint8_t* temp = reinterpret_cast<uint8_t*>(address);
			hde64s hde{};
			while (length <= 14) {
				hde64_disasm(temp, &hde);
				length += hde.len;
				temp += hde.len;
			}

			//trampline
			uint8_t recover[14]{ 0xff, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			*(uint64_t*)&recover[6] = (uint64_t)temp;
			RtlCopyMemory(record->srcbyte, (char*)address, length);
			RtlCopyMemory(trampline, record->srcbyte, length);
			RtlCopyMemory(trampline + length, recover, sizeof(recover));

			//hook
			uint8_t forword[14]{ 0xff, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			*(uint64_t*)&forword[6] = (uint64_t)handler;
			RtlCopyMemory(p, forword, sizeof(forword));

			*(void**)original = trampline;
			record->bytesize = length;
			record->forword = reinterpret_cast<uint64_t>(trampline);
			record->recover = reinterpret_cast<uint64_t>(temp);
			record->address = address;
			record->handler = reinterpret_cast<uint64_t>(handler);
			record->success = true;
			this->m_record_list.push_back(record);
			MmUnmapIoSpace(p, 0x40);
			KeLeaveCriticalRegion();
			ExReleaseResourceLite(&this->m_mutex);
			LOG_INFO("Inline Hook: hook success address: %llx", address);
			return true;
		}

		template<typename _Fn>  boolean Delete(_Fn function)
		{
			uint64_t address = (uint64_t)function;
			if (address == 0) {
				LOG_WARN("invalid address");
				return false;
			}

			HookRecord* record = this->LookupRecord(address);
			if (record == nullptr || record->success == false) {
				LOG_WARN("invalid address or hook");
				return false;
			}

			void* p = MmMapIoSpace(MmGetPhysicalAddress((void*)record->address), 0x40, MmNonCached);
			if (p == nullptr) {
				LOG_WARN("map %llx failed", record->address);
				return false;
			}

			//加锁
			KeEnterCriticalRegion();
			ExAcquireResourceExclusiveLite(&this->m_mutex, true);

			RtlCopyMemory(p, record->srcbyte, record->bytesize);
			ExFreePoolWithTag((void*)record->forword, POOL_FLAG);
			ExFreeToNPagedLookasideList(&this->m_lookaside, record);
			this->m_record_list.remove(record);
			record = nullptr;

			MmUnmapIoSpace(p, 0x40);
			ExReleaseResourceLite(&this->m_mutex);
			KeLeaveCriticalRegion();
			LOG_INFO("Inline Hook: delete hook success address: %llx", address);
			return true;
		}

		HookRecord* LookupRecord(uint64_t address)
		{
			auto it = find_if(this->m_record_list.begin(), this->m_record_list.end(),
				[&address](HookRecord* record) {
					return (record->address == address || record->handler == address);
				});

			if (it != this->m_record_list.end()) {
				return *it;
			}
			return nullptr;
		}

	private:
		std::list<HookRecord*>	m_record_list;
		ERESOURCE				m_mutex;
		NPAGED_LOOKASIDE_LIST	m_lookaside;
	};

	class PageTableHook : public Singleton<PageTableHook>
	{
	public:
		PageTableHook()
		{
			KeInitializeSpinLock(&this->m_spin_lock);
			ExInitializeNPagedLookasideList(&this->m_lookaside, NULL, NULL, NULL, sizeof(PteHookRecord), HOOK_FLAG, NULL);
		}

		~PageTableHook()
		{
			ExDeleteNPagedLookasideList(&this->m_lookaside);
		}

		template<typename _Fn, typename _Or> boolean Install(_Fn function, void* handler, _Or original)
		{
			uint64_t address = (uint64_t)function;
			if (address == 0 || handler == nullptr || original == nullptr) {
				LOG_WARN("invalid address: %llx", address);
				return false;
			}

			PteHookRecord* record = reinterpret_cast<PteHookRecord*>(ExAllocateFromNPagedLookasideList(&this->m_lookaside));
			if (record == nullptr) {
				LOG_WARN("builder PteHookRecord failed");
				return false;
			}

			//获取页表
			PageTableUtils page_table;

			pt_entry_64* new_pdpt = page_table.CreatePageTable();
			if (new_pdpt == nullptr) {
				LOG_WARN("create pdpdtt failed");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				return false;
			}

			pt_entry_64* new_pd = page_table.CreatePageTable();
			if (new_pd == nullptr) {
				LOG_WARN("create pdt failed");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				page_table.FreePageTable(new_pdpt);
				return false;
			}

			pt_entry_64* new_pt = page_table.CreatePageTable();
			if (new_pt == nullptr) {
				LOG_WARN("create ptt failed");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				page_table.FreePageTable(new_pdpt);
				page_table.FreePageTable(new_pd);
				return false;
			}

			void* hook_page = page_table.CreatePageTable();
			if (hook_page == nullptr) {
				LOG_WARN("create page failed");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				page_table.FreePageTable(new_pdpt);
				page_table.FreePageTable(new_pd);
				page_table.FreePageTable(new_pt);
				return false;
			}

			//复制pdpte
			pml4e_64* pml4e = page_table.GetPml4eAddress(address);
			pt_entry_64* pdpt = page_table.GetPageTable(pml4e->page_frame_number);
			page_table.CopyPageTable(new_pdpt, pdpt);

			//复制pde
			pdpte_64* pdpte = page_table.GetPdpteAddress(address);
			pt_entry_64* pd = page_table.GetPageTable(pdpte->page_frame_number);
			page_table.CopyPageTable(new_pd, pd);

			//复制pte
			pde_64* pde = page_table.GetPdeAddress(address);
			pt_entry_64* pt = nullptr;
			if (pde->present == true) {
				if (pde->large_page == true) {
					//大页
					page_table.SplitLargePage(pde, new_pt);
				}
				else {
					//小页
					pt = page_table.GetPageTable(pde->page_frame_number);
					page_table.CopyPageTable(new_pt, pt);
				}
			}

			//复制物理页
			RtlCopyMemory(hook_page, PAGE_ALIGN(address), PAGE_SIZE);

			//定位足够长的代码来写jmp code
			size_t length = 0;
			hde64s hde64;
			while (length < 14) {
				hde64_disasm(((uint8_t*)address + length), &hde64);
				length += hde64.len;
			}

			//生成trampline函数
			auto trampline = new unsigned char[0x100];
			ULARGE_INTEGER jmp_to_back{ .QuadPart = address + length };
			RtlCopyMemory(trampline, (void*)address, length);
			RtlCopyMemory(&trampline[length], jmp_code, sizeof(jmp_code));
			RtlCopyMemory(&trampline[length + 1], &jmp_to_back.LowPart, sizeof(uint32_t));
			RtlCopyMemory(&trampline[length + 9], &jmp_to_back.HighPart, sizeof(uint32_t));

			//在新的页面上hook
			uint64_t page_offset = (uint64_t)(address) & 0xFFF;
			uint8_t* hook_page_temp = reinterpret_cast<uint8_t*>(hook_page);
			ULARGE_INTEGER jmp_to_detour = { .QuadPart = (uint64_t)(handler) };
			RtlCopyMemory(&hook_page_temp[page_offset], jmp_code, sizeof(jmp_code));
			RtlCopyMemory(&hook_page_temp[page_offset + 1], &jmp_to_detour.LowPart, sizeof(uint32_t));
			RtlCopyMemory(&hook_page_temp[page_offset + 9], &jmp_to_detour.HighPart, sizeof(uint32_t));

			LOG_INFO("hook address: %llx", address);
			record->pml4e_page_number = pml4e->page_frame_number;
			record->pdpt = new_pdpt;
			record->pd = new_pd;
			record->pt = new_pt;
			record->page = hook_page;
			record->trampline = trampline;
			record->address = address;
			record->process = PsGetCurrentProcess();
			this->m_record_list.push_back(record);

			uint64_t new_pdpt_pfn = page_table.GetPageNumber(new_pdpt);
			uint64_t new_pd_pfn = page_table.GetPageNumber(new_pd);
			uint64_t new_pt_pfn = page_table.GetPageNumber(new_pt);
			uint64_t new_page_pfn = page_table.GetPageNumber(hook_page);

			KIRQL irql{};
			KeAcquireSpinLock(&this->m_spin_lock, &irql);

			VirtualAddressHelper helper{ .flags = address };

			pml4e->page_frame_number = new_pdpt_pfn;

			new_pdpt[helper.pdpte].page_frame_number = new_pd_pfn;

			new_pd[helper.pde].page_frame_number = new_pt_pfn;
			new_pd[helper.pde].large_page = 0;
			new_pd[helper.pde].global = 0;

			new_pt[helper.pte].page_frame_number = new_page_pfn;
			new_pd[helper.pte].global = 0;

			__invlpg(pml4e);

			KeReleaseSpinLock(&this->m_spin_lock, irql);

			*(void**)original = trampline;
			LOG_INFO("hook success address: %llx", address);
			return true;
		}

		template<typename _Fn, typename _Or> boolean Install(HANDLE pid, _Fn function, void* handler, _Or original)
		{
			PEPROCESS process = nullptr;
			auto status = PsLookupProcessByProcessId(pid, &process);
			auto dereference_process = make_scope_exit([process] {if (process)ObDereferenceObject(process); });
			if (!NT_SUCCESS(status)) {
				LOG_WARN("process non existent");
				return false;
			}

			if (PsGetProcessExitStatus(process) != 0x103) {
				LOG_WARN("process is termination");
				return false;
			}

			KAPC_STATE apc{};
			KeStackAttachProcess(process, &apc);
			auto detach = make_scope_exit([&apc] {KeUnstackDetachProcess(&apc)});

			uint64_t address = (uint64_t)function;
			if (address == 0 || handler == nullptr || original == nullptr) {
				LOG_WARN("invalid address: %llx", address);
				return false;
			}

			PteHookRecord* record = reinterpret_cast<PteHookRecord*>(ExAllocateFromNPagedLookasideList(&this->m_lookaside));
			if (record == nullptr) {
				LOG_WARN("builder PteHookRecord failed");
				return false;
			}

			//获取页表
			PageTableUtils page_table;

			pt_entry_64* new_pdpt = page_table.CreatePageTable();
			if (new_pdpt == nullptr) {
				LOG_WARN("create pdpdtt failed");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				return false;
			}

			pt_entry_64* new_pd = page_table.CreatePageTable();
			if (new_pd == nullptr) {
				LOG_WARN("create pdt failed");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				page_table.FreePageTable(new_pdpt);
				return false;
			}

			pt_entry_64* new_pt = page_table.CreatePageTable();
			if (new_pt == nullptr) {
				LOG_WARN("create ptt failed");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				page_table.FreePageTable(new_pdpt);
				page_table.FreePageTable(new_pd);
				return false;
			}

			void* hook_page = page_table.CreatePageTable();
			if (hook_page == nullptr) {
				LOG_WARN("create page failed");
				ExFreeToNPagedLookasideList(&this->m_lookaside, record);
				page_table.FreePageTable(new_pdpt);
				page_table.FreePageTable(new_pd);
				page_table.FreePageTable(new_pt);
				return false;
			}

			//复制pdpte
			pml4e_64* pml4e = page_table.GetPml4eAddress(address);
			pt_entry_64* pdpt = page_table.GetPageTable(pml4e->page_frame_number);
			page_table.CopyPageTable(new_pdpt, pdpt);

			//复制pde
			pdpte_64* pdpte = page_table.GetPdpteAddress(address);
			pt_entry_64* pd = page_table.GetPageTable(pdpte->page_frame_number);
			page_table.CopyPageTable(new_pd, pd);

			//复制pte
			pde_64* pde = page_table.GetPdeAddress(address);
			pt_entry_64* pt = nullptr;
			if (pde->present == true) {
				if (pde->large_page == true) {
					//大页
					page_table.SplitLargePage(pde, new_pt);
				}
				else {
					//小页
					pt = page_table.GetPageTable(pde->page_frame_number);
					page_table.CopyPageTable(new_pt, pt);
				}
			}

			//复制物理页
			RtlCopyMemory(hook_page, PAGE_ALIGN(address), PAGE_SIZE);

			//定位足够长的代码来写jmp code
			size_t length = 0;
			hde64s hde64;
			while (length < 14) {
				hde64_disasm(((uint8_t*)address + length), &hde64);
				length += hde64.len;
			}

			//生成trampline函数
			auto trampline = new unsigned char[0x100];
			ULARGE_INTEGER jmp_to_back{ .QuadPart = address + length };
			RtlCopyMemory(trampline, (void*)address, length);
			RtlCopyMemory(&trampline[length], jmp_code, sizeof(jmp_code));
			RtlCopyMemory(&trampline[length + 1], &jmp_to_back.LowPart, sizeof(uint32_t));
			RtlCopyMemory(&trampline[length + 9], &jmp_to_back.HighPart, sizeof(uint32_t));

			//在新的页面上hook
			uint64_t page_offset = (uint64_t)(address) & 0xFFF;
			uint8_t* hook_page_temp = reinterpret_cast<uint8_t*>(hook_page);
			ULARGE_INTEGER jmp_to_detour = { .QuadPart = (uint64_t)(handler) };
			RtlCopyMemory(&hook_page_temp[page_offset], jmp_code, sizeof(jmp_code));
			RtlCopyMemory(&hook_page_temp[page_offset + 1], &jmp_to_detour.LowPart, sizeof(uint32_t));
			RtlCopyMemory(&hook_page_temp[page_offset + 9], &jmp_to_detour.HighPart, sizeof(uint32_t));

			LOG_INFO("hook address: %llx", address);
			record->pml4e_page_number = pml4e->page_frame_number;
			record->pdpt = new_pdpt;
			record->pd = new_pd;
			record->pt = new_pt;
			record->page = hook_page;
			record->trampline = trampline;
			record->address = address;
			record->process = process;
			this->m_record_list.push_back(record);

			uint64_t new_pdpt_pfn = page_table.GetPageNumber(new_pdpt);
			uint64_t new_pd_pfn = page_table.GetPageNumber(new_pd);
			uint64_t new_pt_pfn = page_table.GetPageNumber(new_pt);
			uint64_t new_page_pfn = page_table.GetPageNumber(hook_page);

			KIRQL irql{};
			KeAcquireSpinLock(&this->m_spin_lock, &irql);

			VirtualAddressHelper helper{ .flags = address };

			pml4e->page_frame_number = new_pdpt_pfn;

			new_pdpt[helper.pdpte].page_frame_number = new_pd_pfn;

			new_pd[helper.pde].page_frame_number = new_pt_pfn;
			new_pd[helper.pde].large_page = 0;
			new_pd[helper.pde].global = 0;

			new_pt[helper.pte].page_frame_number = new_page_pfn;
			new_pd[helper.pte].global = 0;

			__invlpg(pml4e);

			KeReleaseSpinLock(&this->m_spin_lock, irql);

			*(void**)original = trampline;
			LOG_INFO("hook success address: %llx", address);
			return true;
		}

		template<typename _Fn> boolean Delete(_Fn function)
		{
			uint64_t address = (uint64_t)function;
			PteHookRecord* record = LookupRecord(address);
			if (record == nullptr) {
				return false;
			}

			KAPC_STATE apc{};
			KeStackAttachProcess(record->process, &apc);

			PageTableUtils page_table;
			pml4e_64* pml4e = page_table.GetPml4eAddress(record->address);
			uint64_t pfn = record->pml4e_page_number;

			KIRQL irql{};
			KeAcquireSpinLock(&this->m_spin_lock, &irql);

			pml4e->page_frame_number = pfn;
			__invlpg(pml4e);

			KeReleaseSpinLock(&this->m_spin_lock, irql);
			KeUnstackDetachProcess(&apc);

			page_table.FreePageTable(record->pdpt);
			page_table.FreePageTable(record->pd);
			page_table.FreePageTable(record->pt);
			page_table.FreePageTable(record->page);
			delete[] record->trampline;
			record->trampline = nullptr;
			ExFreeToNPagedLookasideList(&this->m_lookaside, record);
			this->m_record_list.remove(record);
			record = nullptr;

			LOG_INFO("PteHook: delete hook address: %llx\n", address);
			return true;
		}

		PteHookRecord* LookupRecord(uint64_t address)
		{
			auto it = find_if(this->m_record_list.begin(), this->m_record_list.end(), [&address](PteHookRecord* record) {return record->address == address; });
			if (it != this->m_record_list.end()) {
				return *it;
			}
			return nullptr;
		}

	private:
		KSPIN_LOCK m_spin_lock;
		std::list<PteHookRecord*>	m_record_list;
		NPAGED_LOOKASIDE_LIST	m_lookaside;
	};
}