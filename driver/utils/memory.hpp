#pragma once
#include "../standard/base.h"

namespace utils
{
	struct HideRecord
	{
		HANDLE pid;							//进程id
		PEPROCESS process;					//进程对象
		MMPFN* pfnbase;						//页帧基址
		void* address;						//虚拟地址
		unsigned __int64 size;				//大小
		unsigned __int64 index;				//下标
		unsigned __int64 pfn[512];			//页帧
		unsigned __int32 attribute[512];	//属性
	};

	class memory : public Singleton<memory>
	{
	public:

		memory()
		{
			NOTHING;
		}

		~memory()
		{
			NOTHING;
		}

		/// @brief 隐藏内存
		/// @tparam _VA
		/// @param address 虚拟地址
		/// @param size 大小
		/// @return
		template<typename _VA>
		NTSTATUS hide(_VA address, size_t size)
		{
			//参数校验
			void* virtual_address = (void*)address;
			if (virtual_address == 0 || !MmIsAddressValid(virtual_address)) {
				return STATUS_INVALID_ADDRESS;
			}

			//获取MmGetVirtualForPhysical
			UNICODE_STRING name{};
			RtlInitUnicodeString(&name, L"MmGetVirtualForPhysical");
			unsigned __int8* MmGetVirtualForPhysical = static_cast<unsigned __int8*>(MmGetSystemRoutineAddress(&name));
			if (MmGetVirtualForPhysical == 0) {
				return STATUS_UNSUCCESSFUL;
			}

			//获取mmpfndatabase
			MMPFN* pfnbase = 0;
			for (int i = 0; MmGetVirtualForPhysical[i] != 0xc3; i++) {
				if (MmGetVirtualForPhysical[i] == 0x48 && MmGetVirtualForPhysical[i + 1] == 0xb8 && MmGetVirtualForPhysical[i + 2] == 0x08) {
					pfnbase = reinterpret_cast<MMPFN*>(((*reinterpret_cast<unsigned __int64*>(MmGetVirtualForPhysical + i + 2)) - 8));
					if (pfnbase == 0) {
						return STATUS_UNSUCCESSFUL;
					}
					break;
				}
			}

			//记录
			HideRecord record{};
			record.address = virtual_address;
			record.size = size;
			record.pfnbase = pfnbase;
			record.pid = PsGetCurrentProcessId();
			record.process = PsGetCurrentProcess();

			unsigned __int64 start = reinterpret_cast<unsigned __int64>(PAGE_ALIGN(virtual_address));
			unsigned __int64 end = reinterpret_cast<unsigned __int64>(PAGE_ALIGN(start + size));

			while (end > start) {
				//获取页帧
				uint64_t pfn = MmGetPhysicalAddress(reinterpret_cast<void*>(start)).QuadPart >> 12;
				record.pfn[i] = pfn;

				//保存原始属性
				uint32_t attribute = pfnbase[pfn].OriginalPte.u.Soft.Protection;
				record.attribute[i] = attribute;

				//修改属性
				pfnbase[pfn].OriginalPte.u.Soft.Protection = MM_NOACCESS;

				//更新循环条件
				start += PAGE_SIZE;
				record.index++;
			}

			this->m_record.push_back(record);
			return STATUS_SUCCESS;
		}

		/// @brief 恢复被隐藏的内存
		/// @tparam _VA
		/// @param pid
		/// @param address
		/// @return
		template<typename _VA>
		NTSTATUS recovre(HANDLE pid, _VA address)
		{
			//参数校验
			void* virtual_address = (void*)address;
			if (pid == 0 || virtual_address == 0) {
				return STATUS_INVALID_ADDRESS;
			}

			//恢复属性
			for (auto it = this->m_record.begin(); it != this->m_record.end();) {
				HideRecord record = *it;
				if (record.pid == pid && record.address == virtual_address) {
					KAPC_STATE apc{};
					KeStackAttachProcess(record.process, &apc);
					for (int i = 0; i < record.index; i++) {
						record.pfnbase[record.pfn[i]].OriginalPte.u.Soft.Protection = record.attribute[i];
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

		/// @brief 申请内存
		/// @param type
		/// @param size
		/// @return
		static void* malloc(POOL_TYPE type, unsigned long long size)
		{
			void* p = ExAllocatePoolWithTag(type, size, 'mem');
			if (p) {
				RtlZeroMemory(p, size);
			}
			return p;
		}

		/// @brief 释放内存
		/// @param address
		static void free(void* address)
		{
			if (address) {
				ExFreePoolWithTag(address, 'mem');
			}
			return;
		}

		/// @brief 测试内存
		/// @param address 内存地址
		/// @param size 大小
		/// @param alignment 对齐
		/// @return
		static bool probe(void* address, unsigned long long size, unsigned __int32 alignment)
		{
			if (address == nullptr) {
				return false;
			}

			if (size == 0) {
				return false;
			}

			unsigned long long current = (unsigned long long)address;
			if (((unsigned long long)address & (alignment - 1)) != 0) {
				return false;
			}

			unsigned long long last = current + size - 1;
			if ((last < current) || (last >= MmUserProbeAddress)) {
				return false;
			}

			return true;
		}

		/// @brief 映射内存
		/// @param address
		/// @param size
		/// @return
		static void* mapping(void* address, unsigned long long size)
		{
			//初始化字符串
			UNICODE_STRING name{ };
			RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");

			//对象属性
			OBJECT_ATTRIBUTES obj;
			InitializeObjectAttributes(&obj, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

			//打开节区
			HANDLE hmemory = nullptr;
			auto close_hmemory = std::experimental::make_scope_exit([hmemory] {if (hmemory)ZwClose(hmemory); });
			NTSTATUS status = ZwOpenSection(&hmemory, SECTION_ALL_ACCESS, &obj);
			if (!NT_SUCCESS(status)) {
				return nullptr;
			}

			//获取节区对象
			PVOID physical_memory_section = NULL;
			auto dereference_physical_memory_section = std::experimental::make_scope_exit([physical_memory_section] {if (physical_memory_section)ObDereferenceObject(physical_memory_section); });
			status = ObReferenceObjectByHandle(hmemory, SECTION_ALL_ACCESS, NULL, KernelMode, &physical_memory_section, NULL);
			if (!NT_SUCCESS(status)) {
				return nullptr;
			}

			//映射内存
			size_t size = PAGE_SIZE;
			LARGE_INTEGER target{ .QuadPart = (long long)address };
			void* result = nullptr;
			status = ZwMapViewOfSection(hmemory, NtCurrentProcess(), &result, 0, PAGE_SIZE, &target, &size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
			if (!NT_SUCCESS(status)) {
				return nullptr;
			}
			return result;
		}

		/// @brief 释放映射内存
		/// @param address
		/// @return
		static NTSTATUS unmapping(void* address)
		{
			return ZwUnmapViewOfSection(NtCurrentProcess(), address);
		}

	private:
		std::list<HideRecord> m_record;
	};
}