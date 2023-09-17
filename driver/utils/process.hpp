#pragma once
#include "../standard/base.h"
#include "../pdb/analysis.h"
#include "utils.h"
#include "version.hpp"
#include "search.h"

class ProcessUtils
{
public:
	ProcessUtils()
	{
		this->m_mapping_process = nullptr;
		this->m_mapping_cr3_virtual = nullptr;
	}

	~ProcessUtils()
	{
		NOTHING;
	}

	NTSTATUS StackAttachProcess(HANDLE pid)
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
			return status;
		}

		//获取节区对象
		PVOID physical_memory_section = NULL;
		auto dereference_physical_memory_section = std::experimental::make_scope_exit([physical_memory_section] {if (physical_memory_section)ObDereferenceObject(physical_memory_section); });
		status = ObReferenceObjectByHandle(hmemory, SECTION_ALL_ACCESS, NULL, KernelMode, &physical_memory_section, NULL);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//获取进程
		PEPROCESS process = nullptr;
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//复制映射cr3的内存
		this->m_mapping_cr3_virtual = utils::RtlAllocateMemory(NonPagedPool, PAGE_SIZE);
		if (m_mapping_cr3_virtual == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//申请映射进程内存
		this->m_mapping_process = reinterpret_cast<PEPROCESS>(utils::RtlAllocateMemory(NonPagedPool, PAGE_SIZE));
		if (this->m_mapping_process == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//映射进程cr3
		size_t size = PAGE_SIZE;
		LARGE_INTEGER mapping{ .QuadPart = *(int64_t*)((uint8_t*)process + 0x28) };
		void* mapping_address = nullptr;
		status = ZwMapViewOfSection(hmemory, NtCurrentProcess(), &mapping_address, 0, PAGE_SIZE, &mapping, &size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			utils::RtlFreeMemory(this->m_mapping_process);
			utils::RtlFreeMemory(this->m_mapping_cr3_virtual);
			return status;
		}

		//复制cr3
		RtlCopyMemory(this->m_mapping_cr3_virtual, mapping_address, PAGE_SIZE);

		//复制进程
		RtlCopyMemory(this->m_mapping_process, process, PAGE_SIZE);

		//替换cr3
		PHYSICAL_ADDRESS mapping_cr3_physical = MmGetPhysicalAddress(this->m_mapping_cr3_virtual);
		*(uint64_t*)((uint8_t*)this->m_mapping_process + 0x28) = mapping_cr3_physical.QuadPart;

		ZwUnmapViewOfSection(NtCurrentProcess(), mapping_address);

		//附加假进程
		KeStackAttachProcess(this->m_mapping_process, &this->m_apc);
		return STATUS_SUCCESS;
	}

	NTSTATUS StackAttachProcess(PEPROCESS process)
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
			return status;
		}

		//获取节区对象
		PVOID physical_memory_section = nullptr;
		auto dereference_physical_memory_section = std::experimental::make_scope_exit([physical_memory_section] {if (physical_memory_section)ObDereferenceObject(physical_memory_section); });
		status = ObReferenceObjectByHandle(hmemory, SECTION_ALL_ACCESS, NULL, KernelMode, &physical_memory_section, NULL);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//复制映射cr3的内存
		this->m_mapping_cr3_virtual = utils::RtlAllocateMemory(NonPagedPool, PAGE_SIZE);
		if (m_mapping_cr3_virtual == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//申请映射进程内存
		this->m_mapping_process = reinterpret_cast<PEPROCESS>(utils::RtlAllocateMemory(NonPagedPool, PAGE_SIZE));
		if (this->m_mapping_process == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//映射进程cr3
		size_t size = PAGE_SIZE;
		LARGE_INTEGER mapping{ .QuadPart = *(int64_t*)((uint8_t*)process + 0x28) };
		void* mapping_address = nullptr;
		status = ZwMapViewOfSection(hmemory, NtCurrentProcess(), &mapping_address, 0, PAGE_SIZE, &mapping, &size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			utils::RtlFreeMemory(this->m_mapping_process);
			utils::RtlFreeMemory(this->m_mapping_cr3_virtual);
			return status;
		}

		//复制cr3
		RtlCopyMemory(this->m_mapping_cr3_virtual, mapping_address, PAGE_SIZE);

		//复制进程
		RtlCopyMemory(this->m_mapping_process, process, PAGE_SIZE);

		//替换cr3
		PHYSICAL_ADDRESS mapping_cr3 = MmGetPhysicalAddress(this->m_mapping_cr3_virtual);
		*(uint64_t*)((uint8_t*)this->m_mapping_process + 0x28) = mapping_cr3.QuadPart;

		ZwUnmapViewOfSection(NtCurrentProcess(), mapping_address);

		//附加假进程
		KeStackAttachProcess(this->m_mapping_process, &this->m_apc);
		return STATUS_SUCCESS;
	}

	NTSTATUS UnStackAttachProcess()
	{
		KeUnstackDetachProcess(&this->m_apc);
		utils::RtlFreeMemory(this->m_mapping_cr3_virtual);
		utils::RtlFreeMemory(this->m_mapping_process);
		return STATUS_SUCCESS;
	}

	static NTSTATUS RemoveProcessEntryList(HANDLE pid)
	{
		//取进程对象
		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = PsGetProcessExitStatus(process);
		if (status != 0x103) {
			ObDereferenceObject(process);
			return status;
		}

		LOG_INFO("RemoveProcessEntryList\n");

		auto version = Version::get_instance();
		if (version->Windows_7()) {
			//ActiveProcessLinks
			uint64_t ActiveProcessLinksOffset = 0x188;
			PLIST_ENTRY list = (PLIST_ENTRY)((char*)process + ActiveProcessLinksOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ProcessListEntry
			uint64_t ProcessListEntryOffset = 0xe0;
			list = (PLIST_ENTRY)((char*)process + ProcessListEntryOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ObjectTable
			uint64_t ObjectTableOffset = 0x200;
			char* ObjectTable = (char*)*(void**)((char*)process + ObjectTableOffset);

			//HandleTableList
			uint64_t HandleTableListOffset = 0x20;
			list = (PLIST_ENTRY)((char*)ObjectTable + HandleTableListOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ExpLookupHandleTableEntry
			typedef PVOID(*ExpLookupHandleTableEntryProc)(PVOID PspCidTable, HANDLE ProcessId);
			SearchUtils search;
			void* address = search.pattern("ntoskrnl.exe", "PAGE", "8B41*4889***83**8954**4C8B***4C3BC873*4C8B01418BC883**8BC14C2BC085C974*");
			ExpLookupHandleTableEntryProc ExpLookupHandleTableEntry = reinterpret_cast<ExpLookupHandleTableEntryProc>(address);
			LOG_INFO("ExpLookupHandleTableEntry: %llx", ExpLookupHandleTableEntry);
			//PspCidTable
			UNICODE_STRING name{};
			RtlInitUnicodeString(&name, L"PsLookupProcessByProcessId");
			unsigned __int8* temp = (unsigned __int8*)MmGetSystemRoutineAddress(&name);
			LARGE_INTEGER result{};
			for (int i = 0; temp[i] != 0xc3; i++) {
				if (temp[i] == 0x48 && temp[i + 1] == 0x8b && temp[i + 2] == 0x0d) {
					result.QuadPart = (LONGLONG)temp + i + 7;
					result.LowPart += *(PULONG)(temp + i + 3);
					break;
				}
			}
			PVOID PspCidTable = reinterpret_cast<PVOID>(result.QuadPart);
			LOG_INFO("PspCidTable: %llx", PspCidTable);
			PVOID entry = ExpLookupHandleTableEntry(PspCidTable, pid);
			if (MmIsAddressValid(entry)) {
				RtlZeroMemory(entry, sizeof(entry));
				uint64_t UniqueProcessIdOffset = 0x180;
				*(PHANDLE)((char*)process + UniqueProcessIdOffset) = 0;
			}
		}
		else {
			analysis::Pdber* ntos = analysis::Ntoskrnl();
			//ActiveProcessLinks
			uint64_t ActiveProcessLinksOffset = ntos->GetOffset("_EPROCESS", "ActiveProcessLinks");
			PLIST_ENTRY list = (PLIST_ENTRY)((char*)process + ActiveProcessLinksOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ProcessListEntry
			uint64_t ProcessListEntryOffset = ntos->GetOffset("_KPROCESS", "ProcessListEntry");
			list = (PLIST_ENTRY)((char*)process + ProcessListEntryOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ObjectTable
			uint64_t ObjectTableOffset = ntos->GetOffset("_EPROCESS", "ObjectTable");
			char* ObjectTable = (char*)*(void**)((char*)process + ObjectTableOffset);

			//HandleTableList
			uint64_t HandleTableListOffset = ntos->GetOffset("_HANDLE_TABLE", "HandleTableList");
			list = (PLIST_ENTRY)((char*)ObjectTable + HandleTableListOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//PspCidTable
			typedef PVOID(*ExpLookupHandleTableEntryProc)(PVOID PspCidTable, HANDLE ProcessId);
			ExpLookupHandleTableEntryProc ExpLookupHandleTableEntry = reinterpret_cast<ExpLookupHandleTableEntryProc>(ntos->GetPointer("ExpLookupHandleTableEntry"));
			PVOID PspCidTable = reinterpret_cast<PVOID>(ntos->GetPointer("PspCidTable"));
			PVOID entry = ExpLookupHandleTableEntry(PspCidTable, pid);
			if (MmIsAddressValid(entry)) {
				RtlZeroMemory(entry, sizeof(entry));
				uint64_t UniqueProcessIdOffset = ntos->GetOffset("_EPROCESS", "UniqueProcessId");
				*(PHANDLE)((char*)process + UniqueProcessIdOffset) = 0;
			}
		}

		ObDereferenceObject(process);
		return status;
	}

	static NTSTATUS AllocateMemory(HANDLE pid, void** address, size_t size, uint32_t protect)
	{
		//获取进程
		PEPROCESS process = nullptr;
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (PsGetProcessExitStatus(process) != 0x103) {
			return STATUS_PROCESS_IS_TERMINATING;
		}

		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);

		void* allocate_base = nullptr;
		size_t region_size = size;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &allocate_base, 0, &region_size, MEM_COMMIT, protect);
		if (NT_SUCCESS(status)) {
			RtlZeroMemory(allocate_base, size);
		}

		KeUnstackDetachProcess(&apc);

		if (NT_SUCCESS(status) && address) {
			*address = allocate_base;
		}
		return status;
	}

	static NTSTATUS FreeMemory(HANDLE pid, void* address, size_t size)
	{
		PEPROCESS process = nullptr;
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (PsGetProcessExitStatus(process) != 0x103) {
			return STATUS_PROCESS_IS_TERMINATING;
		}

		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);

		void* allocate_base = address;
		size_t region_size = size;
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &allocate_base, &region_size, MEM_RELEASE);

		KeUnstackDetachProcess(&apc);
		return status;
	}

	static NTSTATUS TerminateProcess(HANDLE pid)
	{
		CLIENT_ID clientid{  };
		clientid.UniqueProcess = pid;

		OBJECT_ATTRIBUTES attribute{  };
		attribute.Length = sizeof(OBJECT_ATTRIBUTES);

		HANDLE handle = nullptr;
		auto status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &attribute, &clientid);
		if (!NT_SUCCESS(status) || !handle) {
			return status;
		}

		status = ZwTerminateProcess(handle, STATUS_SUCCESS);
		ZwClose(handle);
		return status;
	}

	//static NTSTATUS SetProcessExceptionCallback(HANDLE pid, void* func)
	//{
	//	//获取进程
	//	PEPROCESS process = nullptr;
	//	auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
	//	auto status = PsLookupProcessByProcessId(pid, &process);
	//	if (!NT_SUCCESS(status)) {
	//		return status;
	//	}

	//	if (PsGetProcessExitStatus(process) != 0x103) {
	//		return STATUS_PROCESS_IS_TERMINATING;
	//	}

	//	analysis::Pdber* ntdll = analysis::Ntdll();
	//	unsigned __int64 KiUserExceptionDispatcher = ntdll->GetPointer("KiUserExceptionDispatcher");
	//	if (!KiUserExceptionDispatcher) {
	//		return STATUS_UNSUCCESSFUL;
	//	}

	//	unsigned __int8 shellcode[] = {
	//		0x50,																				//push  rax
	//		0x51,																				//push  rcx
	//		0x52,																				//push  rdx
	//		0x53,																				//push  rbx
	//		0x55, 																				//push  rbp
	//		0x56, 																				//push  rsi
	//		0x57, 																				//push  rdi
	//		0x41, 0x50, 																		//push  r8
	//		0x41, 0x51, 																		//push  r9
	//		0x41, 0x52, 																		//push  r10
	//		0x41, 0x53, 																		//push  r11
	//		0x41, 0x54, 																		//push  r12
	//		0x41, 0x55, 																		//push  r13
	//		0x41, 0x56, 																		//push  r14
	//		0x41, 0x57, 																		//push  r15
	//		0x49, 0xBB, 0x99, 0x99, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00,							//mov r11, 0x12345678999 handler
	//		0x49, 0xBC, 0x99, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00,							//mov r12, 0x12345678999 KiUserExceptionDispatcher
	//		0x4D, 0x3B, 0xD4,																	//cmp r10, r12
	//		0x75, 0x1B,																			//jne pop r15
	//		0x48, 0x83, 0xEC, 0x28,																//sub rsp, 0x28
	//		0x48, 0x8D, 0x8C, 0x24, 0x90, 0x05, 0x00, 0x00,										//lea rcx, [rsp+0x590]
	//		0x48, 0x8D, 0x94, 0x24, 0xA0, 0x00, 0x00, 0x00,										//lea rdx, [rsp+0xa0]
	//		0x41, 0xFF, 0xD3,																	//call r11
	//		0x48, 0x83, 0xC4, 0x28,																//add rsp, 0x28
	//		0x41, 0x5F, 																		//pop  r15
	//		0x41, 0x5E,																			//pop  r14
	//		0x41, 0x5D, 																		//pop  r13
	//		0x41, 0x5C, 																		//pop  r12
	//		0x41, 0x5B, 																		//pop  r11
	//		0x41, 0x5A, 																		//pop  r10
	//		0x41, 0x59, 																		//pop  r9
	//		0x41, 0x58, 																		//pop  r8
	//		0x5F, 																				//pop  rdi
	//		0x5E, 																				//pop  rsi
	//		0x5D, 																				//pop  rbp
	//		0x5B, 																				//pop  rbx
	//		0x5A,																				//pop  rdx
	//		0x59, 																				//pop  rcx
	//		0x48, 0xB8, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00,							//mov  rax,0x0000000123456789
	//		0x48, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,											//mov  qword ptr ds:[rax],0x0000000000000001
	//		0x58, 																				//pop  rax
	//		0x41, 0xFF, 0xE2																	//jmp  r10
	//	};

	//	*(unsigned __int64*)shellcode[0x25] = (unsigned __int64)func;
	//	*(unsigned __int64*)shellcode[0x35] = (unsigned __int64)KiUserExceptionDispatcher;

	//	KAPC_STATE apc{};
	//	KeStackAttachProcess(process, &apc);

	//	void* base = nullptr;
	//	size_t region_size = sizeof(shellcode);
	//	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &region_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//	if (NT_SUCCESS(status)) {
	//		RtlZeroMemory(base, region_size);
	//		RtlCopyMemory(base, shellcode, sizeof(shellcode));
	//		status = ZwSetInformationProcess(NtCurrentProcess(), ProcessInstrumentationCallback, base, sizeof(shellcode));
	//	}

	//	KeUnstackDetachProcess(&apc);

	//	return status;
	//}

private:
	void* m_mapping_cr3_virtual;
	PEPROCESS m_mapping_process;
	KAPC_STATE m_apc;
};