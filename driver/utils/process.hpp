#pragma once
#include "../standard/base.h"
#include "../pdb/analysis.h"
#include "utils.h"

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
		//��ʼ���ַ���
		UNICODE_STRING name{ };
		RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");

		//��������
		OBJECT_ATTRIBUTES obj;
		InitializeObjectAttributes(&obj, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

		//�򿪽���
		HANDLE hmemory = nullptr;
		auto close_hmemory = make_scope_exit([hmemory] {if (hmemory)ZwClose(hmemory); });
		NTSTATUS status = ZwOpenSection(&hmemory, SECTION_ALL_ACCESS, &obj);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//��ȡ��������
		PVOID physical_memory_section = NULL;
		auto dereference_physical_memory_section = make_scope_exit([physical_memory_section] {if (physical_memory_section)ObDereferenceObject(physical_memory_section); });
		status = ObReferenceObjectByHandle(hmemory, SECTION_ALL_ACCESS, NULL, KernelMode, &physical_memory_section, NULL);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//��ȡ����
		PEPROCESS process = nullptr;
		auto dereference_process = make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//����ӳ��cr3���ڴ�
		this->m_mapping_cr3_virtual = utils::RtlAllocateMemory(NonPagedPool, PAGE_SIZE);
		if (m_mapping_cr3_virtual == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//����ӳ������ڴ�
		this->m_mapping_process = reinterpret_cast<PEPROCESS>(utils::RtlAllocateMemory(NonPagedPool, PAGE_SIZE));
		if (this->m_mapping_process == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//ӳ�����cr3
		size_t size = PAGE_SIZE;
		LARGE_INTEGER mapping{ .QuadPart = *(int64_t*)((uint8_t*)process + 0x28) };
		void* mapping_address = nullptr;
		status = ZwMapViewOfSection(hmemory, NtCurrentProcess(), &mapping_address, 0, PAGE_SIZE, &mapping, &size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			utils::RtlFreeMemory(this->m_mapping_process);
			utils::RtlFreeMemory(this->m_mapping_cr3_virtual);
			return status;
		}

		//����cr3
		RtlCopyMemory(this->m_mapping_cr3_virtual, mapping_address, PAGE_SIZE);

		//���ƽ���
		RtlCopyMemory(this->m_mapping_process, process, PAGE_SIZE);

		//�滻cr3
		PHYSICAL_ADDRESS mapping_cr3_physical = MmGetPhysicalAddress(this->m_mapping_cr3_virtual);
		*(uint64_t*)((uint8_t*)this->m_mapping_process + 0x28) = mapping_cr3_physical.QuadPart;

		ZwUnmapViewOfSection(NtCurrentProcess(), mapping_address);

		//���Ӽٽ���
		KeStackAttachProcess(this->m_mapping_process, &this->m_apc);
		return STATUS_SUCCESS;
	}

	NTSTATUS StackAttachProcess(PEPROCESS process)
	{
		//��ʼ���ַ���
		UNICODE_STRING name{ };
		RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");

		//��������
		OBJECT_ATTRIBUTES obj;
		InitializeObjectAttributes(&obj, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

		//�򿪽���
		HANDLE hmemory = nullptr;
		auto close_hmemory = make_scope_exit([hmemory] {if (hmemory)ZwClose(hmemory); });
		NTSTATUS status = ZwOpenSection(&hmemory, SECTION_ALL_ACCESS, &obj);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//��ȡ��������
		PVOID physical_memory_section = nullptr;
		auto dereference_physical_memory_section = make_scope_exit([physical_memory_section] {if (physical_memory_section)ObDereferenceObject(physical_memory_section); });
		status = ObReferenceObjectByHandle(hmemory, SECTION_ALL_ACCESS, NULL, KernelMode, &physical_memory_section, NULL);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//����ӳ��cr3���ڴ�
		this->m_mapping_cr3_virtual = utils::RtlAllocateMemory(NonPagedPool, PAGE_SIZE);
		if (m_mapping_cr3_virtual == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//����ӳ������ڴ�
		this->m_mapping_process = reinterpret_cast<PEPROCESS>(utils::RtlAllocateMemory(NonPagedPool, PAGE_SIZE));
		if (this->m_mapping_process == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//ӳ�����cr3
		size_t size = PAGE_SIZE;
		LARGE_INTEGER mapping{ .QuadPart = *(int64_t*)((uint8_t*)process + 0x28) };
		void* mapping_address = nullptr;
		status = ZwMapViewOfSection(hmemory, NtCurrentProcess(), &mapping_address, 0, PAGE_SIZE, &mapping, &size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			utils::RtlFreeMemory(this->m_mapping_process);
			utils::RtlFreeMemory(this->m_mapping_cr3_virtual);
			return status;
		}

		//����cr3
		RtlCopyMemory(this->m_mapping_cr3_virtual, mapping_address, PAGE_SIZE);

		//���ƽ���
		RtlCopyMemory(this->m_mapping_process, process, PAGE_SIZE);

		//�滻cr3
		PHYSICAL_ADDRESS mapping_cr3 = MmGetPhysicalAddress(this->m_mapping_cr3_virtual);
		*(uint64_t*)((uint8_t*)this->m_mapping_process + 0x28) = mapping_cr3.QuadPart;

		ZwUnmapViewOfSection(NtCurrentProcess(), mapping_address);

		//���Ӽٽ���
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

	NTSTATUS RemoveProcessEntryList(HANDLE pid)
	{
		//ȡ���̶���
		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (NT_SUCCESS(status)) {
			LOG_INFO("RemoveProcessEntryList\n");
			//ActiveProcessLinks
			analysis::Pdber ntos(L"ntoskrnl.exe");
			ntos.init();

			uint64_t ActiveProcessLinksOffset = ntos.GetOffset("_EPROCESS", "ActiveProcessLinks");
			PLIST_ENTRY list = (PLIST_ENTRY)((char*)process + ActiveProcessLinksOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ProcessListEntry
			uint64_t ProcessListEntryOffset = ntos.GetOffset("_KPROCESS", "ProcessListEntry");
			list = (PLIST_ENTRY)((char*)process + ProcessListEntryOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ObjectTable
			uint64_t ObjectTableOffset = ntos.GetOffset("_EPROCESS", "ObjectTable");
			char* ObjectTable = (char*)*(void**)((char*)process + ObjectTableOffset);

			//HandleTableList
			uint64_t HandleTableListOffset = ntos.GetOffset("_HANDLE_TABLE", "HandleTableList");
			list = *(PLIST_ENTRY*)((char*)ObjectTable + HandleTableListOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//PspCidTable
			typedef PVOID(*ExpLookupHandleTableEntryProc)(PVOID PspCidTable, HANDLE ProcessId);
			ExpLookupHandleTableEntryProc ExpLookupHandleTableEntry = reinterpret_cast<ExpLookupHandleTableEntryProc>(ntos.GetPointer("ExpLookupHandleTableEntry"));
			PVOID PspCidTable = reinterpret_cast<PVOID>(ntos.GetPointer("PspCidTable"));
			PVOID entry = ExpLookupHandleTableEntry(PspCidTable, pid);
			if (MmIsAddressValid(entry)) {
				RtlZeroMemory(entry, sizeof(entry));
				uint64_t UniqueProcessIdOffset = ntos.GetOffset("_EPROCESS", "UniqueProcessId");
				*(PHANDLE)((char*)process + UniqueProcessIdOffset) = 0;
			}

			ObDereferenceObject(process);
		}
		return status;
	}

private:
	void* m_mapping_cr3_virtual;
	PEPROCESS m_mapping_process;
	KAPC_STATE m_apc;
};