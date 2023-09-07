#pragma once
#include "../standard/base.h"
#include "../pdb/oxygenPdb.h"

class ProcessUtils
{
public:
	ProcessUtils()
	{
	}

	~ProcessUtils()
	{
	}

	NTSTATUS StackAttachProcess(HANDLE pid, KAPC_STATE* apc)
	{
		//��ʼ���ַ���
		UNICODE_STRING name{ };
		RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");

		//��������
		OBJECT_ATTRIBUTES obj;
		InitializeObjectAttributes(&obj, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

		//�򿪽���
		HANDLE hmemory;
		NTSTATUS status = ZwOpenSection(&hmemory, SECTION_ALL_ACCESS, &obj);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//��ȡ��������
		PVOID physical_memory_section = NULL;
		status = ObReferenceObjectByHandle(hmemory, SECTION_ALL_ACCESS, NULL, KernelMode, &physical_memory_section, NULL);
		if (!NT_SUCCESS(status)) {
			ZwClose(hmemory);
			return status;
		}

		//��ȡ����
		PEPROCESS process = nullptr;
		status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			ZwClose(hmemory);
			ObDereferenceObject(physical_memory_section);
			return status;
		}

		//ӳ�����cr3
		size_t size = PAGE_SIZE;
		LARGE_INTEGER mapping{ .QuadPart = *(int64_t*)((uint8_t*)process + 0x28) };
		this->m_current_pid = PsGetCurrentProcessId();
		status = ZwMapViewOfSection(hmemory, NtCurrentProcess(), &this->m_mapping_address, 0, PAGE_SIZE, &mapping, &size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			ZwClose(hmemory);
			ObDereferenceObject(process);
			ObDereferenceObject(physical_memory_section);
			return status;
		}

		//����ӳ������ڴ�
		this->m_mapping_process = reinterpret_cast<PEPROCESS>(ExAllocatePoolZero(NonPagedPool, PAGE_SIZE, 'cr3'));
		if (this->m_mapping_process == nullptr) {
			ZwClose(hmemory);
			ObDereferenceObject(process);
			ObDereferenceObject(physical_memory_section);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//���ƽ���
		RtlCopyMemory(this->m_mapping_process, process, PAGE_SIZE);
		PHYSICAL_ADDRESS mapping_cr3 = MmGetPhysicalAddress(this->m_mapping_address);
		*(uint64_t*)((uint8_t*)this->m_mapping_process + 0x28) = mapping_cr3.QuadPart;

		ZwClose(hmemory);
		ObDereferenceObject(process);
		ObDereferenceObject(physical_memory_section);

		//���Ӽٽ���
		KeStackAttachProcess(this->m_mapping_process, apc);
		return STATUS_SUCCESS;
	}

	NTSTATUS StackAttachProcess(PEPROCESS process, KAPC_STATE* apc)
	{
		//��ʼ���ַ���
		UNICODE_STRING name{ };
		RtlInitUnicodeString(&name, L"\\Device\\PhysicalMemory");

		//��������
		OBJECT_ATTRIBUTES obj;
		InitializeObjectAttributes(&obj, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

		//�򿪽���
		HANDLE hmemory;
		NTSTATUS status = ZwOpenSection(&hmemory, SECTION_ALL_ACCESS, &obj);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//��ȡ��������
		PVOID physical_memory_section = NULL;
		status = ObReferenceObjectByHandle(hmemory, SECTION_ALL_ACCESS, NULL, KernelMode, &physical_memory_section, NULL);
		if (!NT_SUCCESS(status)) {
			ZwClose(hmemory);
			return status;
		}

		//ӳ�����cr3
		size_t size = PAGE_SIZE;
		LARGE_INTEGER mapping{ .QuadPart = *(int64_t*)((uint8_t*)process + 0x28) };
		this->m_current_pid = PsGetCurrentProcessId();
		status = ZwMapViewOfSection(hmemory, NtCurrentProcess(), &this->m_mapping_address, 0, PAGE_SIZE, &mapping, &size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			ZwClose(hmemory);
			ObDereferenceObject(physical_memory_section);
			return status;
		}

		//����ӳ������ڴ�
		this->m_mapping_process = reinterpret_cast<PEPROCESS>(ExAllocatePoolZero(NonPagedPool, PAGE_SIZE, 'cr3'));
		if (this->m_mapping_process == nullptr) {
			ZwClose(hmemory);
			ObDereferenceObject(physical_memory_section);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//���ƽ���
		RtlCopyMemory(this->m_mapping_process, process, PAGE_SIZE);
		PHYSICAL_ADDRESS mapping_cr3 = MmGetPhysicalAddress(this->m_mapping_address);
		*(uint64_t*)((uint8_t*)this->m_mapping_process + 0x28) = mapping_cr3.QuadPart;

		ZwClose(hmemory);
		ObDereferenceObject(physical_memory_section);

		//���Ӽٽ���
		KeStackAttachProcess(this->m_mapping_process, apc);
		return STATUS_SUCCESS;
	}

	NTSTATUS StackAttachProcessOriginal(PEPROCESS process, KAPC_STATE* apc)
	{
		//����ӳ������ڴ�
		this->m_mapping_process = reinterpret_cast<PEPROCESS>(ExAllocatePoolZero(NonPagedPool, PAGE_SIZE, 'cr3'));
		if (this->m_mapping_process == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//���ƽ���
		RtlCopyMemory(this->m_mapping_process, process, PAGE_SIZE);
		*(uint64_t*)((uint8_t*)this->m_mapping_process + 0x28) = *(uint64_t*)((uint8_t*)process + 0x28);

		//���Ӽٽ���
		KeStackAttachProcess(this->m_mapping_process, apc);
		return STATUS_SUCCESS;
	}

	NTSTATUS UnStackAttachProcessOriginal(KAPC_STATE* apc)
	{
		KeUnstackDetachProcess(apc);
		ExFreePoolWithTag(this->m_mapping_process, 'cr3');
		return STATUS_SUCCESS;
	}

	NTSTATUS UnStackAttachProcess(KAPC_STATE* apc)
	{
		OBJECT_ATTRIBUTES obj;
		InitializeObjectAttributes(&obj, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);

		CLIENT_ID client_id{ .UniqueProcess = this->m_current_pid };
		HANDLE hprocess = nullptr;
		auto status = ZwOpenProcess(&hprocess, PROCESS_ALL_ACCESS, &obj, &client_id);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		KeUnstackDetachProcess(apc);
		ExFreePoolWithTag(this->m_mapping_process, 'cr3');
		status = ZwUnmapViewOfSection(hprocess, this->m_mapping_address);

		ZwClose(hprocess);
		return status;
	}

	NTSTATUS RemoveProcessEntryList(HANDLE pid)
	{
		//ȡ���̶���
		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (NT_SUCCESS(status)) {
			LOG_INFO("RemoveProcessEntryList\n");
			//ActiveProcessLinks
			oxygenPdb::Pdber ntos(L"ntoskrnl.exe");
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
	PEPROCESS m_mapping_process;
	HANDLE m_current_pid;
	void* m_mapping_address;
};