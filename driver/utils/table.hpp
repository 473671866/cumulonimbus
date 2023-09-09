#pragma once
#include "../Standard/base.h"
#include "../pdb/analysis.h"
#include"../vmp/VMProtectDDK.h"
#include "utils.h"

struct ServiceDescriptorTable
{
	PULONG ServiceTable;
	PVOID CounterTable;
	ULONGLONG NumberOfServices;
	PCHAR ArgumentTable;
};

class ServiceTableUtils :public Singleton<ServiceTableUtils>
{
public:

	ServiceTableUtils()
	{
		analysis::Pdber ntos(L"ntoskrnl.exe"); ntos.init();
		this->m_service_table = reinterpret_cast<ServiceDescriptorTable*>(ntos.GetPointer("KeServiceDescriptorTable"));
		this->m_service_table_shadow = reinterpret_cast<ServiceDescriptorTable*>(ntos.GetPointer("KeServiceDescriptorTableShadow"));
	}

	/**
	 * @brief 获取ssdt表函数
	 * @param service_number 服务号
	 * @return
	*/
	uint64_t GetServiceTableRoutine(uint32_t service_number)
	{
		VMPBegin("GetServiceTableRoutine");
		LONG offset = this->m_service_table->ServiceTable[service_number];
		offset >>= 4;

		LARGE_INTEGER result{ NULL };
		result.QuadPart = (ULONG64)this->m_service_table->ServiceTable;
		result.LowPart += offset;

		VMPEnd();
		return result.QuadPart;
	}

	/**
	 * @brief 获取sssdt表函数
	 * @param service_number 服务号
	 * @return
	*/
	uint64_t GetServiceTableShadowRoutine(uint32_t service_number)
	{
		VMPBegin("GetServiceTableShadowRoutine");

		if (service_number >= 0x1000) {
			service_number -= 0x1000;
		}

		LARGE_INTEGER result{ NULL };
		PEPROCESS process = nullptr;
		KAPC_STATE apc{ NULL };

		if (NT_SUCCESS(utils::LookupProcessByImageFileName("explorer.exe", &process))) {
			KeStackAttachProcess(process, &apc);

			LONG offset = this->m_service_table_shadow->ServiceTable[service_number];
			offset >>= 4;
			result.QuadPart = (ULONG64)this->m_service_table_shadow->ServiceTable;
			result.LowPart += offset;

			KeUnstackDetachProcess(&apc);
			ObDereferenceObject(process);
		}
		VMPEnd();
		return result.QuadPart;
	}

private:
	ServiceDescriptorTable* m_service_table;
	ServiceDescriptorTable* m_service_table_shadow;
};