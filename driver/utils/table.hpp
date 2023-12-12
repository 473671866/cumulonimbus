#pragma once
#include "../standard/base.h"

namespace utils {
	struct ServiceDescriptorTable {
		PULONG ServiceTable;
		PVOID CounterTable;
		ULONGLONG NumberOfServices;
		PCHAR ArgumentTable;
	};

	class service_table {
	public:
		service_table(void* service_table_address, void* service_table_shadow_address) {
			//this->m_service_table = reinterpret_cast<ServiceDescriptorTable*>(ntos->GetPointer("KeServiceDescriptorTable"));
			//this->m_service_table_shadow = reinterpret_cast<ServiceDescriptorTable*>(ntos->GetPointer("KeServiceDescriptorTableShadow"));
			this->m_service_table = static_cast<ServiceDescriptorTable*>(service_table_address);
			this->m_service_table_shadow = static_cast<ServiceDescriptorTable*>(service_table_shadow_address);
		}

		/**
		 * @brief 获取ssdt表函数
		 * @param service_number 服务号
		 * @return
		*/
		template<typename _Ty>
		_Ty GetServiceTableRoutine(unsigned __int32 service_number) {
			if (!this->m_service_table) {
				return 0;
			}

			unsigned long offset = this->m_service_table->ServiceTable[service_number];
			offset >>= 4;

			LARGE_INTEGER result{ NULL };
			result.QuadPart = (unsigned __int64)this->m_service_table->ServiceTable;
			result.LowPart += offset;

			return (_Ty)result.QuadPart;
		}

		/**
		 * @brief 获取sssdt表函数
		 * @param service_number 服务号
		 * @return
		*/
		template<typename _Ty>
		_Ty GetServiceTableShadowRoutine(unsigned __int32 service_number) {
			if (!this->m_service_table_shadow) {
				return 0;
			}

			if (service_number >= 0x1000) {
				service_number -= 0x1000;
			}

			LARGE_INTEGER result{ NULL };
			unsigned long offset = this->m_service_table_shadow->ServiceTable[service_number];
			offset >>= 4;
			result.QuadPart = (unsigned __int64)this->m_service_table_shadow->ServiceTable;
			result.LowPart += offset;

			return (_Ty)result.QuadPart;
		}

	private:
		ServiceDescriptorTable* m_service_table;
		ServiceDescriptorTable* m_service_table_shadow;
	};
}