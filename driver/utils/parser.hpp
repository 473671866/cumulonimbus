#pragma once
#include "../standard/base.h"

namespace utils
{
	typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;

	class parser
	{
	public:
		parser(void* imagebase)
		{
			m_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(imagebase);
			m_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>((m_dos_header->e_lfanew + static_cast<unsigned __int8*>(imagebase)));
			m_imagebase = static_cast<unsigned __int8*>(imagebase);
		}

		/// @brief ��ȡsection�׵�ַ
		/// @param section_name
		/// @param size
		/// @return
		unsigned __int64 get_section_address(const char* section_name, unsigned long long* size)
		{
			PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(m_nt_header);
			PIMAGE_SECTION_HEADER temp_section_header = nullptr;
			unsigned long long SizeOfSection = 0;
			unsigned __int64 base = 0;

			//���ҽ���
			for (int i = 0; i < m_nt_header->FileHeader.NumberOfSections; i++) {
				char name[9]{ 0 };
				RtlCopyMemory(name, section_header->Name, 8);
				if (_stricmp(name, section_name) == 0) {
					temp_section_header = section_header;
					break;
				}
				section_header++;
			}

			//��ȡ�����׵�ַ�ʹ�С
			if (temp_section_header) {
				base = reinterpret_cast<unsigned __int64>(temp_section_header->VirtualAddress + m_imagebase);
				if (size) {
					*size = temp_section_header->SizeOfRawData;
				}
			}
			return base;
		}

		/// @brief ��ȡ����������ַ
		/// @param funation_name
		/// @return
		void* get_export_address(const char* funation_name)
		{
			PIMAGE_DATA_DIRECTORY lpDateDircetory = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&m_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
			PIMAGE_EXPORT_DIRECTORY lpExpotrDircetory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(lpDateDircetory->VirtualAddress + m_imagebase);
			void* function_address = 0;

			for (unsigned long i = 0; i < lpExpotrDircetory->NumberOfNames; i++) {
				int index = -1;
				int* AddressOfFunctions = (int*)(lpExpotrDircetory->AddressOfFunctions + m_imagebase);
				int* AddressOfNames = (int*)(lpExpotrDircetory->AddressOfNames + m_imagebase);
				short* AddressOfNameOrdinals = (short*)(lpExpotrDircetory->AddressOfNameOrdinals + m_imagebase);
				char* name = (char*)(AddressOfNames[i] + m_imagebase);

				if (_stricmp(name, funation_name) == 0) {
					index = AddressOfNameOrdinals[i];
				}

				if (index != -1) {
					function_address = (void*)(AddressOfFunctions[index] + m_imagebase);
					break;
				}
			}
			return function_address;
		}

		/// @brief ��ȡ������ʼ��ַ
		/// @param address
		/// @return
		void* get_function_start_addrss(void* address)
		{
			PIMAGE_DATA_DIRECTORY lpDateDircetory = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&m_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]);
			PRUNTIME_FUNCTION runtime = reinterpret_cast<PRUNTIME_FUNCTION>((lpDateDircetory->VirtualAddress + m_imagebase));

			//�쳣����
			int count = lpDateDircetory->Size / sizeof(RUNTIME_FUNCTION);
			unsigned __int64 temp = reinterpret_cast<unsigned __int64>(address);
			void* result = 0;

			//�����쳣
			for (int i = 0; i < count; i++) {
				if (MmIsAddressValid(&runtime[i])) {
					unsigned __int64 start = reinterpret_cast<unsigned __int64>((runtime[i].BeginAddress + m_imagebase));
					unsigned __int64 end = reinterpret_cast<unsigned __int64>((runtime[i].EndAddress + m_imagebase));
					if (temp >= start && temp <= end) {
						result = reinterpret_cast<void*>(start);
						break;
					}
				}
			}
			return result;
		}

	private:
		unsigned __int8* m_imagebase;
		PIMAGE_DOS_HEADER m_dos_header;
		PIMAGE_NT_HEADERS m_nt_header;
	};
}