#include "utils.h"
#include "memory.h"

namespace Utils
{
	NTSTATUS LookupProcessByImageFileName(std::string name, PEPROCESS* p)
	{
		PEPROCESS process = nullptr;
		auto status = STATUS_UNSUCCESSFUL;
		constexpr uint64_t max_count = 1024 * 1024 * 512;

		for (int i = 8; i < max_count; i += 4) {
			status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(i), &process);
			if (NT_SUCCESS(status)) {
				PUCHAR image_name = PsGetProcessImageFileName(process);
				if (image_name && _stricmp(name.c_str(), reinterpret_cast<LPCCH>(image_name)) == 0) {
					*p = process;
					return status;
				}
				ObDereferenceObject(process);
			}
		}
		return status;
	}

	NTSTATUS  LookupProcessByImageName(std::wstring name, PEPROCESS* p)
	{
		PEPROCESS process = nullptr;
		PUNICODE_STRING image_name{ NULL };
		auto status = STATUS_UNSUCCESSFUL;
		constexpr uint64_t max_count = 1024 * 1024 * 512;

		for (int i = 8; i < max_count; i += 4) {
			status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(i), &process);

			if (!NT_SUCCESS(status)) {
				continue;
			}

			status = SeLocateProcessImageName(process, &image_name);

			if (!NT_SUCCESS(status)) {
				ObDereferenceObject(process);
				continue;
			}

			if (image_name->Length <= 0) {
				ObDereferenceObject(process);
				ExFreePoolWithTag(image_name, 0);
				continue;
			}

			if (_wcsicmp(image_name->Buffer, name.c_str()) != 0) {
				*p = process;
				ExFreePoolWithTag(image_name, 0);
				ObDereferenceObject(process);
				break;
			}

			ObDereferenceObject(process);
			ExFreePoolWithTag(image_name, 0);
		}
		return status;
	}

	char* CharToUper(char* wstr, boolean isAllocateMemory)
	{
		char* result = NULL;

		if (isAllocateMemory) {
			size_t len = strlen(wstr) + 2;
			result = (char*)ExAllocatePoolWithTag(PagedPool, len, 'char');

			if (!result)return 0;

			memset(result, 0, len);
			memcpy(result, wstr, len - 2);
		}
		else {
			result = wstr;
		}
		_strupr(result);
		return result;
	}

	inline char CharToHex(unsigned char* ch)
	{
		unsigned char temps[2] = { 0 };
		for (int i = 0; i < 2; i++) {
			if (ch[i] >= '0' && ch[i] <= '9') {
				temps[i] = (ch[i] - '0');
			}
			else if (ch[i] >= 'A' && ch[i] <= 'F') {
				temps[i] = (ch[i] - 'A') + 0xA;
			}
			else if (ch[i] >= 'a' && ch[i] <= 'f') {
				temps[i] = (ch[i] - 'a') + 0xA;
			}
		}
		return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
	}

	int32_t StringToHex(unsigned char* hex, unsigned char* str, size_t size)
	{
		int i = 0;
		for (; i < size; i++) {
			if (*str == '*' || *str == '?') {
				hex[i] = *str;
				str++;
				continue;
			}
			hex[i] = CharToHex(str);
			str += 2;
		}
		return i;
	}

	uint64_t GetKernelModule(std::string module_name, size_t* size)
	{
		RTL_PROCESS_MODULES process_modules;
		ULONG result = NULL;
		uint64_t base = 0;

		//查询模块
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &process_modules, sizeof(RTL_PROCESS_MODULES), &result);

		//缓冲区长度太小
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			//申请长度
			ULONG length = result + sizeof(RTL_PROCESS_MODULES);
			PRTL_PROCESS_MODULES process_module = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, length, 'size');
			if (!process_module) {
				return 0;
			}
			RtlZeroMemory(process_module, length);

			//第二次查询
			status = ZwQuerySystemInformation(SystemModuleInformation, process_module, length, &result);

			//失败
			if (!NT_SUCCESS(status)) {
				ExFreePoolWithTag(process_module, 'size');
				return 0;
			}

			//开始查询
			if (_stricmp(module_name.c_str(), "ntkrnlpa.exe") == 0 || _stricmp(module_name.c_str(), "ntoskrnl.exe") == 0) {
				PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = &(process_module->Modules[0]);
				base = (uint64_t)ModuleInfo->ImageBase;
				if (size) {
					*size = ModuleInfo->ImageSize;
				}
			}
			else {
				//遍历模块
				for (ULONG i = 0; i < process_module->NumberOfModules; i++) {
					PRTL_PROCESS_MODULE_INFORMATION processModule = &process_module->Modules[i];

					if (_stricmp((PCHAR)processModule->FullPathName, module_name.c_str())) {
						base = (ULONG_PTR)processModule->ImageBase;
						if (size) {
							*size = processModule->ImageSize;
						}
						break;
					}
				}
			}
			ExFreePoolWithTag(process_module, 'size');
		}
		return base;
	}

	uint64_t GetSectionAddress(uint64_t image_base, std::string section_name, size_t* size)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image_base;
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + image_base);
		PIMAGE_SECTION_HEADER lpSectionHeader = IMAGE_FIRST_SECTION(nt);
		PIMAGE_SECTION_HEADER lpTempSectonHeader = NULL;
		SIZE_T SizeOfSection = 0;
		uint64_t base = 0;

		//查找节区
		for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
			char name[9]{ 0 };
			RtlCopyMemory(name, lpSectionHeader->Name, 8);
			if (_stricmp(name, section_name.c_str()) == 0)
			{
				lpTempSectonHeader = lpSectionHeader;
				break;
			}
			lpSectionHeader++;
		}

		//获取节区首地址和大小
		if (lpTempSectonHeader) {
			base = lpTempSectonHeader->VirtualAddress + image_base;
			SizeOfSection = lpTempSectonHeader->SizeOfRawData;
			if (size) {
				*size = SizeOfSection;
			}
		}
		return base;
	}

	void* GetModuleRoutineAddress(uint64_t image_base, std::string funation_name)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image_base;
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + image_base);
		PIMAGE_DATA_DIRECTORY lpDateDircetory = (PIMAGE_DATA_DIRECTORY)&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		PIMAGE_EXPORT_DIRECTORY lpExpotrDircetory = (PIMAGE_EXPORT_DIRECTORY)(lpDateDircetory->VirtualAddress + image_base);
		PVOID function_address = 0;

		for (ULONG i = 0; i < lpExpotrDircetory->NumberOfNames; i++) {
			int index = -1;
			int* AddressOfFunctions = (int*)(lpExpotrDircetory->AddressOfFunctions + image_base);
			int* AddressOfNames = (int*)(lpExpotrDircetory->AddressOfNames + image_base);
			short* AddressOfNameOrdinals = (short*)(lpExpotrDircetory->AddressOfNameOrdinals + image_base);
			char* name = (char*)(AddressOfNames[i] + image_base);

			if (_stricmp(name, funation_name.c_str()) == 0) {
				index = AddressOfNameOrdinals[i];
			}

			if (index != -1) {
				function_address = (PVOID)(AddressOfFunctions[index] + image_base);
				break;
			}
		}
		return function_address;
	}

	PVOID  GetRoutineStartAddress(uint64_t image_base, void* address)
	{
		//遍历异常
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image_base;
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + image_base);
		PIMAGE_DATA_DIRECTORY lpDateDircetory = (PIMAGE_DATA_DIRECTORY)&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		PRUNTIME_FUNCTION runtime = (PRUNTIME_FUNCTION)(lpDateDircetory->VirtualAddress + image_base);

		//异常个数
		int count = lpDateDircetory->Size / sizeof(RUNTIME_FUNCTION);
		ULONG64 temp = reinterpret_cast<ULONG64>(address);
		PVOID result = 0;

		for (int i = 0; i < count; i++) {
			if (MmIsAddressValid(&runtime[i])) {
				uint64_t start = (runtime[i].BeginAddress + image_base);
				uint64_t end = (runtime[i].EndAddress + image_base);

				if (temp >= start && temp <= end) {
					result = reinterpret_cast<PVOID>(start);
					break;
				}
			}
		}
		return result;
	}

	void* LoadImage(std::wstring file_path, size_t* imagesize, size_t* filesize)
	{
		//初始化文件路径
		file_path.insert(0, L"\\??\\");
		UNICODE_STRING path{};
		RtlInitUnicodeString(&path, file_path.c_str());

		//初始化文件属性
		OBJECT_ATTRIBUTES attributes{ };
		InitializeObjectAttributes(&attributes, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);

		//打开文件
		HANDLE hfile = NULL;
		IO_STATUS_BLOCK create_file_io_status{};
		RtlZeroMemory(&create_file_io_status, sizeof(IO_STATUS_BLOCK));
		NTSTATUS status = ZwCreateFile(&hfile, GENERIC_READ, &attributes, &create_file_io_status, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			return nullptr;
		}

		//获取文件大小
		auto close_hfile = make_scope_exit([hfile] {ZwClose(hfile); });
		FILE_STANDARD_INFORMATION fileInfo;
		status = ZwQueryInformationFile(hfile, &create_file_io_status, &fileInfo, sizeof(fileInfo), FileStandardInformation);
		if (!NT_SUCCESS(status)) {
			return nullptr;
		}

		//创建文件缓冲区
		size_t file_buffer_size = fileInfo.EndOfFile.QuadPart;
		void* file_buffer = ExAllocatePool(PagedPool, file_buffer_size);
		if (file_buffer == nullptr) {
			return nullptr;
		}

		//读文件
		LARGE_INTEGER file_pointer{  };
		file_pointer.HighPart = -1;
		file_pointer.LowPart = FILE_USE_FILE_POINTER_POSITION;
		status = ZwReadFile(hfile, NULL, NULL, NULL, &create_file_io_status, file_buffer, file_buffer_size, &file_pointer, NULL);
		if (!NT_SUCCESS(status)) {
			return nullptr;
		}

		if (filesize) {
			*filesize = file_buffer_size;
		}

		if (imagesize) {
			PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)file_buffer;
			PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((uint8_t*)file_buffer + lpDosHeader->e_lfanew);
			*imagesize = lpNtHeader->OptionalHeader.SizeOfImage;
		}

		return file_buffer;
	}
}