#include "utils.h"
#include "memory.h"

namespace utils
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

	void* GetKernelModule(std::string module_name, size_t* size)
	{
		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, sizeof(RTL_PROCESS_MODULES), 'size');
		auto free_memory = make_scope_exit([modules] {	ExFreePoolWithTag(modules, 'size'); });
		ULONG length = 0;
		void* result = 0;

		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, modules, sizeof(RTL_PROCESS_MODULES), &length);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePoolWithTag(modules, 'size');
			modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, length + sizeof(RTL_PROCESS_MODULES), 'size');
			RtlZeroMemory(modules, length);
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, modules, length + sizeof(RTL_PROCESS_MODULES), &length);
		if (!NT_SUCCESS(status)) {
			return 0;
		}

		if (_stricmp(module_name.c_str(), "ntkrnlpa.exe") == 0 || _stricmp(module_name.c_str(), "ntoskrnl.exe") == 0) {
			PRTL_PROCESS_MODULE_INFORMATION module_information = &(modules->Modules[0]);
			result = module_information->ImageBase;
			if (size) {
				*size = module_information->ImageSize;
			}
			return result;
		}

		//遍历模块
		for (size_t i = 0; i < modules->NumberOfModules; i++) {
			PRTL_PROCESS_MODULE_INFORMATION module_information = &modules->Modules[i];
			if (_stricmp((PCHAR)module_information->FullPathName, module_name.c_str())) {
				result = module_information->ImageBase;
				if (size) {
					*size = module_information->ImageSize;
				}
				return result;
			}
		}
		return result;
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
#pragma warning (push)
#pragma warning(disable:4996)
#pragma warning(disable:4267)

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

		PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)file_buffer;
		PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((uint8_t*)file_buffer + lpDosHeader->e_lfanew);
		if (lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			return nullptr;
		}

#pragma warning (pop)

		if (filesize) {
			*filesize = file_buffer_size;
		}

		if (imagesize) {
			*imagesize = lpNtHeader->OptionalHeader.SizeOfImage;
		}

		return file_buffer;
	}

	void* RtlAllocateMemory(POOL_TYPE type, size_t size)
	{
		void* p = ExAllocatePoolWithTag(type, size, 'mem');
		if (p) {
			RtlZeroMemory(p, size);
		}
		return p;
	}

	void RtlFreeMemory(void* address)
	{
		if (address) {
			ExFreePoolWithTag(address, 'mem');
		}
		return;
	}

	namespace ldr
	{
#pragma pack(push)
#pragma pack(4)

		typedef struct _PEB_LDR_DATA32
		{
			ULONG Length;                                                           //0x0
			UCHAR Initialized;                                                      //0x4
			ULONG SsHandle;                                                         //0x8
			LIST_ENTRY32 InLoadOrderModuleList;										//0xc
			LIST_ENTRY32 InMemoryOrderModuleList;									//0x14
			LIST_ENTRY32 InInitializationOrderModuleList;							//0x1c
			ULONG EntryInProgress;                                                  //0x24
			UCHAR ShutdownInProgress;                                               //0x28
			ULONG ShutdownThreadId;                                                 //0x2c
		}PEB_LDR_DATA32, * PPEB_LDR_DATA32;

		typedef struct _LDR_DATA_TABLE_ENTRY32
		{
			LIST_ENTRY32 InLoadOrderLinks;											//0x0
			LIST_ENTRY32 InMemoryOrderLinks;										//0x8
			LIST_ENTRY32 InInitializationOrderLinks;								//0x10
			ULONG DllBase;                                                          //0x18
			ULONG EntryPoint;                                                       //0x1c
			ULONG SizeOfImage;                                                      //0x20
			UNICODE_STRING32 FullDllName;											//0x24
			UNICODE_STRING32 BaseDllName;											//0x2c
			ULONG Flags;                                                            //0x34
			USHORT LoadCount;                                                       //0x38
			USHORT TlsIndex;                                                        //0x3a
			union
			{
				LIST_ENTRY32 HashLinks;												//0x3c
				struct
				{
					ULONG SectionPointer;                                           //0x3c
					ULONG CheckSum;                                                 //0x40
				};
			};
			union
			{
				ULONG TimeDateStamp;                                                //0x44
				ULONG LoadedImports;                                                //0x44
			};
			ULONG EntryPointActivationContext;										//0x48
			ULONG PatchInformation;                                                 //0x4c
			LIST_ENTRY32 ForwarderLinks;											//0x50
			LIST_ENTRY32 ServiceTagLinks;											//0x58
			LIST_ENTRY32 StaticLinks;												//0x60
			ULONG ContextInformation;                                               //0x68
			ULONG OriginalBase;                                                     //0x6c
			LARGE_INTEGER LoadTime;													//0x70
		}LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

		typedef struct _PEB32
		{
			UCHAR InheritedAddressSpace;                                            //0x0
			UCHAR ReadImageFileExecOptions;                                         //0x1
			UCHAR BeingDebugged;                                                    //0x2
			union
			{
				UCHAR BitField;                                                     //0x3
				struct
				{
					UCHAR ImageUsesLargePages : 1;                                    //0x3
					UCHAR IsProtectedProcess : 1;                                     //0x3
					UCHAR IsLegacyProcess : 1;                                        //0x3
					UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
					UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
					UCHAR SpareBits : 3;                                              //0x3
				};
			};
			ULONG Mutant;                                                           //0x4
			ULONG ImageBaseAddress;                                                 //0x8
			ULONG Ldr;																//0xc
		}PEB32, * PPEB32;

#pragma pack(pop)

		typedef struct _PEB_LDR_DATA
		{
			ULONG Length;                                                           //0x0
			UCHAR Initialized;                                                      //0x4
			VOID* SsHandle;                                                         //0x8
			LIST_ENTRY InLoadOrderModuleList;                               //0x10
			LIST_ENTRY InMemoryOrderModuleList;                             //0x20
			LIST_ENTRY InInitializationOrderModuleList;                     //0x30
			VOID* EntryInProgress;                                                  //0x40
			UCHAR ShutdownInProgress;                                               //0x48
			VOID* ShutdownThreadId;                                                 //0x50
		}PEB_LDR_DATA, * PPEB_LDR_DATA;

		typedef struct _LDR_DATA_TABLE_ENTRY
		{
			LIST_ENTRY InLoadOrderLinks;                                    //0x0
			LIST_ENTRY InMemoryOrderLinks;                                  //0x10
			LIST_ENTRY InInitializationOrderLinks;                          //0x20
			VOID* DllBase;                                                          //0x30
			VOID* EntryPoint;                                                       //0x38
			ULONG64 SizeOfImage;                                                      //0x40
			UNICODE_STRING FullDllName;                                     //0x48
			UNICODE_STRING BaseDllName;                                     //0x58
			ULONG Flags;                                                            //0x68
			USHORT LoadCount;                                                       //0x6c
			USHORT TlsIndex;                                                        //0x6e
			union
			{
				LIST_ENTRY HashLinks;                                       //0x70
				struct
				{
					VOID* SectionPointer;                                           //0x70
					ULONG CheckSum;                                                 //0x78
				};
			};
			union
			{
				ULONG TimeDateStamp;                                                //0x80
				VOID* LoadedImports;                                                //0x80
			};
			struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
			VOID* PatchInformation;                                                 //0x90
			LIST_ENTRY ForwarderLinks;                                      //0x98
			LIST_ENTRY ServiceTagLinks;                                     //0xa8
			LIST_ENTRY StaticLinks;                                         //0xb8
			VOID* ContextInformation;                                               //0xc8
			ULONGLONG OriginalBase;                                                 //0xd0
			LARGE_INTEGER LoadTime;                                          //0xd8
		}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

		typedef struct _PEB
		{
			ULONG64 x;
			VOID* Mutant;                                                           //0x8
			VOID* ImageBaseAddress;                                                 //0x10
			PEB_LDR_DATA* Ldr;														 //0x18
		}PEB, * PPEB;

		PVOID GetApplicationModule(HANDLE process_id, PCHAR module_name, PSIZE_T image_size)
		{
			if (!process_id || !module_name) {
				return 0;
			}
			PVOID module_base_address = 0;
			PEPROCESS process = nullptr;
			NTSTATUS status = PsLookupProcessByProcessId(process_id, &process);
			auto dereference_process = make_scope_exit([process] {if (process) ObDereferenceObject(process); });
			if (!NT_SUCCESS(status)) {
				return 0;
			}

			status = PsGetProcessExitStatus(process);
			if (status != 0x103) {
				return 0;
			}

			ANSI_STRING ansi_module_name{ NULL };
			RtlInitAnsiString(&ansi_module_name, module_name);
			UNICODE_STRING wcs_module_name{ NULL };
			status = RtlAnsiStringToUnicodeString(&wcs_module_name, &ansi_module_name, TRUE);
			if (!NT_SUCCESS(status)) {
				return 0;
			}

			_wcsupr(wcs_module_name.Buffer);

			KAPC_STATE apc{ NULL };
			KeStackAttachProcess(process, &apc);

			PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(process);

			if (peb32) {
				PPEB_LDR_DATA32 ldr_data = reinterpret_cast<PPEB_LDR_DATA32>(peb32->Ldr);
				PLIST_ENTRY32 module_list = reinterpret_cast<PLIST_ENTRY32>(&ldr_data->InLoadOrderModuleList);
				PLDR_DATA_TABLE_ENTRY32 ldr_data_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY32>(module_list->Flink);
				while (module_list != reinterpret_cast<PLIST_ENTRY32>(ldr_data_entry)) {
					PWCHAR name = (PWCHAR)ldr_data_entry->BaseDllName.Buffer;
					UNICODE_STRING dll_name_compare{};
					RtlInitUnicodeString(&dll_name_compare, name);
					if (RtlCompareUnicodeString(&dll_name_compare, &wcs_module_name, TRUE) == 0) {
						module_base_address = reinterpret_cast<PVOID>(ldr_data_entry->DllBase);
						if (image_size) {
							*image_size = ldr_data_entry->SizeOfImage;
						}
						break;
					}
					ldr_data_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY32>(ldr_data_entry->InLoadOrderLinks.Flink);
				}
			}
			else {
				PPEB peb = reinterpret_cast<PPEB>(PsGetProcessPeb(process));
				PPEB_LDR_DATA ldr_data = peb->Ldr;
				PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(&ldr_data->InLoadOrderModuleList);
				PLDR_DATA_TABLE_ENTRY ldr_data_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(module_list->Flink);
				while (module_list != reinterpret_cast<PLIST_ENTRY>(ldr_data_entry)) {
					if (RtlCompareUnicodeString(&ldr_data_entry->BaseDllName, &wcs_module_name, TRUE) == 0) {
						module_base_address = reinterpret_cast<PVOID>(ldr_data_entry->DllBase);
						if (image_size) {
							*image_size = ldr_data_entry->SizeOfImage;
						}
						break;
					}
					ldr_data_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ldr_data_entry->InLoadOrderLinks.Flink);
				}
			}
			KeUnstackDetachProcess(&apc);
			RtlFreeUnicodeString(&wcs_module_name);
			return module_base_address;
		}
	}
}