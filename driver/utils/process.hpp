#pragma once
#include "../standard/base.h"

namespace utils
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
		ULONG64 InheritedAddressSpace;
		VOID* Mutant;                                                           //0x8
		VOID* ImageBaseAddress;                                                 //0x10
		PEB_LDR_DATA* Ldr;														//0x18
	}PEB, * PPEB;

	class processor {
	public:
		/// @brief 根据名字查找进程
		/// @param name
		/// @param p
		/// @return
		static NTSTATUS get_process_image_file_name(std::string name, PEPROCESS* p)
		{
			PEPROCESS process = nullptr;
			auto status = STATUS_UNSUCCESSFUL;
			constexpr unsigned __int64 max_count = 1024 * 1024 * 512;

			for (unsigned __int64 i = 8; i < max_count; i += 4) {
				status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(i), &process);
				if (NT_SUCCESS(status)) {
					unsigned char* image_name = PsGetProcessImageFileName(process);
					if (image_name && _stricmp(name.c_str(), reinterpret_cast<LPCCH>(image_name)) == 0) {
						*p = process;
						return status;
					}
					ObDereferenceObject(process);
				}
			}
			return status;
		}

		/// @brief 根据进程完整路径查找进程
		/// @param name
		/// @param p
		/// @return
		static NTSTATUS  get_process_image_name(std::wstring name, PEPROCESS* p)
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

		/// @brief 获取进程模块
		/// @param process_id 进程id
		/// @param module_name 模块名字
		/// @param image_size 模块大小
		/// @return
		static void* get_process_module(HANDLE process_id, char* module_name, unsigned long long* image_size)
		{
			if (!process_id || !module_name) {
				return 0;
			}

			//获取进程
			PVOID module_base_address = 0;
			PEPROCESS process = nullptr;
			NTSTATUS status = PsLookupProcessByProcessId(process_id, &process);
			auto dereference_process = std::experimental::make_scope_exit([process] {if (process) ObDereferenceObject(process); });
			if (!NT_SUCCESS(status)) {
				return 0;
			}

			//进程状态
			status = PsGetProcessExitStatus(process);
			if (status != 0x103) {
				return 0;
			}

			//转换为unicode
			ANSI_STRING ansi_module_name{ NULL };
			RtlInitAnsiString(&ansi_module_name, module_name);

			UNICODE_STRING wcs_module_name{ NULL };
			status = RtlAnsiStringToUnicodeString(&wcs_module_name, &ansi_module_name, TRUE);
			if (!NT_SUCCESS(status)) {
				return 0;
			}

			//大写
			_wcsupr(wcs_module_name.Buffer);

			//附加
			KAPC_STATE apc{ NULL };
			KeStackAttachProcess(process, &apc);

			PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(process);
			if (peb32) {
				//x86进程
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
				//x64进程
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

		/// @brief 结束进程
		/// @param pid
		/// @return
		NTSTATUS terminate(HANDLE pid)
		{
			CLIENT_ID clientid{  };
			clientid.UniqueProcess = pid;

			OBJECT_ATTRIBUTES attribute{  };
			attribute.Length = sizeof(OBJECT_ATTRIBUTES);

			HANDLE handle = nullptr;
			auto status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &attribute, &clientid);
			if (!NT_SUCCESS(status)) {
				return status;
			}
			status = ZwTerminateProcess(handle, STATUS_SUCCESS);
			ZwClose(handle);
			return status;
		}

		/// @brief 申请进程内存
		/// @param pid
		/// @param address
		/// @param size
		/// @param protect
		/// @return
		NTSTATUS malloc(HANDLE pid, void** address, size_t size, unsigned __int32 protect)
		{
			//获取进程
			PEPROCESS process = nullptr;
			auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
			auto status = PsLookupProcessByProcessId(pid, &process);
			if (!NT_SUCCESS(status)) {
				return status;
			}

			//进程状态
			if (PsGetProcessExitStatus(process) != 0x103) {
				return STATUS_PROCESS_IS_TERMINATING;
			}

			//附加
			KAPC_STATE apc{};
			KeStackAttachProcess(process, &apc);

			//申请内存
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

		/// @brief 释放进程内存
		/// @param pid
		/// @param address
		/// @param size
		/// @return
		NTSTATUS free(HANDLE pid, void* address, size_t size)
		{
			//获取进程
			PEPROCESS process = nullptr;
			auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
			auto status = PsLookupProcessByProcessId(pid, &process);
			if (!NT_SUCCESS(status)) {
				return status;
			}

			//进程状态
			if (PsGetProcessExitStatus(process) != 0x103) {
				return STATUS_PROCESS_IS_TERMINATING;
			}

			//附加
			KAPC_STATE apc{};
			KeStackAttachProcess(process, &apc);

			//释放内存
			void* allocate_base = address;
			size_t region_size = size;
			status = ZwFreeVirtualMemory(NtCurrentProcess(), &allocate_base, &region_size, MEM_RELEASE);

			//解除附加
			KeUnstackDetachProcess(&apc);
			return status;
		}
	};
}