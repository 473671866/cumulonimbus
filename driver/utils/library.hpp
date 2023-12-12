#include "../standard/base.h"

namespace utils {
	class library {
	public:
		/// @brief ��ȡ�ں�ģ��
		/// @param module_name ģ����
		/// @param size
		/// @return
		static void* kernel_module(std::string module_name, std::size_t* size) {
#pragma warning (push)
#pragma warning(disable:4996)
#pragma warning(disable:4267)
			//��ʼ��
			unsigned long length = sizeof(RTL_PROCESS_MODULES);
			PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, length);
			if (modules == nullptr) {
				return 0;
			}

			//��ѯ����
			void* result = 0;
			NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, modules, length, &length);
			if (status == STATUS_INFO_LENGTH_MISMATCH) {
				ExFreePool(modules);
				modules = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, length);
				if (!modules) {
					return result;
				}
			}

			//����ģ��
			status = ZwQuerySystemInformation(SystemModuleInformation, modules, length, &length);
			if (NT_SUCCESS(status)) {
				for (unsigned int i = 0; i < modules->NumberOfModules; i++) {
					PRTL_PROCESS_MODULE_INFORMATION module_infomation = &modules->Modules[i];
					unsigned char* filename = module_infomation->FullPathName + module_infomation->OffsetToFileName;
					if (_stricmp((char*)filename, module_name.c_str()) == 0) {
						result = module_infomation->ImageBase;
						if (size) {
							*size = module_infomation->ImageSize;
						}
						break;
					}
				}
			}
			ExFreePool(modules);
			return result;
#pragma warning (pop)
		}

		/// @brief ��ȡģ���ļ�
		/// @param filepath �ļ�·��
		/// @param imagesize
		/// @param filesize
		/// @return
		static void* load_library(std::wstring filepath, std::size_t* imagesize, std::size_t* filesize)
		{
			//��ʼ���ļ�·��
			filepath.insert(0, L"\\??\\");
			UNICODE_STRING path{};
			RtlInitUnicodeString(&path, filepath.c_str());

			//��ʼ���ļ�����
			OBJECT_ATTRIBUTES attributes{ };
			InitializeObjectAttributes(&attributes, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);

			//���ļ�
			HANDLE hfile = NULL;
			IO_STATUS_BLOCK create_file_iostatus{};
			NTSTATUS status = ZwCreateFile(&hfile, GENERIC_READ, &attributes, &create_file_iostatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, NULL);
			if (!NT_SUCCESS(status)) {
				return nullptr;
			}

			//��ȡ�ļ���С
			auto close_hfile = std::experimental::make_scope_exit([hfile] {ZwClose(hfile); });
			FILE_STANDARD_INFORMATION information{};
			status = ZwQueryInformationFile(hfile, &create_file_iostatus, &information, sizeof(information), FileStandardInformation);
			if (!NT_SUCCESS(status)) {
				return nullptr;
			}

#pragma warning (push)
#pragma warning(disable:4996)
#pragma warning(disable:4267)
			//�����ļ�������
			size_t file_buffer_size = information.EndOfFile.QuadPart;
			void* filebuffer = ExAllocatePool(PagedPool, file_buffer_size);
			if (filebuffer == nullptr) {
				return nullptr;
			}
#pragma warning (pop)

			//���ļ�
			LARGE_INTEGER file_pointer{  };
			file_pointer.HighPart = -1;
			file_pointer.LowPart = FILE_USE_FILE_POINTER_POSITION;
			status = ZwReadFile(hfile, NULL, NULL, NULL, &create_file_iostatus, filebuffer, file_buffer_size, &file_pointer, NULL);
			if (!NT_SUCCESS(status)) {
				return nullptr;
			}

			PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)filebuffer;
			PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((uint8_t*)filebuffer + lpDosHeader->e_lfanew);
			if (lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
				return nullptr;
			}

			if (filesize) {
				*filesize = file_buffer_size;
			}

			if (imagesize) {
				*imagesize = lpNtHeader->OptionalHeader.SizeOfImage;
			}

			return filebuffer;
		}
	};
}