#include "utils.h"
#include "nt.h"
#include <ntimage.h>

void* RtlAllocatePool(POOL_TYPE type, unsigned __int64 size)
{
	void* buffer = ExAllocatePoolWithTag(type, size, 'mem');
	if (buffer) {
		RtlZeroMemory(buffer, size);
	}
	return buffer;
}

void RtlFreePool(void* address)
{
	ExFreePoolWithTag(address, 'mem');
	return;
}

unsigned __int64* GetKenelModule(unsigned char* module_name, unsigned __int64* module_size)
{
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)RtlAllocatePool(PagedPool, sizeof(RTL_PROCESS_MODULES));
	ULONG length = 0;
	void* result = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, modules, sizeof(RTL_PROCESS_MODULES), &length);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		RtlFreePool(modules);
		modules = RtlAllocatePool(PagedPool, length + sizeof(RTL_PROCESS_MODULES));
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, length + sizeof(RTL_PROCESS_MODULES), &length);
	if (!NT_SUCCESS(status)) {
		RtlFreePool(modules);
		return 0;
	}

	for (unsigned int i = 0; i < modules->NumberOfModules; i++)
	{
		PRTL_PROCESS_MODULE_INFORMATION module_infomation = &modules->Modules[i];
		unsigned char* filename = module_infomation->FullPathName + module_infomation->OffsetToFileName;
		if (_stricmp((char*)filename, (char*)module_name) == 0) {
			result = module_infomation->ImageBase;
			if (module_size) {
				*module_size = module_infomation->ImageSize;
			}
			RtlFreePool(modules);
			return result;
		}
	}

	RtlFreePool(modules);
	return result;
}

void* GetSystemRoutine(unsigned __int8* imagebuffer, char* function)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)imagebuffer;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(imagebuffer + lpDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY lpDataDirectory = (PIMAGE_DATA_DIRECTORY)&lpNtHeader->OptionalHeader.DataDirectory[0];
	PIMAGE_EXPORT_DIRECTORY lpExporyDircetory = (PIMAGE_EXPORT_DIRECTORY)(imagebuffer + lpDataDirectory->VirtualAddress);

	void* address = 0;
	for (unsigned __int32 i = 0; i < lpExporyDircetory->NumberOfNames; i++) {
		int index = -1;
		int* funcAddress = (int*)(imagebuffer + lpExporyDircetory->AddressOfFunctions);
		int* names = (int*)(imagebuffer + lpExporyDircetory->AddressOfNames);
		short* fh = (short*)(imagebuffer + lpExporyDircetory->AddressOfNameOrdinals);
		char* name = (char*)(imagebuffer + names[i]);
		if (_stricmp(name, function) == 0) {
			index = fh[i];
		}

		if (index != -1) {
			address = imagebuffer + funcAddress[index];
			break;
		}
	}
	return address;
}

NTSTATUS DeleteRegisterPath(PUNICODE_STRING register_path)
{
	wchar_t* enum_path = (wchar_t*)RtlAllocatePool(PagedPool, register_path->MaximumLength + 0x100);
	RtlCopyMemory(enum_path, register_path->Buffer, register_path->Length);
	wcscat(enum_path, L"\\Enum");

	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, register_path->Buffer, L"DisplayName");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, register_path->Buffer, L"ErrorControl");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, register_path->Buffer, L"ImagePath");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, register_path->Buffer, L"Start");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, register_path->Buffer, L"Type");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, register_path->Buffer, L"WOW64");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enum_path, L"enumPath");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enum_path, L"INITSTARTFAILED");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, enum_path, L"NextInstance");

	UNICODE_STRING enum_name;
	RtlInitUnicodeString(&enum_name, enum_path);
	OBJECT_ATTRIBUTES attribute;
	InitializeObjectAttributes(&attribute, &enum_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE key = NULL;
	NTSTATUS status = ZwOpenKey(&key, KEY_ALL_ACCESS, &attribute);
	if (NT_SUCCESS(status)) {
		ZwDeleteKey(key);
		ZwClose(key);
	}

	OBJECT_ATTRIBUTES root_attribute = { 0 };
	InitializeObjectAttributes(&root_attribute, register_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE root_key = NULL;
	status = ZwOpenKey(&root_key, KEY_ALL_ACCESS, &root_attribute);
	if (NT_SUCCESS(status)) {
		ZwDeleteKey(root_key);
		ZwClose(root_key);
	}

	RtlFreePool(enum_path);
	return status;
}

NTSTATUS SelfDeleteFile(wchar_t* path)
{
	UNICODE_STRING file_name;
	RtlInitUnicodeString(&file_name, path);
	OBJECT_ATTRIBUTES file_attribute;
	InitializeObjectAttributes(&file_attribute, &file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hfile = NULL;
	IO_STATUS_BLOCK file_block;
	NTSTATUS status = ZwCreateFile(&hfile, GENERIC_READ, &file_attribute, &file_block, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	PFILE_OBJECT file_object = NULL;
	status = ObReferenceObjectByHandle(hfile, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, &file_object, NULL);
	if (!NT_SUCCESS(status)) {
		ZwClose(hfile);
		return status;
	}

	file_object->DeleteAccess = TRUE;
	file_object->DeletePending = FALSE;
	file_object->SectionObjectPointer->DataSectionObject = NULL;
	file_object->SectionObjectPointer->ImageSectionObject = NULL;
	ObDereferenceObject(file_object);
	ZwClose(hfile);
	return ZwDeleteFile(&file_attribute);
}