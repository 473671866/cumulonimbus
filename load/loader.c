#include "loader.h"
#include "utils.h"
#include <ntimage.h>
#include <stdbool.h>

typedef struct _IMAGE_RELOC
{
	UINT16	Offset : 12;		// 低12位---偏移
	UINT16	Type : 4;			// 高4位---类型
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef NTSTATUS(NTAPI* DriverEntryProc)(PDRIVER_OBJECT lpDrivrObject, PUNICODE_STRING lpRegisterPath);

unsigned __int8* FileToImage(unsigned __int8* filebuffer)
{
	if (filebuffer == NULL) {
		return NULL;
	}

	//复制PE头
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)filebuffer;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(filebuffer + lpDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER lpSectionHeader = IMAGE_FIRST_SECTION(lpNtHeader);
	unsigned __int32 imagesize = lpNtHeader->OptionalHeader.SizeOfImage;
	unsigned __int8* imagebuffer = (unsigned __int8*)RtlAllocatePool(NonPagedPool, imagesize);
	unsigned __int32 NumberOfSections = lpNtHeader->FileHeader.NumberOfSections;
	RtlCopyMemory(imagebuffer, filebuffer, lpNtHeader->OptionalHeader.SizeOfHeaders);

	//拉伸PE 结构
	for (unsigned __int32 i = 0; i < NumberOfSections; i++) {
		RtlCopyMemory(imagebuffer + lpSectionHeader->VirtualAddress, filebuffer + lpSectionHeader->PointerToRawData, lpSectionHeader->SizeOfRawData);
		lpSectionHeader++;
	}
	return imagebuffer;
}

bool UpdataRelocation(unsigned __int8* imagebuffer)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)imagebuffer;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(imagebuffer + lpDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY lpRelocationDircetory = &lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_BASE_RELOCATION lpBaseRelocation = (PIMAGE_BASE_RELOCATION)(imagebuffer + lpRelocationDircetory->VirtualAddress);

	while (lpBaseRelocation->SizeOfBlock && lpBaseRelocation->VirtualAddress) {
		PIMAGE_RELOC lpRelocationBlock = (PIMAGE_RELOC)((unsigned __int8*)lpBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		unsigned __int32 NumberOfRelocations = (lpBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

		for (unsigned __int32 i = 0; i < NumberOfRelocations; i++) {
			if (lpRelocationBlock[i].Type == IMAGE_REL_BASED_DIR64) {
				unsigned __int64* Address = (unsigned __int64*)((unsigned __int8*)imagebuffer + lpBaseRelocation->VirtualAddress + lpRelocationBlock[i].Offset);
				unsigned __int64  Delta = (unsigned __int64)(*Address - lpNtHeader->OptionalHeader.ImageBase + imagebuffer);
				*Address = Delta;
			}
			else if (lpRelocationBlock[i].Type == IMAGE_REL_BASED_HIGHLOW) {
				unsigned __int32* Address = (unsigned __int32*)((unsigned __int8*)imagebuffer + lpBaseRelocation->VirtualAddress + (lpRelocationBlock[i].Offset));
				unsigned __int32  Delta = (unsigned __int32)(*Address - lpNtHeader->OptionalHeader.ImageBase + (unsigned __int64)imagebuffer);
				*Address = Delta;
			}
		}
		lpBaseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)lpBaseRelocation + lpBaseRelocation->SizeOfBlock);
	}

	return TRUE;
}

BOOLEAN UpdataIAT(unsigned __int8* imagebuffer)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)imagebuffer;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(imagebuffer + lpDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY lpDataDricetory = &lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR lpImportDricetory = (PIMAGE_IMPORT_DESCRIPTOR)(imagebuffer + lpDataDricetory->VirtualAddress);
	BOOLEAN isSuccess = TRUE;

	for (; lpImportDricetory->FirstThunk; lpImportDricetory++) {
		unsigned char* module_name = (imagebuffer + lpImportDricetory->Name);
		void* base = GetKenelModule(module_name, NULL);
		if (!base) {
			isSuccess = FALSE;
			break;
		}

		PIMAGE_THUNK_DATA lpThuckName = (PIMAGE_THUNK_DATA)(imagebuffer + lpImportDricetory->OriginalFirstThunk);
		PIMAGE_THUNK_DATA lpThuckFunc = (PIMAGE_THUNK_DATA)(imagebuffer + lpImportDricetory->FirstThunk);
		for (; lpThuckName->u1.Function; ++lpThuckName, ++lpThuckFunc) {
			PIMAGE_IMPORT_BY_NAME lpFuncName = (PIMAGE_IMPORT_BY_NAME)(imagebuffer + lpThuckName->u1.AddressOfData);
			void* func = GetSystemRoutine((unsigned __int8*)base, lpFuncName->Name);
			KdPrintEx((77, 0, "lpFuncName->Name: %s address: %llx\n", lpFuncName->Name, func));
			if (func) {
				lpThuckFunc->u1.Function = (unsigned __int64)func;
			}
			else {
				isSuccess = FALSE;
				break;
			}
		}

		if (!isSuccess) {
			break;
		}
	}

	return isSuccess;
}

VOID UpdateCookie(unsigned __int8* imagebuffer)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)imagebuffer;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(imagebuffer + lpDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY lpDataDricetory = &lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	PIMAGE_LOAD_CONFIG_DIRECTORY lpLoadConfigDriectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)(lpDataDricetory->VirtualAddress + imagebuffer);
	*(unsigned __int64*)(lpLoadConfigDriectory->SecurityCookie) += 10;
	return;
}

BOOLEAN LoadDriver(unsigned __int8* filebuffer)
{
	unsigned __int8* imagebuffer = FileToImage(filebuffer);
	if (!imagebuffer) {
		RtlFreePool(imagebuffer);
		return FALSE;
	}

	BOOLEAN isSuccess = UpdataRelocation(imagebuffer);
	if (!isSuccess) {
		RtlFreePool(imagebuffer);
		return isSuccess;
	}

	isSuccess = UpdataIAT(imagebuffer);
	if (!isSuccess) {
		RtlFreePool(imagebuffer);
		return isSuccess;
	}

	UpdateCookie(imagebuffer);

	//call 入口点
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)imagebuffer;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(imagebuffer + lpDosHeader->e_lfanew);
	unsigned __int64 Entry = lpNtHeader->OptionalHeader.AddressOfEntryPoint;
	DriverEntryProc entry = (DriverEntryProc)(imagebuffer + Entry);
	NTSTATUS status = entry(NULL, NULL);
	if (!NT_SUCCESS(status)) {
		RtlFreePool(imagebuffer);
		return FALSE;
	}
	//清空PE头
	RtlZeroMemory(imagebuffer, PAGE_SIZE);
	return isSuccess;
}