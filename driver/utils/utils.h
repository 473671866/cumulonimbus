#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "../Standard/base.h"

namespace Utils
{
	typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;

	NTSTATUS LookupProcessByImageFileName(std::string name, PEPROCESS* p);
	NTSTATUS LookupProcessByImageName(std::wstring image_name, PEPROCESS* p);

	char* CharToUper(char* wstr, boolean isAllocateMemory);
	int32_t StringToHex(unsigned char* hex, unsigned char* str, size_t size);

	uint64_t GetKernelModule(std::string module_name, size_t* size);
	uint64_t GetSectionAddress(uint64_t image_base, std::string section_name, size_t* size);
	void* GetModuleRoutineAddress(uint64_t image_base, std::string funation_name);
	PVOID  GetRoutineStartAddress(uint64_t image_base, void* address);

	void* LoadImage(std::wstring file_path, size_t* imagesize, size_t* filesize);
}
