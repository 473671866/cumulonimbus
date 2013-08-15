#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "../standard/base.h"

namespace utils
{
	NTSTATUS LookupProcessByImageFileName(std::string name, PEPROCESS* p);

	NTSTATUS LookupProcessByImageName(std::wstring image_name, PEPROCESS* p);

	void* GetKernelModule(std::string module_name, size_t* size);

	uint64_t GetSectionAddress(uint64_t image_base, std::string section_name, size_t* size);

	void* GetModuleRoutineAddress(uint64_t image_base, std::string funation_name);

	PVOID  GetRoutineStartAddress(uint64_t image_base, void* address);

	void* LoadImage(std::wstring file_path, size_t* imagesize, size_t* filesize);
}
