#pragma once
#include <ntifs.h>

void* RtlAllocatePool(POOL_TYPE type, unsigned __int64 size);

void RtlFreePool(void* address);

unsigned __int64* GetKenelModule(unsigned char* module_name, unsigned __int64* module_size);

void* GetSystemRoutine(unsigned __int8* imagebuffer, char* function);

NTSTATUS DeleteRegisterPath(PUNICODE_STRING register_path);

NTSTATUS SelfDeleteFile(wchar_t* path);