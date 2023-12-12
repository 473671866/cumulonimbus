#pragma once
#include "standard/base.h"

namespace business
{
	NTSTATUS ReadMappingMemory(HANDLE pid, void* address, void* buffer, size_t size);

	NTSTATUS ReadPhysicalMemory(HANDLE pid, void* address, void* buffer, size_t size);

	NTSTATUS WritePhysicalMemory(HANDLE pid, void* address, void* buffer, size_t size);

	NTSTATUS RemoteCall(HANDLE pid, void* shellcode, size_t size);

	NTSTATUS LoadLibrary_x64(HANDLE pid, void* filebuffer, size_t filesize, size_t imagesize);

	NTSTATUS LoadLibrary_x86(HANDLE pid, void* filebuffer, size_t filesize, size_t imagesize);

	NTSTATUS HideProcess(HANDLE pid);
};
