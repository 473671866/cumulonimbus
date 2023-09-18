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

	NTSTATUS RemoveProcessEntryList(HANDLE pid);

	NTSTATUS AllocateMemory(HANDLE pid, void** address, size_t size, uint32_t protect);

	NTSTATUS FreeProcessMemory(HANDLE pid, void* address, size_t size);

	NTSTATUS TerminateProcess(HANDLE pid);

	uint64_t GetZwUserGetForegroundWindowAddress();

	uint64_t GetZwUserWindowFromPointAddress();

	uint64_t GetNtUserBuildHwndListAddress();

	uint64_t GetNtUserQueryWindowAddress();

	uint64_t GetNtUserFindWindowExAddress();

	void WindowProtected(_In_ unsigned long SystemCallIndex, _Inout_ void** SystemCallFunction);
};
