#include "rw.h"
#include "utils/utils.h"
#include "utils/process.hpp"
#include "utils/memory.hpp"

NTSTATUS ReadMappingMemory(HANDLE pid, void* address, void* buffer, size_t size)
{
	if (address > MmHighestUserAddress) {
		return STATUS_INVALID_ADDRESS;
	}

	if (((uint64_t)address + size) >> (uint64_t)MmHighestUserAddress)
	{
		return STATUS_INVALID_ADDRESS;
	}

	if (((uint64_t)address + size) < (uint64_t)address)
	{
		return STATUS_INVALID_ADDRESS;
	}

	if (buffer == nullptr || !MmIsAddressValid(buffer)) {
		return STATUS_INVALID_ADDRESS;
	}

	void* temp = utils::RtlAllocateMemory(PagedPool, size);
	if (temp == nullptr) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	ProcessUtils prc;
	auto status = prc.StackAttachProcess(pid);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	if (MmIsAddressValid(address)) {
		RtlCopyMemory(temp, address, size);
	}

	prc.UnStackAttachProcess();
	RtlCopyMemory(buffer, temp, size);
	utils::RtlFreeMemory(temp);
	return status;
}

NTSTATUS ReadPhysicalMemory(HANDLE pid, void* address, void* buffer, size_t size)
{
	PEPROCESS  process = nullptr;
	auto status = PsLookupProcessByProcessId(pid, &process);
	auto dereference_process = make_scope_exit([process] {if (process)ObDereferenceObject(process); });
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = PsGetProcessExitStatus(process);
	if (status != 0x103) {
		return status;
	}

	if (address > MmHighestUserAddress) {
		return STATUS_INVALID_ADDRESS;
	}

	if (((uint64_t)address + size) >> (uint64_t)MmHighestUserAddress)
	{
		return STATUS_INVALID_ADDRESS;
	}

	if (((uint64_t)address + size) < (uint64_t)address)
	{
		return STATUS_INVALID_ADDRESS;
	}

	if (buffer == nullptr || !MmIsAddressValid(buffer)) {
		return STATUS_INVALID_ADDRESS;
	}

	void* temp = utils::RtlAllocateMemory(PagedPool, size);
	if (temp == nullptr) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	uint64_t system_dicetory = __readcr3();
	uint64_t process_dircetory = *(uint64_t*)((uint8_t*)process + 0x28);

	KeEnterCriticalRegion();
	_disable();
	__writecr3(process_dircetory);

	if (MmIsAddressValid(address)) {
		RtlCopyMemory(temp, address, size);
	}

	_enable();
	__writecr3(system_dicetory);
	KeLeaveCriticalRegion();

	RtlCopyMemory(buffer, temp, size);
	utils::RtlFreeMemory(temp);

	return status;
}

NTSTATUS WritePhysicalMemory(HANDLE pid, void* address, void* buffer, size_t size)
{
	PEPROCESS  process = nullptr;
	auto status = PsLookupProcessByProcessId(pid, &process);
	auto dereference_process = make_scope_exit([process] {if (process)ObDereferenceObject(process); });
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = PsGetProcessExitStatus(process);
	if (status != 0x103) {
		return status;
	}

	if (address > MmHighestUserAddress) {
		return STATUS_INVALID_ADDRESS;
	}

	if (((uint64_t)address + size) >> (uint64_t)MmHighestUserAddress)
	{
		return STATUS_INVALID_ADDRESS;
	}

	if (((uint64_t)address + size) < (uint64_t)address)
	{
		return STATUS_INVALID_ADDRESS;
	}

	if (buffer == nullptr || !MmIsAddressValid(buffer)) {
		return STATUS_INVALID_ADDRESS;
	}

	void* temp = utils::RtlAllocateMemory(PagedPool, size);
	if (temp == nullptr) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlCopyMemory(temp, buffer, size);

	uint64_t system_dicetory = __readcr3();
	uint64_t process_dircetory = *(uint64_t*)((uint8_t*)process + 0x28);

	KeEnterCriticalRegion();
	_disable();
	__writecr3(process_dircetory);

	if (MmIsAddressValid(address)) {
		void* mapping = MmMapIoSpace(MmGetPhysicalAddress(address), size, MmCached);
		if (mapping) {
			RtlCopyMemory(address, temp, size);
			MmUnmapIoSpace(mapping, size);
		}
	}

	_enable();
	__writecr3(system_dicetory);
	KeLeaveCriticalRegion();

	utils::RtlFreeMemory(temp);

	return status;
}