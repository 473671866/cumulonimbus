#include "standard/base.h"
#include "comm.h"
#include "business.h"
#include "utils/memory.hpp"
#include "utils/process.hpp"

NTSTATUS Controller(stream* package)
{
	auto status = STATUS_UNSUCCESSFUL;
	switch (package->cmd) {
	case command::link: {
		*(unsigned __int64*)package->buffer = 0x77777;
		status = STATUS_SUCCESS;
		break;
	}

	case command::library: {
		library_stream* data = reinterpret_cast<library_stream*>(package->buffer);
		unsigned __int64 size = 0;
		unsigned __int64 address = (unsigned __int64)utils::processor::get_process_module((HANDLE)data->pid, (char*)data->name, &size);
		data->address = address;
		data->size = size;
		status = address == 0 ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
		break;
	}

	case command::read: {
		memory_stream* data = reinterpret_cast<memory_stream*>(package->buffer);
		status = business::ReadPhysicalMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
		break;
	}

	case command::write: {
		memory_stream* data = reinterpret_cast<memory_stream*>(package->buffer);
		status = business::WritePhysicalMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
		break;
	}

					   //case command::Call: {
					   //	//Ô¶³Ìcall
					   //	RemoteCallPackage* data = reinterpret_cast<RemoteCallPackage*>(package->buffer);
					   //	return business::RemoteCall((HANDLE)data->pid, (void*)data->shellcode, data->size);
					   //}

					   //case Command::LoadLibrary_x64: {
					   //	InjectPackage* data = reinterpret_cast<InjectPackage*>(package->buffer);
					   //	if (!utils::memory::probe((void*)data->filebuffer, data->filesize, 1)) {
					   //		return STATUS_INVALID_ADDRESS;
					   //	}

					   //	void* filebuffer = utils::memory::malloc(PagedPool, data->filesize);
					   //	if (!filebuffer) {
					   //		return STATUS_MEMORY_NOT_ALLOCATED;
					   //	}

					   //	RtlCopyMemory(filebuffer, reinterpret_cast<void*>(data->filebuffer), data->filesize);
					   //	auto status = business::LoadLibrary_x64(reinterpret_cast<HANDLE>(data->pid), filebuffer, data->filesize, data->imagesize);
					   //	utils::memory::free(filebuffer);
					   //	return status;
					   //}

					   //case Command::LoadLibrary_x86: {
					   //	InjectPackage* data = reinterpret_cast<InjectPackage*>(package->buffer);
					   //	if (!utils::ProbeUserAddress((void*)data->filebuffer, data->filesize, 1)) {
					   //		LOG_INFO("LoadLibrary_x86 invalid filebuffer");
					   //		return STATUS_INVALID_ADDRESS;
					   //	}

					   //	void* filebuffer = utils::RtlAllocateMemory(PagedPool, data->filesize);
					   //	if (!filebuffer) {
					   //		return STATUS_MEMORY_NOT_ALLOCATED;
					   //	}

					   //	RtlCopyMemory(filebuffer, reinterpret_cast<void*>(data->filebuffer), data->filesize);
					   //	auto status = business::LoadLibrary_x86(reinterpret_cast<HANDLE>(data->pid), filebuffer, data->filesize, data->imagesize);
					   //	utils::RtlFreeMemory(filebuffer);
					   //	return status;
					   //}

					   //case Command::HideMemory: {
					   //	auto version = version::get_instance();
					   //	if (version->windows_7()) {
					   //		return STATUS_UNSUCCESSFUL;
					   //	}
					   //	else {
					   //		HideMemoryPackage* data = reinterpret_cast<HideMemoryPackage*>(package->buffer);
					   //		memory::MemoryUtils* mem = memory::MemoryUtils::get_instance();
					   //		return mem->HideMemory(reinterpret_cast<HANDLE>(data->pid), data->address, data->size);
					   //	}
					   //}

					   //case Command::RecovreMemory: {
					   //	auto version = version::get_instance();
					   //	if (version->windows_7()) {
					   //		return STATUS_UNSUCCESSFUL;
					   //	}
					   //	else {
					   //		memory::MemoryUtils* mem = memory::MemoryUtils::get_instance();
					   //		HideMemoryPackage* data = reinterpret_cast<HideMemoryPackage*>(package->buffer);
					   //		return mem->RecovreMemory((HANDLE)data->pid, data->address);
					   //	}
					   //}

					   //case Command::AllocateMemory: {
					   //	MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
					   //	void* address = nullptr;
					   //	auto status = business::AllocateProcessMemory((HANDLE)data->pid, &address, data->size, (uint32_t)data->protect);
					   //	data->address = reinterpret_cast<uint64_t>(address);
					   //	return status;
					   //}

					   //case Command::FreeMemory: {
					   //	MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
					   //	return business::FreeProcessMemory((HANDLE)data->pid, (void*)data->address, data->size);
					   //}

					   //case Command::HideProcess: {
					   //	return business::HideProcess(reinterpret_cast<HANDLE>(package->buffer));
					   //}

					   //case Command::TerminateProcess: {
					   //	return business::TerminateProcess((HANDLE)package->buffer);
					   //}

					   //case Command::ReadMapping: {
					   //	MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
					   //	return business::ReadMappingMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
					   //}
					   //case Command::AntiScreenShot: {
					   //	return routine::GreProtectSpriteContent((HWND)package->buffer) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
					   //}

	default:
		break;
	}
	return status;
}

void DriverUnload(PDRIVER_OBJECT)
{
	comm::UnRegister();
	return;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING)
{
	if (driver_object != nullptr) {
		driver_object->DriverUnload = DriverUnload;
	}
	return comm::Register(Controller);
}