#include "standard/base.h"
#include "rw.h"
#include "comm.h"
#include "call.h"
#include "utils/utils.h"
#include "utils/memory.hpp"
#include "utils/process.hpp"

//TODO:
//Ä£¿éhook
//»úÆ÷Âë
//Í¼±ê
//´°¿Ú
//·´½ØÍ¼
//ÉêÇëÄÚ´æ

NTSTATUS Controller(CommPackage* package)
{
	switch (package->command) {
	case Command::Link: {
		*(uint64_t*)package->buffer = 0x77777;
		LOG_INFO("link success");
		return STATUS_SUCCESS;
	}

	case Command::Call: {
		LOG_INFO("Call");
		RemoteCallPackage* data = reinterpret_cast<RemoteCallPackage*>(package->buffer);
		return RemoteCall((HANDLE)data->pid, (void*)data->shellcode, data->size);
	}

	case Command::Inject: {
		LOG_INFO("Inject");
		InjectPackage* data = reinterpret_cast<InjectPackage*>(package->buffer);
		if (!MmIsAddressValid(reinterpret_cast<void*>(data->filebuffer))) {
			return STATUS_INVALID_ADDRESS;
		}

		void* filebuffer = utils::RtlAllocateMemory(PagedPool, data->filesize);

		if (!filebuffer) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		RtlCopyMemory(filebuffer, reinterpret_cast<void*>(data->filebuffer), data->filesize);
		auto status = LoadLibrary_x64(reinterpret_cast<HANDLE>(data->pid), filebuffer, data->filesize, data->imagesize);
		utils::RtlFreeMemory(filebuffer);
		return status;
	}

	case Command::HideMemory: {
		LOG_INFO("HideMemory");
		HideMemoryPackage* data = reinterpret_cast<HideMemoryPackage*>(package->buffer);
		memory::MemoryUtils* mem = memory::MemoryUtils::get_instance();
		return mem->HideMemory(reinterpret_cast<HANDLE>(data->pid), data->address, data->size);
	}

	case Command::RecovreMemory: {
		LOG_INFO("RecovreMemory");
		memory::MemoryUtils* mem = memory::MemoryUtils::get_instance();
		return mem->RecovreMemory(package->buffer);
	}

	case Command::HideProcess: {
		LOG_INFO("HideProcess");
		return ProcessUtils::RemoveProcessEntryList(reinterpret_cast<HANDLE>(package->buffer));
	}

	case Command::Module: {
		LOG_INFO("Module");
		ModulePackage* data = reinterpret_cast<ModulePackage*>(package->buffer);
		size_t size = 0;
		uint64_t address = (uint64_t)utils::ldr::GetApplicationModule((HANDLE)data->pid, (char*)data->name, &size);
		data->address = address;
		data->size = size;
		return address == 0 ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
	}

	case Command::ReadMapping: {
		LOG_INFO("ReadMapping");
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return ReadMappingMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	case Command::ReadPhysical: {
		LOG_INFO("ReadPhysical");
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return ReadPhysicalMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	case Command::WritePhysical: {
		LOG_INFO("WritePhysical");
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return WritePhysicalMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	default:
		break;
	}
	return STATUS_UNSUCCESSFUL;
}

void DriverUnload(PDRIVER_OBJECT)
{
	LogTermination();
	UnRegister();
	return;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING)
{
	constexpr auto log_level = (IsReleaseBuild()) ? kLogPutLevelInfo : kLogPutLevelDebug;
	constexpr wchar_t log_file_path[] = L"\\SystemRoot\\cumulonimbus.log";
	auto status = LogInitialization(log_level, log_file_path);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	if (driver_object != nullptr) {
		driver_object->DriverUnload = DriverUnload;
	}
	return Register(Controller);
}