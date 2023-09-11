#include "standard/base.h"
#include "rw.h"
#include "comm.h"
#include "call.h"
#include "window.h"
#include "utils/utils.h"
#include "utils/memory.hpp"
#include "utils/process.hpp"

//TODO:
//模块hook
//机器码
//图标
//窗口
//反截图

NTSTATUS Controller(CommPackage* package)
{
	switch (package->command) {
	case Command::Link: {
		*(uint64_t*)package->buffer = 0x77777;
		LOG_INFO("link success");
		return STATUS_SUCCESS;
	}

	case Command::Call: {
		LOG_DEBUG("Call");
		RemoteCallPackage* data = reinterpret_cast<RemoteCallPackage*>(package->buffer);
		return RemoteCall((HANDLE)data->pid, (void*)data->shellcode, data->size);
	}

	case Command::Inject: {
		LOG_DEBUG("Inject");
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
		LOG_DEBUG("HideMemory");
		HideMemoryPackage* data = reinterpret_cast<HideMemoryPackage*>(package->buffer);
		memory::MemoryUtils* mem = memory::MemoryUtils::get_instance();
		return mem->HideMemory(reinterpret_cast<HANDLE>(data->pid), data->address, data->size);
	}

	case Command::RecovreMemory: {
		LOG_DEBUG("RecovreMemory");
		memory::MemoryUtils* mem = memory::MemoryUtils::get_instance();
		return mem->RecovreMemory(package->buffer);
	}

	case Command::AllocateMemory: {
		LOG_DEBUG("AllocateMemory");
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		void* address = nullptr;
		auto status = ProcessUtils::PsAllocateMemory((HANDLE)data->pid, &address, data->size, (uint32_t)data->proteced);
		data->address = reinterpret_cast<uint64_t>(address);
		return status;
	}

	case Command::FreeMemory: {
		LOG_DEBUG("FreeMemory");
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return ProcessUtils::PsFreeMemory((HANDLE)data->pid, (void*)data->address, data->size);
	}

	case Command::HideProcess: {
		LOG_DEBUG("HideProcess");
		return ProcessUtils::RemoveProcessEntryList(reinterpret_cast<HANDLE>(package->buffer));
	}

	case Command::Module: {
		LOG_DEBUG("Module");
		ModulePackage* data = reinterpret_cast<ModulePackage*>(package->buffer);
		size_t size = 0;
		uint64_t address = (uint64_t)utils::ldr::GetApplicationModule((HANDLE)data->pid, (char*)data->name, &size);
		data->address = address;
		data->size = size;
		return address == 0 ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
	}

	case Command::ReadMapping: {
		LOG_DEBUG("ReadMapping");
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return ReadMappingMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	case Command::ReadPhysical: {
		LOG_DEBUG("ReadPhysical");
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return ReadPhysicalMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	case Command::WritePhysical: {
		LOG_DEBUG("WritePhysical");
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return WritePhysicalMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	case Command::AntiScreenShot: {
		return AntiScreenShot((HWND)package->buffer) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
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
	AntiScreenShot(nullptr);
	return Register(Controller);
}