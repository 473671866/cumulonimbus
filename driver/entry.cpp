#include "standard/base.h"
#include "rw.h"
#include "comm.h"
#include "call.h"
#include "window.h"
#include "global.h"
#include "utils/utils.h"
#include "utils/memory.hpp"
#include "utils/process.hpp"
#include "utils/version.hpp"
#include "InfinityHook/hook.h"

//TODO:
//Ä£¿éhook
//»úÆ÷Âë
//Í¼±ê

NTSTATUS Controller(CommPackage* package)
{
	switch (package->command) {
	case Command::Link: {
		*(uint64_t*)package->buffer = 0x77777;
		LOG_INFO("link success");
		return STATUS_SUCCESS;
	}

	case Command::Call: {
		RemoteCallPackage* data = reinterpret_cast<RemoteCallPackage*>(package->buffer);
		return RemoteCall((HANDLE)data->pid, (void*)data->shellcode, data->size);
	}

	case Command::LoadLibrary_x64: {
		InjectPackage* data = reinterpret_cast<InjectPackage*>(package->buffer);
		if (!utils::ProbeUserAddress((void*)data->filebuffer, data->filesize, 1)) {
			LOG_INFO("LoadLibrary_x64 invalid filebuffer");
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

	case Command::LoadLibrary_x86: {
		InjectPackage* data = reinterpret_cast<InjectPackage*>(package->buffer);
		if (!utils::ProbeUserAddress((void*)data->filebuffer, data->filesize, 1)) {
			LOG_INFO("LoadLibrary_x86 invalid filebuffer");
			return STATUS_INVALID_ADDRESS;
		}

		void* filebuffer = utils::RtlAllocateMemory(PagedPool, data->filesize);
		if (!filebuffer) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		RtlCopyMemory(filebuffer, reinterpret_cast<void*>(data->filebuffer), data->filesize);
		auto status = LoadLibrary_x86(reinterpret_cast<HANDLE>(data->pid), filebuffer, data->filesize, data->imagesize);
		utils::RtlFreeMemory(filebuffer);
		return status;
	}

	case Command::HideMemory: {
		auto version = Version::get_instance();
		if (version->Windows_7()) {
			return STATUS_UNSUCCESSFUL;
		}
		else {
			HideMemoryPackage* data = reinterpret_cast<HideMemoryPackage*>(package->buffer);
			memory::MemoryUtils* mem = memory::MemoryUtils::get_instance();
			return mem->HideMemory(reinterpret_cast<HANDLE>(data->pid), data->address, data->size);
		}
	}

	case Command::RecovreMemory: {
		auto version = Version::get_instance();
		if (version->Windows_7()) {
			return STATUS_UNSUCCESSFUL;
		}
		else {
			memory::MemoryUtils* mem = memory::MemoryUtils::get_instance();
			HideMemoryPackage* data = reinterpret_cast<HideMemoryPackage*>(package->buffer);
			return mem->RecovreMemory((HANDLE)data->pid, data->address);
		}
	}

	case Command::AllocateMemory: {
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		void* address = nullptr;
		auto status = ProcessUtils::AllocateMemory((HANDLE)data->pid, &address, data->size, (uint32_t)data->protect);
		data->address = reinterpret_cast<uint64_t>(address);
		return status;
	}

	case Command::FreeMemory: {
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return ProcessUtils::FreeMemory((HANDLE)data->pid, (void*)data->address, data->size);
	}

	case Command::HideProcess: {
		return ProcessUtils::RemoveProcessEntryList(reinterpret_cast<HANDLE>(package->buffer));
	}

	case Command::Module: {
		ModulePackage* data = reinterpret_cast<ModulePackage*>(package->buffer);
		size_t size = 0;
		uint64_t address = (uint64_t)utils::ldr::GetApplicationModule((HANDLE)data->pid, (char*)data->name, &size);
		data->address = address;
		data->size = size;
		return address == 0 ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
	}

	case Command::TerminateProcess: {
		return ProcessUtils::TerminateProcess((HANDLE)package->buffer);
	}

	case Command::ReadMapping: {
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return ReadMappingMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	case Command::ReadPhysical: {
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return ReadPhysicalMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	case Command::WritePhysical: {
		MemoryPackage* data = reinterpret_cast<MemoryPackage*>(package->buffer);
		return WritePhysicalMemory((HANDLE)data->pid, (void*)data->address, (void*)data->buffer, data->size);
	}

	case Command::AntiScreenShot: {
		return AntiScreenShot((HWND)package->buffer) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	case Command::InitializeWindowProtected: {
		if (hook::Initialize(WindowProtected)) {
			if (hook::Launcher()) {
				return STATUS_SUCCESS;
			}
		}
		return STATUS_UNSUCCESSFUL;
	}

	case Command::InstallWindowProtected: {
		auto collection = GetGlobalVector();
		collection->push_back(package->buffer);
		return STATUS_SUCCESS;
	}

	case Command::UnloadWindowProtected: {
		return hook::Terminator() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	default:
		break;
	}
	return STATUS_UNSUCCESSFUL;
}

void DriverUnload(PDRIVER_OBJECT)
{
	LogTermination();
	comm::UnRegister();
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

	//GetZwUserGetForegroundWindowAddress();
	//GetZwUserWindowFromPointAddress();
	//GetNtUserBuildHwndListAddress();
	//GetNtUserQueryWindowAddress();
	//GetNtUserFindWindowExAddress();

	return comm::Register(Controller);
}