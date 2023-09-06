#include "standard/base.h"
#include "utils/utils.h"
#include "utils/memory.hpp"
#include "comm.h"
#include "call.h"

//TODO:
//ÄÚ´æ
//¶ÁÐ´
//×¢Èë
//Ä£¿éhook

NTSTATUS Controller(CommPackage* package)
{
	switch (package->command) {
	case Command::Link: {
		*(uint64_t*)package->buffer = 0x77777;
		LOG_INFO("link success");
		break;
	}
	case Command::Call: {
		LOG_INFO("remote call");
		RemoteCallPackage* data = reinterpret_cast<RemoteCallPackage*>(package->buffer);
		return RemoteCall((HANDLE)data->pid, (void*)data->shellcode, data->size);
	}
	default:
		break;
	}
	return STATUS_SUCCESS;
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