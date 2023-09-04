#include "standard/base.h"
#include "comm.h"
//TODO:
//¶ÁÐ´
//call
//×¢Èë
//ÄÚ´æ
//Ä£¿éhook

NTSTATUS Controller(CommPackage* package)
{
	switch (package->command) {
	case Command::Link: {
		*(uint64_t*)package->buffer = 0x77777;
		LOG_INFO("link success\n");
		break;
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

	if (driver_object != nullptr) {
		driver_object->DriverUnload = DriverUnload;
	}

	if (!NT_SUCCESS(status)) {
		return status;
	}

	return Register(Controller);
}