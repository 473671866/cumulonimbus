#include "standard/base.h"
#include "utils/utils.h"
#include "comm.h"
#include "call.h"

//TODO:
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

#include "pdb/oxygenPdb.h"

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

	size_t imagesize = 0;
	size_t file_size = 0;
	void* file_buffer = Utils::LoadImage(L"C:\\Users\\ljw-cccc\\Desktop\\Dll.dll", &imagesize, &file_size);
	if (file_buffer != nullptr) {
		LoadLibrary_x64((HANDLE)3692, file_buffer, file_size, imagesize);
	}
	ExFreePool(file_buffer);

	return Register(Controller);
}