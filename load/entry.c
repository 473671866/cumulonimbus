#include <ntifs.h>
#include "loader.h"
#include "utils.h"
#include "nt.h"
typedef struct _CommPackage
{
	ULONG64 filesize;
	ULONG64 filebuffer;
}CommPackage;

PUNICODE_STRING g_register_path;

NTSTATUS CreateAndClose(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;//响应成功;
	IoCompleteRequest(Irp, 0);//请求完成;
	_Unreferenced_parameter_(DeviceObject);
	return STATUS_SUCCESS;
}

NTSTATUS ControlDispath(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);//获取当前栈
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ULONG length = stack->Parameters.Write.Length;
	void* buffer = Irp->AssociatedIrp.SystemBuffer;
	CommPackage* package = (CommPackage*)buffer;
	if (!MmIsAddressValid(buffer) || length <= 0) {
		KdPrintEx((77, 0, "invalid buffer\n"));
		return STATUS_INVALID_ADDRESS;
	}

	__try {
		ProbeForRead((void*)package->filebuffer, package->filesize, 1);
		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KdPrintEx((77, 0, "invalid filebuffer\n"));
		status = STATUS_INVALID_ADDRESS;
	}

	if (NT_SUCCESS(status)) {
		unsigned __int8* filebuffer = (unsigned __int8*)RtlAllocatePool(PagedPool, package->filesize);
		RtlCopyMemory(filebuffer, (void*)package->filebuffer, package->filesize);
		if (!LoadDriver(filebuffer)) {
			status = STATUS_UNSUCCESSFUL;
			KdPrintEx((77, 0, "driver mapping failed\n"));
		}
		RtlFreePool(filebuffer);
	}

	//PVOID hsection = NULL;
	//OBJECT_ATTRIBUTES attributes = { 0 };
	//InitializeObjectAttributes(&attributes, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
	//LARGE_INTEGER section_size = { .QuadPart = length };
	//status = MmCreateSection(&hsection, SECTION_ALL_ACCESS, &attributes, &section_size, PAGE_EXECUTE_READWRITE, 0x1000000, NULL, NULL);
	//if (!NT_SUCCESS(status)) {
	//	return status;
	//}

	//void* section_view = 0;
	//SIZE_T view_size = 0;
	//status = ZwMapViewOfSection(hsection, ZwCurrentProcess(), &section_view, NULL, package->filesize, NULL, &view_size, ViewUnmap, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//if (!NT_SUCCESS(status)) {
	//	return status;
	//}

	//RtlCopyMemory(section_view, package->filebuffer, package->filesize);

	//void* mapping = 0;
	//status = MmMapViewInSystemSpace(hsection, &mapping, &view_size);
	//if (!NT_SUCCESS(status)) {
	//	return status;
	//}

	UNREFERENCED_PARAMETER(DeviceObject);
	return status;
}

VOID DriverUnload(PDRIVER_OBJECT driver_object)
{
	UNICODE_STRING symbol_name;
	RtlInitUnicodeString(&symbol_name, L"\\??\\ljw");
	IoDeleteSymbolicLink(&symbol_name);
	if (driver_object->DeviceObject) {
		IoDeleteDevice(driver_object->DeviceObject);
	}

	//PKLDR_DATA_TABLE_ENTRY LdrTableEntry = (PKLDR_DATA_TABLE_ENTRY)driver_object->DriverSection;
	//if (LdrTableEntry) {
	//	SelfDeleteFile(LdrTableEntry->FullDllName.Buffer);
	//}

	//if (g_register_path) {
	//	DeleteRegisterPath(g_register_path);
	//}

	KdPrintEx((77, 0, "driver unload\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING register_path)
{
	driver_object->DriverUnload = DriverUnload;
	g_register_path = register_path;
	UNICODE_STRING device_name;
	RtlInitUnicodeString(&device_name, L"\\device\\Reincarnation");

	PDEVICE_OBJECT device_object;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	UNICODE_STRING symbol_name;
	RtlInitUnicodeString(&symbol_name, L"\\??\\ljw");
	status = IoCreateSymbolicLink(&symbol_name, &device_name);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	device_object->Flags &= (~DO_DEVICE_INITIALIZING);
	device_object->Flags |= DO_BUFFERED_IO;
	driver_object->MajorFunction[IRP_MJ_CREATE] = CreateAndClose;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = CreateAndClose;
	driver_object->MajorFunction[IRP_MJ_WRITE] = ControlDispath;

	KdPrintEx((77, 0, "driver load\n"));
	return STATUS_SUCCESS;
}