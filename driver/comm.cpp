#include "comm.h"
#include "pdb/analysis.h"
#include "utils/utils.h"

//typedef NTSTATUS(NTAPI* KdEnumerateDebuggingDevicesProc)(PVOID UnKnown1, PVOID UnKnown2, PVOID UnKnown3);
//KdEnumerateDebuggingDevicesProc KdEnumerateDebuggingDevicesOriginal = nullptr;
//CommCallbackProc CommCallback = nullptr;
//uint64_t* g_hook_pointer = nullptr;
//
//NTSTATUS KdEnumerateDebuggingDevices(PVOID UnKnown1, PVOID UnKnown2, PVOID UnKnown3)
//{
//	if (MmIsAddressValid(UnKnown1)) {
//		CommPackage* package = static_cast<CommPackage*>(UnKnown1);
//		if (package->flags == 0x55555) {
//			package->result = CommCallback(package);
//		}
//		else {
//			if (KdEnumerateDebuggingDevicesOriginal) {
//				return KdEnumerateDebuggingDevicesOriginal(UnKnown1, UnKnown2, UnKnown3);
//			}
//		}
//	}
//	return STATUS_SUCCESS;
//}
//
//NTSTATUS Register(CommCallbackProc callback)
//{
//	analysis::Pdber* ntos = analysis::Ntoskrnl();
//	uint64_t address = ntos->GetPointer("NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
//	if (address == 0 || !MmIsAddressValid((void*)address)) {
//		LOG_INFO("invaild address");
//		return STATUS_UNSUCCESSFUL;
//	}
//
//	unsigned char* temp = reinterpret_cast<unsigned char*>(address);
//	uint64_t* pointer = nullptr;
//	for (uint64_t i = 0; i < 0x1000 || temp[i] != 0xc3; i++) {
//		if (temp[i] == 0x48 && temp[i + 1] == 0x8b && temp[i + 2] == 0x05) {
//			LARGE_INTEGER result{};
//			result.QuadPart = address + i + 7;
//			result.LowPart += *reinterpret_cast<uint32_t*>(address + i + 3);
//			pointer = reinterpret_cast<uint64_t*>(result.QuadPart);
//			break;
//		}
//	}
//
//	if (pointer) {
//		g_hook_pointer = pointer;
//		KdEnumerateDebuggingDevicesOriginal = reinterpret_cast<KdEnumerateDebuggingDevicesProc>(pointer[0]);
//		pointer[0] = reinterpret_cast<uint64_t>(KdEnumerateDebuggingDevices);
//		CommCallback = callback;
//		LOG_INFO("comm register success\n");
//		return STATUS_SUCCESS;
//	}
//	else {
//		LOG_INFO("comm register failed\n");
//	}
//
//	return STATUS_UNSUCCESSFUL;
//}
//
//boolean UnRegister()
//{
//	if (KdEnumerateDebuggingDevicesOriginal && g_hook_pointer) {
//		g_hook_pointer[0] = reinterpret_cast<uint64_t>(KdEnumerateDebuggingDevicesOriginal);
//		g_hook_pointer = nullptr;
//		KdEnumerateDebuggingDevicesOriginal = nullptr;
//		return true;
//	}
//	return false;
//}

namespace comm
{
	PVOID g_comm_handle;
	CommCallbackProc g_callback;

	typedef struct _PEB
	{
		ULONG64 InheritedAddressSpace;
		VOID* Mutant;                                                           //0x8
	}PEB, * PPEB;

	VOID Dispather(
		IN PVOID CallbackContext,
		IN PVOID Argument1,
		IN PVOID Argument2
	)
	{
		UNREFERENCED_PARAMETER(CallbackContext);
		UNREFERENCED_PARAMETER(Argument1);
		UNREFERENCED_PARAMETER(Argument2);

		KIRQL irql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		PPEB peb = reinterpret_cast<PPEB>(PsGetProcessPeb(PsGetCurrentProcess()));
		auto package = reinterpret_cast<CommPackage*>(peb->Mutant);
		bool success = utils::ProbeUserAddress(package, sizeof(CommPackage), 1);
		if (success && g_callback) {
			if (package->flags == 0x55555) {
				package->result = g_callback(package);
			}
		}
		KeRaiseIrql(irql, &irql);
	}

	NTSTATUS Register(CommCallbackProc callback)
	{
		UNICODE_STRING name{};
		RtlInitUnicodeString(&name, L"\\CallBack\\SetSystemTime");

		OBJECT_ATTRIBUTES attribute{};
		InitializeObjectAttributes(&attribute, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

		PCALLBACK_OBJECT callback_object = nullptr;//回调对象的地址
		auto dereference_callback_object = std::experimental::make_scope_exit([callback_object] {if (callback_object)ObDereferenceObject(callback_object); });
		NTSTATUS status = ExCreateCallback(&callback_object, &attribute, TRUE, TRUE);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		g_comm_handle = ExRegisterCallback(callback_object, Dispather, NULL);
		if (g_comm_handle == nullptr) {
			status = STATUS_UNSUCCESSFUL;
		}

		if (NT_SUCCESS(status) && callback) {
			g_callback = callback;
		}

		return status;
	}

	VOID UnRegister()
	{
		if (g_comm_handle) {
			ExUnregisterCallback(g_comm_handle);
			g_comm_handle = nullptr;
			g_callback = nullptr;
		}
	}
}