#include "comm.h"
#include "pdb/analysis.h"

typedef NTSTATUS(NTAPI* KdEnumerateDebuggingDevicesProc)(PVOID UnKnown1, PVOID UnKnown2, PVOID UnKnown3);
KdEnumerateDebuggingDevicesProc KdEnumerateDebuggingDevicesOriginal = nullptr;
CommCallbackProc CommCallback = nullptr;
uint64_t* g_hook_pointer = nullptr;

NTSTATUS KdEnumerateDebuggingDevices(PVOID UnKnown1, PVOID UnKnown2, PVOID UnKnown3)
{
	if (MmIsAddressValid(UnKnown1)) {
		CommPackage* package = static_cast<CommPackage*>(UnKnown1);
		if (package->flags == 0x55555) {
			package->result = CommCallback(package);
		}
		else {
			if (KdEnumerateDebuggingDevicesOriginal) {
				return KdEnumerateDebuggingDevicesOriginal(UnKnown1, UnKnown2, UnKnown3);
			}
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS Register(CommCallbackProc callback)
{
	analysis::Pdber* ntos = analysis::Ntoskrnl();
	uint64_t address = ntos->GetPointer("NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	if (address == 0 || !MmIsAddressValid((void*)address)) {
		LOG_INFO("invaild address");
		return STATUS_UNSUCCESSFUL;
	}

	unsigned char* temp = reinterpret_cast<unsigned char*>(address);
	uint64_t* pointer = nullptr;
	for (uint64_t i = 0; i < 0x1000 || temp[i] != 0xc3; i++) {
		if (temp[i] == 0x48 && temp[i + 1] == 0x8b && temp[i + 2] == 0x05) {
			LARGE_INTEGER result{};
			result.QuadPart = address + i + 7;
			result.LowPart += *reinterpret_cast<uint32_t*>(address + i + 3);
			pointer = reinterpret_cast<uint64_t*>(result.QuadPart);
			break;
		}
	}

	if (pointer) {
		g_hook_pointer = pointer;
		KdEnumerateDebuggingDevicesOriginal = reinterpret_cast<KdEnumerateDebuggingDevicesProc>(pointer[0]);
		pointer[0] = reinterpret_cast<uint64_t>(KdEnumerateDebuggingDevices);
		CommCallback = callback;
		LOG_INFO("comm register success\n");
		return STATUS_SUCCESS;
	}
	else {
		LOG_INFO("comm register failed\n");
	}

	return STATUS_UNSUCCESSFUL;
}

boolean UnRegister()
{
	if (KdEnumerateDebuggingDevicesOriginal && g_hook_pointer) {
		g_hook_pointer[0] = reinterpret_cast<uint64_t>(KdEnumerateDebuggingDevicesOriginal);
		g_hook_pointer = nullptr;
		KdEnumerateDebuggingDevicesOriginal = nullptr;
		return true;
	}
	return false;
}