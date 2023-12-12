#include "comm.h"
#include "utils/memory.hpp"

namespace comm
{
	PVOID g_comm_handle;
	CommCallbackProc g_callback;

	typedef struct _PEB
	{
		ULONG64 InheritedAddressSpace;
		VOID* Mutant;                                                           //0x8
	}PEB, * PPEB;

	VOID dispather(
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
		auto package = reinterpret_cast<stream*>(peb->Mutant);
		bool success = utils::memory::probe(package, sizeof(stream), 1);
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

		g_comm_handle = ExRegisterCallback(callback_object, dispather, NULL);
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