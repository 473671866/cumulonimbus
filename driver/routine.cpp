#include "routine.h"
#include "pdb/analysis.h"
#include "utils/utils.h"
#include "utils/search.h"
#include "utils/version.hpp"

namespace routine
{
	PETHREAD PsGetNextProcessThread(
		IN PEPROCESS Process,
		IN PETHREAD Thread
	)
	{
		typedef PETHREAD(*PsGetNextProcessThreadProc)(
			IN PEPROCESS Process,
			IN PETHREAD Thread
			);

		static PsGetNextProcessThreadProc proc = nullptr;
		if (proc == nullptr) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				SearchUtils search;
				void* address = search.pattern("ntoskrnl.exe", "PAGE", "4889***4889***4889***57415441554156415748***65********4533FF488BF266FF*****4D8BF74C8D*****418BEF4C8D*****33C0418D**F049****0F");
				proc = reinterpret_cast<PsGetNextProcessThreadProc>(address);
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				proc = reinterpret_cast<PsGetNextProcessThreadProc>(ntos->GetPointer("PsGetNextProcessThread"));
			}
			LOG_INFO("proc: %llx", proc);
		}
		return proc(Process, Thread);
	}

	NTSTATUS PsSuspendThread(
		IN PETHREAD Thread,
		OUT PULONG PreviousSuspendCount OPTIONAL
	)
	{
		typedef NTSTATUS(*PsSuspendThreadProc)(
			IN PETHREAD Thread,
			OUT PULONG PreviousSuspendCount OPTIONAL
			);

		static PsSuspendThreadProc proc = nullptr;

		if (proc == nullptr) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				SearchUtils search;
				void* address = search.pattern("ntoskrnl.exe", "PAGE", "4889***4889***5356574154415548***4C8BEA488BF133FF897C**65********4C89******6641*******48******0F**488B0148***488D**F0480FB1110F");
				proc = reinterpret_cast<PsSuspendThreadProc>(address);
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				proc = reinterpret_cast<PsSuspendThreadProc>(ntos->GetPointer("PsSuspendThread"));
			}
			LOG_INFO("proc: %llx", proc);
		}
		return proc(Thread, PreviousSuspendCount);
	}

	NTSTATUS PsResumeThread(
		IN PETHREAD Thread,
		OUT PULONG PreviousSuspendCount OPTIONAL
	)
	{
		typedef NTSTATUS(*PsResumeThreadProc)(
			IN PETHREAD Thread,
			OUT PULONG PreviousSuspendCount OPTIONAL
			);
		static PsResumeThreadProc proc = nullptr;

		if (proc == nullptr) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				SearchUtils search;
				void* address = search.pattern("ntoskrnl.exe", "PAGE", "FFF348***488BDAE8****4885DB74*890333C048***5BC3");
				proc = reinterpret_cast<PsResumeThreadProc>(address);
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				proc = reinterpret_cast<PsResumeThreadProc>(ntos->GetPointer("PsResumeThread"));
			}
			LOG_INFO("proc: %llx", proc);
		}
		return proc(Thread, PreviousSuspendCount);
	}

	NTSTATUS ZwCreateThreadEx(
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ProcessHandle,
		IN PVOID StartRoutine,
		IN PVOID StartContext,
		IN ULONG CreateThreadFlags,
		IN SIZE_T ZeroBits OPTIONAL,
		IN SIZE_T StackSize OPTIONAL,
		IN SIZE_T MaximumStackSize OPTIONAL,
		IN PVOID AttributeList
	)
	{
		typedef NTSTATUS(NTAPI* ZwCreateThreadExProc)(
			OUT PHANDLE ThreadHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
			IN HANDLE ProcessHandle,
			IN PVOID StartRoutine,
			IN PVOID StartContext,
			IN ULONG CreateThreadFlags,
			IN SIZE_T ZeroBits OPTIONAL,
			IN SIZE_T StackSize OPTIONAL,
			IN SIZE_T MaximumStackSize OPTIONAL,
			IN PVOID AttributeList
			);

		static ZwCreateThreadExProc proc = nullptr;

		if (proc == nullptr) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				UNICODE_STRING name{};
				RtlInitUnicodeString(&name, L"ZwCreateSymbolicLinkObject");
				void* address = MmGetSystemRoutineAddress(&name);
				proc = reinterpret_cast<ZwCreateThreadExProc>((unsigned __int64)address + 0x20);
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				proc = reinterpret_cast<ZwCreateThreadExProc>(ntos->GetPointer("ZwCreateThreadEx"));
			}
			LOG_INFO("proc: %llx", proc);
		}
		return proc(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, StartContext, CreateThreadFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	}

	BOOL GreProtectSpriteContent(HWND hwnd)
	{
		typedef BOOL(__fastcall* GreProtectSpriteContentProc)(LPVOID, HWND, INT, UINT);

		BOOL success = false;
		PEPROCESS process = nullptr;
		auto status = utils::LookupProcessByImageFileName("explorer.exe", &process);
		if (NT_SUCCESS(status)) {
			KAPC_STATE apc{};
			KeStackAttachProcess(process, &apc);
			unsigned __int64 address = 0;
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				SearchUtils search;
				address = (unsigned __int64)search.pattern("win32k.sys", ".text", "4889***4889***565741544155415648***4533F6418BD9488BFA4585C00F*****");
			}
			else {
				analysis::Pdber* win32kfull = analysis::Win32kfull();
				address = win32kfull->GetPointer("GreProtectSpriteContent");
			}

			if (address) {
				GreProtectSpriteContentProc proc = (GreProtectSpriteContentProc)address;
				success = proc(NULL, hwnd, TRUE, 0x00000011);
			}
			KeUnstackDetachProcess(&apc);
			ObDereferenceObject(process);
		}
		return success;
	}

	PVOID ExpLookupHandleTableEntry(PVOID PspCidTable, HANDLE ProcessId)
	{
		typedef PVOID(*ExpLookupHandleTableEntryProc)(PVOID PspCidTable, HANDLE ProcessId);
		static ExpLookupHandleTableEntryProc proc = nullptr;
		void* address = nullptr;
		if (!proc) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				SearchUtils search;
				address = search.pattern("ntoskrnl.exe", "PAGE", "8B41*4889***83**8954**4C8B***4C3BC873*4C8B01418BC883**8BC14C2BC085C974*");
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				proc = reinterpret_cast<ExpLookupHandleTableEntryProc>(ntos->GetPointer("ExpLookupHandleTableEntry"));
			}

			if (address) {
				proc = reinterpret_cast<ExpLookupHandleTableEntryProc>(address);
			}
		}
		LOG_INFO("ExpLookupHandleTableEntry: %llx", ExpLookupHandleTableEntry);
		return proc(PspCidTable, ProcessId);
	}
};