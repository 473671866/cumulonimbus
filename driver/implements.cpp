#include "implements.h"
#include "utils/process.hpp"

namespace impl
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

		analysis::Pdber* ntos = analysis::Ntoskrnl();
		static PsGetNextProcessThreadProc proc = reinterpret_cast<PsGetNextProcessThreadProc>(ntos->GetPointer("PsGetNextProcessThread"));
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

		analysis::Pdber* ntos = analysis::Ntoskrnl();
		static PsSuspendThreadProc proc = reinterpret_cast<PsSuspendThreadProc>(ntos->GetPointer("PsSuspendThread"));
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

		analysis::Pdber* ntos = analysis::Ntoskrnl();
		static PsResumeThreadProc	proc = reinterpret_cast<PsResumeThreadProc>(ntos->GetPointer("PsResumeThread"));
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

		analysis::Pdber* ntos = analysis::Ntoskrnl();
		static ZwCreateThreadExProc proc = reinterpret_cast<ZwCreateThreadExProc>(ntos->GetPointer("ZwCreateThreadEx"));
		return proc(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, StartContext, CreateThreadFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	}

	BOOL GreProtectSpriteContent(IN HWND hwnd)
	{
		typedef BOOL(__fastcall* GreProtectSpriteContentProc)(LPVOID, HWND, INT, UINT);
		BOOL success = false;
		PEPROCESS process = nullptr;

		auto status = utils::processor::get_process_image_file_name("explorer.exe", &process);
		if (NT_SUCCESS(status)) {
			KAPC_STATE apc{};
			KeStackAttachProcess(process, &apc);
			unsigned __int64 address = 0;
			analysis::Pdber* win32kfull = analysis::Win32kfull();
			address = win32kfull->GetPointer("GreProtectSpriteContent");
			if (address) {
				GreProtectSpriteContentProc proc = (GreProtectSpriteContentProc)address;
				success = proc(NULL, hwnd, TRUE, 0x00000011);
			}
			KeUnstackDetachProcess(&apc);
			ObDereferenceObject(process);
		}
		return success;
	}

	PVOID ExpLookupHandleTableEntry(IN PVOID PspCidTable, IN HANDLE ProcessId)
	{
		typedef PVOID(*ExpLookupHandleTableEntryProc)(PVOID PspCidTable, HANDLE ProcessId);
		analysis::Pdber* ntos = analysis::Ntoskrnl();
		static ExpLookupHandleTableEntryProc  proc = reinterpret_cast<ExpLookupHandleTableEntryProc>(ntos->GetPointer("ExpLookupHandleTableEntry"));
		return proc(PspCidTable, ProcessId);
	}
};