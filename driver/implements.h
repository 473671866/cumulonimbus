#pragma once
#include "standard/base.h"

namespace impl
{
	PETHREAD PsGetNextProcessThread(
		IN PEPROCESS Process,
		IN PETHREAD Thread
	);

	NTSTATUS PsSuspendThread(
		IN PETHREAD Thread,
		OUT PULONG PreviousSuspendCount OPTIONAL
	);

	NTSTATUS PsResumeThread(
		IN PETHREAD Thread,
		OUT PULONG PreviousSuspendCount OPTIONAL
	);

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
	);

	PVOID ExpLookupHandleTableEntry(
		IN PVOID PspCidTable,
		IN HANDLE ProcessId
		IN
	);

	BOOL GreProtectSpriteContent(IN HWND hwnd);
};
