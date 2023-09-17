#pragma once
#include <ntifs.h>

EXTERN_C
NTKERNELAPI
PVOID
PsGetThreadTeb(
	__in PETHREAD Thread
);

EXTERN_C
NTKERNELAPI
PVOID PsGetProcessSectionBaseAddress(
	IN PEPROCESS eprocess
);

EXTERN_C
NTKERNELAPI
NTSTATUS PsReferenceProcessFilePointer(
	IN PEPROCESS Process,
	OUT PVOID* OutFileObject
);

EXTERN_C
NTKERNELAPI
PVOID
PsGetProcessWow64Process(
	__in PEPROCESS Process
);

EXTERN_C
NTKERNELAPI
PPEB
PsGetProcessPeb(
	__in PEPROCESS Process
);

EXTERN_C
NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
);

EXTERN_C
NTKERNELAPI
PVOID
PsGetProcessDebugPort(
	__in PEPROCESS Process
);

EXTERN_C
NTKERNELAPI
PPEB
PsGetProcessPeb(
	__in PEPROCESS Process
);
