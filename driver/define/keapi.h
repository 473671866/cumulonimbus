#pragma once
#include <ntifs.h>

//»½ÐÑÏß³Ì
EXTERN_C
BOOLEAN
KeAlertThread(
	__inout PKTHREAD Thread,
	__in KPROCESSOR_MODE ProcessorMode
);

//dpc
EXTERN_C
NTKERNELAPI
VOID
KeInitializeDpc(
	__out PRKDPC Dpc,
	__in PKDEFERRED_ROUTINE DeferredRoutine,
	__in_opt PVOID DeferredContext
);

EXTERN_C
NTKERNELAPI
VOID
KeGenericCallDpc(
	__in PKDEFERRED_ROUTINE Routine,
	__in_opt PVOID Context
);

EXTERN_C
NTKERNELAPI
VOID
KeSignalCallDpcDone(
	__in PVOID SystemArgument1
);

EXTERN_C
NTKERNELAPI
LOGICAL
KeSignalCallDpcSynchronize(
	__in PVOID SystemArgument2
);

//apc
typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID(*PKNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);

typedef
VOID(*PKKERNEL_ROUTINE) (
	IN struct _KAPC* Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
	);

typedef
VOID(*PKRUNDOWN_ROUTINE) (
	IN struct _KAPC* Apc
	);

EXTERN_C
NTKERNELAPI
VOID
KeInitializeApc(
	__out PRKAPC Apc,
	__in PRKTHREAD Thread,
	__in KAPC_ENVIRONMENT Environment,
	__in PKKERNEL_ROUTINE KernelRoutine,
	__in_opt PKRUNDOWN_ROUTINE RundownRoutine,
	__in_opt PKNORMAL_ROUTINE NormalRoutine,
	__in_opt KPROCESSOR_MODE ProcessorMode,
	__in_opt PVOID NormalContext
);

EXTERN_C
NTKERNELAPI
BOOLEAN
KeInsertQueueApc(
	__inout PRKAPC Apc,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2,
	__in KPRIORITY Increment
);
