#pragma once
#include <ntifs.h>

#pragma region Ps

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

#pragma endregion Ps

#pragma region Mm
EXTERN_C
NTKERNELAPI
NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN CONST VOID* FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);
#pragma endregion Mm

#pragma region Ke

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

#pragma region Apc

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

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

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

#pragma endregion Apc

#pragma endregion Ke

#pragma region Zw
// ZwQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

EXTERN_C
NTKERNELAPI
NTSTATUS NTAPI ZwQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);
// ZwQuerySystemInformation

EXTERN_C NTSTATUS NTAPI ZwFlushInstructionCache(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in SIZE_T Length
);
#pragma endregion Zw

#pragma region Ob

EXTERN_C
NTKERNELAPI
NTSTATUS ObCreateObject(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID* Object
);

EXTERN_C
NTKERNELAPI
NTSTATUS ObCreateObjectType(
	__in PUNICODE_STRING TypeName,
	__in PVOID ObjectTypeInitializer,
	__in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
	__out POBJECT_TYPE* ObjectType
);

EXTERN_C
NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
);

EXTERN_C POBJECT_TYPE* IoDriverObjectType;

#pragma endregion Ob

#pragma region Ex

EXTERN_C
VOID
DECLSPEC_NOINLINE
FASTCALL ExfAcquirePushLockShared(__inout PEX_PUSH_LOCK PushLock);

EXTERN_C
VOID
DECLSPEC_NOINLINE
FASTCALL ExfReleasePushLockShared(__inout PEX_PUSH_LOCK PushLock);

#pragma endregion Ex

#pragma region Rtl

EXTERN_C
NTKERNELAPI
PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID baseAddr);

#pragma endregion Rtl
