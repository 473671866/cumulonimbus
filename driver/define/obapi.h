#pragma once
#include <ntifs.h>

EXTERN_C POBJECT_TYPE* IoDriverObjectType;

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
