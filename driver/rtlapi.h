#pragma once
#include <ntifs.h>

EXTERN_C
NTKERNELAPI
PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID imagebase);

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
	PVOID PcValue,
	PVOID* BaseOfImage
);
