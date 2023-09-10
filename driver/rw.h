#pragma once
#include "standard/base.h"

NTSTATUS ReadMappingMemory(HANDLE pid, void* address, void* buffer, size_t size);

NTSTATUS ReadPhysicalMemory(HANDLE pid, void* address, void* buffer, size_t size);

NTSTATUS WritePhysicalMemory(HANDLE pid, void* address, void* buffer, size_t size);
