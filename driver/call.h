#pragma once
#include "standard/base.h"
NTSTATUS RemoteCall(HANDLE pid, void* shellcode, size_t size);