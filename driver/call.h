#pragma once
#include "standard/base.h"
NTSTATUS RemoteCall(HANDLE pid, void* shellcode, size_t size);
NTSTATUS LoadLibrary_x64(HANDLE pid, void* filebuffer, size_t filesize, size_t imagesize);