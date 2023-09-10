#pragma once
#include <iostream>
#include <windows.h>

boolean Examine();
boolean Launcher();
boolean RemoteCall(uint64_t pid, void* shellcode, size_t size);
boolean LoadLibrary_x64(uint64_t pid, const char* filepath);
boolean HideMemory(uint64_t pid, uint64_t address, size_t size);
boolean RecoverMemory(uint64_t address);
boolean HideProcess(uint64_t pid);
boolean GetApplicationModule(uint64_t pid, const char* module_name, void* address, size_t* size);
boolean ReadMappingMemory(uint64_t pid, uint64_t address, void* buffer, size_t size);
boolean ReadPhysicalMemory(uint64_t pid, uint64_t address, void* buffer, size_t size);
boolean WritePhysicalMemory(uint64_t pid, uint64_t address, void* buffer, size_t size);
