#pragma once
#include <iostream>
#include <windows.h>

boolean Examine();
boolean RemoteCall(uint64_t pid, void* shellcode, size_t size);
