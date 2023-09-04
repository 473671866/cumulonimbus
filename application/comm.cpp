#include "comm.h"

typedef ULONG(WINAPI* NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc)(char UnKnown1, void* UnKnown2, void* UnKnown3, void* UnKnown4);
NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = nullptr;

inline boolean Register()
{
	HMODULE hmodule = GetModuleHandleA("ntdll.dll");
	NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = (NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc)GetProcAddress(hmodule, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	return true;
}

boolean SengMessageEx(Command command, void* buffer, size_t length)
{
	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
		Register();
	}

	CommPackage package{  };
	package.flags = 0x55555;
	package.command = command;
	package.buffer = reinterpret_cast<uint64_t>(buffer);
	package.length = length;
	uint64_t unknown = 0;
	CommPackage* data = &package;
	NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(1, (PVOID)&data, (PVOID)&unknown, NULL);
	return package.result >= 0;
}