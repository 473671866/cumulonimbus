#include "comm.h"

//typedef ULONG(WINAPI* NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc)(char UnKnown1, void* UnKnown2, void* UnKnown3, void* UnKnown4);
//NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = nullptr;

//bool SengMessageEx(Command command, void* buffer, unsigned __int64 length)
//{
//	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
//		HMODULE hmodule = GetModuleHandleA("ntdll.dll");
//		NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = (NtConvertBetweenAuxiliaryCounterAndPerformanceCounterProc)GetProcAddress(hmodule, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
//		if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
//			return false;
//		}
//	}
//
//	CommPackage package{  };
//	package.flags = 0x55555;
//	package.command = command;
//	package.buffer = reinterpret_cast<uint64_t>(buffer);
//	package.length = length;
//	uint64_t unknown = 0;
//	CommPackage* data = &package;
//	NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(1, (PVOID)&data, (PVOID)&unknown, NULL);
//	return package.result >= 0;
//}

typedef struct _PEB
{
	ULONG64 InheritedAddressSpace;
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
}PEB, * PPEB;

bool SendMessageEx(Command command, void* buffer, unsigned __int64 length)
{
	CommPackage package{  };
	package.flags = 0x55555;
	package.command = command;
	package.buffer = reinterpret_cast<uint64_t>(buffer);
	package.length = length;

	PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	peb->Mutant = &package;
	SYSTEMTIME system_time;
	GetLocalTime(&system_time);
	SetSystemTime(&system_time);

	return package.result >= 0;
}