#include "comm.h"

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
	SYSTEMTIME system_time{};
	GetLocalTime(&system_time);
	SetSystemTime(&system_time);

	return package.result >= 0;
}