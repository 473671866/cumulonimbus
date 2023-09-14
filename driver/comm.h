#pragma once
#include "standard/base.h"

enum class  Command : unsigned __int64
{
	Link = 555,
	Call,
	LoadLibrary_x64,
	LoadLibrary_x86,
	HideMemory,
	RecovreMemory,
	AllocateMemory,
	FreeMemory,
	HideProcess,
	TerminateProcess,
	Module,
	ReadMapping,
	ReadPhysical,
	WritePhysical,
	AntiScreenShot,
	InitializeWindowProtected,
	InstallWindowProtected,
	UnloadWindowProtected,
};

#pragma pack(push)
#pragma pack(8)

struct CommPackage
{
	unsigned __int64 flags;
	Command command;
	unsigned __int64 buffer;
	unsigned __int64 length;
	__int64 result;
};

struct RemoteCallPackage
{
	unsigned __int64 pid;
	unsigned __int64 shellcode;
	unsigned __int64 size;
};

struct InjectPackage
{
	unsigned __int64 pid;
	unsigned __int64 filebuffer;
	unsigned __int64 filesize;
	unsigned __int64 imagesize;
};

struct HideMemoryPackage
{
	unsigned __int64 pid;
	unsigned __int64 address;
	unsigned __int64 size;
};

struct ModulePackage
{
	unsigned __int64 pid;
	unsigned __int64 name;
	unsigned __int64 address;
	unsigned __int64 size;
};

struct MemoryPackage
{
	unsigned __int64 pid;
	unsigned __int64 address;
	unsigned __int64 buffer;
	unsigned __int64 size;
	unsigned __int64 protect;
};

#pragma pack(pop)

//typedef NTSTATUS(*CommCallbackProc)(CommPackage* package);
//NTSTATUS Register(CommCallbackProc callback);
//boolean UnRegister();

namespace comm
{
	typedef NTSTATUS(*CommCallbackProc)(CommPackage* package);
	NTSTATUS Register(CommCallbackProc callback);
	VOID UnRegister();
}
