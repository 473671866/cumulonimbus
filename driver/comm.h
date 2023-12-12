#pragma once
#include "standard/base.h"

enum class  command : unsigned __int64
{
	link = 555,
	library,
	read,
	write,
	//Call,
	//LoadLibrary_x64,
	//LoadLibrary_x86,
	//HideMemory,
	//RecovreMemory,
	//AllocateMemory,
	//FreeMemory,
	//HideProcess,
	//TerminateProcess,

	//ReadMapping,
	//ReadPhysical,
	//WritePhysical,
	//AntiScreenShot,
	//InitializeWindowProtected,
	//InstallWindowProtected,
	//UnloadWindowProtected,
};

#pragma pack(push)
#pragma pack(8)

struct stream
{
	command cmd;
	unsigned __int64 flags;
	unsigned __int64 buffer;
	unsigned __int64 length;
	__int64 result;
};

struct library_stream
{
	unsigned __int64 pid;
	unsigned __int64 name;
	unsigned __int64 address;
	unsigned __int64 size;
};

struct memory_stream
{
	unsigned __int64 pid;
	unsigned __int64 address;
	unsigned __int64 buffer;
	unsigned __int64 size;
	unsigned __int64 protect;
};

//struct RemoteCallPackage
//{
//	unsigned __int64 pid;
//	unsigned __int64 shellcode;
//	unsigned __int64 size;
//};
//
//struct InjectPackage
//{
//	unsigned __int64 pid;
//	unsigned __int64 filebuffer;
//	unsigned __int64 filesize;
//	unsigned __int64 imagesize;
//};
//
//struct HideMemoryPackage
//{
//	unsigned __int64 pid;
//	unsigned __int64 address;
//	unsigned __int64 size;
//};
//

//

#pragma pack(pop)

namespace comm
{
	typedef NTSTATUS(*CommCallbackProc)(stream* package);
	NTSTATUS Register(CommCallbackProc callback);
	VOID UnRegister();
}
