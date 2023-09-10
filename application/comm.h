#pragma once
#include <iostream>
#include<windows.h>

enum class  Command : uint64_t
{
	Link = 555,
	Call,
	Inject,
	HideMemory,
	RecovreMemory,
	HideProcess,
	Module,
	ReadMapping,
	ReadPhysical,
	WritePhysical
};

struct CommPackage
{
	uint64_t flags;
	Command command;
	uint64_t buffer;
	uint64_t length;
	int64_t result;
};

struct RemoteCallPackage
{
	uint64_t pid;
	uint64_t shellcode;
	uint64_t size;
};

struct InjectPackage
{
	uint64_t pid;
	uint64_t filebuffer;
	uint64_t filesize;
	uint64_t imagesize;
};

struct HideMemoryPackage
{
	uint64_t pid;
	uint64_t address;
	uint64_t size;
};

struct ModulePackage
{
	uint64_t pid;
	uint64_t name;
	uint64_t address;
	uint64_t size;
};

struct MemoryPackage
{
	uint64_t pid;
	uint64_t address;
	uint64_t buffer;
	uint64_t size;
};

boolean SengMessageEx(Command command, void* buffer, size_t length);
