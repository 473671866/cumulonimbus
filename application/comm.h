#pragma once
#include <iostream>
#include<windows.h>

enum class  Command : uint64_t
{
	Link = 555,
};

struct CommPackage
{
	uint64_t flags;
	Command command;
	uint64_t buffer;
	uint64_t length;
	int64_t result;
};

boolean SengMessageEx(Command command, void* buffer, size_t length);
