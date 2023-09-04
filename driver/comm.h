#pragma once
#include "standard/base.h"

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

typedef NTSTATUS(*CommCallbackProc)(CommPackage* package);
NTSTATUS Register(CommCallbackProc callback);
boolean UnRegister();
