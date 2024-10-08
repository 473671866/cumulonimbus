#pragma once

#include <sal.h>
#include <stdarg.h>
#include "base.h"

struct ATEXIT_ENTRY
{
	ATEXIT_ENTRY(
		__in void(__cdecl* destructor)(void),
		__in ATEXIT_ENTRY* next
	)
	{
		Destructor = destructor;
		Next = next;
	}

	~ATEXIT_ENTRY()
	{
		Destructor();
	}

	void(_cdecl* Destructor)();
	ATEXIT_ENTRY* Next;
};

extern "C"
int
__cdecl
cc_atexit(
	__in void(__cdecl * destructor)(void)
);

extern "C"
int
__cdecl
cc_init(
	__in int
);

extern "C"
void
__cdecl
cc_doexit(
	__in int,
	__in int,
	__in int
);
