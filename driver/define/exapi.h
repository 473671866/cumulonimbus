#pragma once
#include <ntifs.h>

EXTERN_C
VOID
DECLSPEC_NOINLINE
FASTCALL ExfAcquirePushLockShared(__inout PEX_PUSH_LOCK PushLock);

EXTERN_C
VOID
DECLSPEC_NOINLINE
FASTCALL ExfReleasePushLockShared(__inout PEX_PUSH_LOCK PushLock);
