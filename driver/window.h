#pragma once
#include "standard/base.h"
#include "pdb/analysis.h"

uint64_t GetZwUserGetForegroundWindowAddress();
uint64_t GetZwUserWindowFromPointAddress();
uint64_t GetNtUserBuildHwndListAddress();
uint64_t GetNtUserQueryWindowAddress();
uint64_t GetNtUserFindWindowExAddress();

BOOL AntiScreenShot(HWND hwnd);
void WindowProtected(_In_ unsigned long SystemCallIndex, _Inout_ void** SystemCallFunction);
