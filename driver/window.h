#pragma once
#include "standard/base.h"
#include "pdb/analysis.h"

BOOL AntiScreenShot(HWND hwnd);
void InfintyHook(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction);
