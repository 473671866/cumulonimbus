#define _CRT_SECURE_NO_WARNINGS
#pragma once
#include "../Standard/base.h"

class SearchUtils
{
	//pattern
private:
	UCHAR CharToHex(PUCHAR ch);
	INT InitializeHardCode(PUCHAR HardCode, PUCHAR CharCode);
	PVOID Compare(PUCHAR HardCode, ULONG64 StartAddress, ULONG64 EndAdress, ULONG64 Length);

public:
	PVOID pattern(const char* AnsiModuleName, const char* SegmentName, const char* Code);
};
