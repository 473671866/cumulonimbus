#include "search.h"
#include "utils.h"

UCHAR SearchUtils::CharToHex(PUCHAR ch)
{
	unsigned char temps[2] = { 0 };
	for (int i = 0; i < 2; i++)
	{
		if (ch[i] >= '0' && ch[i] <= '9')
		{
			temps[i] = (ch[i] - '0');
		}
		else if (ch[i] >= 'A' && ch[i] <= 'F')
		{
			temps[i] = (ch[i] - 'A') + 0xA;
		}
		else if (ch[i] >= 'a' && ch[i] <= 'f')
		{
			temps[i] = (ch[i] - 'a') + 0xA;
		}
	}
	return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
}

/**
 * @brief 把字符串转换为字节
* @param HardCode
* @param CharCode
 * @return 特征码长度
*/
INT SearchUtils::InitializeHardCode(PUCHAR HardCode, PUCHAR CharCode)
{
	INT i = 0;
	for (i = 0; *CharCode != '\0'; i++)
	{
		if (*CharCode == '*' || *CharCode == '?')
		{
			HardCode[i] = *CharCode;
			CharCode++;
			continue;
		}

		HardCode[i] = CharToHex(CharCode);
		CharCode += 2;
	}
	return i;
}

PVOID SearchUtils::Compare(PUCHAR HardCode, ULONG64 StartAddress, ULONG64 EndAdress, ULONG64 Length)
{
	ULONG64 result = 0;
	ULONG64 j = 0;
	PUCHAR TempCode = NULL;

	for (ULONG64 Index = StartAddress; Index <= EndAdress; Index++)
	{
		//如果地址不能访问，就跳到下一个物理页
		if (!MmIsAddressValid((PVOID)Index))
		{
			Index = (Index & (~0xFFF)) + PAGE_SIZE - 1;
			continue;
		}

		TempCode = (PUCHAR)Index;

		for (j = 0; j < Length; j++)
		{
			if (!MmIsAddressValid(TempCode + j))break;

			if (HardCode[j] == '*' || HardCode[j] == '?')continue;

			if (TempCode[j] != HardCode[j])break;
		}

		if (j == Length)
		{
			result = Index;
			break;
		}
	}
	return (PVOID)result;
}

/**
 * @brief 搜索特征
 * @param StartAddress 开始地址
 * @param Size 大小
 * @param Code 特征码
 * @return 特征地址
*/
/**
 * @brief 搜索内核模块特征
 * @param AnsiModuleName 模块名
 * @param SegmentName 节区名
 * @param Code 特征码
 * @return 特征地址
*/
PVOID SearchUtils::pattern(const char* AnsiModuleName, const char* SegmentName, const char* Code)
{
	//硬编码数组
	UCHAR HardCode[0x200] = { NULL };
	RtlZeroMemory(HardCode, 0x200);
	INT Length = this->InitializeHardCode(HardCode, (PUCHAR)Code);

	//获取模块首地址
	ULONG64 ModuleBase = (ULONG64)utils::GetKernelModule(AnsiModuleName, NULL);

	if (!ModuleBase)
	{
		return 0;
	}

	//获取节区
	SIZE_T section_size = 0;
	ULONG64 section_address = 0;
	section_address = (ULONG64)utils::GetSectionAddress(ModuleBase, SegmentName, &section_size);

	if (section_size == 0 || section_address == 0)
	{
		return 0;
	}

	return this->Compare(HardCode, section_address, section_address + section_size, Length);
}