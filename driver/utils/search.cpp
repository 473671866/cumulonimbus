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
 * @brief ���ַ���ת��Ϊ�ֽ�
* @param HardCode
* @param CharCode
 * @return �����볤��
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
		//�����ַ���ܷ��ʣ���������һ������ҳ
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
 * @brief ��������
 * @param StartAddress ��ʼ��ַ
 * @param Size ��С
 * @param Code ������
 * @return ������ַ
*/
/**
 * @brief �����ں�ģ������
 * @param AnsiModuleName ģ����
 * @param SegmentName ������
 * @param Code ������
 * @return ������ַ
*/
PVOID SearchUtils::pattern(const char* AnsiModuleName, const char* SegmentName, const char* Code)
{
	//Ӳ��������
	UCHAR HardCode[0x200] = { NULL };
	RtlZeroMemory(HardCode, 0x200);
	INT Length = this->InitializeHardCode(HardCode, (PUCHAR)Code);

	//��ȡģ���׵�ַ
	ULONG64 ModuleBase = (ULONG64)utils::GetKernelModule(AnsiModuleName, NULL);

	if (!ModuleBase)
	{
		return 0;
	}

	//��ȡ����
	SIZE_T section_size = 0;
	ULONG64 section_address = 0;
	section_address = (ULONG64)utils::GetSectionAddress(ModuleBase, SegmentName, &section_size);

	if (section_size == 0 || section_address == 0)
	{
		return 0;
	}

	return this->Compare(HardCode, section_address, section_address + section_size, Length);
}