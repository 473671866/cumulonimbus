#pragma once
#include "headers.hpp"

namespace hook
{
	// SSDT�ص�����
	typedef void(__fastcall* fssdt_call_back)(unsigned long ssdt_index, void** ssdt_address);

	// ��ʼ������
	bool Initialize(fssdt_call_back ssdt_call_back);

	// ��ʼ���غ�������
	bool Launcher();

	// �������غ�������
	bool Terminator();
}