#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <random>
#include <ctime>
#include "api.h"

DWORD GetPid()
{
	uint32_t pid = 0;
	HANDLE hprocess = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 process_entry = { .dwSize = sizeof(PROCESSENTRY32) };

	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot_handle == INVALID_HANDLE_VALUE || snapshot_handle == nullptr) {
		return 0;
	}

	boolean success = Process32First(snapshot_handle, &process_entry);
	while (success) {
		if (_wcsicmp(process_entry.szExeFile, L"Project1.exe") == 0) {
			return  process_entry.th32ProcessID;
			break;
		}
		success = Process32Next(snapshot_handle, &process_entry);
	}
	CloseHandle(snapshot_handle);
	return 0;
}

int main(int arg, char** argv)
{
	//��������
	//if (!Launcher()) {
	//	system("pause");
	//}

	//auto hwnd = FindWindowA(NULL, "Cheat Engine 7.4");

	//DWORD pid = 0;
	//GetWindowThreadProcessId(hwnd, &pid);

		//ȡģ��
		//uint64_t base = 0;
		//boolean success = GetApplicationModule(pid, "Project1.exe", &base, nullptr);
		//if (!success || !base) {
		//	std::cerr << "��ȡģ��ʧ��\n";
		//}

		//���ڴ�
		//uint64_t address = 0x15a000 + base;
		//uint64_t result = 0;
		//ReadMappingMemory(pid, address, &result, sizeof(result));
		//std::cout << "��: " << result << std::endl;
		//uint64_t calladdress = base + 0xe6f0;

		//д�ڴ�
		//result = 123456;
		//WritePhysicalMemory(pid, address, &result, sizeof(uint64_t));

	//Զ��call
	//HMODULE hmodule = LoadLibraryA("user32.dll");
	//uint64_t msg = (uint64_t)GetProcAddress(hmodule, "MessageBoxA");
	//uint8_t buffer[]
	//{
	//	0x31, 0xC9,													//xor rcx, rcx
	//	0x31, 0xD2,													//xor rdx, rdx
	//	0x4D, 0x31, 0xC0,											//xor r8, r8
	//	0x4D, 0x31, 0xC9,											//xor r9, r9
	//	0x48, 0xB8, 0x99, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00,	//mov rax, 0x123456789
	//	0x48, 0x81, 0xEC, 0xA8, 0x00, 0x00, 0x00,					//sup rsp, 0xa8
	//	0xFF, 0xD0,													//call rax
	//	0x48, 0x81, 0xC4, 0xA8, 0x00, 0x00, 0x00,					//add rsp, 0xa8
	//	0xC3														//ret
	//};
	//*(uint64_t*)&buffer[12] = msg;
	//RemoteCall(pid, buffer, sizeof(buffer));

	//���ؽ���
	//HideProcess(pid);

	//��������
	//TermiateProcess(pid);

	//����ͼ
	//AntiSrceenShot(hwnd);

	//�����ڴ�
	//auto address = AllocateMemory(pid, 0x1000, PAGE_EXECUTE_READWRITE);

	//�����ڴ�
	//HideMemory(pid, address, 0x1000);

	//�ָ������ص��ڴ�
	//RecoverMemory(address);

	//�ͷ��ڴ�
	//FreeMemory(pid, address, 0x1000);

	//ע��
	//LoadLibrary_x64(pid, "F:\\Code\\Kernel\\cumolonimbus\\x64\\Release\\Dll.dll");
	//LoadLibrary_x86(pid, "F:\\Code\\Kernel\\cumolonimbus\\x64\\Release\\Dll.dll");

	system("pause");
	return 0;
}