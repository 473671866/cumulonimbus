#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
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

int main()
{
	int code = 0;
	HMODULE hmodule = LoadLibraryA("library.dll");
	if (!hmodule) {
		code = GetLastError();
		std::cout << "����ģ��ʧ��: " << code << "\n";
		system("pause");
		return 0;
	}
	else {
		std::cout << "����ģ��ɹ�\n";
	}

	//QueryProc Query = (QueryProc)GetProcAddress(hmodule, "Query");
	//ExamineProc Examine = (ExamineProc)GetProcAddress(hmodule, "Examine");
	//InitializeWindowProtectedProc InitializeWindowProtected = (InitializeWindowProtectedProc)GetProcAddress(hmodule, "InitializeWindowProtected");
	//InstallWindowProtectProc InstallWindowProtect = (InstallWindowProtectProc)GetProcAddress(hmodule, "InstallWindowProtect");
	//UnloadWindowProtectedProc UnloadWindowProtected = (UnloadWindowProtectedProc)GetProcAddress(hmodule, "UnloadWindowProtected");

	//ע��
	RegisterKeyProc RegisterKey = (RegisterKeyProc)GetProcAddress(hmodule, "RegisterKey");
	RegisterKey("CUMOBKNE2N8TCW22WXHV54G004AI8VDD");

	//��������
	LauncherProc Launcher = (LauncherProc)GetProcAddress(hmodule, "Launcher");
	code = Launcher();
	if (code != 0) {
		std::cerr << "��������ʧ��, �������: " << code << "\n";
		system("pause");
	}
	else {
		std::cout << "���������ɹ�\n";
	}

	auto pid = GetPid();

	//ģ��
	system("pause");
	unsigned __int64 module_address = 0;
	GetApplicationModuleProc GetApplicationModule = (GetApplicationModuleProc)GetProcAddress(hmodule, "GetApplicationModule");
	bool success = GetApplicationModule(pid, "Project1.exe", &module_address, nullptr);
	if (success || module_address) {
		std::cout << "ģ���ַ: " << (void*)module_address << "\n";
	}
	else {
		std::cerr << "��ȡģ��ʧ��\n";
		system("pause");
	}

	system("pause");
	//��
	unsigned __int64 address = 0x7ff670287000;
	unsigned __int64 mapping = 0;
	ReadMappingMemoryProc ReadMappingMemory = (ReadMappingMemoryProc)GetProcAddress(hmodule, "ReadMappingMemory");
	success = ReadMappingMemory(pid, address, &mapping, 8);
	if (success) {
		std::cout << "ReadMappingMemory ��ȡ���: " << mapping << "\n";
	}
	else {
		std::cerr << "ReadMappingMemory ��ȡʧ�� " << mapping << "\n";
		system("pause");
	}

	system("pause");
	unsigned __int64 physical = 0;
	ReadPhysicalMemoryProc ReadPhysicalMemory = (ReadPhysicalMemoryProc)GetProcAddress(hmodule, "ReadPhysicalMemory");
	success = ReadPhysicalMemory(pid, address, &physical, 8);
	if (success) {
		std::cout << "ReadPhysicalMemory ��ȡ���: " << physical << "\n";
	}
	else {
		std::cerr << "ReadPhysicalMemory ��ȡʧ��\n" << physical << "\n";;
		system("pause");
	}

	system("pause");
	//д
	unsigned __int64 write = 555555;
	WritePhysicalMemoryProc WritePhysicalMemory = (WritePhysicalMemoryProc)GetProcAddress(hmodule, "WritePhysicalMemory");
	success = WritePhysicalMemory(pid, address, &write, 8);
	if (success) {
		std::cout << "д��ɹ�\n";
	}
	else {
		std::cerr << "д��ʧ��\n";
	}

	system("pause");
	//x64call
	unsigned __int8 x64buffer[]{
		0x31, 0xC9,													//xor rcx, rcx
		0x31, 0xD2,													//xor rdx, rdx
		0x4D, 0x31, 0xC0,											//xor r8, r8
		0x4D, 0x31, 0xC9,											//xor r9, r9
		0x48, 0xB8, 0x99, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00,	//mov rax, 0x123456789
		0x48, 0x81, 0xEC, 0xA8, 0x00, 0x00, 0x00,					//sup rsp, 0xa8
		0xFF, 0xD0,													//call rax
		0x48, 0x81, 0xC4, 0xA8, 0x00, 0x00, 0x00,					//add rsp, 0xa8
		0xC3
	};

	*(unsigned __int64*)&x64buffer[12] = 0x7ff6701c1000;
	RemoteCallProc RemoteCall = (RemoteCallProc)GetProcAddress(hmodule, "RemoteCall");
	success = RemoteCall(pid, x64buffer, sizeof(x64buffer));
	if (success) {
		std::cout << "RemoteCall�ɹ�\n";
	}
	else {
		std::cerr << "RemoteCallʧ��\n";
	}

	system("pause");
	//x64ע��
	LoadLibrary_x64Proc LoadLibrary_x64 = (LoadLibrary_x64Proc)GetProcAddress(hmodule, "LoadLibrary_x64");
	success = LoadLibrary_x64(pid, "C:\\Users\\ljw-cccc\\Desktop\\dll.dll");
	if (success) {
		std::cout << "x64ע��ɹ�\n";
	}
	else {
		std::cerr << "x64ע��ʧ��\n";
	}

	system("pause");
	//�����ڴ�
	AllocateMemoryProc AllocateMemory = (AllocateMemoryProc)GetProcAddress(hmodule, "AllocateMemory");
	void* mem = AllocateMemory(pid, 0x1000, PAGE_EXECUTE_READWRITE);
	if (mem) {
		std::cout << "�����ڴ�ɹ�: " << mem << "\n";
	}
	else {
		std::cerr << "�����ڴ�ʧ��\n";
	}

	system("pause");
	//�����ڴ�
	HideMemoryProc HideMemory = (HideMemoryProc)GetProcAddress(hmodule, "HideMemory");
	success = HideMemory(pid, mem, 0x1000);
	if (success) {
		std::cout << "�����ڴ�ɹ�: " << mem << "\n";
	}
	else {
		std::cerr << "�����ڴ�ʧ��\n";
	}

	system("pause");
	//�ָ������ص��ڴ�
	RecoverMemoryProc RecoverMemory = (RecoverMemoryProc)GetProcAddress(hmodule, "RecoverMemory");
	success = RecoverMemory(pid, mem, 0);
	if (success) {
		std::cout << "�ָ������ڴ�ɹ�: " << mem << "\n";
	}
	else {
		std::cerr << "�ָ������ڴ�ʧ��\n";
	}

	system("pause");
	//�ͷ��ڴ�
	FreeMemoryProc FreeMemory = (FreeMemoryProc)GetProcAddress(hmodule, "FreeMemory");
	success = FreeMemory(pid, mem, 0x1000);
	if (success) {
		std::cout << "�ͷ��ڴ�ɹ�: " << mem << "\n";
	}
	else {
		std::cerr << "�ͷ��ڴ�ʧ��\n";
	}
	system("pause");
	//���ؽ���
	HideProcessProc HideProcess = (HideProcessProc)GetProcAddress(hmodule, "HideProcess");
	success = HideProcess(pid);
	if (success) {
		std::cout << "���ؽ��̳ɹ�: " << mem << "\n";
	}
	else {
		std::cerr << "���ؽ���ʧ��\n";
	}

	system("pause");
	//��������
	TermiateProcessProc TermiateProcess = (TermiateProcessProc)GetProcAddress(hmodule, "TermiateProcess");
	success = TermiateProcess(pid);
	if (success) {
		std::cout << "�������̳ɹ�: " << mem << "\n";
	}
	else {
		std::cerr << "��������ʧ��\n";
	}

	system("pause");
	//����ͼ
	HWND hwnd = FindWindowA(NULL, "Cheat Engine 7.4");
	if (hwnd) {
		std::cout << "��ȡ���ھ���ɹ�\n";
		AntiSrceenShotProc AntiSrceenShot = (AntiSrceenShotProc)GetProcAddress(hmodule, "AntiSrceenShot");
		AntiSrceenShot(hwnd);
	}
	else {
		std::cerr << "��ȡ���ھ��ʧ��\n";
	}

	////=====================================x86=======================================
	////x86ע��
	//LoadLibrary_x86Proc LoadLibrary_x86 = (LoadLibrary_x86Proc)GetProcAddress(hmodule, "LoadLibrary_x86");
	//auto success = LoadLibrary_x86(pid, "C:\\Users\\ljw-cccc\\Desktop\\dll.dll");
	//if (success) {
	//	std::cout << "x86ע��ɹ�\n";
	//}
	//else {
	//	std::cerr << "x86ע��ʧ��\n";
	//}

	////x86call
	//RemoteCallProc RemoteCall = (RemoteCallProc)GetProcAddress(hmodule, "RemoteCall");
	//unsigned __int8 x86_buffer[] = {
	//	0xB8, 0x78, 0x56, 0x34, 0x12, //mov eax, 0x12345678
	//	0x83, 0xEC, 0xa0,			  //sub esp, 0x40
	//	0xFF,0xD0,					  //call eax
	//	0x83,0xC4, 0xa0,			  //add esp, 0x40
	//	0xC3						  //ret
	//};

	//*(unsigned __int32*)&x86_buffer[1] = 0x621000;
	//success = RemoteCall(pid, x86_buffer, sizeof(x86_buffer));
	//if (success) {
	//	std::cout << "RemoteCall�ɹ�\n";
	//}
	//else {
	//	std::cerr << "RemoteCallʧ��\n";
	//}

	system("pause");
	return 0;
}