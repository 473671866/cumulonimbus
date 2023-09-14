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
		std::cout << "加载模块失败: " << code << "\n";
		system("pause");
		return 0;
	}
	else {
		std::cout << "加载模块成功\n";
	}

	//QueryProc Query = (QueryProc)GetProcAddress(hmodule, "Query");
	//ExamineProc Examine = (ExamineProc)GetProcAddress(hmodule, "Examine");
	//InitializeWindowProtectedProc InitializeWindowProtected = (InitializeWindowProtectedProc)GetProcAddress(hmodule, "InitializeWindowProtected");
	//InstallWindowProtectProc InstallWindowProtect = (InstallWindowProtectProc)GetProcAddress(hmodule, "InstallWindowProtect");
	//UnloadWindowProtectedProc UnloadWindowProtected = (UnloadWindowProtectedProc)GetProcAddress(hmodule, "UnloadWindowProtected");

	//注册
	RegisterKeyProc RegisterKey = (RegisterKeyProc)GetProcAddress(hmodule, "RegisterKey");
	RegisterKey("CUMOBKNE2N8TCW22WXHV54G004AI8VDD");

	//加载驱动
	LauncherProc Launcher = (LauncherProc)GetProcAddress(hmodule, "Launcher");
	code = Launcher();
	if (code != 0) {
		std::cerr << "加载驱动失败, 错误代码: " << code << "\n";
		system("pause");
	}
	else {
		std::cout << "加载驱动成功\n";
	}

	auto pid = GetPid();

	//模块
	system("pause");
	unsigned __int64 module_address = 0;
	GetApplicationModuleProc GetApplicationModule = (GetApplicationModuleProc)GetProcAddress(hmodule, "GetApplicationModule");
	bool success = GetApplicationModule(pid, "Project1.exe", &module_address, nullptr);
	if (success || module_address) {
		std::cout << "模块地址: " << (void*)module_address << "\n";
	}
	else {
		std::cerr << "获取模块失败\n";
		system("pause");
	}

	system("pause");
	//读
	unsigned __int64 address = 0x7ff670287000;
	unsigned __int64 mapping = 0;
	ReadMappingMemoryProc ReadMappingMemory = (ReadMappingMemoryProc)GetProcAddress(hmodule, "ReadMappingMemory");
	success = ReadMappingMemory(pid, address, &mapping, 8);
	if (success) {
		std::cout << "ReadMappingMemory 读取结果: " << mapping << "\n";
	}
	else {
		std::cerr << "ReadMappingMemory 读取失败 " << mapping << "\n";
		system("pause");
	}

	system("pause");
	unsigned __int64 physical = 0;
	ReadPhysicalMemoryProc ReadPhysicalMemory = (ReadPhysicalMemoryProc)GetProcAddress(hmodule, "ReadPhysicalMemory");
	success = ReadPhysicalMemory(pid, address, &physical, 8);
	if (success) {
		std::cout << "ReadPhysicalMemory 读取结果: " << physical << "\n";
	}
	else {
		std::cerr << "ReadPhysicalMemory 读取失败\n" << physical << "\n";;
		system("pause");
	}

	system("pause");
	//写
	unsigned __int64 write = 555555;
	WritePhysicalMemoryProc WritePhysicalMemory = (WritePhysicalMemoryProc)GetProcAddress(hmodule, "WritePhysicalMemory");
	success = WritePhysicalMemory(pid, address, &write, 8);
	if (success) {
		std::cout << "写入成功\n";
	}
	else {
		std::cerr << "写入失败\n";
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
		std::cout << "RemoteCall成功\n";
	}
	else {
		std::cerr << "RemoteCall失败\n";
	}

	system("pause");
	//x64注入
	LoadLibrary_x64Proc LoadLibrary_x64 = (LoadLibrary_x64Proc)GetProcAddress(hmodule, "LoadLibrary_x64");
	success = LoadLibrary_x64(pid, "C:\\Users\\ljw-cccc\\Desktop\\dll.dll");
	if (success) {
		std::cout << "x64注入成功\n";
	}
	else {
		std::cerr << "x64注入失败\n";
	}

	system("pause");
	//申请内存
	AllocateMemoryProc AllocateMemory = (AllocateMemoryProc)GetProcAddress(hmodule, "AllocateMemory");
	void* mem = AllocateMemory(pid, 0x1000, PAGE_EXECUTE_READWRITE);
	if (mem) {
		std::cout << "申请内存成功: " << mem << "\n";
	}
	else {
		std::cerr << "申请内存失败\n";
	}

	system("pause");
	//隐藏内存
	HideMemoryProc HideMemory = (HideMemoryProc)GetProcAddress(hmodule, "HideMemory");
	success = HideMemory(pid, mem, 0x1000);
	if (success) {
		std::cout << "隐藏内存成功: " << mem << "\n";
	}
	else {
		std::cerr << "隐藏内存失败\n";
	}

	system("pause");
	//恢复被隐藏的内存
	RecoverMemoryProc RecoverMemory = (RecoverMemoryProc)GetProcAddress(hmodule, "RecoverMemory");
	success = RecoverMemory(pid, mem, 0);
	if (success) {
		std::cout << "恢复隐藏内存成功: " << mem << "\n";
	}
	else {
		std::cerr << "恢复隐藏内存失败\n";
	}

	system("pause");
	//释放内存
	FreeMemoryProc FreeMemory = (FreeMemoryProc)GetProcAddress(hmodule, "FreeMemory");
	success = FreeMemory(pid, mem, 0x1000);
	if (success) {
		std::cout << "释放内存成功: " << mem << "\n";
	}
	else {
		std::cerr << "释放内存失败\n";
	}
	system("pause");
	//隐藏进程
	HideProcessProc HideProcess = (HideProcessProc)GetProcAddress(hmodule, "HideProcess");
	success = HideProcess(pid);
	if (success) {
		std::cout << "隐藏进程成功: " << mem << "\n";
	}
	else {
		std::cerr << "隐藏进程失败\n";
	}

	system("pause");
	//结束进程
	TermiateProcessProc TermiateProcess = (TermiateProcessProc)GetProcAddress(hmodule, "TermiateProcess");
	success = TermiateProcess(pid);
	if (success) {
		std::cout << "结束进程成功: " << mem << "\n";
	}
	else {
		std::cerr << "结束进程失败\n";
	}

	system("pause");
	//反截图
	HWND hwnd = FindWindowA(NULL, "Cheat Engine 7.4");
	if (hwnd) {
		std::cout << "获取窗口句柄成功\n";
		AntiSrceenShotProc AntiSrceenShot = (AntiSrceenShotProc)GetProcAddress(hmodule, "AntiSrceenShot");
		AntiSrceenShot(hwnd);
	}
	else {
		std::cerr << "获取窗口句柄失败\n";
	}

	////=====================================x86=======================================
	////x86注入
	//LoadLibrary_x86Proc LoadLibrary_x86 = (LoadLibrary_x86Proc)GetProcAddress(hmodule, "LoadLibrary_x86");
	//auto success = LoadLibrary_x86(pid, "C:\\Users\\ljw-cccc\\Desktop\\dll.dll");
	//if (success) {
	//	std::cout << "x86注入成功\n";
	//}
	//else {
	//	std::cerr << "x86注入失败\n";
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
	//	std::cout << "RemoteCall成功\n";
	//}
	//else {
	//	std::cerr << "RemoteCall失败\n";
	//}

	system("pause");
	return 0;
}