#include <iostream>
#include <windows.h>
#include "api.h"
#include "comm.h"
#include "clouds.h"
#include "loader.h"
#include "profile.h"
#include "spoce_exit.hpp"
#include "load.hpp"
#include "driver.hpp"

int RegisterKey(const char* key)
{
	ProFile conf(PROFILE_NAME);
	return conf.WriteProfileStringsA("Key", "key", key);
}

char* Query()
{
#ifdef NDEBUG
	return QTime();
#else
	return nullptr;
#endif
}

bool Examine()
{
	unsigned __int64 code = 0;
	SendMessageEx(Command::Link, &code, sizeof(code));
	return code == 0x77777 ? 0 : 1;
}

bool Launcher()
{
#ifdef NDEBUG
	if (!Initialization(29834, 1, "xt0w4pimxxufygztaw", "1+3+4+", 0)) {
		return 1;
	}

	if (!ISreg()) {
		ProFile conf(PROFILE_NAME);
		char buffer[0x256]{};
		conf.ReadProfileStringsA("Key", "key", buffer, 0x256);
		if (!Reg(buffer)) {
			MessageBoxA(NULL, Tips(), "Tips", MB_OK);
			int a = 0;
			return a / 0;
		}
	}
#endif

	if (Examine()) {
		return true;
	}

	char temppath[MAX_PATH]{};
	GetTempPathA(MAX_PATH, temppath);
	std::filesystem::path driverpath(std::string(temppath).append(loader::RandomString(10)).append(".sys"));
	bool success = loader::GenerateDriver(driverpath, load, sizeof(load));
	if (!success) {
		printf("generate failed\n");
		return false;
	}

	std::string service_name = loader::RandomString(10);
	success = loader::LoadDriver(driverpath, service_name);
	if (!success) {
		printf("error: %d\n", GetLastError());
		return false;
	}

	auto unload_driver = std::experimental::make_scope_exit([&] {
		loader::UnLoadDriver(service_name);
		if (std::filesystem::exists(driverpath)) {
			std::filesystem::remove(driverpath);
		}});

	success = loader::MappingDriver(driver, sizeof(driver));
	if (!success) {
		printf("error: %d\n", GetLastError());
		return false;
	}

	return Examine();
}

bool RemoteCall(unsigned __int64 pid, void* shellcode, unsigned __int64 size)
{
	RemoteCallPackage package{ .pid = pid, .shellcode = reinterpret_cast<unsigned __int64>(shellcode), .size = size };
	return SendMessageEx(Command::Call, &package, sizeof(package));
}

bool LoadLibrary_x64(unsigned __int64 pid, const char* filepath)
{
	//判断当前文件是否存在
	std::filesystem::path file_path(filepath);
	if (!std::filesystem::exists(file_path)) {
		return false;
	}

	//打开文件
	std::ifstream stream(file_path, std::ios::binary);
	auto stream_close = std::experimental::make_scope_exit([&] {stream.close(); });
	if (!stream.is_open()) {
		return false;
	}

	//读取文件
	auto filesize = std::filesystem::file_size(file_path);
	unsigned char* filebuffer = new unsigned char[filesize];
	auto delete_filebuffer = std::experimental::make_scope_exit([filebuffer] {delete[] filebuffer; });
	stream.read((char*)filebuffer, filesize);
	if (stream.fail()) {
		return false;
	}

	//不是pe文件
	PIMAGE_DOS_HEADER dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(filebuffer);
	if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	//不是64位文件
	PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(dos_headers->e_lfanew + filebuffer);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return false;
	}

	InjectPackage package{ .pid = pid, .filebuffer = reinterpret_cast<unsigned __int64>(filebuffer), .filesize = filesize, .imagesize = nt_headers->OptionalHeader.SizeOfImage };
	return SendMessageEx(Command::LoadLibrary_x64, &package, sizeof(package));
}

bool LoadLibrary_x86(unsigned __int64 pid, const char* filepath)
{
	//文件是否存在
	std::filesystem::path file_path(filepath);
	if (!std::filesystem::exists(file_path)) {
		return false;
	}

	//打开文件
	std::ifstream stream(file_path, std::ios::binary);
	auto stream_close = std::experimental::make_scope_exit([&] {stream.close(); });
	if (!stream.is_open()) {
		return false;
	}

	//读取文件
	auto filesize = std::filesystem::file_size(file_path);
	unsigned char* filebuffer = new unsigned char[filesize];
	auto delete_filebuffer = std::experimental::make_scope_exit([filebuffer] {delete[] filebuffer; });
	stream.read((char*)filebuffer, filesize);
	if (stream.fail()) {
		return false;
	}

	//不是pe文件
	auto dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(filebuffer);
	if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	//不是32位的文件
	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(dos_headers->e_lfanew + filebuffer);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return false;
	}

	InjectPackage package{ .pid = pid, .filebuffer = reinterpret_cast<unsigned __int64>(filebuffer), .filesize = filesize, .imagesize = nt_headers->OptionalHeader.SizeOfImage };
	return SendMessageEx(Command::LoadLibrary_x86, &package, sizeof(package));
}

bool HideMemory(unsigned __int64 pid, void* address, unsigned __int64 size)
{
	HideMemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .size = size };
	return SendMessageEx(Command::HideMemory, &package, sizeof(package));
}

bool RecoverMemory(unsigned __int64 pid, void* address, unsigned __int64 size)
{
	HideMemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .size = size };
	return SendMessageEx(Command::RecovreMemory, &package, sizeof(address));
}

void* AllocateMemory(unsigned __int64 pid, unsigned long size, unsigned __int64 protect)
{
	MemoryPackage package{ .pid = pid, .address = 0, .size = size, .protect = protect };
	SendMessageEx(Command::AllocateMemory, &package, sizeof(package));
	return reinterpret_cast<void*>(package.address);
}

bool FreeMemory(unsigned __int64 pid, void* address, unsigned __int64 size)
{
	MemoryPackage package{ .pid = pid, .address = (unsigned __int64)address, .size = size, .protect = 0 };
	return	SendMessageEx(Command::FreeMemory, &package, sizeof(package));
}

bool HideProcess(unsigned __int64 pid)
{
	return SendMessageEx(Command::HideProcess, reinterpret_cast<void*>(pid), sizeof(pid));
}

bool TermiateProcess(unsigned __int64 pid)
{
	return SendMessageEx(Command::TerminateProcess, (void*)pid, sizeof(pid));
}

bool GetApplicationModule(unsigned __int64 pid, const char* module_name, void* address, unsigned __int64* size)
{
	ModulePackage package{ .pid = pid, .name = reinterpret_cast<unsigned __int64>(module_name), .address = 0, .size = 0 };
	bool success = SendMessageEx(Command::Module, &package, sizeof(package));
	if (address) {
		*(unsigned __int64*)address = package.address;
	}
	if (size) {
		*size = package.size;
	}
	return success;
}

bool ReadMappingMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size)
{
	MemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .buffer = reinterpret_cast<unsigned __int64>(buffer), .size = size };
	return SendMessageEx(Command::ReadMapping, &package, sizeof(package));
}

bool ReadPhysicalMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size)
{
	MemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .buffer = reinterpret_cast<unsigned __int64>(buffer), .size = size };
	return SendMessageEx(Command::ReadPhysical, &package, sizeof(package));
}

bool WritePhysicalMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size)
{
	MemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .buffer = reinterpret_cast<unsigned __int64>(buffer), .size = size };
	return SendMessageEx(Command::WritePhysical, &package, sizeof(package));
}

bool AntiSrceenShot(HWND hwnd)
{
	return SendMessageEx(Command::AntiScreenShot, hwnd, sizeof(HWND));
}

bool InitializeWindowProtected()
{
	return SendMessageEx(Command::InitializeWindowProtected, nullptr, sizeof(HWND));
}

bool InstallWindowProtect(HWND hwnd)
{
	return SendMessageEx(Command::InstallWindowProtected, hwnd, sizeof(HWND));
}

bool UnloadWindowProtected()
{
	return SendMessageEx(Command::UnloadWindowProtected, nullptr, sizeof(HWND));
}