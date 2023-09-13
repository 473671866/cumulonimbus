#include <iostream>
#include <windows.h>
#include "api.h"
#include "comm.h"
#include "load.hpp"
#include "loader.h"
#include "profile.h"
#include "driver.hpp"
#include "spoce_exit.hpp"
#include "clouds.h"

int RegisterKey(const char* key)
{
	ProFile conf(PROFILE_NAME);
	return conf.WriteProfileStringsA("Key", "key", key);
}

char* Query()
{
	return QTime();
}

bool Examine()
{
	unsigned __int64 code = 0;
	SengMessageEx(Command::Link, &code, sizeof(code));
	return code == 0x77777 ? 0 : 1;
}

int Launcher()
{
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

	if (Examine() == 0) {
		return 0;
	}

	int result = 0;
	char temppath[MAX_PATH]{};
	GetTempPathA(MAX_PATH, temppath);
	std::string filename = loader::RandomString(10);
	std::string service_name = loader::RandomString(10);
	std::filesystem::path driverpath(std::string(temppath).append(filename).append(".sys"));
	bool success = loader::GenerateDriver(driverpath, load, sizeof(load));
	if (!success) {
		result = GetLastError();
		goto unload;
	}

	success = loader::LoadDriver(driverpath, service_name);
	if (!success) {
		result = GetLastError();
		goto unload;
	}

	success = loader::MappingDriver(driver, sizeof(driver));
	if (!success) {
		result = GetLastError();
		goto unload;
	}

unload:
	loader::UnLoadDriver(service_name);
	if (std::filesystem::exists(driverpath)) {
		std::filesystem::remove(driverpath);
	}
	return result == 0 ? Examine() : result;
}

bool RemoteCall(unsigned __int64 pid, void* shellcode, unsigned __int64 size)
{
	RemoteCallPackage package{ .pid = pid, .shellcode = reinterpret_cast<unsigned __int64>(shellcode), .size = size };
	return SengMessageEx(Command::Call, &package, sizeof(package));
}

bool LoadLibrary_x64(unsigned __int64 pid, const char* filepath)
{
	std::filesystem::path file_path(filepath);
	if (!std::filesystem::exists(file_path)) {
		return false;
	}

	std::ifstream stream(file_path, std::ios::binary);
	auto stream_close = std::experimental::make_scope_exit([&] {stream.close(); });
	if (!stream.is_open()) {
		return false;
	}

	auto filesize = std::filesystem::file_size(file_path);
	unsigned char* filebuffer = new unsigned char[filesize];
	auto delete_filebuffer = std::experimental::make_scope_exit([filebuffer] {delete[] filebuffer; });
	stream.read((char*)filebuffer, filesize);
	if (stream.fail()) {
		return false;
	}

	PIMAGE_DOS_HEADER dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(filebuffer);
	if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(dos_headers->e_lfanew + filebuffer);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return false;
	}

	InjectPackage package{ .pid = pid, .filebuffer = reinterpret_cast<unsigned __int64>(filebuffer), .filesize = filesize, .imagesize = nt_headers->OptionalHeader.SizeOfImage };
	return SengMessageEx(Command::LoadLibrary_x64, &package, sizeof(package));
}

bool LoadLibrary_x86(unsigned __int64 pid, const char* filepath)
{
	std::filesystem::path file_path(filepath);
	if (!std::filesystem::exists(file_path)) {
		return false;
	}

	std::ifstream stream(file_path, std::ios::binary);
	auto stream_close = std::experimental::make_scope_exit([&] {stream.close(); });
	if (!stream.is_open()) {
		return false;
	}

	auto filesize = std::filesystem::file_size(file_path);
	unsigned char* filebuffer = new unsigned char[filesize];
	auto delete_filebuffer = std::experimental::make_scope_exit([filebuffer] {delete[] filebuffer; });
	stream.read((char*)filebuffer, filesize);
	if (stream.fail()) {
		return false;
	}

	auto dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(filebuffer);
	if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(dos_headers->e_lfanew + filebuffer);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return false;
	}

	InjectPackage package{ .pid = pid, .filebuffer = reinterpret_cast<unsigned __int64>(filebuffer), .filesize = filesize, .imagesize = nt_headers->OptionalHeader.SizeOfImage };
	return SengMessageEx(Command::LoadLibrary_x86, &package, sizeof(package));
}

bool HideMemory(unsigned __int64 pid, void* address, unsigned __int64 size)
{
	HideMemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .size = size };
	return SengMessageEx(Command::HideMemory, &package, sizeof(package));
}

bool RecoverMemory(unsigned __int64 pid, void* address, unsigned __int64 size)
{
	HideMemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .size = size };
	return SengMessageEx(Command::RecovreMemory, &package, sizeof(address));
}

void* AllocateMemory(unsigned __int64 pid, unsigned long size, unsigned __int64 protect)
{
	MemoryPackage package{ .pid = pid, .address = 0, .size = size, .protect = protect };
	SengMessageEx(Command::AllocateMemory, &package, sizeof(package));
	return reinterpret_cast<void*>(package.address);
}

bool FreeMemory(unsigned __int64 pid, void* address, unsigned __int64 size)
{
	MemoryPackage package{ .pid = pid, .address = (unsigned __int64)address, .size = size, .protect = 0 };
	return	SengMessageEx(Command::FreeMemory, &package, sizeof(package));
}

bool HideProcess(unsigned __int64 pid)
{
	return SengMessageEx(Command::HideProcess, reinterpret_cast<void*>(pid), sizeof(pid));
}

bool TermiateProcess(unsigned __int64 pid)
{
	return SengMessageEx(Command::TerminateProcess, (void*)pid, sizeof(pid));
}

bool GetApplicationModule(unsigned __int64 pid, const char* module_name, void* address, unsigned __int64* size)
{
	ModulePackage package{ .pid = pid, .name = reinterpret_cast<unsigned __int64>(module_name),.address = 0, .size = 0 };
	bool success = SengMessageEx(Command::Module, &package, sizeof(package));
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
	return SengMessageEx(Command::ReadMapping, &package, sizeof(package));
}

bool ReadPhysicalMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size)
{
	MemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .buffer = reinterpret_cast<unsigned __int64>(buffer), .size = size };
	return SengMessageEx(Command::ReadPhysical, &package, sizeof(package));
}

bool WritePhysicalMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size)
{
	MemoryPackage package{ .pid = pid, .address = reinterpret_cast<unsigned __int64>(address), .buffer = reinterpret_cast<unsigned __int64>(buffer), .size = size };
	return SengMessageEx(Command::WritePhysical, &package, sizeof(package));
}

bool AntiSrceenShot(HWND hwnd)
{
	return SengMessageEx(Command::AntiScreenShot, hwnd, sizeof(HWND));
}

bool InitializeWindowProtected()
{
	return SengMessageEx(Command::InitializeWindowProtected, nullptr, sizeof(HWND));
}

bool InstallWindowProtect(HWND hwnd)
{
	return SengMessageEx(Command::InstallWindowProtected, hwnd, sizeof(HWND));
}

bool UnloadWindowProtected()
{
	return SengMessageEx(Command::UnloadWindowProtected, nullptr, sizeof(HWND));
}