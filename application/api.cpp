#include "api.h"
#include "comm.h"
#include "load.hpp"
#include "loader.h"
#include "driver.hpp"
#include "spoce_exit.hpp"

boolean Examine()
{
	uint64_t code = 0;
	SengMessageEx(Command::Link, &code, sizeof(code));
	return code == 0x77777;
}

boolean Launcher()
{
	if (Examine()) {
		return true;
	}

	char temppath[MAX_PATH]{};
	GetTempPathA(MAX_PATH, temppath);
	std::string filename = loader::RandomString(10);
	std::string service_name = loader::RandomString(10);
	std::filesystem::path driverpath(std::string(temppath).append(filename).append(".sys"));
	boolean success = loader::GenerateDriver(driverpath, load, sizeof(load));
	if (!success) {
		std::cerr << "Éú³ÉÇý¶¯Ê§°Ü\n";
		goto unload;
	}

	success = loader::LoadDriver(driverpath, service_name);
	if (!success) {
		std::cerr << "¼ÓÔØÇý¶¯Ê§°Ü: " << GetLastError() << std::endl;
		goto unload;
	}

	success = loader::MappingDriver(driver, sizeof(driver));
	if (!success) {
		std::cerr << "Ó³ÉäÇý¶¯Ê§°Ü\n";
		goto unload;
	}

unload:
	success = loader::UnLoadDriver(service_name);
	if (std::filesystem::exists(driverpath))std::filesystem::remove(driverpath);
	if (!success) {
		return success;
	}
	return Examine();
}

boolean RemoteCall(uint64_t pid, void* shellcode, size_t size)
{
	RemoteCallPackage package{ .pid = pid, .shellcode = reinterpret_cast<uint64_t>(shellcode), .size = size };
	return SengMessageEx(Command::Call, &package, sizeof(package));
}

boolean LoadLibrary_x64(uint64_t pid, const char* filepath)
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

	InjectPackage package{ .pid = pid, .filebuffer = reinterpret_cast<uint64_t>(filebuffer), .filesize = filesize, .imagesize = nt_headers->OptionalHeader.SizeOfImage };
	return SengMessageEx(Command::Inject, &package, sizeof(package));
}

boolean HideMemory(uint64_t pid, uint64_t address, size_t size)
{
	HideMemoryPackage package{ .pid = pid, .address = address, .size = size };
	return SengMessageEx(Command::HideMemory, &package, sizeof(package));
}

boolean RecoverMemory(uint64_t address)
{
	return SengMessageEx(Command::HideMemory, reinterpret_cast<void*>(address), sizeof(address));
}

boolean HideProcess(uint64_t pid)
{
	return SengMessageEx(Command::HideProcess, reinterpret_cast<void*>(pid), sizeof(pid));
}

boolean GetApplicationModule(uint64_t pid, const char* module_name, void* address, size_t* size)
{
	ModulePackage package{ .pid = pid, .name = reinterpret_cast<uint64_t>(module_name),.address = 0, .size = 0 };
	boolean success = SengMessageEx(Command::Module, &package, sizeof(package));
	*(uint64_t*)address = package.address;
	if (size) {
		*size = package.size;
	}
	return success;
}

boolean ReadMappingMemory(uint64_t pid, uint64_t address, void* buffer, size_t size)
{
	MemoryPackage package{ .pid = pid, .address = address, .buffer = reinterpret_cast<uint64_t>(buffer), .size = size };
	return SengMessageEx(Command::ReadMapping, &package, sizeof(package));
}

boolean ReadPhysicalMemory(uint64_t pid, uint64_t address, void* buffer, size_t size)
{
	MemoryPackage package{ .pid = pid, .address = address, .buffer = reinterpret_cast<uint64_t>(buffer), .size = size };
	return SengMessageEx(Command::ReadPhysical, &package, sizeof(package));
}

boolean WritePhysicalMemory(uint64_t pid, uint64_t address, void* buffer, size_t size)
{
	MemoryPackage package{ .pid = pid, .address = address, .buffer = reinterpret_cast<uint64_t>(buffer), .size = size };
	return SengMessageEx(Command::WritePhysical, &package, sizeof(package));
}