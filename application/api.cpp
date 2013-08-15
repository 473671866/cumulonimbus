#include "api.h"
#include "comm.h"
#include "load.hpp"
#include "loader.h"
#include "driver.hpp"

boolean Launcher()
{
	char temppath[MAX_PATH]{};
	GetTempPathA(MAX_PATH, temppath);
	std::string filename = loader::RandomString(10);
	std::filesystem::path driverpath(std::string(temppath).append(filename).append(".sys"));
	boolean success = loader::GenerateDriver(driverpath, load, sizeof(load));
	if (!success) {
		return success;
	}

	std::string service_name = loader::RandomString(10);
	success = loader::LoadDriver(driverpath, service_name);
	if (!success) {
		return success;
	}

	success = loader::MappingDriver(driver, sizeof(driver));
	if (!success) {
		return success;
	}

	success = loader::UnLoadDriver(service_name);
	if (!success) {
		return success;
	}
	return success;
}

boolean Examine()
{
	uint64_t code = 0;
	SengMessageEx(Command::Link, &code, sizeof(code));
	return code == 0x77777;
}

boolean RemoteCall(uint64_t pid, void* shellcode, size_t size)
{
	RemoteCallPackage package{};
	package.pid = pid;
	package.shellcode = reinterpret_cast<uint64_t>(shellcode);
	package.size = size;
	return SengMessageEx(Command::Call, &package, sizeof(package));
}