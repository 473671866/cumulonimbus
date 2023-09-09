#include "loader.h"
#include "spoce_exit.hpp"

namespace loader
{
	struct DriverBuffer
	{
		unsigned __int64 filesize;
		unsigned __int64 filebuffer;
	};

	std::string RandomString(const int length)
	{
		std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<size_t> dis(0, characters.size() - 1);
		std::string randomstring;
		randomstring.reserve(length);

		for (int i = 0; i < length; ++i) {
			randomstring += characters[dis(gen)];
		}

		return randomstring;
	}

	boolean GenerateDriver(std::filesystem::path driverpath, unsigned char* filebuffer, size_t filesize)
	{
		std::ofstream stream(driverpath, std::ios::binary);
		if (!stream.is_open()) {
			return false;
		}

		unsigned char* buffer = new unsigned char[filesize];
		memcpy(buffer, filebuffer, filesize);

		for (int i = 0; i < filesize; i++) {
			buffer[i] ^= 0xF;
			buffer[i] ^= 0xA;
			stream << buffer[i];
		}

		delete[] buffer;
		return !stream.fail();
	}

	boolean LoadDriver(std::filesystem::path dirverpath, std::string service_name)
	{
		SC_HANDLE hmanager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		auto close_hmanager = std::experimental::make_scope_exit([&] {if (hmanager) { CloseServiceHandle(hmanager); }});
		if (!hmanager) {
			return false;
		}

		SC_HANDLE hservice = CreateServiceA(hmanager, service_name.c_str(), service_name.c_str(), SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, dirverpath.string().c_str(), NULL, NULL, NULL, NULL, NULL);
		auto close_hservcie = std::experimental::make_scope_exit([&] {if (hservice) { CloseServiceHandle(hservice); }});
		if (!hservice) {
			hservice = OpenServiceA(hmanager, service_name.c_str(), SERVICE_ALL_ACCESS);
			if (!hservice) {
				return false;
			}
		}

		boolean success = StartServiceA(hservice, 0, NULL);
		return success;
	}

	boolean UnLoadDriver(std::string service_name)
	{
		SC_HANDLE hmanager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		auto close_hmanager = std::experimental::make_scope_exit([&] {if (hmanager) { CloseServiceHandle(hmanager); }});
		if (!hmanager) {
			return false;
		}

		SC_HANDLE  hservice = OpenServiceA(hmanager, service_name.c_str(), SERVICE_ALL_ACCESS);
		auto close_hservcie = std::experimental::make_scope_exit([&] {if (hservice) { CloseServiceHandle(hservice); }});
		if (!hservice) {
			return false;
		}

		SERVICE_STATUS status{};
		boolean success = ControlService(hservice, SERVICE_CONTROL_STOP, &status);
		if (!success) {
			return false;
		}
		return DeleteService(hservice);
	}

	boolean MappingDriver(unsigned char* filebuffer, size_t filesize)
	{
		HANDLE hdevice = CreateFileA("\\\\.\\ljw", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hdevice) {
			return false;
		}
		unsigned char* driverbuffer = new unsigned char[filesize];
		memcpy(driverbuffer, filebuffer, filesize);
		for (int i = 0; i < filesize; i++) {
			driverbuffer[i] ^= 0xF;
			driverbuffer[i] ^= 0xA;
		}

		DriverBuffer package{ };
		package.filebuffer = reinterpret_cast<unsigned __int64>(driverbuffer);
		package.filesize = filesize;
		unsigned long bytes_returned;
		boolean success = WriteFile(hdevice, &package, sizeof(DriverBuffer), &bytes_returned, NULL);

		CloseHandle(hdevice);
		delete[] driverbuffer;
		return success;
	}
}