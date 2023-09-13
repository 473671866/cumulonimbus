#pragma once
#include <iostream>
#include <fstream>
#include <filesystem>
#include <random>
#include <string>
#include <windows.h>
namespace loader
{
	std::string RandomString(const int length);
	bool GenerateDriver(std::filesystem::path driverpath, unsigned char* filebuffer, unsigned long filesize);
	bool LoadDriver(std::filesystem::path dirverpath, std::string service_name);
	bool UnLoadDriver(std::string service_name);
	bool MappingDriver(unsigned char* filebuffer, unsigned long filesize);
}
