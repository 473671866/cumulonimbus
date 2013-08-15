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
	boolean GenerateDriver(std::filesystem::path driverpath, unsigned char* filebuffer, size_t filesize);
	boolean LoadDriver(std::filesystem::path dirverpath, std::string service_name);
	boolean UnLoadDriver(std::string service_name);
	boolean MappingDriver(unsigned char* filebuffer, size_t filesize);
}
