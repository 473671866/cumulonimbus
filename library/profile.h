#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <map>
#include <mutex>
#include <codecvt>
#include <list>

#define PROFILE_NAME "config.ini"

class ProFile
{
private:
	std::string m_file;
	std::recursive_mutex  m_mtx;
public:
	ProFile(std::string file);

	std::list<std::string> ReadPrivateProfileSectionNames();
	unsigned int ReadProfileIntegerA(std::string section, std::string key);
	unsigned int ReadProfileStringsA(std::string section, std::string key, char* buffer, unsigned long size);
	std::map<std::string, std::string> ReadProfileSectionsA(std::string section);

	bool WriteProfileStringsA(std::string section, std::string key, std::string buffer);
	bool WriteProfileIntegerA(std::string seciton, std::string key, int32_t contect);
	bool WriteProfileSectonsA(std::string section, std::string buffer);

	bool DeleteProfileString(std::string section, std::string key);
	bool DeleteProfileSection(std::string section);
};
