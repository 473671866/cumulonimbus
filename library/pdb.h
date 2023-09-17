#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <imagehlp.h>
#include <locale.h>
#include <psapi.h>
#include <urlmon.h>
#include <map>
#include <string>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Imagehlp.lib")

namespace pdb
{
	uint64_t EnumModuleRoutineAddress(IN const char* module_name, OUT std::map<std::string, uint64_t>* returned);
}