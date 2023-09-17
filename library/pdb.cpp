#include "pdb.h"
#include "symsrv.hpp"
#define SYMBOL_PATH  "srv* %s *http://msdl.microsoft.com/download/symbols"

namespace pdb
{
	BOOL EnumModuleSymbol(
		_In_ PSYMBOL_INFO pSymInfo,
		_In_ ULONG SymbolSize,
		_In_opt_ PVOID UserContext)
	{
		std::map<std::string, uint64_t>* collection = reinterpret_cast<std::map<std::string, uint64_t>*>(UserContext);
		collection->emplace(pSymInfo->Name, pSymInfo->Address);
		return true;
	}

	uint64_t EnumModuleRoutineAddress(IN const char* module_name, OUT std::map<std::string, uint64_t>* returned)
	{
		//获取dll路径
		PLOADED_IMAGE image = ImageLoad(module_name, NULL);
		if (image == nullptr) {
			return 0;
		}

		char buffer[0x256]{};

		//符号路径
		char SymbolPath[MAX_PATH]{ NULL };
		GetCurrentDirectoryA(MAX_PATH, SymbolPath);
		strcat(SymbolPath, "\\symbols");

		//下载路径
		char DownloadPath[MAX_PATH]{ NULL };
		sprintf_s(DownloadPath, SYMBOL_PATH, SymbolPath);

		//打开当前进程
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		CloseHandle(hProcess);

		//初始化
		if (!SymInitialize(hProcess, DownloadPath, FALSE)) {
			return false;
		}

		SymSetOptions(SymGetOptions() | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_CASE_INSENSITIVE);

		//下载符号文件
		//下载失败可能是没有symsrv.dll
		//尝试把symsrv.dll复制到system32中然后再次下载
		char SymbolFile[MAX_PATH]{ NULL };
		if (!SymGetSymbolFile(hProcess, NULL, image->ModuleName, sfPdb, SymbolFile, MAX_PATH, SymbolFile, MAX_PATH)) {
			unsigned long dwImageSize = sizeof(symsrv);
			unsigned long dwByteWrite = 0;

			unsigned char* pMemory = (unsigned char*)malloc(dwImageSize);
			memcpy(pMemory, symsrv, dwImageSize);

			for (ULONG i = 0; i < dwImageSize; i++) {
				pMemory[i] ^= 0xF;
				pMemory[i] ^= 0xA;
			}

			HANDLE hFile = CreateFileA(
				"C:\\Windows\\System32\\symsrv.dll",
				GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			);

			if (hFile == INVALID_HANDLE_VALUE) {
				sprintf_s(buffer, "CreateFileA: %s Failed Error: %d\r\n", module_name, GetLastError());
				OutputDebugStringA(buffer);
				return false;
			}

			if (!WriteFile(hFile, pMemory, dwImageSize, &dwByteWrite, NULL)) {
				sprintf_s(buffer, "WriteFile: %s Failed Error: %d\r\n", module_name, GetLastError());
				OutputDebugStringA(buffer);
				CloseHandle(hFile);
				return false;
			}

			if (dwByteWrite != dwImageSize) {
				sprintf_s(buffer, "dwByteWrite: %s Failed Error: %d\r\n", module_name, GetLastError());
				OutputDebugStringA(buffer);
				CloseHandle(hFile);
				return false;
			}

			CloseHandle(hFile);
		}

		if (!SymGetSymbolFile(hProcess, NULL, image->ModuleName, sfPdb, SymbolFile, MAX_PATH, SymbolFile, MAX_PATH)) {
			sprintf_s(buffer, "GetSymbolFile: %s Failed Error: %d\r\n", module_name, GetLastError());
			OutputDebugStringA(buffer);
			return false;
		}

		//加载模块
		uint64_t dwSymModule = SymLoadModuleEx(hProcess, NULL, image->ModuleName, NULL, 0, 0, NULL, 0);
		if (0 == dwSymModule) {
			SymCleanup(hProcess);
			return -1;
		}

		//
		//枚举
		//
		if (!SymEnumSymbols(hProcess, dwSymModule, 0, EnumModuleSymbol, returned)) {
			SymCleanup(hProcess);
			return -1;
		}

		return dwSymModule;
	}
}