#pragma once
#include <fltKernel.h>
#pragma comment(lib, "./pdb/analysis_pdb.lib")

namespace analysis {
	class Pdber {
	public:
		Pdber(const wchar_t* moduleName);
		bool init();
		~Pdber();
		ULONG_PTR GetPointer(const char* name);
		size_t GetOffset(const char* structName, const char* propertyName);
	private:
		char padding[1000];//can not revise this!!! else it will ocurrs stack overflow!!
	};
}
