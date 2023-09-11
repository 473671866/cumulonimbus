#include "global.h"

std::vector<uint64_t>* GetGlobalVector()
{
	static std::vector<uint64_t>collection;
	return &collection;
}