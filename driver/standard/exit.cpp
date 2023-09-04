#include "exit.h"

scope_exit::scope_exit(std::function<void()>fn)
{
	this->fn = fn;
}

scope_exit::~scope_exit()
{
	fn();
}