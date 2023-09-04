#pragma once
#include "base.h"

#define make_scope_exit(_function_) (scope_exit(_function_))

class scope_exit
{
private:
	std::function<void()>fn;
public:
	scope_exit(std::function<void()>fn);
	~scope_exit();
};
