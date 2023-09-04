#include "api.h"
#include "comm.h"

boolean Examine()
{
	uint64_t code = 0;
	SengMessageEx(Command::Link, &code, sizeof(code));
	return code == 0x77777;
}