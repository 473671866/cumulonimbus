#include "api.h"
#include "comm.h"

boolean Examine()
{
	uint64_t code = 0;
	SengMessageEx(Command::Link, &code, sizeof(code));
	return code == 0x77777;
}

boolean RemoteCall(uint64_t pid, void* shellcode, size_t size)
{
	RemoteCallPackage package{};
	package.pid = pid;
	package.shellcode = reinterpret_cast<uint64_t>(shellcode);
	package.size = size;
	return SengMessageEx(Command::Call, &package, sizeof(package));
}