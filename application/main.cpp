#include <iostream>
#include <windows.h>
#include "api.h"

int main(int arg, char** argv)
{
	if (!Launcher())
	{
		std::cerr << "加载失败\n";
	}

	if (!Examine()) {
		printf("链接失败\n");
		system("pause");
		return 0;
	}
	printf("链接成功\n");
	//HMODULE hmodule = LoadLibraryA("user32.dll");
	//uint64_t msg = (uint64_t)GetProcAddress(hmodule, "MessageBoxA");
	//printf("msg: %llx\n", msg);

	//uint8_t buffer[]
	//{
	//	0x31, 0xC9,													//xor rcx, rcx
	//	0x31, 0xD2,													//xor rdx, rdx
	//	0x4D, 0x31, 0xC0,											//xor r8, r8
	//	0x4D, 0x31, 0xC9,											//xor r9, r9
	//	0x48, 0xB8, 0x99, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00,	//mov rax, 0x123456789
	//	0x48, 0x81, 0xEC, 0xA8, 0x00, 0x00, 0x00,					//sup rsp, 0xa8
	//	0xFF, 0xD0,													//call rax
	//	0x48, 0x81, 0xC4, 0xA8, 0x00, 0x00, 0x00,					//add rsp, 0xa8
	//	0xC3														//ret
	//};
	////0x7FFDE739A9C0

	//*(uint64_t*)&buffer[12] = msg;
	//RemoteCall(3692, buffer, sizeof(buffer));
	//int64_t buffer = 0x123456789;
	//Comm::controller(&buffer, sizeof(buffer));
	//std::cout << buffer << std::endl;
	system("pause");

	return 0;
}