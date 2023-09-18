#pragma once
#include <iostream>
#include <memory>
#include <windows.h>
#include "loader.h"
#include "spoce_exit.hpp"
#include "../library/load.hpp"
#include "../library/driver.hpp"

namespace cumulonimbus
{
	enum class  Command : unsigned __int64
	{
		Link = 555,
		Initialize,
		Call,
		LoadLibrary_x64,
		LoadLibrary_x86,
		HideMemory,
		RecovreMemory,
		AllocateMemory,
		FreeMemory,
		HideProcess,
		TerminateProcess,
		Module,
		ReadMapping,
		ReadPhysical,
		WritePhysical,
		AntiScreenShot,
		InitializeWindowProtected,
		InstallWindowProtected,
		UnloadWindowProtected,
	};

#pragma pack(push)
#pragma pack(8)

	struct CommPackage
	{
		unsigned __int64 flags;
		Command command;
		unsigned __int64 buffer;
		unsigned __int64 length;
		__int64 result;
	};

	struct RemoteCallPackage
	{
		unsigned __int64 pid;
		unsigned __int64 shellcode;
		unsigned __int64 size;
	};

	struct InjectPackage
	{
		unsigned __int64 pid;
		unsigned __int64 filebuffer;
		unsigned __int64 filesize;
		unsigned __int64 imagesize;
	};

	struct HideMemoryPackage
	{
		unsigned __int64 pid;
		unsigned __int64 address;
		unsigned __int64 size;
	};

	struct ModulePackage
	{
		unsigned __int64 pid;
		unsigned __int64 name;
		unsigned __int64 address;
		unsigned __int64 size;
	};

	struct MemoryPackage
	{
		unsigned __int64 pid;
		unsigned __int64 address;
		unsigned __int64 buffer;
		unsigned __int64 size;
		unsigned __int64 protect;
	};

	typedef struct _PEB
	{
		unsigned long long InheritedAddressSpace;
		void* Mutant;                                                           //0x8
		void* ImageBaseAddress;                                                 //0x10
	}PEB, * PPEB;

	class comm
	{
	public:
		bool SendMessageEx(Command command, void* buffer, unsigned __int64 length)
		{
			CommPackage package{  };
			package.flags = 0x55555;
			package.command = command;
			package.buffer = reinterpret_cast<uint64_t>(buffer);
			package.length = length;

			PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
			peb->Mutant = &package;
			SYSTEMTIME system_time;
			GetLocalTime(&system_time);
			SetSystemTime(&system_time);

			return package.result >= 0;
		}
	};

	class invoker
	{
	public:
		static invoker* make_invoker()
		{
			std::shared_ptr<comm> link = std::make_shared<comm>();

			unsigned __int64 flags = 0;
			link->SendMessageEx(Command::Link, &flags, sizeof(flags));
			if (flags == 0x77777) {
				return get_instance(link.get());
			}

			//生成驱动
			int result = 0;
			char temppath[MAX_PATH]{};
			GetTempPathA(MAX_PATH, temppath);
			std::string filename = loader::RandomString(10);
			std::filesystem::path driverpath(std::string(temppath).append(filename).append(".sys"));
			bool success = loader::GenerateDriver(driverpath, load, sizeof(load));
			if (!success) {
				return nullptr;
			}

			//加载驱动
			std::string service_name = loader::RandomString(10);
			success = loader::LoadDriver(driverpath, service_name);
			if (!success) {
				return nullptr;
			}

			//卸载
			auto unload = std::experimental::make_scope_exit([&] {
				loader::UnLoadDriver(service_name);
				if (std::filesystem::exists(driverpath)) {
					std::filesystem::remove(driverpath);
				}});

			//映射
			success = loader::MappingDriver(driver, sizeof(driver));
			if (!success) {
				return nullptr;
			}

			flags = 0;
			link->SendMessageEx(Command::Link, &flags, sizeof(flags));
			if (flags == 0x77777) {
				return get_instance(link.get());
			}

			return nullptr;
		}

		static invoker* get_instance(comm* m)
		{
			static invoker dvr(m);
			return &dvr;
		}

		invoker(comm* m) :m_link(m)
		{
			;
		}

		~invoker()
		{
			delete m_link;
		}

		template<typename _VA>
		bool read(unsigned __int64 pid, _VA address, void* buffer, unsigned __int64 size)
		{
			MemoryPackage package{ .pid = pid, .address = (unsigned __int64)address, .size = size };
			return m_link->SendMessageEx(Command::ReadPhysical, &package, sizeof(package));
		}

		template<typename _VA>
		bool write(unsigned __int64 pid, _VA address, void* buffer, unsigned __int64 size)
		{
			MemoryPackage package{ .pid = pid, .address = (unsigned __int64)address, .size = size };
			return m_link->SendMessageEx(Command::WritePhysical, &package, sizeof(package));
		}

		bool remote_invoke(unsigned __int64 pid, void* shellcode, unsigned __int64 size)
		{
			RemoteCallPackage package{ .pid = pid, .shellcode = reinterpret_cast<unsigned __int64>(shellcode), .size = size };
			return m_link->SendMessageEx(Command::Call, &package, sizeof(package));
		}

	private:
		comm* m_link;
	};
}