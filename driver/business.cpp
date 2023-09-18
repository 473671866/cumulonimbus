#include "business.h"
#include "global.h"
#include "routine.h"
#include "pdb/analysis.h"
#include "utils/utils.h"
#include "utils/search.h"
#include "utils/memory.hpp"
#include "utils/process.hpp"
#include "utils/version.hpp"
#include "utils/MemLoadDll.h"

namespace business
{
	struct FreeMemory
	{
		WORK_QUEUE_ITEM item;
		HANDLE pid;
		uint64_t base;
		uint64_t flags;
		size_t size;
	};

	uint64_t GetTrapFrameOffset()
	{
		static uint64_t offset = 0;
		if (offset == 0) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				offset = 0x1d8;
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				offset = ntos->GetOffset("_KTHREAD", "TrapFrame");
			}
			LOG_INFO("offset: %llx", offset);
		}
		return offset;
	}

	uint64_t GetThreadIdOffset()
	{
		static uint64_t offset = 0;
		if (offset == 0) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				offset = 0x3b0;
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				offset = ntos->GetOffset("_ETHREAD", "Cid");
			}
			LOG_INFO("offset: %llx", offset);
		}
		return offset;
	}

	uint64_t GetStartAddressOffset()
	{
		static uint64_t offset = 0;
		if (offset == 0) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				offset = 0x388;
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				offset = ntos->GetOffset("_ETHREAD", "StartAddress");
			}
			LOG_INFO("offset: %llx", offset);
		}
		return offset;
	}

	uint64_t GetWin32StartAddressOffset()
	{
		static uint64_t offset = 0;
		if (offset == 0) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				offset = 0x410;
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				offset = ntos->GetOffset("_ETHREAD", "Win32StartAddress");
			}
			LOG_INFO("offset: %llx", offset);
		}
		return offset;
	}

	uint64_t GetThreadListOffset()
	{
		static uint64_t offset = 0;
		if (offset == 0) {
			auto version = Version::get_instance();
			if (version->Windows_7()) {
				offset = 0x420;
			}
			else {
				analysis::Pdber* ntos = analysis::Ntoskrnl();
				offset = ntos->GetOffset("_ETHREAD", "ThreadListEntry");
			}
			LOG_INFO("offset: %llx", offset);
		}
		return offset;
	}

	NTSTATUS ReadMappingMemory(HANDLE pid, void* address, void* buffer, size_t size)
	{
		if (!utils::ProbeUserAddress(address, size, 1) || !utils::ProbeUserAddress(buffer, size, 1)) {
			return STATUS_INVALID_ADDRESS;
		}

		void* temp = utils::RtlAllocateMemory(PagedPool, size);
		if (temp == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		ProcessUtils prc;
		auto status = prc.StackAttachProcess(pid);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (MmIsAddressValid(address)) {
			RtlCopyMemory(temp, address, size);
		}

		prc.UnStackAttachProcess();
		RtlCopyMemory(buffer, temp, size);
		utils::RtlFreeMemory(temp);
		return status;
	}

	NTSTATUS ReadPhysicalMemory(HANDLE pid, void* address, void* buffer, size_t size)
	{
		if (!utils::ProbeUserAddress(address, size, 1) || !utils::ProbeUserAddress(buffer, size, 1)) {
			return STATUS_INVALID_ADDRESS;
		}

		PEPROCESS  process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = PsGetProcessExitStatus(process);
		if (status != 0x103) {
			return status;
		}

		void* temp = utils::RtlAllocateMemory(PagedPool, size);
		if (temp == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		uint64_t system_dicetory = __readcr3();
		uint64_t process_dircetory = *(uint64_t*)((uint8_t*)process + 0x28);

		KeEnterCriticalRegion();
		_disable();
		__writecr3(process_dircetory);

		if (MmIsAddressValid(address)) {
			RtlCopyMemory(temp, address, size);
		}

		_enable();
		__writecr3(system_dicetory);
		KeLeaveCriticalRegion();

		RtlCopyMemory(buffer, temp, size);
		utils::RtlFreeMemory(temp);

		return status;
	}

	NTSTATUS WritePhysicalMemory(HANDLE pid, void* address, void* buffer, size_t size)
	{
		if (!utils::ProbeUserAddress(address, size, 1) || !utils::ProbeUserAddress(buffer, size, 1)) {
			return STATUS_INVALID_ADDRESS;
		}

		PEPROCESS  process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = PsGetProcessExitStatus(process);
		if (status != 0x103) {
			return status;
		}

		void* temp = utils::RtlAllocateMemory(PagedPool, size);
		if (temp == nullptr) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		RtlCopyMemory(temp, buffer, size);

		uint64_t system_dicetory = __readcr3();
		uint64_t process_dircetory = *(uint64_t*)((uint8_t*)process + 0x28);

		KeEnterCriticalRegion();
		_disable();
		__writecr3(process_dircetory);

		if (MmIsAddressValid(address)) {
			void* mapping = MmMapIoSpace(MmGetPhysicalAddress(address), size, MmCached);
			if (mapping) {
				RtlCopyMemory(address, temp, size);
				MmUnmapIoSpace(mapping, size);
			}
		}

		_enable();
		__writecr3(system_dicetory);
		KeLeaveCriticalRegion();

		utils::RtlFreeMemory(temp);

		return status;
	}

	VOID WorkerRoutine(
		_In_ PVOID Parameter
	)
	{
		FreeMemory* fm = reinterpret_cast<FreeMemory*>(Parameter);

		//获取进程
		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(fm->pid, &process);
		if (!NT_SUCCESS(status)) {
			return;
		}

		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);

		//读取标记
		LARGE_INTEGER time{ .QuadPart = 10 * -10000 };
		uint64_t flags = 0;

		for (int i = 0; i < 10000; i++) {
			status = PsGetProcessExitStatus(process);
			if (status != 0x103) {
				KeUnstackDetachProcess(&apc);
				ObDereferenceObject(process);
				return;
			}

			RtlCopyMemory(&flags, (void*)fm->flags, 8);
			if (flags == 1) {
				break;
			}
			KeDelayExecutionThread(KernelMode, false, &time);
		}

		//释放内存
		ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&fm->base, &fm->size, MEM_RELEASE);
		ExFreePool(fm);
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
		return;
	}

	NTSTATUS RemoteCall(HANDLE pid, void* shellcode, size_t size)
	{
		//获取进程
		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//进程是否在运行
		status = PsGetProcessExitStatus(process);
		if (status != 0x103) {
			return STATUS_PROCESS_IS_TERMINATING;
		}

		//获取主线程
		PETHREAD  thread = routine::PsGetNextProcessThread(process, nullptr);
		auto dereference_thread = std::experimental::make_scope_exit([thread] {if (thread)ObDereferenceObject(thread); });
		if (thread == nullptr) {
			return STATUS_THREAD_NOT_IN_PROCESS;
		}

		//挂起线程
		status = routine::PsSuspendThread(thread, nullptr);
		if (!NT_SUCCESS(status)) {
			return status;
		}

#pragma warning (push)
#pragma warning(disable:4996)
#pragma warning(disable:4311)
#pragma warning(disable:4302)

		//申请内核内存
		PVOID kernel_buffer = utils::RtlAllocateMemory(NonPagedPool, size);
		auto free_kernel_buffer = std::experimental::make_scope_exit([=] {if (kernel_buffer)  utils::RtlFreeMemory(kernel_buffer); });
		if (!kernel_buffer) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//把shellcode复制到内核
		RtlZeroMemory(kernel_buffer, size);
		RtlCopyMemory(kernel_buffer, shellcode, size);

		//附加
		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);
		auto detach = std::experimental::make_scope_exit([&apc] {	KeUnstackDetachProcess(&apc); });

		//申请r3内存
		PVOID user_buffer = 0;
		SIZE_T region_size = size + PAGE_SIZE;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &user_buffer, 0, &region_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//把shellcode复制到r3
		char* shell_code_buffer = (char*)user_buffer + PAGE_SIZE;
		RtlZeroMemory(user_buffer, region_size);
		RtlCopyMemory(shell_code_buffer, kernel_buffer, size);

		//x86
		PVOID wow64 = PsGetProcessWow64Process(process);
		if (wow64) {
			uint8_t x86_buffer[]
			{
				0x60,									//60              pushad
				0xB8, 0x78, 0x56, 0x34, 0x12,			//B8 78563412     mov eax,12345678
				0x83, 0xEC, 0x40,						//83EC 40         sub esp,40
				0xFF, 0xD0,								//FFD0            call eax
				0x83, 0xC4, 0x40,						//83C4 40         add esp,40
				0xB8, 0x78, 0x56, 0x34, 0x12,			//B8 78563412     mov eax,12345678
				0xC7, 0x00,	0x01, 0x00, 0x00,0x00,		//C700 01000000   mov dword ptr ds : [eax] ,1
				0x61,									//61              popad
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,		//FF25 00000000   jmp dword ptr ds:[0]
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			};
			char* teb = reinterpret_cast<char*>(PsGetThreadTeb(thread));
			PUCHAR context = (PUCHAR) * (PULONG64)(teb + 0x1488);
			*(uint32_t*)&x86_buffer[2] = (uint32_t)shell_code_buffer;										//shellcode
			*(uint32_t*)&x86_buffer[15] = ((uint32_t)user_buffer + 0x500);									//flags
			*(uint32_t*)&x86_buffer[32] = *(uint32_t*)(context + 0xbc);										//ret
			RtlCopyMemory(user_buffer, x86_buffer, sizeof(x86_buffer));										//注入
			*(uint32_t*)(context + 0xbc) = reinterpret_cast<uint32_t>(user_buffer);							//修改eip
		}
		else {
			uint8_t x64_buffer[] =
			{
				0x50,																				//push  rax
				0x51,																				//push  rcx
				0x52,																				//push  rdx
				0x53,																				//push  rbx
				0x55, 																				//push  rbp
				0x56, 																				//push  rsi
				0x57, 																				//push  rdi
				0x41, 0x50, 																		//push  r8
				0x41, 0x51, 																		//push  r9
				0x41, 0x52, 																		//push  r10
				0x41, 0x53, 																		//push  r11
				0x41, 0x54, 																		//push  r12
				0x41, 0x55, 																		//push  r13
				0x41, 0x56, 																		//push  r14
				0x41, 0x57, 																		//push  r15
				0x48, 0xB8, 0x99, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00,0x00, 							//mov  rax,0x0000012345678999
				0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 											//sub  rsp,0x00000000000000A8
				0xFF, 0xD0, 																		//call  rax
				0x48, 0x81, 0xC4, 0xA0, 0x00, 0x00, 0x00, 											//add  rsp,0x00000000000000A8
				0x41, 0x5F, 																		//pop  r15
				0x41, 0x5E,																			//pop  r14
				0x41, 0x5D, 																		//pop  r13
				0x41, 0x5C, 																		//pop  r12
				0x41, 0x5B, 																		//pop  r11
				0x41, 0x5A, 																		//pop  r10
				0x41, 0x59, 																		//pop  r9
				0x41, 0x58, 																		//pop  r8
				0x5F, 																				//pop  rdi
				0x5E, 																				//pop  rsi
				0x5D, 																				//pop  rbp
				0x5B, 																				//pop  rbx
				0x5A,																				//pop  rdx
				0x59, 																				//pop  rcx
				0x48, 0xB8, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00,							//mov  rax,0x0000000123456789
				0x48, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,											//mov  qword ptr ds:[rax],0x0000000000000001
				0x58, 																				//pop  rax
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	//jmp  qword ptr ds : [PCHunter64.00000001403ABA27]
			};

			PKTRAP_FRAME trap = *(PKTRAP_FRAME*)((char*)thread + GetTrapFrameOffset());		//线程
			*(uint64_t*)&x64_buffer[25] = (uint64_t)shell_code_buffer;						//shellcode
			*(uint64_t*)&x64_buffer[73] = (uint64_t)user_buffer + 0x500;					//falgs
			*(uint64_t*)&x64_buffer[95] = trap->Rip;										//ret
			RtlCopyMemory(user_buffer, x64_buffer, sizeof(x64_buffer));						//注入
			trap->Rip = (uint64_t)user_buffer;												//修改rip
		}

		//恢复线程
		status = routine::PsResumeThread(thread, nullptr);
		if (NT_SUCCESS(status)) {
			FreeMemory* fm = reinterpret_cast<FreeMemory*>(ExAllocatePool(NonPagedPool, sizeof(FreeMemory)));
			fm->pid = pid;
			fm->flags = reinterpret_cast<uint64_t>(user_buffer) + 0x500;
			fm->base = reinterpret_cast<uint64_t>(user_buffer);
			fm->size = region_size;
			ExInitializeWorkItem(&fm->item, WorkerRoutine, fm);
			ExQueueWorkItem(&fm->item, DelayedWorkQueue);
		}
		else {
			ZwFreeVirtualMemory(NtCurrentProcess(), &user_buffer, &region_size, MEM_RELEASE);
		}

#pragma warning(pop)
		return status;
	}

	NTSTATUS LoadLibrary_x64(HANDLE pid, void* filebuffer, size_t filesize, size_t imagesize)
	{
		if (pid == 0 || filebuffer == nullptr || filesize == 0 || imagesize == 0) {
			return STATUS_INVALID_PARAMETER;
		}

		//获取进程
		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//进程是否在运行
		status = PsGetProcessExitStatus(process);
		if (status != 0x103) {
			return STATUS_PROCESS_IS_TERMINATING;
		}

		//获取主线程
		PETHREAD  thread = routine::PsGetNextProcessThread(process, nullptr);
		auto dereference_thread = std::experimental::make_scope_exit([thread] {if (thread)ObDereferenceObject(thread); });
		if (thread == nullptr) {
			return STATUS_THREAD_NOT_IN_PROCESS;
		}

		//if (PsGetThreadExitStatus(thread) != 0x103){
		//	return STATUS_THREAD_IS_TERMINATING;
		//}

		//挂起线程
		status = routine::PsSuspendThread(thread, nullptr);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);
		auto detach = std::experimental::make_scope_exit([&apc] {	KeUnstackDetachProcess(&apc); });

		//dll文件内存
		void* library_file_buffer = nullptr;
		size_t library_file_buffer_size = filesize;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &library_file_buffer, 0, &library_file_buffer_size, MEM_COMMIT, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		//dll镜像内存
		void* library_image_buffer = nullptr;
		size_t library_image_buffer_size = imagesize;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &library_image_buffer, 0, &library_image_buffer_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &library_image_buffer, &library_image_buffer_size, MEM_RELEASE);
			return status;
		}

		//shellcode内存
		uint8_t* shell_code_buffer = nullptr;
		size_t shell_code_buffer_size = sizeof(MemLoadShellcode_x64) + PAGE_SIZE;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), (void**)&shell_code_buffer, 0, &shell_code_buffer_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &library_file_buffer, &library_file_buffer_size, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &library_image_buffer, &library_image_buffer_size, MEM_RELEASE);
			return status;
		}

		uint8_t* flags = shell_code_buffer + 0x500;
		uint8_t* load_shell_code = shell_code_buffer + PAGE_SIZE;

		RtlZeroMemory(library_image_buffer, library_image_buffer_size);

		//把dll文件复制到进程
		RtlZeroMemory(library_file_buffer, library_file_buffer_size);
		RtlCopyMemory(library_file_buffer, filebuffer, filesize);

		//把shellcode复制到进程
		RtlZeroMemory(shell_code_buffer, shell_code_buffer_size);
		RtlCopyMemory(load_shell_code, MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64));

		uint8_t x64_buffer[] =
		{
			0x50,																				//push  rax
			0x51,																				//push  rcx
			0x52,																				//push  rdx
			0x53,																				//push  rbx
			0x55, 																				//push  rbp
			0x56, 																				//push  rsi
			0x57, 																				//push  rdi
			0x41, 0x50, 																		//push  r8
			0x41, 0x51, 																		//push  r9
			0x41, 0x52, 																		//push  r10
			0x41, 0x53, 																		//push  r11
			0x41, 0x54, 																		//push  r12
			0x41, 0x55, 																		//push  r13
			0x41, 0x56, 																		//push  r14
			0x41, 0x57, 																		//push  r15
			0x48, 0xB8, 0x99, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00,0x00, 							//mov  rax,0x0000012345678999
			0x48, 0xB9, 0x99, 0x99, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00,							//mov  rcx,0x0000012345678999
			0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 											//sub  rsp,0x00000000000000A8
			0xFF, 0xD0, 																		//call rax
			0x48, 0x81, 0xC4, 0xA0, 0x00, 0x00, 0x00, 											//add  rsp,0x00000000000000A8
			0x41, 0x5F, 																		//pop  r15
			0x41, 0x5E,																			//pop  r14
			0x41, 0x5D, 																		//pop  r13
			0x41, 0x5C, 																		//pop  r12
			0x41, 0x5B, 																		//pop  r11
			0x41, 0x5A, 																		//pop  r10
			0x41, 0x59, 																		//pop  r9
			0x41, 0x58, 																		//pop  r8
			0x5F, 																				//pop  rdi
			0x5E, 																				//pop  rsi
			0x5D, 																				//pop  rbp
			0x5B, 																				//pop  rbx
			0x5A,																				//pop  rdx
			0x59, 																				//pop  rcx
			0x48, 0xB8, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00,							//mov  rax,0x0000000123456789
			0x48, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,											//mov  qword ptr ds:[rax],0x0000000000000001
			0x58, 																				//pop  rax
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	//jmp  qword ptr ds : [PCHunter64.00000001403ABA27]
		};

		PKTRAP_FRAME trap = *(PKTRAP_FRAME*)((char*)thread + GetTrapFrameOffset());		//线程
		load_shell_code[0x50f] = 0x90;
		load_shell_code[0x510] = 0x48;
		load_shell_code[0x511] = 0xb8;
		*(uint64_t*)&load_shell_code[0x512] = (uint64_t)library_image_buffer;
		*(uint64_t*)&x64_buffer[25] = (uint64_t)load_shell_code;						//shellcode
		*(uint64_t*)&x64_buffer[35] = (uint64_t)library_file_buffer;					//dll文件
		*(uint64_t*)&x64_buffer[83] = (uint64_t)flags;									//falgs
		*(uint64_t*)&x64_buffer[105] = trap->Rip;										//ret
		RtlCopyMemory(shell_code_buffer, x64_buffer, sizeof(x64_buffer));				//注入
		trap->Rip = (uint64_t)shell_code_buffer;										//修改rip

		//恢复线程
		status = routine::PsResumeThread(thread, nullptr);
		if (!NT_SUCCESS(status)) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &library_file_buffer, &library_file_buffer_size, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &library_image_buffer, &library_image_buffer_size, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&shell_code_buffer, &shell_code_buffer_size, MEM_RELEASE);
			return status;
		}

		LOG_INFO("imagebuffer: %llx", library_image_buffer);

		LARGE_INTEGER time{ .QuadPart = 10 * -10000 };
		uint64_t complete = 0;
		boolean success = true;

		for (int i = 0; i < 10000; i++) {
			if (PsGetProcessExitStatus(process) != 0x103) {
				return STATUS_PROCESS_IS_TERMINATING;
			}
			//读取标记
			RtlCopyMemory(&complete, flags, 8);
			if (complete == 1) {
				success = true;
				break;
			}
			KeDelayExecutionThread(KernelMode, false, &time);
		}

		if (success) {
			//隐藏内存
			status = memory::MemoryUtils::get_instance()->HideMemory(library_image_buffer, library_image_buffer_size);
			if (!NT_SUCCESS(status)) {
				ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&library_image_buffer, &library_image_buffer_size, MEM_RELEASE);
			}
		}
		else {
			ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&library_image_buffer, &library_image_buffer_size, MEM_RELEASE);
		}

		//释放内存
		ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&library_file_buffer, &library_file_buffer_size, MEM_RELEASE);
		ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&shell_code_buffer, &shell_code_buffer_size, MEM_RELEASE);
		return status;
	}

	NTSTATUS LoadLibrary_x86(HANDLE pid, void* filebuffer, size_t filesize, size_t imagesize)
	{
		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		if (!NT_SUCCESS(status)) {
			return status;
		}

		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);
		auto detach = std::experimental::make_scope_exit([&apc] {	KeUnstackDetachProcess(&apc); });

		//文件内存
		size_t regionsize = filesize;
		void* filebase = nullptr;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &filebase, 0, &regionsize, MEM_COMMIT, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			KeUnstackDetachProcess(&apc);
			return status;
		}

		//运行内存
		size_t image_region = imagesize;
		void* imagebuffer = nullptr;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &imagebuffer, 0, &image_region, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &filebase, &regionsize, MEM_RELEASE);
			KeUnstackDetachProcess(&apc);
			return status;
		}

		//shellcode内存
		size_t shellcode_region_size = sizeof(MemLoadShellcode_x86);
		uint8_t* shellcodebuffer = nullptr;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), (void**)&shellcodebuffer, 0, &shellcode_region_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &filebase, &regionsize, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &imagebuffer, &image_region, MEM_RELEASE);
			KeUnstackDetachProcess(&apc);
			return status;
		}

		RtlZeroMemory(imagebuffer, imagesize);

		RtlZeroMemory(filebase, regionsize);
		RtlCopyMemory(filebase, filebuffer, filesize);

		RtlZeroMemory(shellcodebuffer, shellcode_region_size);
		RtlCopyMemory(shellcodebuffer, MemLoadShellcode_x86, sizeof(MemLoadShellcode_x86));

#pragma warning(push)
#pragma warning(disable:4311)
#pragma warning(disable:4302)
		shellcodebuffer[0x337] = 0x90;
		shellcodebuffer[0x338] = 0x90;
		shellcodebuffer[0x339] = 0x90;
		shellcodebuffer[0x33a] = 0x90;
		shellcodebuffer[0x33b] = 0x90;
		shellcodebuffer[0x33c] = 0x90;
		shellcodebuffer[0x33d] = 0x90;
		shellcodebuffer[0x33e] = 0x90;
		shellcodebuffer[0x33f] = 0x90;
		shellcodebuffer[0x340] = 0x90;
		shellcodebuffer[0x341] = 0x90;
		shellcodebuffer[0x342] = 0x90;
		shellcodebuffer[0x343] = 0x90;
		shellcodebuffer[0x344] = 0x90;
		shellcodebuffer[0x345] = 0x90;
		shellcodebuffer[0x346] = 0x90;
		shellcodebuffer[0x347] = 0x90;
		shellcodebuffer[0x348] = 0x90;
		shellcodebuffer[0x349] = 0x90;
		shellcodebuffer[0x337] = 0xb8;
		*(uint32_t*)&shellcodebuffer[0x338] = (uint32_t)imagebuffer;

#pragma warning(pop)

		HANDLE hthread = nullptr;
		auto hthread_close = std::experimental::make_scope_exit([hthread] {if (hthread)ZwClose(hthread); });
		status = routine::ZwCreateThreadEx(&hthread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), shellcodebuffer, filebase, 0, 0, 0x100000, 0x200000, NULL);
		if (!NT_SUCCESS(status)) {
			ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&imagebuffer, &image_region, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &filebase, &regionsize, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&shellcodebuffer, &shellcode_region_size, MEM_RELEASE);
		}

		PETHREAD thread = nullptr;
		auto dereference_thread = std::experimental::make_scope_exit([thread] {if (thread)ObDereferenceObject(thread); });
		status = ObReferenceObjectByHandle(hthread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (void**)&thread, NULL);
		if (!NT_SUCCESS(status)) {
			ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&imagebuffer, &image_region, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &filebase, &regionsize, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&shellcodebuffer, &shellcode_region_size, MEM_RELEASE);
		}

		KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);

		//隐藏内存
		status = memory::MemoryUtils::get_instance()->HideMemory(imagebuffer, image_region);
		if (!NT_SUCCESS(status)) {
			ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&imagebuffer, &image_region, MEM_RELEASE);
		}

		//隐藏线程
		uint64_t ModuleAddress = (uint64_t)PsGetProcessSectionBaseAddress(process);
		uint64_t StartAddresOffset = GetStartAddressOffset();
		uint64_t Win32StartAddresOffset = GetWin32StartAddressOffset();
		PLIST_ENTRY ThreadList = (PLIST_ENTRY)((PUCHAR)thread + GetThreadListOffset());
		if (ModuleAddress && StartAddresOffset && Win32StartAddresOffset && ThreadList) {
			*(PULONG64)((PUCHAR)thread + StartAddresOffset) = ModuleAddress + 1000;
			*(PULONG64)((PUCHAR)thread + Win32StartAddresOffset) = ModuleAddress + 2000;
			RemoveEntryList(ThreadList);
			InitializeListHead(ThreadList);
		}

		ZwFreeVirtualMemory(NtCurrentProcess(), &filebase, &regionsize, MEM_RELEASE);
		ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&shellcodebuffer, &shellcode_region_size, MEM_RELEASE);
		return status;
	}

	NTSTATUS RemoveProcessEntryList(HANDLE pid)
	{
		//取进程对象
		PEPROCESS process = nullptr;
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = PsGetProcessExitStatus(process);
		if (status != 0x103) {
			ObDereferenceObject(process);
			return status;
		}

		LOG_INFO("RemoveProcessEntryList\n");

		auto version = Version::get_instance();
		if (version->Windows_7()) {
			//ActiveProcessLinks
			uint64_t ActiveProcessLinksOffset = 0x188;
			PLIST_ENTRY list = (PLIST_ENTRY)((char*)process + ActiveProcessLinksOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ProcessListEntry
			uint64_t ProcessListEntryOffset = 0xe0;
			list = (PLIST_ENTRY)((char*)process + ProcessListEntryOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ObjectTable
			uint64_t ObjectTableOffset = 0x200;
			char* ObjectTable = (char*)*(void**)((char*)process + ObjectTableOffset);

			//HandleTableList
			uint64_t HandleTableListOffset = 0x20;
			list = (PLIST_ENTRY)((char*)ObjectTable + HandleTableListOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ExpLookupHandleTableEntry
			//PspCidTable
			UNICODE_STRING name{};
			RtlInitUnicodeString(&name, L"PsLookupProcessByProcessId");
			unsigned __int8* temp = (unsigned __int8*)MmGetSystemRoutineAddress(&name);
			LARGE_INTEGER result{};
			for (int i = 0; temp[i] != 0xc3; i++) {
				if (temp[i] == 0x48 && temp[i + 1] == 0x8b && temp[i + 2] == 0x0d) {
					result.QuadPart = (LONGLONG)temp + i + 7;
					result.LowPart += *(PULONG)(temp + i + 3);
					break;
				}
			}
			PVOID PspCidTable = reinterpret_cast<PVOID>(result.QuadPart);
			LOG_INFO("PspCidTable: %llx", PspCidTable);
			PVOID entry = routine::ExpLookupHandleTableEntry(PspCidTable, pid);
			if (MmIsAddressValid(entry)) {
				RtlZeroMemory(entry, sizeof(entry));
				uint64_t UniqueProcessIdOffset = 0x180;
				*(PHANDLE)((char*)process + UniqueProcessIdOffset) = 0;
			}
		}
		else {
			analysis::Pdber* ntos = analysis::Ntoskrnl();
			//ActiveProcessLinks
			uint64_t ActiveProcessLinksOffset = ntos->GetOffset("_EPROCESS", "ActiveProcessLinks");
			PLIST_ENTRY list = (PLIST_ENTRY)((char*)process + ActiveProcessLinksOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ProcessListEntry
			uint64_t ProcessListEntryOffset = ntos->GetOffset("_KPROCESS", "ProcessListEntry");
			list = (PLIST_ENTRY)((char*)process + ProcessListEntryOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//ObjectTable
			uint64_t ObjectTableOffset = ntos->GetOffset("_EPROCESS", "ObjectTable");
			char* ObjectTable = (char*)*(void**)((char*)process + ObjectTableOffset);

			//HandleTableList
			uint64_t HandleTableListOffset = ntos->GetOffset("_HANDLE_TABLE", "HandleTableList");
			list = (PLIST_ENTRY)((char*)ObjectTable + HandleTableListOffset);
			RemoveEntryList(list);
			InitializeListHead(list);

			//PspCidTable
			PVOID PspCidTable = reinterpret_cast<PVOID>(ntos->GetPointer("PspCidTable"));
			PVOID entry = routine::ExpLookupHandleTableEntry(PspCidTable, pid);
			if (MmIsAddressValid(entry)) {
				RtlZeroMemory(entry, sizeof(entry));
				uint64_t UniqueProcessIdOffset = ntos->GetOffset("_EPROCESS", "UniqueProcessId");
				*(PHANDLE)((char*)process + UniqueProcessIdOffset) = 0;
			}
		}

		ObDereferenceObject(process);
		return status;
	}

	NTSTATUS AllocateMemory(HANDLE pid, void** address, size_t size, uint32_t protect)
	{
		//获取进程
		PEPROCESS process = nullptr;
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (PsGetProcessExitStatus(process) != 0x103) {
			return STATUS_PROCESS_IS_TERMINATING;
		}

		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);

		void* allocate_base = nullptr;
		size_t region_size = size;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &allocate_base, 0, &region_size, MEM_COMMIT, protect);
		if (NT_SUCCESS(status)) {
			RtlZeroMemory(allocate_base, size);
		}

		KeUnstackDetachProcess(&apc);

		if (NT_SUCCESS(status) && address) {
			*address = allocate_base;
		}
		return status;
	}

	NTSTATUS FreeProcessMemory(HANDLE pid, void* address, size_t size)
	{
		PEPROCESS process = nullptr;
		auto dereference_process = std::experimental::make_scope_exit([process] {if (process)ObDereferenceObject(process); });
		auto status = PsLookupProcessByProcessId(pid, &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (PsGetProcessExitStatus(process) != 0x103) {
			return STATUS_PROCESS_IS_TERMINATING;
		}

		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);

		void* allocate_base = address;
		size_t region_size = size;
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &allocate_base, &region_size, MEM_RELEASE);

		KeUnstackDetachProcess(&apc);
		return status;
	}

	NTSTATUS TerminateProcess(HANDLE pid)
	{
		CLIENT_ID clientid{  };
		clientid.UniqueProcess = pid;

		OBJECT_ATTRIBUTES attribute{  };
		attribute.Length = sizeof(OBJECT_ATTRIBUTES);

		HANDLE handle = nullptr;
		auto status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &attribute, &clientid);
		if (!NT_SUCCESS(status) || !handle) {
			return status;
		}

		status = ZwTerminateProcess(handle, STATUS_SUCCESS);
		ZwClose(handle);
		return status;
	}

	/*----------------------------------------获取前置窗口-------------------------------------*/
	uint64_t GetZwUserGetForegroundWindowAddress()
	{
		static uint64_t address = 0;
		if (address == 0) {
			PEPROCESS process = nullptr;
			auto status = utils::LookupProcessByImageFileName("explorer.exe", &process);
			if (NT_SUCCESS(status)) {
				KAPC_STATE apc{};
				KeStackAttachProcess(process, &apc);
				auto version = Version::get_instance();
				if (version->Windows_7()) {
					SearchUtils search;
					address = (unsigned __int64)search.pattern("win32k.sys", ".text", "4889***5748***48******FF15****4C******33DB4C3BDB74*4939**74*498B**FF15****488B**4839*****75*488B1F");
				}
				else {
					analysis::Pdber* win32 = analysis::Win32k();
					address = win32->GetPointer("NtUserGetForegroundWindow");
				}
				LOG_DEBUG("%llx", address);
				KeUnstackDetachProcess(&apc);
				ObDereferenceObject(process);
			}
		}

		return address;
	}

	PVOID NtUserGetForegroundWindow()
	{
		typedef PVOID(NTAPI* NtUserGetForegroundWindowProc)(VOID);
		NtUserGetForegroundWindowProc proc = reinterpret_cast<NtUserGetForegroundWindowProc>(GetZwUserGetForegroundWindowAddress());

		PVOID hwnd = proc();

		auto collection = GetGlobalVector();
		auto cmp = [hwnd](uint64_t WindowsHandle) {return reinterpret_cast<uint64_t>(hwnd) == WindowsHandle; };
		if (find_if(collection->begin(), collection->end(), cmp) != collection->end()) {
			return NULL;
		}

		return hwnd;
	}

	/*----------------------------------------根据坐标获取窗口-------------------------------------*/
	uint64_t GetZwUserWindowFromPointAddress()
	{
		static uint64_t address = 0;
		if (address == 0) {
			PEPROCESS process = nullptr;
			auto status = utils::LookupProcessByImageFileName("explorer.exe", &process);
			if (NT_SUCCESS(status)) {
				KAPC_STATE apc{};
				KeStackAttachProcess(process, &apc);
				auto version = Version::get_instance();
				if (version->Windows_7()) {
					SearchUtils search;
					address = (unsigned __int64)search.pattern("win32k.sys", ".text", "4889***4889***5748***48******FF15****C6******48******E8****");
				}
				else {
					analysis::Pdber* win32 = analysis::Win32k();
					address = win32->GetPointer("NtUserWindowFromPoint");
				}
				LOG_DEBUG("%llx", address);
				KeUnstackDetachProcess(&apc);
				ObDereferenceObject(process);
			}
		}

		return address;
	}

	PVOID NtUserWindowFromPoint(PVOID Point)
	{
		typedef PVOID(NTAPI* NtUserWindowFromPointProc)(PVOID Point);
		NtUserWindowFromPointProc proc = reinterpret_cast<NtUserWindowFromPointProc>(GetZwUserWindowFromPointAddress());
		PVOID hwnd = proc(Point);

		auto collection = GetGlobalVector();
		auto cmp = [hwnd](uint64_t WindowsHandle) {return reinterpret_cast<uint64_t>(hwnd) == WindowsHandle; };
		if (find_if(collection->begin(), collection->end(), cmp) != collection->end()) {
			return NULL;
		}
		return hwnd;
	}

	/*----------------------------------------遍历窗口-------------------------------------*/
	uint64_t GetNtUserBuildHwndListAddress()
	{
		static uint64_t address = 0;
		if (address == 0) {
			PEPROCESS process = nullptr;
			auto status = utils::LookupProcessByImageFileName("explorer.exe", &process);
			if (NT_SUCCESS(status)) {
				KAPC_STATE apc{};
				KeStackAttachProcess(process, &apc);
				auto version = Version::get_instance();
				if (version->Windows_7()) {
					SearchUtils search;
					address = (unsigned __int64)search.pattern("win32k.sys", ".text", "4889***4889***4889***41544155415648***418BD9458BF0488BFA488BF14533E4458D***48******FF15****");
				}
				else {
					analysis::Pdber* win32 = analysis::Win32k();
					address = win32->GetPointer("NtUserBuildHwndList");
				}
				KeUnstackDetachProcess(&apc);
				ObDereferenceObject(process);
			}
		}
		return address;
	}

#pragma  warning(push)
#pragma warning(disable:4702)

	NTSTATUS NtUserBuildHwndList(PVOID a1, PVOID a2, PVOID Address, unsigned int a4, ULONG count, PVOID Addressa, PULONG pretCount)
	{
		typedef NTSTATUS(NTAPI* MyNtUserBuildHwndListProc)(PVOID a1, PVOID a2, PVOID Address, unsigned int a4, ULONG count, PVOID Addressa, PULONG pretCount);
		MyNtUserBuildHwndListProc 	proc = reinterpret_cast<MyNtUserBuildHwndListProc>(GetNtUserBuildHwndListAddress());
		NTSTATUS status = proc(a1, a2, Address, a4, count, Addressa, pretCount);

		if (!NT_SUCCESS(status)) {
			return status;
		}

		if (!MmIsAddressValid(pretCount) || !MmIsAddressValid(Addressa)) {
			return status;
		}

		int scount = *pretCount;//数组大小
		PVOID* arrays = reinterpret_cast<PVOID*>(Addressa);	//窗口句柄数组

		for (int i = 0; i < scount; i++)
		{
			PVOID Hwnd = arrays[i];//窗口句柄
			auto collection = GetGlobalVector();
			auto cmp = [Hwnd](uint64_t WindowsHandle) {return reinterpret_cast<uint64_t>(Hwnd) == WindowsHandle; };
			if (find_if(collection->begin(), collection->end(), cmp) != collection->end()) {
				return status;
			}
			//找到了
			if (i == 0)
			{
				if (scount == 1)
				{
					arrays[i] = 0;
					*pretCount = 0;
					break;
				}
				arrays[i] = arrays[i + 1];
				break;
			}
			else
			{
				arrays[i] = arrays[i - 1];
				break;
			}
		}
		return status;
	}
#pragma warning(pop)

	/*----------------------------------------查询窗口-------------------------------------*/
	uint64_t GetNtUserQueryWindowAddress()
	{
		static uint64_t address = 0;
		if (address == 0) {
			PEPROCESS process = nullptr;
			auto status = utils::LookupProcessByImageFileName("explorer.exe", &process);
			if (NT_SUCCESS(status)) {
				KAPC_STATE apc{};
				KeStackAttachProcess(process, &apc);
				auto version = Version::get_instance();
				if (version->Windows_7()) {
					SearchUtils search;
					address = (unsigned __int64)search.pattern("win32k.sys", ".text", "4889***5748***488BD948******8BFAFF15****488BCBE8****488BD84885C075*");
				}
				else {
					analysis::Pdber* win32 = analysis::Win32k();
					address = win32->GetPointer("NtUserQueryWindow");
				}
				LOG_DEBUG("%llx", address);
				KeUnstackDetachProcess(&apc);
				ObDereferenceObject(process);
			}
		}
		return address;
	}

	uint64_t NtUserQueryWindow(IN PVOID hwnd, IN ULONG TypeInformation)
	{
		typedef uint64_t(NTAPI* MyNtUserQueryWindowProc)(PVOID Hwnd, int flags);
		MyNtUserQueryWindowProc proc = (MyNtUserQueryWindowProc)GetNtUserQueryWindowAddress();

		auto collection = GetGlobalVector();
		auto cmp = [hwnd](uint64_t WindowsHandle) {return reinterpret_cast<uint64_t>(hwnd) == WindowsHandle; };
		if (find_if(collection->begin(), collection->end(), cmp) != collection->end()) {
			return NULL;
		}
		return proc(hwnd, TypeInformation);
	}

	/*----------------------------------------查找窗口-------------------------------------*/
	uint64_t GetNtUserFindWindowExAddress()
	{
		static uint64_t address = 0;
		if (address == 0) {
			PEPROCESS process = nullptr;
			auto status = utils::LookupProcessByImageFileName("explorer.exe", &process);
			if (NT_SUCCESS(status)) {
				KAPC_STATE apc{};
				KeStackAttachProcess(process, &apc);
				auto version = Version::get_instance();
				if (version->Windows_7()) {
					SearchUtils search;
					address = (unsigned __int64)search.pattern("win32k.sys", ".text", "488BC44889**4889**4889**4C89**415548***4D8BE94D8BE0488BF2488BF948******FF15****");
				}
				else {
					analysis::Pdber* win32 = analysis::Win32k();
					address = win32->GetPointer("NtUserFindWindowEx");
				}
				LOG_DEBUG("%llx", address);
				KeUnstackDetachProcess(&apc);
				ObDereferenceObject(process);
			}
		}
		return address;
	}

	PVOID NtUserFindWindowEx(
		IN HWND hwndParent,
		IN HWND hwndChild,
		IN PUNICODE_STRING pstrClassName OPTIONAL,
		IN PUNICODE_STRING pstrWindowName OPTIONAL,
		IN DWORD dwType
	)
	{
		typedef PVOID(NTAPI* MyUserFindWindowExProc)(
			IN HWND hwndParent,
			IN HWND hwndChild,
			IN PUNICODE_STRING pstrClassName OPTIONAL,
			IN PUNICODE_STRING pstrWindowName OPTIONAL,
			IN DWORD dwType
			);
		MyUserFindWindowExProc proc = reinterpret_cast<MyUserFindWindowExProc>(GetNtUserFindWindowExAddress());
		PVOID hwnd = proc(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);

		auto collection = GetGlobalVector();
		auto cmp = [hwnd](uint64_t WindowsHandle) {return reinterpret_cast<uint64_t>(hwnd) == WindowsHandle; };
		if (find_if(collection->begin(), collection->end(), cmp) != collection->end()) {
			return NULL;
		}
		return hwnd;
	}

	void WindowProtected(
		_In_ unsigned long SystemCallIndex,
		_Inout_ void** SystemCallFunction
	)
	{
		if (reinterpret_cast<uint64_t>(*SystemCallFunction) == GetZwUserGetForegroundWindowAddress()) {
			*SystemCallFunction = NtUserGetForegroundWindow;
		}
		else if (reinterpret_cast<uint64_t>(*SystemCallFunction) == GetZwUserWindowFromPointAddress()) {
			*SystemCallFunction = NtUserWindowFromPoint;
		}
		else if (reinterpret_cast<uint64_t>(*SystemCallFunction) == GetNtUserBuildHwndListAddress()) {
			*SystemCallFunction = NtUserBuildHwndList;
		}
		else if (reinterpret_cast<uint64_t>(*SystemCallFunction) == GetNtUserQueryWindowAddress()) {
			*SystemCallFunction = NtUserQueryWindow;
		}
		else if (reinterpret_cast<uint64_t>(*SystemCallFunction) == GetNtUserFindWindowExAddress()) {
			*SystemCallFunction = NtUserFindWindowEx;
		}
		_Unreferenced_parameter_(SystemCallIndex);
	}
};