#include "call.h"
#include "pdb/analysis.h"
#include "utils/utils.h"
#include "utils/memory.hpp"
#include "utils/process.hpp"
#include "utils/MemLoadDll.h"

//0x70 bytes (sizeof)
typedef struct _FLOATING_SAVE_AREA
{
	ULONG ControlWord;                                                      //0x0
	ULONG StatusWord;                                                       //0x4
	ULONG TagWord;                                                          //0x8
	ULONG ErrorOffset;                                                      //0xc
	ULONG ErrorSelector;                                                    //0x10
	ULONG DataOffset;                                                       //0x14
	ULONG DataSelector;                                                     //0x18
	UCHAR RegisterArea[80];                                                 //0x1c
	ULONG Spare0;                                                           //0x6c
}FLOATING_SAVE_AREA;

typedef struct _CONTEXT_x86
{
	ULONG ContextFlags;                                                     //0x0
	ULONG Dr0;                                                              //0x4
	ULONG Dr1;                                                              //0x8
	ULONG Dr2;                                                              //0xc
	ULONG Dr3;                                                              //0x10
	ULONG Dr6;                                                              //0x14
	ULONG Dr7;                                                              //0x18
	FLOATING_SAVE_AREA FloatSave;											//0x1c
	ULONG SegGs;                                                            //0x8c
	ULONG SegFs;                                                            //0x90
	ULONG SegEs;                                                            //0x94
	ULONG SegDs;                                                            //0x98
	ULONG Edi;                                                              //0x9c
	ULONG Esi;                                                              //0xa0
	ULONG Ebx;                                                              //0xa4
	ULONG Edx;                                                              //0xa8
	ULONG Ecx;                                                              //0xac
	ULONG Eax;                                                              //0xb0
	ULONG Ebp;                                                              //0xb4
	ULONG Eip;                                                              //0xb8
	ULONG SegCs;                                                            //0xbc
	ULONG EFlags;                                                           //0xc0
	ULONG Esp;                                                              //0xc4
	ULONG SegSs;                                                            //0xc8
	UCHAR ExtendedRegisters[512];                                           //0xcc
}CONTEXT_x86;
//*(*(teb + 1488)+4) CONTEXT

struct FreeMemory
{
	WORK_QUEUE_ITEM item;
	HANDLE pid;
	uint64_t base;
	uint64_t flags;
	size_t size;
};

typedef
PETHREAD
(*PsGetNextProcessThreadProc)(
	IN PEPROCESS Process,
	IN PETHREAD Thread
	);

typedef
NTSTATUS
(*PsSuspendThreadProc)(
	IN PETHREAD Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

typedef
NTSTATUS
(*PsResumeThreadProc)(
	IN PETHREAD Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

PETHREAD
PsGetNextProcessThread(
	IN PEPROCESS Process,
	IN PETHREAD Thread
)
{
	static PsGetNextProcessThreadProc proc = nullptr;
	if (proc == nullptr) {
		analysis::Pdber* ntos = analysis::Ntoskrnl();
		proc = reinterpret_cast<PsGetNextProcessThreadProc>(ntos->GetPointer("PsGetNextProcessThread"));
		LOG_INFO("proc: %llx", proc);
	}
	return proc(Process, Thread);
}

NTSTATUS
PsSuspendThread(
	IN PETHREAD Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
)
{
	static PsSuspendThreadProc proc = nullptr;

	if (proc == nullptr) {
		analysis::Pdber* ntos = analysis::Ntoskrnl();
		proc = reinterpret_cast<PsSuspendThreadProc>(ntos->GetPointer("PsSuspendThread"));
		LOG_INFO("proc: %llx", proc);
	}
	return proc(Thread, PreviousSuspendCount);
}

NTSTATUS
PsResumeThread(
	IN PETHREAD Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL
)
{
	static PsResumeThreadProc proc = nullptr;

	if (proc == nullptr) {
		analysis::Pdber* ntos = analysis::Ntoskrnl();
		proc = reinterpret_cast<PsResumeThreadProc>(ntos->GetPointer("PsResumeThread"));
		LOG_INFO("proc: %llx", proc);
	}
	return proc(Thread, PreviousSuspendCount);
}

uint64_t GetTrapFrameOffset()
{
	static uint64_t offset = 0;
	if (offset == 0) {
		analysis::Pdber* ntos = analysis::Ntoskrnl();
		offset = ntos->GetOffset("_KTHREAD", "TrapFrame");
		LOG_INFO("offset: %llx", offset);
	}
	return offset;
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
	PETHREAD  thread = PsGetNextProcessThread(process, nullptr);
	auto dereference_thread = std::experimental::make_scope_exit([thread] {if (thread)ObDereferenceObject(thread); });
	if (thread == nullptr) {
		return STATUS_THREAD_NOT_IN_PROCESS;
	}

	if (PsGetThreadExitStatus(thread) != 0x103)
	{
		return STATUS_THREAD_IS_TERMINATING;
	}

	//挂起线程
	status = PsSuspendThread(thread, nullptr);
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
		CONTEXT_x86* context = reinterpret_cast<CONTEXT_x86*>(((char*)*(uint64_t*)(teb + 0x1488) + 4));	//wow64 context
		*(uint32_t*)&x86_buffer[2] = (uint32_t)shell_code_buffer;										//shellcode
		*(uint32_t*)&x86_buffer[15] = ((uint32_t)user_buffer + 0x500);									//flags
		*(uint32_t*)&x86_buffer[32] = context->Eip;														//ret
		RtlCopyMemory(user_buffer, x86_buffer, sizeof(x86_buffer));										//注入
		context->Eip = reinterpret_cast<uint32_t>(user_buffer);											//修改eip
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
	status = PsResumeThread(thread, nullptr);
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
	PETHREAD  thread = PsGetNextProcessThread(process, nullptr);
	auto dereference_thread = std::experimental::make_scope_exit([thread] {if (thread)ObDereferenceObject(thread); });
	if (thread == nullptr) {
		return STATUS_THREAD_NOT_IN_PROCESS;
	}

	if (PsGetThreadExitStatus(thread) != 0x103)
	{
		return STATUS_THREAD_IS_TERMINATING;
	}

	//挂起线程
	status = PsSuspendThread(thread, nullptr);
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
	status = PsResumeThread(thread, nullptr);
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