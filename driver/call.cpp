#include "call.h"
#include "pdb/oxygenPdb.h"

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
		oxygenPdb::Pdber ntos(L"ntoskrnl.exe"); ntos.init();
		proc = reinterpret_cast<PsGetNextProcessThreadProc>(ntos.GetPointer("PsGetNextProcessThread"));
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
		oxygenPdb::Pdber ntos(L"ntoskrnl.exe"); ntos.init();
		proc = reinterpret_cast<PsSuspendThreadProc>(ntos.GetPointer("PsSuspendThread"));
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
		oxygenPdb::Pdber ntos(L"ntoskrnl.exe"); ntos.init();
		proc = reinterpret_cast<PsResumeThreadProc>(ntos.GetPointer("PsResumeThread"));
		LOG_INFO("proc: %llx", proc);
	}
	return proc(Thread, PreviousSuspendCount);
}

uint64_t GetTrapFrameOffset()
{
	static uint64_t offset = 0;
	if (offset == 0) {
		oxygenPdb::Pdber ntos(L"ntoskrnl.exe"); ntos.init();
		offset = ntos.GetOffset("_KTHREAD", "TrapFrame");
		LOG_INFO("offset: %llx", offset);
	}
	return offset;
}

VOID WorkerRoutine(
	_In_ PVOID Parameter
)
{
	FreeMemory* fm = reinterpret_cast<FreeMemory*>(Parameter);

	PEPROCESS process = nullptr;
	auto status = PsLookupProcessByProcessId(fm->pid, &process);
	if (!NT_SUCCESS(status)) {
		return;
	}
	auto dereference_process = make_scope_exit([process] {ObDereferenceObject(process); });

	uint64_t flags = 0;
	size_t returned_bytes = 0;
	boolean success = true;
	int count = 0;

	while (1) {
		if (count > 10000) {
			break;
		}
		status = MmCopyVirtualMemory(process, (PVOID)fm->flags, IoGetCurrentProcess(), &flags, 8, KernelMode, &returned_bytes);
		if (NT_SUCCESS(status) && flags == 1) {
			success = true;
			break;
		}

		LARGE_INTEGER inTime;
		inTime.QuadPart = 10 * -10000;
		KeDelayExecutionThread(KernelMode, false, &inTime);
		count++;
	}

	if (success) {
		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);
		ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&fm->base, &fm->size, MEM_RELEASE);
		ExFreePool(fm);
		KeUnstackDetachProcess(&apc);
	}
	return;
}

NTSTATUS RemoteCall(HANDLE pid, void* shellcode, size_t size)
{
	//��ȡ����
	PEPROCESS process = nullptr;
	auto status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	//�����Ƿ�������
	auto dereference_process = make_scope_exit([process] {ObDereferenceObject(process); });
	status = PsGetProcessExitStatus(process);
	if (status != 0x103) {
		return STATUS_PROCESS_IS_TERMINATING;
	}

	//��ȡ���߳�
	PETHREAD  thread = PsGetNextProcessThread(process, nullptr);
	if (thread == nullptr) {
		return STATUS_THREAD_IS_TERMINATING;
	}

	//�����߳�
	auto dereference_thread = make_scope_exit([thread] {ObDereferenceObject(thread); });
	status = PsSuspendThread(thread, nullptr);
	if (!NT_SUCCESS(status)) {
		return status;
	}

#pragma warning (push)
#pragma warning(disable:4996)
#pragma warning(disable:4311)
#pragma warning(disable:4302)

	//�����ں��ڴ�
	PVOID kernel_buffer = ExAllocatePool(NonPagedPool, size);
	if (!kernel_buffer) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	auto free_kernel_buffer = make_scope_exit([=] {if (kernel_buffer)ExFreePool(kernel_buffer); });

	//��shellcode���Ƶ��ں�
	RtlZeroMemory(kernel_buffer, size);
	RtlCopyMemory(kernel_buffer, shellcode, size);

	//����
	KAPC_STATE apc{};
	KeStackAttachProcess(process, &apc);

	//����r3�ڴ�
	PVOID user_buffer = 0;
	SIZE_T region_size = size + PAGE_SIZE;
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &user_buffer, 0, &region_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	//��shellcode���Ƶ�r3
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
		RtlCopyMemory(user_buffer, x86_buffer, sizeof(x86_buffer));										//ע��
		context->Eip = reinterpret_cast<uint32_t>(user_buffer);											//�޸�eip
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

		PKTRAP_FRAME trap = *(PKTRAP_FRAME*)((char*)thread + GetTrapFrameOffset());		//�߳�
		*(uint64_t*)&x64_buffer[25] = (uint64_t)shell_code_buffer;						//shellcode
		*(uint64_t*)&x64_buffer[73] = (uint64_t)user_buffer + 0x500;					//falgs
		*(uint64_t*)&x64_buffer[95] = trap->Rip;										//ret
		RtlCopyMemory(user_buffer, x64_buffer, sizeof(x64_buffer));						//ע��
		trap->Rip = (uint64_t)user_buffer;												//�޸�rip
	}

	//�ָ��߳�
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
#pragma warning(pop)
	KeUnstackDetachProcess(&apc);
	return status;
}