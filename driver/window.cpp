#include "window.h"
#include "global.h"
#include "utils/utils.h"
#include "utils/search.h"
#include "utils/version.hpp"

typedef BOOL(__fastcall* GreProtectSpriteContentProc)(LPVOID, HWND, INT, UINT);

BOOL AntiScreenShot(HWND hwnd)
{
	BOOL success = false;
	PEPROCESS process = nullptr;
	auto status = utils::LookupProcessByImageFileName("explorer.exe", &process);
	if (NT_SUCCESS(status)) {
		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);
		unsigned __int64 address = 0;
		auto version = Version::get_instance();
		if (version->Windows_7()) {
			SearchUtils search;
			address = (unsigned __int64)search.pattern("win32k.sys", ".text", "4889***4889***565741544155415648***4533F6418BD9488BFA4585C00F*****");
		}
		else {
			analysis::Pdber* win32kfull = analysis::Win32kfull();
			address = win32kfull->GetPointer("GreProtectSpriteContent");
		}

		if (address) {
			GreProtectSpriteContentProc proc = (GreProtectSpriteContentProc)address;
			success = proc(NULL, hwnd, TRUE, 0x00000011);
		}
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(process);
	}
	return success;
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