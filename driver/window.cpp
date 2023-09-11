#include "window.h"
#include "utils/utils.h"

typedef BOOL(__fastcall* GreProtectSpriteContentProc)(LPVOID, HWND, INT, UINT);

boolean AntiScreenShot(HWND hwnd)
{
	boolean success = false;
	PEPROCESS process = nullptr;
	auto status = utils::LookupProcessByImageFileName("explorer.exe", &process);
	if (NT_SUCCESS(status)) {
		KAPC_STATE apc{};
		KeStackAttachProcess(process, &apc);
		analysis::Pdber* win32kfull = analysis::Win32kfull();
		auto address = win32kfull->GetPointer("GreProtectSpriteContent");
		if (address) {
			GreProtectSpriteContentProc proc = (GreProtectSpriteContentProc)address;
			success = proc(NULL, hwnd, TRUE, 0x00000011);
		}
		KeUnstackDetachProcess(&apc);
	}
	return success;
}