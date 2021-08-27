#include "winuser-hook.h"
#include "utils.h"
#include "commands.h"
#include <string>
#include <stdlib.h> 

int GetKeyboardTypeHook(
	int nTypeFlag
) {
	switch (nTypeFlag) {
		case 0: {
			std::string tag = GetTag("GetKeyboardType");
			Message("[W] GetKeyboardType (%i) -> tag_out: %s\n", nTypeFlag, tag.c_str());
			return S2ESymbolicInt(tag.c_str(), 0x4);
		}
		case 1:
			Message("[W] GetKeyboardType (%i) -> force_ret: %i\n", nTypeFlag, 0);
			// 0 is a valid return value when nTypeFlag is 1
			return 0;
		case 2: {
			std::string tag = GetTag("GetKeyboardType");
			Message("[W] GetKeyboardType (%i) -> tag_out: %s\n", nTypeFlag, tag.c_str());
			return S2ESymbolicInt(tag.c_str(), 0x4);
		}
	}

}

HKL GetKeyboardLayoutHook(
	DWORD idThread
) {
	std::string tag = GetTag("GetKeyboardLayout");
	LPCTSTR layout = L"";
	S2EMakeSymbolic((PVOID)layout, DEFAULT_MEM_LEN, tag.c_str());
	HKL symLayout = LoadKeyboardLayout(layout, KLF_SUBSTITUTE_OK);
	Message("[W] GetKeyboardLayout (%ld) -> tag_out: %s and %p\n", idThread, tag.c_str(), symLayout);
	return symLayout;
}

int GetSystemMetricsHook(
	int nIndex
) {
	int ret = GetSystemMetrics(nIndex);
	std::string tag = GetTag("GetSystemMetrics");
	Message("[W] GetSystemMetrics (%i) Ret: %i -> tag_out: %s\n", nIndex, ret, tag.c_str());
	return S2ESymbolicInt(tag.c_str(), ret);
}

BOOL EnumDisplayMonitorsHook(
	HDC             hdc,
	LPCRECT         lprcClip,
	MONITORENUMPROC lpfnEnum,
	LPARAM          dwData
) {
	Message("[W] EnumDisplayMonitors (%p, %p, %p, %p)\n", hdc, lprcClip, lpfnEnum, dwData);
	return TRUE;
}

HDC GetDCHook(
	HWND hWnd
) {
	HDC handle = GetDC(hWnd);
	Message("[W] GetDCHook (%p) Ret: %p\n", hWnd, handle);
	return handle;
}

DWORD GetSysColorHook(
	int nIndex
) {
	DWORD ret = GetSysColor(nIndex);
	Message("[W] GetSysColor (%i) Ret: %ld\n", nIndex, ret);
	return ret;
}

BOOL GetCursorPosHook(
	LPPOINT lpPoint
) {
	std::string tag = GetTag("GetCursorPos");
	Message("[W] GetCursorPos (%p) -> tag_out: %s\n", lpPoint, tag.c_str());
	lpPoint->x = rand() % 10;
	lpPoint->y = rand() % 30;
	S2EMakeSymbolic(lpPoint, sizeof(POINT), tag.c_str());
	return TRUE;
}

BOOL GetLastInputInfoHook(
	PLASTINPUTINFO plii
) {
	std::string tag = GetTag("GetLastInputInfo");
	// Use concrete execution to initialize the struct size first?
	BOOL res = GetLastInputInfo(plii);
	Message("[W] GetLastInputInfo (%p) Ret: %i -> tag_out: %s\n", plii, res, tag.c_str());
	plii->cbSize = sizeof(LASTINPUTINFO);
	S2EMakeSymbolic(&(plii->dwTime), sizeof(DWORD), tag.c_str());
	return TRUE;
}