#include "winuser-hook.h"
#include "utils.h"
#include "commands.h"
#include <string>
#include <stdlib.h> 

int WINAPI GetKeyboardTypeHook(
	int nTypeFlag
) {
	if (checkCaller("GetKeyboardType")) {
		std::string tag = GetTag("GetKeyboardType");
		switch (nTypeFlag) {
		case 0: {
			Message("[W] GetKeyboardType (%i) tag_out:%s\n", nTypeFlag, tag.c_str());
			return S2ESymbolicInt(tag.c_str(), GetKeyboardType(nTypeFlag));
		}
		case 1:
			Message("[W] GetKeyboardType (%i) tag_out:%s\n", nTypeFlag, tag.c_str());
			// 0 is a valid return value when nTypeFlag is 1
			return S2ESymbolicInt(tag.c_str(), GetKeyboardType(nTypeFlag));
		case 2: {
			Message("[W] GetKeyboardType (%i) tag_out:%s\n", nTypeFlag, tag.c_str());
			return S2ESymbolicInt(tag.c_str(), GetKeyboardType(nTypeFlag));
		}
		default:
			return S2ESymbolicInt(tag.c_str(), GetKeyboardType(nTypeFlag));
		}
	}
	return GetKeyboardType(nTypeFlag);
}

HKL WINAPI GetKeyboardLayoutHook(
	DWORD idThread
) {
	if (checkCaller("GetKeyboardLayout")) {
		std::string tag = GetTag("GetKeyboardLayout");
		LPCTSTR layout = L"";
		S2EMakeSymbolic((PVOID)layout, DEFAULT_MEM_LEN, tag.c_str());
		HKL symLayout = LoadKeyboardLayout(layout, KLF_SUBSTITUTE_OK);
		Message("[W] GetKeyboardLayout (%ld) tag_out:%s ret:%p\n", idThread, tag.c_str(), symLayout);
		return symLayout;
	}
	return GetKeyboardLayout(idThread);
}

int WINAPI GetSystemMetricsHook(
	int nIndex
) {
	if (checkCaller("GetSystemMetrics")) {

		int ret = GetSystemMetrics(nIndex);
		std::string tag = GetTag("GetSystemMetrics");
		Message("[W] GetSystemMetrics (%i) ret:%i tag_out:%s\n", nIndex, ret, tag.c_str());
		return S2ESymbolicInt(tag.c_str(), ret);
	}
	return GetSystemMetrics(nIndex);
}

BOOL WINAPI EnumDisplayMonitorsHook(
	HDC             hdc,
	LPCRECT         lprcClip,
	MONITORENUMPROC lpfnEnum,
	LPARAM          dwData
) {
	Message("Calling EnumDisplayMonitor");
	if (checkCaller("EnumDisplayMonitors")) {

		Message("[W] EnumDisplayMonitors (%p [|] %p [|] %p [|] %p)\n", hdc, lprcClip, lpfnEnum, dwData);
		return TRUE;
	}
	return EnumDisplayMonitors(hdc, lprcClip, lpfnEnum, dwData);
}

HDC WINAPI GetDCHook(
	HWND hWnd
) {
	if (checkCaller("GetDCHook")) {

		HDC handle = GetDC(hWnd);
		Message("[W] GetDCHook (%p) ret:%p\n", hWnd, handle);
		return handle;
	}
	return GetDC(hWnd);
}

DWORD WINAPI GetSysColorHook(
	int nIndex
) {
	if (checkCaller("GetSysColor")) {

		DWORD ret = GetSysColor(nIndex);
		Message("[W] GetSysColor (%i) ret:%ld\n", nIndex, ret);
		return ret;
	}
	return GetSysColor(nIndex);
}

BOOL WINAPI GetCursorPosHook(
	LPPOINT lpPoint
) {
	if (checkCaller("GetCursorPos")) {
		std::string tag = GetTag("GetCursorPos");
		Message("[W] GetCursorPos (%p) tag_out:%s\n", lpPoint, tag.c_str());
		lpPoint->x = rand() % 10;
		lpPoint->y = rand() % 30;
		S2EMakeSymbolic(lpPoint, sizeof(POINT), tag.c_str());
		return TRUE;
	}
	return GetCursorPos(lpPoint);
}

BOOL WINAPI GetLastInputInfoHook(
	PLASTINPUTINFO plii
) {
	if (checkCaller("GetLastInputInfo")) {

		std::string tag = GetTag("GetLastInputInfo");
		// Use concrete execution to initialize the struct size first?
		BOOL res = GetLastInputInfo(plii);
		Message("[W] GetLastInputInfo (%p) ret:%i tag_out:%s\n", plii, res, tag.c_str());
		plii->cbSize = sizeof(LASTINPUTINFO);
		S2EMakeSymbolic(&(plii->dwTime), sizeof(DWORD), tag.c_str());
		return TRUE;
	}
	return GetLastInputInfo(plii);
}

int WINAPIV wsprintfAHook(
	LPSTR fmt,
	LPCSTR buffer,
	...
) {
	va_list args;
	va_start(args, buffer);
	Message("[W] wsprintfA (%s [|] %s [|] %p)\n", fmt, buffer, args);
	int res = wsprintfA(fmt, buffer, args);
	va_end(args);
	return res;
}

BOOL WINAPI ShowWindowHook(
	HWND hWnd,
	int  nCmdShow
) {
	if (checkCaller("ShowWindow")) {
		Message("[W] ShowWindow (%p [|] %i)\n", hWnd, nCmdShow);
		return TRUE;
	}
	return ShowWindow(hWnd, nCmdShow);
}

SHORT WINAPI GetAsyncKeyStateHook(
	int vKey
) {
	if (checkCaller("GetAsyncKeyState")) {
		std::string tag = GetTag("GetAsynckeyState");
		SHORT ret = GetAsyncKeyState(vKey);
		Message("[W] GetAsyncKeyState(%d) ret:%d", vKey, ret);
		S2EMakeSymbolic(&ret, sizeof(ret), tag.c_str());
		return ret;
	}

	return GetAsyncKeyState(vKey);
}

int WINAPI LoadStringAHook(
	HINSTANCE hInstance,
	UINT      uID,
	LPSTR     lpBuffer,
	int       cchBufferMax
) {
	if (checkCaller("LoadStringA")) {

		std::string tag = GetTag("LoadStringA");
		int ret = 0;
		if (cchBufferMax == 0) {
			ret = DEFAULT_MEM_LEN;
		}
		else {
			ret = min(cchBufferMax, DEFAULT_MEM_LEN);
		}
		Message("[W] LoadStringA (%p [|] %i [|] %p [|] %i) tag_out:%s\n", hInstance, uID, lpBuffer, cchBufferMax, tag.c_str());
		S2EMakeSymbolic(lpBuffer, ret, tag.c_str());
		return ret;
	}
	return LoadStringA(hInstance, uID, lpBuffer, cchBufferMax);
}

BOOL WINAPI PeekMessageAHook(
	LPMSG lpMsg,
	HWND  hWnd,
	UINT  wMsgFilterMin,
	UINT  wMsgFilterMax,
	UINT  wRemoveMsg
) {
	Message("[W] PeekMessageA (%p [|] %p [|] %i [|] %i [|] %i)\n", lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	return TRUE;
}