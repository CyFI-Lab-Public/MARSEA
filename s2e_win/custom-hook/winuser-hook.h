#pragma once
#include <Windows.h>
namespace winuser {
#include <winuser.h>
}

int WINAPI GetKeyboardTypeHook(
	int nTypeFlag
);

HKL WINAPI GetKeyboardLayoutHook(
	DWORD idThread
);

int WINAPI GetSystemMetricsHook(
	int nIndex
);

BOOL WINAPI EnumDisplayMonitorsHook(
	HDC             hdc,
	LPCRECT         lprcClip,
	MONITORENUMPROC lpfnEnum,
	LPARAM          dwData
);

BOOL WINAPI GetCursorPosHook(
	LPPOINT lpPoint
);

HDC WINAPI GetDCHook(
	HWND hWnd
);

DWORD WINAPI GetSysColorHook(
	int nIndex
);

BOOL WINAPI GetLastInputInfoHook(
	PLASTINPUTINFO plii
);

int WINAPIV wsprintfAHook(
	LPSTR fmt,
	LPCSTR buffer,
	...
);

BOOL WINAPI ShowWindowHook(
	HWND hWnd,
	int  nCmdShow
);

SHORT WINAPI GetAsyncKeyStateHook(
	int vKey
);