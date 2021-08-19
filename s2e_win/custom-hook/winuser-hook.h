#pragma once
#include <Windows.h>
namespace winuser {
#include <winuser.h>
}

int GetKeyboardTypeHook(
	int nTypeFlag
);

HKL GetKeyboardLayoutHook(
	DWORD idThread
);

int GetSystemMetricsHook(
	int nIndex
);

BOOL EnumDisplayMonitorsHook(
	HDC             hdc,
	LPCRECT         lprcClip,
	MONITORENUMPROC lpfnEnum,
	LPARAM          dwData
);

BOOL GetCursorPosHook(
	LPPOINT lpPoint
);