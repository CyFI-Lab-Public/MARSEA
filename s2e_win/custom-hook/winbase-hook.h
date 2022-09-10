#pragma once
#include <Windows.h>
#include <WinBase.h>


int WINAPI lstrlenAHook(
	LPCSTR lpString
);

int WINAPI lstrlenWHook(
	LPCWSTR lpString
);

HLOCAL WINAPI LocalAllocHook(
	UINT   uFlags,
	SIZE_T uBytes
);