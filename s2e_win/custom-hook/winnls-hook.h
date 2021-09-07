#pragma once
#include <Windows.h>
#include <WinNls.h>

LANGID WINAPI GetUserDefaultUILanguageHook();

int WINAPI GetLocaleInfoAHook(
	LCID   Locale,
	LCTYPE LCType,
	LPSTR  lpLCData,
	int    cchData
);

UINT WINAPI GetOEMCPHook();

LCID WINAPI GetThreadLocaleHook();
