#pragma once
#include <Windows.h>
#include <WinNls.h>

LANGID GetUserDefaultUILanguageHook();

int GetLocaleInfoAHook(
	LCID   Locale,
	LCTYPE LCType,
	LPSTR  lpLCData,
	int    cchData
);

UINT GetOEMCPHook();

LCID GetThreadLocaleHook();
