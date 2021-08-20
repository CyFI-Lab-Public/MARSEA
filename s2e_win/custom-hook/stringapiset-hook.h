#pragma once
#include <Windows.h>
#include <stringapiset.h>


int MultiByteToWideCharHook(
	UINT                              CodePage,
	DWORD                             dwFlags,
	_In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
	int                               cbMultiByte,
	LPWSTR                            lpWideCharStr,
	int                               cchWideChar
);