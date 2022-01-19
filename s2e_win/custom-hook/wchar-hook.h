#pragma once
#include <wchar.h>

wchar_t* wcschrHook(wchar_t* str, wchar_t c);
wchar_t* wcsrchrHook(wchar_t* str, wchar_t c);

int wcscmpHook(const wchar_t* string1, const wchar_t* string2);

char* strstrhook(
	char* str,
	const char* strSearch
);

char* _strlwrhook(
	char* str
);

