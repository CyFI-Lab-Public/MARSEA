#include "wchar-hook.h"
#include "utils.h"
#include "commands.h"

wchar_t* wcschrHook(
	wchar_t* str,
	wchar_t c)
{
	Message("[W] wcschr (A\"%s\", A\"%s\")\n", str, c);

	return wcschr(str, c);
}

wchar_t* wcsrchrHook(
	wchar_t* str,
	wchar_t c
) {
	Message("[W] wcsrchr (A\"%s\", A\"%s\")\n", str, c);

	return wcsrchr(str, c);
}


int wcscmpHook(
	const wchar_t* string1,
	const wchar_t* string2
) {
	Message("[W] wcscmp (A\"%s\", A\"%s\")\n", string1, string2);

	return wcscmp(string1, string2);
}

