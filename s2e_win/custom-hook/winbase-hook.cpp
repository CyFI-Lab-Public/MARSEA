#include "winbase-hook.h"
#include "utils.h"
#include "commands.h"
#include <string>
#include <wchar.h>

int WINAPI lstrlenAHook(
	LPCSTR lpString
) {
	if (checkCaller("lstrlenA")) {

		// If the pointer itself is symbolic, concretize it here
		if (S2EIsSymbolic(&lpString, sizeof(&lpString))) {
			S2EConcretize(&lpString, sizeof(&lpString));
		}

		int con_len = lstrlenA(lpString);

		std::string tagin = ReadTag((PVOID)lpString);

		if (tagin != "") {
			std::string tag = GetTag("lstrlenA");
			Message("[W] lstrlenA(%p) tag_in: %s, tag_out: %s", lpString, tagin.c_str(), tag.c_str());
			return S2ESymbolicInt(tag.c_str(), con_len);
		}
		else {
			return con_len;
		}
	}

	return lstrlenA(lpString);
}

int WINAPI lstrlenWHook(
	LPCWSTR lpString
) {
	if (checkCaller("lstrlenW")) {

		int con_len = lstrlenW(lpString);

		std::string tagin = ReadTag((PVOID)lpString);
		if (tagin != "") {
			std::string tag = GetTag("lstrlenW");
			Message("[W] lstrlenW(%p) tag_in: %s, tag_out: %s", lpString, tagin.c_str(), tag.c_str());
			return S2ESymbolicInt(tag.c_str(), con_len);
		}
		else {
			return con_len;
		}
	}

	return lstrlenW(lpString);
}

HLOCAL WINAPI LocalAllocHook(
	UINT   uFlags,
	SIZE_T uBytes
) {
	if (checkCaller("LocalAlloc")) {
		// If the size is symbolic, concretize it to avoid seg fault problem
		if (S2EIsSymbolic(&uBytes, sizeof(SIZE_T))) {
			S2EConcretize(&uBytes, sizeof(SIZE_T));
		}

		Message("[W] LocalAlloc(%d, %d)\n", uFlags, uBytes);

		return LocalAlloc(uFlags, uBytes);
	}

	return LocalAlloc(uFlags, uBytes);
}