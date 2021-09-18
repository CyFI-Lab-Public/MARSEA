#include "handleapi-hook.h"
#include "utils.h"

BOOL WINAPI CloseHandleHook(
	HANDLE hObject
) {
	if (checkCaller("CloseHandle")) {
		BOOL res = CloseHandle(hObject);
		if (!res) {
			free(hObject);
		}
		return TRUE;
	}

	return CloseHandle(hObject);
}