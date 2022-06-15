#include "handleapi-hook.h"
#include "utils.h"
#include "fileapi-hook.h"

BOOL WINAPI CloseHandleHook(
	HANDLE hObject
) {
	if (checkCaller("CloseHandle")) {

		perHandleBytesToRead.erase(hObject);
		perHandleBytesWritten.erase(hObject);

		S2EBeginAtomic();
		cyFiCopyFile(hObject);
		S2EEndAtomic();

		BOOL res = CloseHandle(hObject);
		if (!res) {
			free(hObject);
		}
		return TRUE;
	}

	return CloseHandle(hObject);
}
