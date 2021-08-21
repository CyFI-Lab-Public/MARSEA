#include "stringapiset-hook.h"
#include "utils.h"


int MultiByteToWideCharHook(
	UINT                              CodePage,
	DWORD                             dwFlags,
	_In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
	int                               cbMultiByte,
	LPWSTR                            lpWideCharStr,
	int                               cchWideChar
) {
	Message("[W] MultiByteToWideChar (%i, %i, A\"%s\", %i, A\"%ls\", %p)\n",
		CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
	return MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);

}