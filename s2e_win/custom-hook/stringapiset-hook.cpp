#include "stringapiset-hook.h"
#include "utils.h"


int WINAPI WideCharToMultiByteHook(
	UINT                               CodePage,
	DWORD                              dwFlags,
	_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
	int                                cchWideChar,
	LPSTR                              lpMultiByteStr,
	int                                cbMultiByte,
	LPCCH                              lpDefaultChar,
	LPBOOL                             lpUsedDefaultChar
) {
    if (checkCaller("WideCharToMultiByte")) {
        std::string tag = ReadTag((PVOID)lpWideCharStr);
        if (tag != "") {
            if (cchWideChar == -1) {
                cchWideChar = DEFAULT_MEM_LEN;
            }
            Message("[W] WideCharToMultiByte (%i, %d, %ls, %i, %p, %i, %p, %p) ret: %i, tag_out: %s\n", CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar, cchWideChar, tag.c_str());
            S2EMakeSymbolic((PVOID)lpMultiByteStr, cchWideChar, tag.c_str());
            int ret = S2ESymbolicInt(tag.c_str(), cchWideChar);
            return ret;
        }
        int ret = WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
        Message("[W] WideCharToMultiByte (%i, %d, %ls, %i, %p, %i, %p, %p) ret: %i\n", CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar, cchWideChar);
        return ret;
    }
    return WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}


