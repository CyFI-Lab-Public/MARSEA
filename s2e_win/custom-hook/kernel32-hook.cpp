#include"kernel32-hook.h"
#include "utils.h"
#include <set>

void SleepHook(
	DWORD dwMilliseconds
) {
	if (checkCaller("Sleep")) {
		Message("[W] Sleep(%ld)\n", dwMilliseconds);
		return;
	}
	return Sleep(dwMilliseconds);
}

LPSTR GetCommandLineAHook()
{
	if (checkCaller("GetCommandLineA")) {
		std::string tag = GetTag("GetCommandLineA");
		LPSTR cmd_line_str = "";
		S2EMakeSymbolic((PVOID)cmd_line_str, DEFAULT_MEM_LEN, tag.c_str());
		Message("[W] GetCommandLineA () -> tag_out: %s\n", tag.c_str());
		return cmd_line_str;
	}
	return GetCommandLineA();
}

LPWSTR GetCommandLineWHook()
{
	if (checkCaller("GetCommandLineW")) {
		std::string tag = GetTag("GetCommandLineW");
		LPWSTR cmd_line_str = L"";
		S2EMakeSymbolic((PVOID)cmd_line_str, DEFAULT_MEM_LEN, tag.c_str());
		Message("[W] GetCommandLineW () -> tag_out: %s\n", tag.c_str());
		return cmd_line_str;
	}
	return GetCommandLineW();
}

HMODULE LoadLibraryWHook(LPCWSTR lpLibFileName)
{
	Message("[W] LoadLibraryW (%ls)\n", lpLibFileName);
	return LoadLibraryW(lpLibFileName);

}

BOOL QueryPerformanceCounterHook(
	LARGE_INTEGER* lpPerformanceCount
) {
	if (checkCaller("QueryPerformanceCounter")) {
		QueryPerformanceCounter(lpPerformanceCount);
		std::string tag = GetTag("QueryPerformanceCounter");
		S2EMakeSymbolic(lpPerformanceCount, 8, tag.c_str());
		Message("[W]  QueryPerformanceCounter (%p) -> tag_out: %s\n", lpPerformanceCount, tag.c_str());
		return TRUE;
	}

	return QueryPerformanceCounter(lpPerformanceCount);
	
}

DWORD GetModuleFileNameAHook(
	HMODULE hModule,
	LPSTR   lpFilename,
	DWORD   nSize
) {
	if (checkCaller("GetModuleFileNameA")) {
		GetModuleFileNameA(hModule, lpFilename, nSize);
		std::string tag = GetTag("GetModuleFileNameA");
		S2EMakeSymbolic(lpFilename, min(nSize, DEFAULT_MEM_LEN), tag.c_str());
		Message("[W] GetModuleFileNameA (%p, %p, %ld) -> tag_out: %s\n", hModule, lpFilename, nSize, tag.c_str());
		return nSize;
	}
	return GetModuleFileNameA(hModule, lpFilename, nSize);
}

DWORD GetModuleFileNameWHook(
	HMODULE hModule,
	LPWSTR  lpFilename,
	DWORD   nSize
) {
	if (checkCaller("GetModuleFileNameW")) {
		GetModuleFileNameW(hModule, lpFilename, nSize);
		std::string tag = GetTag("GetModuleFileNameW");
		S2EMakeSymbolic(lpFilename, min(nSize, DEFAULT_MEM_LEN) * 2, tag.c_str());
		Message("[W] GetModuleFileNameW (%p, %p, %ld) -> tag_out: %s\n", hModule, lpFilename, nSize, tag.c_str());
		return nSize;
	}
	return GetModuleFileNameW(hModule, lpFilename, nSize);
}

BOOL IsProcessorFeaturePresentHook(
	DWORD ProcessorFeature
) {
	if (checkCaller("IsProcessorFeaturePresent")) {
		Message("[W] IsProcessorFeaturePresent (%ld)\n", ProcessorFeature);
		return TRUE;
	}
	return IsProcessorFeaturePresent(ProcessorFeature);
}

LPWCH GetEnvironmentStringsWHook() {
	if (checkCaller("GetEnvironmentStringsW")) {
		std::string tag = GetTag("GetEnvironmentStringsW");
		LPWCH env_string = GetEnvironmentStringsW();
		size_t env_string_len = wcslen(env_string);
		Message("[W] GetEnvironmentStringsW () Ret: %p -> tag_out: %s\n", env_string, tag.c_str());
		S2EMakeSymbolic(env_string, env_string_len * 2, tag.c_str());
		return env_string;
	}
	return GetEnvironmentStringsW();
}

void GetSystemTimeAsFileTimeHook(
	LPFILETIME lpSystemTimeAsFileTime
) {
	GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
	if (checkCaller("GetSystemTimeAsFileTime")) {
		std::string tag = GetTag("GetSystemTimeAsFileTime");
		Message("[W] GetSystemTimeAsFileTime (%p) -> tag_out: %s\n", lpSystemTimeAsFileTime, tag.c_str());
		S2EMakeSymbolic(lpSystemTimeAsFileTime, 8, tag.c_str());
	}
}

DWORD GetTickCountHook() {
	if (checkCaller("GetTickCount")) {
		std::string tag = GetTag("GetTickCount");
		Message("[W] GetTickCount() -> tag_out: %s\n", tag.c_str());
		DWORD def_value = GetTickCount();
		return S2ESymbolicInt(tag.c_str(), def_value);
	}
	return GetTickCount();
}

