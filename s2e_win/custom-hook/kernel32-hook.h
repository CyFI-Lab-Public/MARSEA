#pragma once
#include <Windows.h>


void SleepHook(DWORD dwMilliseconds);


//HMODULE LoadLibraryAHook(LPCSTR lpLibFileName);
HMODULE LoadLibraryWHook(LPCWSTR lpLibFileName);

LPSTR WINAPI GetCommandLineAHook();

LPWSTR WINAPI GetCommandLineWHook();

BOOL QueryPerformanceCounterHook(LARGE_INTEGER* lpPerformanceCount);

DWORD WINAPI GetModuleFileNameAHook(HMODULE hModule, LPSTR lpFilename, DWORD nSize);

DWORD GetModuleFileNameWHook(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

BOOL WINAPI IsProcessorFeaturePresentHook(DWORD ProcessorFeature);

LPWCH WINAPI GetEnvironmentStringsWHook();

BOOL WINAPI FreeEnvironmentStringsWHook(
	LPWCH penv
);

void WINAPI GetSystemTimeAsFileTimeHook(LPFILETIME lpSystemTimeAsFileTime);

DWORD WINAPI GetTickCountHook();