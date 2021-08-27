#pragma once
#include <Windows.h>


void SleepHook(DWORD dwMilliseconds);
LPSTR GetCommandLineAHook();


//HMODULE LoadLibraryAHook(LPCSTR lpLibFileName);
HMODULE LoadLibraryWHook(LPCWSTR lpLibFileName);

LPSTR GetCommandLineAHook();

LPWSTR GetCommandLineWHook();

BOOL QueryPerformanceCounterHook(LARGE_INTEGER* lpPerformanceCount);

DWORD GetModuleFileNameAHook(HMODULE hModule, LPSTR lpFilename, DWORD nSize);

DWORD GetModuleFileNameWHook(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

BOOL IsProcessorFeaturePresentHook(DWORD ProcessorFeature);

LPWCH GetEnvironmentStringsWHook();

void GetSystemTimeAsFileTimeHook(LPFILETIME lpSystemTimeAsFileTime);

DWORD GetTickCountHook();