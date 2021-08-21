#pragma once
#include <Windows.h>


void SleepHook(DWORD dwMilliseconds);
LPSTR GetCommandLineAHook();


//HMODULE LoadLibraryAHook(LPCSTR lpLibFileName);
HMODULE LoadLibraryWHook(LPCWSTR lpLibFileName);
