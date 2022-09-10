#pragma once
#include <Windows.h>
#include <debugapi.h>

BOOL WINAPI CheckRemoteDebuggerPresentHook(
	HANDLE hProcess,
	PBOOL  pbDebuggerPresent
);

BOOL WINAPI IsDebuggerPresentHook();
