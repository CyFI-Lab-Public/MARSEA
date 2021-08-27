#pragma once
#include <Windows.h>
#include <debugapi.h>

BOOL CheckRemoteDebuggerPresentHook(
	HANDLE hProcess,
	PBOOL  pbDebuggerPresent
);

BOOL IsDebuggerPresentHook();
