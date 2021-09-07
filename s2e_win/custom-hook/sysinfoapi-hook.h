#pragma once
#include <Windows.h>
#include <sysinfoapi.h>

void WINAPI GetLocalTimeHook(
	LPSYSTEMTIME lpSystemTime
);


void WINAPI GetSystemInfoHook(
	LPSYSTEM_INFO lpSystemInfo
);