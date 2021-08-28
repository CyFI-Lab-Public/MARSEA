#pragma once
#include <Windows.h>
#include <sysinfoapi.h>

void GetLocalTimeHook(
	LPSYSTEMTIME lpSystemTime
);


void GetSystemInfoHook(
	LPSYSTEM_INFO lpSystemInfo
);