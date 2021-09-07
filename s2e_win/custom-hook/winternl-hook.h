#pragma once
#include <Windows.h>
#include <winternl.h>

BOOLEAN NTAPI RtlTimeToSecondsSince1970Hook(
	PLARGE_INTEGER Time,
	PULONG         ElapsedSeconds
);
