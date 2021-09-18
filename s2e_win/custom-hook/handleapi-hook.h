#pragma once
#include <Windows.h>
#include <handleapi.h>

BOOL WINAPI CloseHandleHook(
	HANDLE hObject
);
