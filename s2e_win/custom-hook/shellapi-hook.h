#pragma once
#include <Windows.h>
#include <shellapi.h>

HINSTANCE WINAPI ShellExecuteAHook(
	HWND   hwnd,
	LPCSTR lpOperation,
	LPCSTR lpFile,
	LPCSTR lpParameters,
	LPCSTR lpDirectory,
	INT    nShowCmd
);

HINSTANCE WINAPI ShellExecuteWHook(
	HWND    hwnd,
	LPCWSTR lpOperation,
	LPCWSTR lpFile,
	LPCWSTR lpParameters,
	LPCWSTR lpDirectory,
	INT     nShowCmd
);

int WINAPI SHFileOperationAHook(
	LPSHFILEOPSTRUCTA lpFileOp
);