#include "shellapi-hook.h"
#include "utils.h"
#include "commands.h"

HINSTANCE WINAPI ShellExecuteAHook(
	HWND   hwnd,
	LPCSTR lpOperation,
	LPCSTR lpFile,
	LPCSTR lpParameters,
	LPCSTR lpDirectory,
	INT    nShowCmd
) {
	if (checkCaller("ShellExecuteA")) {
		std::string file_tag = getFileTag(lpFile);
		if (file_tag.length() > 1) {
			Message("[W] ShellExecuteA(%p, %s, %s, %s, %s, %i) tag_in: %s\n", hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd, file_tag.c_str());
		}
		else {
			Message("[W] ShellExecuteA(%p, %s, %s, %s, %s, %i)\n", hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
		}
		return ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
	}

	return ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);

}

HINSTANCE WINAPI ShellExecuteWHook(
	HWND    hwnd,
	LPCWSTR lpOperation,
	LPCWSTR lpFile,
	LPCWSTR lpParameters,
	LPCWSTR lpDirectory,
	INT     nShowCmd
) {
	if (checkCaller("ShellExecuteW")) {
		std::string file_tag = getFileTag(lpFile);
		if (file_tag.length() > 1) {
			Message("[W] ShellExecuteW(%p, %ls, %ls, %ls, %ls, %i) tag_in: %s\n", hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd, file_tag.c_str());
		}
		else {
			Message("[W] ShellExecuteW(%p, %ls, %ls, %ls, %ls, %i)\n", hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
		}
		return ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
	}

	return ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}