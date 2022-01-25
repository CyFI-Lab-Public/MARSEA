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
		HINSTANCE ret = ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
		std::string file_tag = getFileTag(lpFile);
		if (file_tag.length() > 1) {
			Message("[W] ShellExecuteA(%p, %s, %s, %s, %s, %i) ret: %p tag_in: %s\n", hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd, ret, file_tag.c_str());
		}
		else {
			Message("[W] ShellExecuteA(%p, %s, %p=%s, %s, %s, %i) ret: %p\n", hwnd, lpOperation, lpFile, lpFile, lpParameters, lpDirectory, nShowCmd, ret);
		}
		return ret;
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
		HINSTANCE ret = ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
		std::string file_tag = getFileTag(lpFile);
		if (file_tag.length() > 1) {
			Message("[W] ShellExecuteW(%p, %ls, %p=%ls, %ls, %ls, %i) ret: %p tag_in: %s\n", hwnd, lpOperation, lpFile, lpFile, lpParameters, lpDirectory, nShowCmd, ret, file_tag.c_str());
		}
		else {
			Message("[W] ShellExecuteW(%p, %ls, %ls, %ls, %ls, %i) ret: %p\n", hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd, ret);
		}
		return ret;
	}
	return ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

int WINAPI SHFileOperationAHook(
	LPSHFILEOPSTRUCTA lpFileOp
) {
	int ret = SHFileOperationA(lpFileOp);
	Message("[W] SHFileOperationA(%i, %s, %p) ret: %i\n", lpFileOp->wFunc, lpFileOp->pFrom, lpFileOp->pTo, ret);
	if (ret == 0 || ret == 183) {
		return ret;
	}
	return 0;
}
