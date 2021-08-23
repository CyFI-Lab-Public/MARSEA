#include "fileapi-hook.h"
#include "utils.h"
#include <set>

static std::set<HANDLE> dummyHandles;

HANDLE CreateFileAHook(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	//HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
	//dummyHandles.insert(fileHandle);
	Message("[W] CreateFileA (A\"%s\", %ld, %ld, %p, %ld, %ld, %p), Ret: %p\n",
		lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);//, fileHandle);
	//return fileHandle;
	return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); 
}

HANDLE CreateFileWHook(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
	dummyHandles.insert(fileHandle);
	Message("[W] CreateFileW (A\"%ls\", %ld, %ld, %p, %ld, %ld, %p), Ret: %p\n",
		lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle);
	return fileHandle;
}

BOOL DeleteFileAHook(
	LPCSTR lpFileName
) {
	Message("[W] DeleteFileA (A\"%s\")\n", lpFileName);
	return TRUE;
}

BOOL DeleteFileWHook(
	LPCWSTR lpFileName
) {
	Message("[W] DeleteFileW (A\"%ls\")\n", lpFileName);
	return TRUE;
}

HANDLE FindFirstFileAHook(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
) {
	HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
	dummyHandles.insert(fileHandle);
	Message("[W] FindFirstFileA (A\"%s\", %p), Ret: %p\n",
		lpFileName, lpFindFileData, fileHandle);
	return fileHandle;
}

HANDLE FindFirstFileWHook(
	LPCWSTR            lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
	dummyHandles.insert(fileHandle);
	Message("[W] FindFirstFileW (A\"%ls\", %p), Ret: %p\n",
		lpFileName, lpFindFileData, fileHandle);
	return fileHandle;
}

DWORD GetFileTypeHook(
	HANDLE hFile
) {

	std::set<HANDLE>::iterator it = dummyHandles.find(hFile);

	if (it == dummyHandles.end()) {
		// The handle is not one of our dummy handles, so call the original
		// function
		Message("[W] GetFileType (%p)\n", hFile);
		return GetFileType(hFile);
	}
	else {
		std::string tag = GetTag("GetFileType");
		Message("[W] GetFileType (%p) -> tag_out: %s\n", hFile, tag.c_str());
		return S2ESymbolicInt(tag.c_str(), 0x4);
	}
}