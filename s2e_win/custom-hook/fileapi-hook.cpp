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
	if (checkCaller("CreateFileA")) {
		if (S2EIsSymbolic((PVOID)lpFileName, 0x4)) {
			HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
			dummyHandles.insert(fileHandle);
			Message("[W] CreateFileA (A\"%s\", %d, %d, %p, %d, %d, %p), Ret: %p\n",
				lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle);
			return fileHandle;
		}
		else {
			HANDLE fileHandle = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
				Message("[W] CreateFileA (A\"%ls\", %ld, %ld, %p, %ld, %ld, %p), Ret: %p\n",
					lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle);
				return fileHandle;
			}
		}
	}
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
	if (checkCaller("CreateFileW")) {

		if (S2EIsSymbolic((PVOID)lpFileName, 0x4)) {
			HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
			dummyHandles.insert(fileHandle);
			Message("[W] CreateFileW (A\"%ls\", %ld, %ld, %p, %ld, %ld, %p), Ret: %p\n",
				lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle);
			return fileHandle;
		}
		else {
			HANDLE fileHandle = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
				Message("[W] CreateFileW (A\"%ls\", %ld, %ld, %p, %ld, %ld, %p), Ret: %p\n",
					lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle);
				return fileHandle;
			}
		}
	}
	return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL DeleteFileAHook(
	LPCSTR lpFileName
) {
	if (checkCaller("DeleteFileA")) {
		Message("[W] DeleteFileA (A\"%s\")\n", lpFileName);
		return TRUE;
	}
	return DeleteFileA(lpFileName);
}

BOOL DeleteFileWHook(
	LPCWSTR lpFileName
) {
	if (checkCaller("DeleteFileW")) {
		Message("[W] DeleteFileW (A\"%ls\")\n", lpFileName);
		return TRUE;
	}
	return DeleteFileW(lpFileName);
}

HANDLE FindFirstFileAHook(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
) {
	if (checkCaller("FindFirstFileA")) {
		if (S2EIsSymbolic((PVOID)lpFileName, 0x4)) {
			HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
			dummyHandles.insert(fileHandle);
			Message("[W] FindFirstFileA (A\"%s\", %p), Ret: %p\n",
				lpFileName, lpFindFileData, fileHandle);
			return fileHandle;
		}
		else {
			HANDLE fileHandle = FindFirstFileA(lpFileName, lpFindFileData);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
				Message("[W] FindFirstFileA (A\"%s\", %p), Ret: %p\n",
					lpFileName, lpFindFileData, fileHandle);
				return fileHandle;
			}
		}
	}
	return FindFirstFileA(lpFileName, lpFindFileData);
}

HANDLE FindFirstFileWHook(
	LPCWSTR            lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	if (checkCaller("FindFirstFileW")) {
		if (S2EIsSymbolic((PVOID)lpFileName, 0x4)) {
			HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
			dummyHandles.insert(fileHandle);
			Message("[W] FindFirstFileW (A\"%ls\", %p), Ret: %p\n",
				lpFileName, lpFindFileData, fileHandle);
			return fileHandle;
		}
		else {
			HANDLE fileHandle = FindFirstFileW(lpFileName, lpFindFileData);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
				Message("[W] FindFirstFileW (A\"%ls\", %p), Ret: %p\n",
					lpFileName, lpFindFileData, fileHandle);
				return fileHandle;
			}
		}
	}
	return FindFirstFileW(lpFileName, lpFindFileData);
}

DWORD GetFileTypeHook(
	HANDLE hFile
) {
	if (checkCaller("GetFiletype")) {
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
	return GetFileType(hFile);
}

BOOL ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
) {
	if (checkCaller("ReadFile")) {
		std::string tag = GetTag("ReadFile");
		Message("[W] ReadFile (%p, %p, %ld, %p, %p) -> tag_out: %s\n", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, tag.c_str());
		std::set<HANDLE>::iterator it = dummyHandles.find(hFile);
		if (it == dummyHandles.end()) {
			BOOL res = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			if (res) {
				S2EMakeSymbolic(lpBuffer, *lpNumberOfBytesRead, tag.c_str());
			}
			else {
				S2EMakeSymbolic(lpBuffer, DEFAULT_MEM_LEN, tag.c_str());
			}
		}
		else {
			S2EMakeSymbolic(lpBuffer, min(nNumberOfBytesToRead, DEFAULT_MEM_LEN), tag.c_str());
			S2EMakeSymbolic(lpNumberOfBytesRead, min(nNumberOfBytesToRead, DEFAULT_MEM_LEN), tag.c_str());
		}
		return TRUE;
	}
	return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

DWORD GetFileSizeHook(
	HANDLE  hFile,
	LPDWORD lpFileSizeHigh
) {
	if (checkCaller("GetFileSize")) {
		std::set<HANDLE>::iterator it = dummyHandles.find(hFile);
		if (it == dummyHandles.end()) {
			return GetFileSize(hFile, lpFileSizeHigh);
		}
		else {
			std::string tag = GetTag("GetFileSize");
			Message("[W] GetFileSize(%p, %p) -> tag_out: %s\n", hFile, lpFileSizeHigh, tag.c_str());
			DWORD res = S2ESymbolicInt(tag.c_str(), DEFAULT_MEM_LEN);

			if (lpFileSizeHigh != NULL) {
				S2EMakeSymbolic(lpFileSizeHigh, 4, tag.c_str());
			}
			return res;
		}
	}
	return GetFileSize(hFile, lpFileSizeHigh);
}

DWORD GetFileAttributesAHook(
	LPCSTR lpFileName
) {
	if (checkCaller("GetFileAttributesA")) {
		std::string tag = GetTag("GetFileAttributesA");
		DWORD ret = GetFileAttributesA(lpFileName);
		Message("[W] GetFileAttributesA (%s) Ret: %ld -> tag_out: %s\n", lpFileName, ret, tag.c_str());
		S2EMakeSymbolic(&ret, sizeof(ret), tag.c_str());
		return ret;
	}
	return GetFileAttributesA(lpFileName);
}

DWORD GetFileAttributesWHook(
	LPCWSTR lpFileName
) {
	std::string tag = GetTag("GetFileAttributesW");
	DWORD ret = GetFileAttributesW(lpFileName);
	Message("[W] GetFileAttributesW (%s) Ret: %ld -> tag_out: %s\n", lpFileName, ret, tag.c_str());
	S2EMakeSymbolic(&ret, sizeof(ret), tag.c_str());
	return ret;
}

DWORD GetFullPathNameAHook(
	LPCSTR lpFileName,
	DWORD  nBufferLength,
	LPSTR  lpBuffer,
	LPSTR* lpFilePart
) {
	if (checkCaller("GetFullPathNameA")) {
		std::string tag = GetTag("GetFullPathNameA");
		DWORD ret = GetFullPathNameA(lpFileName, nBufferLength, lpBuffer, lpFilePart);
		Message("[W] GetFullPathNameA (%s, %ld, %p, %p) Ret: %ld -> tag_out: %s\n", lpFileName, nBufferLength, lpBuffer, lpFilePart, ret, tag.c_str());
		if (ret == 0) {
			// If the function faield, symbolize the buffer and the return
			S2EMakeSymbolic(lpBuffer, min(DEFAULT_MEM_LEN, nBufferLength), tag.c_str());
			DWORD hack_ret = nBufferLength;
			S2EMakeSymbolic(&hack_ret, sizeof(DWORD), tag.c_str());
			return hack_ret;
		}
		else {
			S2EMakeSymbolic(lpBuffer, ret, tag.c_str());
			return ret;
		}
	}
	return GetFullPathNameA(lpFileName, nBufferLength, lpBuffer, lpFilePart);
}

BOOL FindCloseHook(
	HANDLE hFindFile
) {
	std::set<HANDLE>::iterator it = dummyHandles.find(hFindFile);

	if (it == dummyHandles.end()) {
		return FindClose(hFindFile);
	}
	else {
		free(*it);
		dummyHandles.erase(it);

		return TRUE;
	}
}

BOOL GetFileTimeHook(
	HANDLE     hFile,
	LPFILETIME lpCreationTime,
	LPFILETIME lpLastAccessTime,
	LPFILETIME lpLastWriteTime
) {
	if (checkCaller("GetFileTime")) {

		std::set<HANDLE>::iterator it = dummyHandles.find(hFile);

		if (it == dummyHandles.end()) {
			GetFileTime(hFile, lpCreationTime,
				lpLastAccessTime, lpLastWriteTime);
		}
		std::string tag = GetTag("GetFileTime");
		Message("[W] GetFileTimeHook (%p, %p, %p, %p) -> tag_out: %s\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime, tag.c_str());
		S2EMakeSymbolic(&lpCreationTime->dwHighDateTime, sizeof(DWORD), tag.c_str());
		S2EMakeSymbolic(&lpCreationTime->dwLowDateTime, sizeof(DWORD), tag.c_str());
		S2EMakeSymbolic(&lpLastAccessTime->dwHighDateTime, sizeof(DWORD), tag.c_str());
		S2EMakeSymbolic(&lpLastAccessTime->dwLowDateTime, sizeof(DWORD), tag.c_str());
		S2EMakeSymbolic(&lpLastWriteTime->dwHighDateTime, sizeof(DWORD), tag.c_str());
		S2EMakeSymbolic(&lpLastWriteTime->dwLowDateTime, sizeof(DWORD), tag.c_str());
		return TRUE;
	}

	return GetFileTime(hFile, lpCreationTime,
		lpLastAccessTime, lpLastWriteTime);

}