#pragma once
#include <Windows.h>
#include <fileapi.h>

HANDLE CreateFileAHook(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

HANDLE CreateFileWHook(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

BOOL DeleteFileAHook(
	LPCSTR lpFileName
);

BOOL DeleteFileWHook(
	LPCWSTR lpFileName
);

HANDLE FindFirstFileAHook(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
);

HANDLE FindFirstFileWHook(
	LPCWSTR            lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
);

DWORD GetFileTypeHook(
	HANDLE hFile
);

BOOL ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);

DWORD GetFileSizeHook(
	HANDLE  hFile,
	LPDWORD lpFileSizeHigh
);

DWORD GetFileAttributesAHook(
	LPCSTR lpFileName
);

DWORD GetFileAttributesWHook(
	LPCWSTR lpFileName
);

DWORD GetFullPathNameAHook(
	LPCSTR lpFileName,
	DWORD  nBufferLength,
	LPSTR  lpBuffer,
	LPSTR* lpFilePart
);

BOOL FindCloseHook(
	HANDLE hFindFile
);

BOOL GetFileTimeHook(
	HANDLE     hFile,
	LPFILETIME lpCreationTime,
	LPFILETIME lpLastAccessTime,
	LPFILETIME lpLastWriteTime
);