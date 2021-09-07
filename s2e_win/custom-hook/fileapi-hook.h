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

HANDLE WINAPI CreateFileWHook(
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

DWORD WINAPI GetFileTypeHook(
	HANDLE hFile
);

BOOL WINAPI ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);

DWORD WINAPI GetFileSizeHook(
	HANDLE  hFile,
	LPDWORD lpFileSizeHigh
);

DWORD WINAPI GetFileAttributesAHook(
	LPCSTR lpFileName
);

DWORD WINAPI GetFileAttributesWHook(
	LPCWSTR lpFileName
);

DWORD WINAPI GetFullPathNameAHook(
	LPCSTR lpFileName,
	DWORD  nBufferLength,
	LPSTR  lpBuffer,
	LPSTR* lpFilePart
);

BOOL FindCloseHook(
	HANDLE hFindFile
);

BOOL WINAPI GetFileTimeHook(
	HANDLE     hFile,
	LPFILETIME lpCreationTime,
	LPFILETIME lpLastAccessTime,
	LPFILETIME lpLastWriteTime
);