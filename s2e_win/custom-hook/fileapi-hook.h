#pragma once
#include <Windows.h>
#include <fileapi.h>
#include <unordered_map>

extern std::unordered_map<HANDLE, DWORD> perHandleBytesToRead;
extern std::unordered_map<HANDLE, DWORD> perHandleBytesWritten;

HANDLE WINAPI CreateFileAHook(
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

BOOL WINAPI DeleteFileAHook(
	LPCSTR lpFileName
);

BOOL WINAPI DeleteFileWHook(
	LPCWSTR lpFileName
);

HANDLE WINAPI FindFirstFileAHook(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
);

HANDLE WINAPI FindFirstFileWHook(
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

BOOL WINAPI WriteFileHook(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);

DWORD WINAPI SetFilePointerHook(
	HANDLE hFile,
	LONG   lDistanceToMove,
	PLONG  lpDistanceToMoveHigh,
	DWORD  dwMoveMethod
);

BOOL WINAPI CopyFileAHook(
	LPCSTR lpExistingFileName,
	LPCSTR lpNewFileName,
	BOOL    bFailIfExists
);

BOOL WINAPI CopyFileWHook(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	BOOL    bFailIfExists
);

BOOL PathFileExistsAHook(
	LPCSTR pszPath
);

BOOL PathFileExistsWHook(
	LPCWSTR pszPath
);