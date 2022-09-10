#include "fileapi-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>
#include <shlwapi.h>

static std::set<HANDLE> dummyHandles;
std::map<HANDLE, std::string> fileMap;
std::unordered_map<HANDLE, DWORD> perHandleBytesToRead;
std::unordered_map<HANDLE, DWORD> perHandleBytesWritten;


HANDLE WINAPI CreateFileAHook(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	std::string fileName = lpcstrToString(lpFileName);
	if (checkCaller("CreateFileA")) {
		if (S2EIsSymbolic((PVOID)lpFileName, 0x4)) {
			std::string file_name_tag = ReadTag((PVOID)lpFileName);
			S2EDisableForking();
			HANDLE fileHandle = CreateFileA(lpFileName, dwDesiredAccess, 7, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				Message("CreateFileA Invalid Handle. Need to fake it. %ld \n", GetLastError());
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
			}
			fileMap[fileHandle] = PathFindFileNameA(lpFileName);
			
			Message("[W] CreateFileA (%s [|] 0x%x [|] %ld [|] %p [|] %ld [|] %ld [|] %p) ret:%p tag_in:%s\n",
				lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle, file_name_tag.c_str());
			S2EEnableForking();
			return fileHandle;
		}
		else {
			HANDLE fileHandle = CreateFileA(lpFileName, dwDesiredAccess, 7, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				Message("CreateFileA Invalid Handle. Need to fake it. %ld \n", GetLastError());
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
			}
			
			Message("[W] CreateFileA (%s [|] 0x%x [|] %ld [|] %p [|] %ld [|] %ld [|] %p) ret:%p\n",
				lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle);
			fileMap[fileHandle] = PathFindFileNameA(lpFileName);
			return fileHandle;
		}
	}
	return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); 
}

HANDLE WINAPI CreateFileWHook(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	std::string fileName = lpcwstrToString(lpFileName);

	if (checkCaller("CreateFileW")) {

		if (S2EIsSymbolic((PVOID)lpFileName, 0x4)) {
			S2EDisableForking();
			std::string file_name_tag = ReadTag((PVOID)lpFileName);
			HANDLE fileHandle = CreateFileW(lpFileName, dwDesiredAccess, 7, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
			}
			fileMap[fileHandle] = lpcwstrToString(PathFindFileNameW(lpFileName));
			Message("[W] CreateFileW (%ls [|] %ld [|] %ld [|] %p [|] %ld [|] %ld [|] %p) ret:%p tag_in:%s\n",
				lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle, file_name_tag.c_str());
			S2EEnableForking();
			return fileHandle;
		}
		else {
			HANDLE fileHandle = CreateFileW(lpFileName, dwDesiredAccess, 7, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
			}
			Message("[W] CreateFileW (%ls [|] %ld [|] %ld [|] %p [|] %ld [|] %ld [|] %p) ret:%p\n",
				lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, fileHandle);
			fileMap[fileHandle] = lpcwstrToString(PathFindFileNameW(lpFileName));
			return fileHandle;
		}
	}
	return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI DeleteFileAHook(
	LPCSTR lpFileName
) {
	if (checkCaller("DeleteFileA")) {
		Message("[W] DeleteFileA (%s)\n", lpFileName);
		return TRUE;
	}
	return DeleteFileA(lpFileName);
}

BOOL WINAPI DeleteFileWHook(
	LPCWSTR lpFileName
) {
	if (checkCaller("DeleteFileW")) {
		Message("[W] DeleteFileW (%ls)\n", lpFileName);
		return TRUE;
	}
	return DeleteFileW(lpFileName);
}

HANDLE WINAPI FindFirstFileAHook(
	LPCSTR             lpFileName,
	LPWIN32_FIND_DATAA lpFindFileData
) {
	if (checkCaller("FindFirstFileA")) {
		if (S2EIsSymbolic((PVOID)lpFileName, 0x4)) {
			HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
			dummyHandles.insert(fileHandle);
			Message("[W] FindFirstFileA (%s [|] %p) ret:%p\n",
				lpFileName, lpFindFileData, fileHandle);
			return fileHandle;
		}
		else {
			HANDLE fileHandle = FindFirstFileA(lpFileName, lpFindFileData);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
				Message("[W] FindFirstFileA (%s [|] %p) ret:%p\n",
					lpFileName, lpFindFileData, fileHandle);
			}
			return fileHandle;
		}
	}
	return FindFirstFileA(lpFileName, lpFindFileData);
}

HANDLE WINAPI FindFirstFileWHook(
	LPCWSTR            lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	if (checkCaller("FindFirstFileW")) {
		if (S2EIsSymbolic((PVOID)lpFileName, 0x4)) {
			HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
			dummyHandles.insert(fileHandle);
			Message("[W] FindFirstFileW (%ls [|] %p) ret:%p\n",
				lpFileName, lpFindFileData, fileHandle);
			return fileHandle;
		}
		else {
			HANDLE fileHandle = FindFirstFileW(lpFileName, lpFindFileData);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				HANDLE fileHandle = (HANDLE)malloc(sizeof(HANDLE));
				dummyHandles.insert(fileHandle);
				Message("[W] FindFirstFileW (%ls [|] %p) ret:%p\n",
					lpFileName, lpFindFileData, fileHandle);
			}
			return fileHandle;
		}
	}
	return FindFirstFileW(lpFileName, lpFindFileData);
}

DWORD WINAPI GetFileTypeHook(
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
			Message("[W] GetFileType (%p) tag_out:%s\n", hFile, tag.c_str());
			return S2ESymbolicInt(tag.c_str(), 0x4);
		}
	}
	return GetFileType(hFile);
}

BOOL WINAPI ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
) {
	if (checkCaller("ReadFile")) {
		auto it = perHandleBytesToRead.find(hFile);
		if (it == perHandleBytesToRead.end()) {
			perHandleBytesToRead[hFile] = 128;
			it = perHandleBytesToRead.find(hFile);
		}
		DWORD bytes_left = it->second;
		DWORD bytes_read = bytes_left < nNumberOfBytesToRead ? bytes_left : nNumberOfBytesToRead;
		it->second -= bytes_read;

		std::string tagIn = "";
		//Try to get the fileName
		if (fileMap.find(hFile) != fileMap.end()) {
			std::string file_name = fileMap[hFile];
			//If the file is reading the file itself
			if (file_name.find(moduleName) != std::string::npos) {
				return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			}

		}
		if (fileMap.find(hFile) != fileMap.end() && taintFile.find(fileMap[hFile]) != taintFile.end()) {
			std::string tagIn = taintFile[fileMap[hFile]];
		}

		std::string tag = GetTag("ReadFile");
		if (tagIn.length() > 0) {
			Message("[W] ReadFile (%p [|] %p [|] %ld [|] %p [|] %p) tag_in:%s tag_out:%s\n", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, tagIn.c_str(), tag.c_str());
		}
		else {
			Message("[W] ReadFile (%p [|] %p [|] %ld [|] %p [|] %p) tag_out:%s\n", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, tag.c_str());
		}

		std::set<HANDLE>::iterator it_2 = dummyHandles.find(hFile);
		if (it_2 == dummyHandles.end()) {
			BOOL res = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			if (res) {
				cyfiTaint(lpBuffer, *lpNumberOfBytesRead, tag.c_str());
			}
			
		}
		else {
			*lpNumberOfBytesRead = bytes_read;
			S2EMakeSymbolic(lpBuffer, *lpNumberOfBytesRead, tag.c_str());
			S2EMakeSymbolic(lpNumberOfBytesRead, sizeof(DWORD), tag.c_str());
		}

		return TRUE;
	}
	return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI ReadFileHookDep(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
) {
	if (checkCaller("ReadFile")) {
		auto it = perHandleBytesToRead.find(hFile);
		if (it == perHandleBytesToRead.end()) {
			perHandleBytesToRead[hFile] = 128;
			it = perHandleBytesToRead.find(hFile);
		}
		DWORD bytes_left = it->second;
		DWORD bytes_read = bytes_left < nNumberOfBytesToRead ? bytes_left : nNumberOfBytesToRead;
		it->second -= bytes_read;

		std::string tagIn = "";
		//Try to get the fileName
		if (fileMap.find(hFile) != fileMap.end()) {
			std::string file_name = fileMap[hFile];
			//If the file is reading the file itself
			if (file_name.find(moduleName) != std::string::npos) {
				return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			}

		}
		if (fileMap.find(hFile) != fileMap.end() && taintFile.find(fileMap[hFile]) != taintFile.end()) {
			std::string tagIn = taintFile[fileMap[hFile]];
		}

		std::string tag = GetTag("ReadFile");
		if (tagIn.length() > 0) {
			Message("[W] ReadFile (%p [|] %p [|] %ld [|] %p [|] %p) tag_in:%s tag_out:%s\n", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, tagIn.c_str(), tag.c_str());
		}
		else {
			Message("[W] ReadFile (%p [|] %p [|] %ld [|] %p [|] %p) tag_out:%s\n", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, tag.c_str());
		}

		std::set<HANDLE>::iterator it_2 = dummyHandles.find(hFile);
		if (it_2 == dummyHandles.end()) {
			BOOL res = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
			*lpNumberOfBytesRead = bytes_read;
			S2EMakeSymbolic(lpBuffer, *lpNumberOfBytesRead, tag.c_str());
		}
		else {
			*lpNumberOfBytesRead = bytes_read;
			S2EMakeSymbolic(lpBuffer, *lpNumberOfBytesRead, tag.c_str());
			S2EMakeSymbolic(lpNumberOfBytesRead, sizeof(DWORD), tag.c_str());
		}

		return TRUE;
	}
	return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

DWORD WINAPI GetFileSizeHook(
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
			Message("[W] GetFileSize(%p [|] %p) tag_out:%s\n", hFile, lpFileSizeHigh, tag.c_str());
			DWORD res = S2ESymbolicInt(tag.c_str(), DEFAULT_MEM_LEN);

			if (lpFileSizeHigh != NULL) {
				S2EMakeSymbolic(lpFileSizeHigh, 4, tag.c_str());
			}
			return res;
		}
	}
	return GetFileSize(hFile, lpFileSizeHigh);
}

DWORD WINAPI GetFileAttributesAHook(
	LPCSTR lpFileName
) {
	if (checkCaller("GetFileAttributesA")) {
		std::string tag = GetTag("GetFileAttributesA");
		DWORD ret = GetFileAttributesA(lpFileName);
		Message("[W] GetFileAttributesA (%s) ret:%ld tag_out:%s\n", lpFileName, ret, tag.c_str());
		S2EMakeSymbolic(&ret, sizeof(ret), tag.c_str());
		return ret;
	}
	return GetFileAttributesA(lpFileName);
}

DWORD WINAPI GetFileAttributesWHook(
	LPCWSTR lpFileName
) {
	std::string tag = GetTag("GetFileAttributesW");
	DWORD ret = GetFileAttributesW(lpFileName);
	Message("[W] GetFileAttributesW (%ls) ret:%ld tag_out:%s\n", lpFileName, ret, tag.c_str());
	S2EMakeSymbolic(&ret, sizeof(ret), tag.c_str());
	return ret;
}

DWORD WINAPI GetFullPathNameAHook(
	LPCSTR lpFileName,
	DWORD  nBufferLength,
	LPSTR  lpBuffer,
	LPSTR* lpFilePart
) {
	if (checkCaller("GetFullPathNameA")) {
		std::string tag = GetTag("GetFullPathNameA");
		DWORD ret = GetFullPathNameA(lpFileName, nBufferLength, lpBuffer, lpFilePart);
		Message("[W] GetFullPathNameA (%s [|] %ld [|] %p [|] %p) ret:%ld tag_out:%s\n", lpFileName, nBufferLength, lpBuffer, lpFilePart, ret, tag.c_str());
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

BOOL WINAPI GetFileTimeHook(
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
		Message("[W] GetFileTimeHook (%p [|] %p [|] %p [|] %p) tag_out:%s\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime, tag.c_str());
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

BOOL WINAPI WriteFileHook(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
) {
	if (checkCaller("WriteFile")) {

		//Check the tag of the buffer
		std::string buffer_tag = ReadTag((LPVOID)lpBuffer);

		if (buffer_tag.length() > 0) {
			Message("[W] WriteFile (%p [|] %p [|] %ld [|] %p [|] %p) tag_in:%s\n", hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped, buffer_tag.c_str());
			//Update the taintFile map
			if (fileMap.find(hFile) != fileMap.end()) {
				std::string fileName = fileMap[hFile];
				taintFile[fileName] = buffer_tag;
			}
			cyfiPrintMemory((PVOID)lpBuffer, nNumberOfBytesToWrite);
		}
		else {
			Message("[W] WriteFile (%p [|] %p [|] %ld [|] %p [|] %p)", hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
		}

		std::set<HANDLE>::iterator it = dummyHandles.find(hFile);
		if (it == dummyHandles.end()) {
			bool ret = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
			if (lpNumberOfBytesWritten) {
				DWORD written = *lpNumberOfBytesWritten;

				if (written == 0 && perHandleBytesWritten.find(hFile) != perHandleBytesWritten.end()) {
					BOOL cyfi_copy = cyFiCopyFile(hFile);
					Message("Dumping file in WriteFile result: %d", cyfi_copy);
				}
				else {
					if (written > 0) {
						perHandleBytesWritten[hFile] = 1;
					}

				}
			}
			return TRUE;
		}
		else {
			return TRUE;
		}
	}
	else {
		return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	}
}

DWORD WINAPI SetFilePointerHook(
	HANDLE hFile,
	LONG   lDistanceToMove,
	PLONG  lpDistanceToMoveHigh,
	DWORD  dwMoveMethod
)
{
	Message("[W] SetFilePointer (%p [|] %ld [|] %p [|] %ld)", hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
	return -1;

}
