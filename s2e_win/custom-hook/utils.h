#pragma once

// We need this header file to make things symbolic and to write to the S2E log
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}

#include <Windows.h>
#include <string>
#include <map>

/// Maximum timeout to wait for child processes to terminate (in milliseconds).
/// Can also be set to INFINITE.
#define CHILD_PROCESS_TIMEOUT 10 * 1000

/// Maximum message length to write to S2E debug log
#define S2E_MSG_LEN 1024//512

/// Maximum path length
#define MAX_PATH_LEN 256

/// Default mem length
#define DEFAULT_MEM_LEN 128

/// S2E version number, or 0 if not running in S2E mode
extern INT s2eVersion;

extern std::map<std::string, std::string> taintFile;

extern char moduleName[MAX_PATH];

void Message(LPCSTR fmt, ...);

std::string GetTag(PCSTR funcName);

bool checkCaller(std::string funcName);

void killAnalysis(std::string funcName);

std::string lpcstrToString(LPCSTR name);

std::string lpcwstrToString(LPCWSTR name);

std::string ReadTag(PVOID Buffer);

void concretizeAll(PVOID Buffer);

std::string getFileTag(LPCSTR buffer);

std::string getFileTag(LPCWSTR buffer);

bool cyFiCopyFile(HANDLE hFile);

bool cyFiDumpFile(char* lpStrFilePath, std::string tag);

void cyfiTaint(PVOID Buffer, UINT32 Size, PCSTR Name, bool remove=true);

bool IsTainted(PVOID Buffer);

void cyfiPrintMemory(PVOID Buffer, size_t Size);

size_t cyfiwcslen(wchar_t* Buffer);

size_t cyfistrlen(char* Buffer);
