///
/// Copyright (C) 2018, Adrian Herrera
/// All rights reserved.
///
/// 

/*
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif*/

#include <set>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <cassert>

#ifndef WIN32
#define WIN32
#endif
#include <winsock2.h>
#include <Windows.h>
#pragma comment(lib, "Ws2_32.lib")

#include <WinInet.h>
namespace winhttp {
#include <winhttp.h>
}

#include <string.h>
#include <stdlib.h>
#include <strsafe.h>

#include <easyhook.h>

#include <heapapi.h>

#include <atlbase.h>
#include "commands.h"
#include "utils.h"
#include "socket-hook.h"
#include "msvcrt-hook.h"
#include "kernel32-hook.h"
#include "shlwapi-hook.h"
#include "winhttp-hook.h"
#include "wininet-hook.h"
#include "wchar-hook.h"
#include "urlmon-hook.h"
#include "winuser-hook.h"
#include "fileapi-hook.h"
#include "stringapiset-hook.h"
#include "advapi-hook.h"
#include "wingdi-hook.h"
#include "winnls-hook.h"
#include "debugapi-hook.h"
#include "winternl-hook.h"
#include "sysinfoapi-hook.h"
#include "string-hook.h"
#include "timeapi-hook.h"
#include "consoleapi3-hook.h"
#include "processthreadsapi-hook.h"
#include "handleapi-hook.h"
#include "shellapi-hook.h"
#include "winbase-hook.h"
#include "stringapiset-hook.h"
#include "stdlib-hook.h"
#include "esent-hook.h"
#include <synchapi.h>

INT s2eVersion = 0;

std::map<std::string, std::string> taintFile;

/// Keep track of thread handles we've created
static std::set<HANDLE> dummyThreadHandles;

/// Keep track of dummy Stream handles that we've created
static std::set<HGLOBAL> dummyStreams;

/// Keep track of base addrs
static std::set<LPVOID> dummyBaseAddrs;

char moduleName[MAX_PATH];


////////////////////////////////////////////////////////////////////
/// KERNEL32
////////////////////////////////////////////////////////////////////

static HANDLE CreateThreadHook(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
) {

    //UINT8 returnHandle = S2ESymbolicChar("handle", 1);
    //if (returnHandle) {

    HANDLE rHandle = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    dummyThreadHandles.insert(rHandle);
    Message("[W] CreateThread(%p)\n", rHandle);
    return rHandle;
}

static VOID ExitThreadHook(
    DWORD dwExitCode
)
{
    Message("[W] ExitThread(%i)\n", dwExitCode);

    auto threadID = dummyThreadHandles.begin();
    DWORD exitcode;
    BOOL ret;
    ret = GetExitCodeThread(*threadID, &exitcode);
    free(*threadID);
    dummyThreadHandles.erase(threadID);
    ExitThread(exitcode);
}


static LPVOID WINAPI VirtualAllocHook(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) {
    if (lpAddress != 0 && S2EIsSymbolic(&lpAddress, 4)) {
        Message("VirtualAlloc Pointer Symbolic!\n");
        std::string tag = ReadTag(&lpAddress);
        if (tag != "") {
            Message("VA Pointer constraints %s\n", tag.c_str());
        }
    }

    if (S2EIsSymbolic(&dwSize, 4)) {
        Message("VirtualAlloc Size Symbolic!\n");
        std::string tag = ReadTag(&dwSize);
        if (tag != "") {
            Message("VA Size constraints %s\n", tag.c_str());
        }
    }

    if (lpAddress != 0 && S2EIsSymbolic(lpAddress, dwSize)) {
        Message("VirtualAlloc Symbolic!\n");
    }

    Message("[W] VirtualAlloc (%p [|] %i [|] %ld [|] %ld)\n", lpAddress, dwSize, flAllocationType, flProtect);

    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}


static BOOL WINAPI VirtualFreeHook(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
) {
    bool ignore_vf = false;

    Message("[W] VirtualFree (%p [|] %i [|] %ld)\n", lpAddress, dwSize, dwFreeType);

    if (S2EIsSymbolic(&lpAddress, 4)) {
        ignore_vf = true;
        Message("VirtualFree symbolic pointer\n");
        std::string tag = ReadTag(&lpAddress);
        if (tag != "") {
            Message("VF Pointer constraints %s\n", tag.c_str());
        }
    }

    if (S2EIsSymbolic(lpAddress, 4)) {
        Message("VirtualFree symbolic buffer\n");
    }

    if (S2EIsSymbolic(&dwSize, 4)) {
        ignore_vf = true;
        Message("VirtualFree symbolic size\n");
        std::string tag = ReadTag(&dwSize);
        if (tag != "") {
            Message("VF dwSize constraints %s\n", tag.c_str());
        }
    }

    if (ignore_vf) {
        return true;
    }
    else {
        return VirtualFree(lpAddress, dwSize, dwFreeType);
    }
    
}

static HRESULT CreateStreamOnHGlobalHook(
    HGLOBAL  hGlobal,
    BOOL     fDeleteOnRelease,
    LPSTREAM* ppstm
) {
    
    //HGLOBAL hMem = GlobalAlloc(0x0042, 0x1000);
    HRESULT hr = 0x00000000;
    //dummyStreams.insert(stream);
    try {
        HRESULT hr = CreateStreamOnHGlobal(hGlobal, fDeleteOnRelease, ppstm);//  0x00000000;
        Message("[W] CreateStreamOnHGlobal (%p [|] %i [|] %p) ret:%p\n", hGlobal, fDeleteOnRelease, ppstm, hr);

    }
    catch (int e) {
        Message("CreateStreamOnHGlobal Failed %i!\n", e);

    }
    return E_OUTOFMEMORY;
}

void ExitProcessHook(
    UINT uExitCode
) {
    return ExitThread(uExitCode);
}

class CyFIFuncType {
public:
    LPCSTR lib;
    LPCSTR funcName;
    LPVOID hookFunc;
    HOOK_TRACE_INFO hook;
    CyFIFuncType(LPCSTR lib, LPCSTR funcName, LPVOID hookFunc, HOOK_TRACE_INFO hook) {
        this->lib = lib;
        this->funcName = funcName;
        this->hookFunc = hookFunc;
        this->hook = hook;
    }
};

static BOOL WINAPI SetProcessDEPPolicyHook(DWORD dwFlags)
{
    Message("[W] SetProcessDepPolicy (%ld)\n", dwFlags);
    return SetProcessDEPPolicy(dwFlags);
}

#include <Dbghelp.h>
static BOOL WINAPI MiniDumpWriteDumpHook(
    HANDLE                            hProcess,
    DWORD                             ProcessId,
    HANDLE                            hFile,
    MINIDUMP_TYPE                     DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
) {
    Message("[W] MiniDumpWriteDump ()\n");
    return TRUE;
}

#include <sysinfoapi.h>
static UINT WINAPI GetSystemDirectoryAHook(
    LPSTR lpBuffer,
    UINT  uSize
) {
    Message("[W] GetSystemDirectoryA (%s [|] %i)\n", lpBuffer, uSize);
    return GetSystemDirectoryA(lpBuffer, uSize);

}

static DWORD WINAPI GetCurrentProcessIdHook() {
    DWORD ret = GetCurrentProcessId();
    Message("ProcID %d\n", ret);
    return ret;
}
static DWORD WINAPI GetCurrentThreadIdHook() {
    DWORD ret = GetCurrentThreadId();
    Message("ThreadID %d\n", ret);
    return ret;
}
static HMODULE WINAPI GetModuleHandleWHook(
    LPCWSTR lpModuleName
) {
    Message("GetModuleHandleW tid=%d\n", GetCurrentThreadId());
    return GetModuleHandleW(lpModuleName);

}

static FARPROC WINAPI GetProcAddressHook(
    HMODULE hModule,
    LPCSTR  lpProcName
) {
    if (checkCaller("GetProcAddress")) {
        FARPROC ret = GetProcAddress(hModule, lpProcName);
        Message("[W] GetProcAddress (%p [|] %s) ret:%d\n", hModule, lpProcName, ret);
        return ret;
    }

    return GetProcAddress(hModule, lpProcName);
}

static HWND WINAPI GetCaptureHook() {
    HWND ret = GetCapture();
    if (ret == 0) {
        ret = (HWND)malloc(sizeof(HWND));
    }
    Message("[W] GetCaptureHook() res:%p\n", ret);
    return ret;
}


static int MultiByteToWideCharHook(
    UINT                              CodePage,
    DWORD                             dwFlags,
    _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
    int                               cbMultiByte,
    LPWSTR                            lpWideCharStr,
    int                               cchWideChar
) {
    killAnalysis("MultiByteToWideChar");
    return 0;

}

DWORD WINAPI WaitForSingleObjectHook(
    HANDLE hHandle,
    DWORD  dwMilliseconds
) {
    Message("[W] WaitForSingleObject(%p [|] %ld)\n", hHandle, dwMilliseconds);
    return WAIT_TIMEOUT;
}

CyFIFuncType functionToHook[] = {

    //CyFIFuncType("dbghelp", "MiniDumpWriteDump", MiniDumpWriteDumpHook, {NULL}),
    //CyFIFuncType("kernel32", "GetSystemDirectoryA", GetSystemDirectoryAHook, {NULL}),

    //CyFIFuncType("kernel32", "LoadLibraryExW", LoadLibraryExWHook, {NULL}),
    //CyFIFuncType("kernel32", "GetTickCount", GetTickCountHook, {NULL}),
    //CyFIFuncType("kernel32", "GetProcAddress", GetProcAddressHook, {NULL}),
    //CyFIFuncType("User32", "GetCapture", GetCaptureHook, {NULL}),

    //CyFIFuncType("kernel32", "VirtualAlloc", VirtualAllocHook, {NULL}),
    CyFIFuncType("Kernel32", "VirtualFree", VirtualFreeHook, {NULL}),
    //CyFIFuncType("Kernel32", "lstrlenA", lstrlenAHook, {NULL}),

    /* Won't work...for testing razy only*/
    //CyFIFuncType("kernel32", "MultiByteToWideChar", MultiByteToWideCharHook, {NULL}),
    //CyFIFuncType("ole32", "CreateStreamOnHGlobal", CreateStreamOnHGlobalHook, {NULL}),
    //CyFIFuncType("kernel32", "ExitProcess", ExitProcessHook, {NULL}),

    CyFIFuncType("Ws2_32", "socket", sockethook, {NULL}),
    CyFIFuncType("Ws2_32", "connect", connecthook, {NULL}),
    CyFIFuncType("Ws2_32", "closesocket", closesockethook, {NULL}),
    CyFIFuncType("Ws2_32", "getaddrinfo", getaddrinfohook, {NULL}),
    CyFIFuncType("Ws2_32", "getsockname", getsocknamehook, {NULL}),   
    CyFIFuncType("Ws2_32", "getpeername", getpeernamehook, {NULL}),
    CyFIFuncType("Ws2_32", "ntohs", ntohshook, {NULL}),
    CyFIFuncType("Ws2_32", "recv", recvhook, {NULL}),
    CyFIFuncType("Ws2_32", "accept", accepthook, {NULL}),
    CyFIFuncType("Ws2_32", "select", selecthook, {NULL}),
    CyFIFuncType("Ws2_32", "send", sendhook, {NULL}),
    CyFIFuncType("Ws2_32", "sendto", sendtohook, {NULL}),
    CyFIFuncType("Ws2_32", "bind", bindhook, {NULL}),
    CyFIFuncType("Ws2_32", "gethostbyname", gethostbynamehook, {NULL}),
    CyFIFuncType("Ws2_32", "inet_ntoa", inet_ntoahook, {NULL}),
    CyFIFuncType("Ws2_32", "inet_ntop", inet_ntophook, {NULL}),

    CyFIFuncType("wsock32", "socket", sockethook, {NULL}),
    CyFIFuncType("wsock32", "connect", connecthook, {NULL}),
    CyFIFuncType("wsock32", "closesocket", closesockethook, {NULL}),
    CyFIFuncType("wsock32", "getaddrinfo", getaddrinfohook, {NULL}),
    CyFIFuncType("wsock32", "getsockname", getsocknamehook, {NULL}),
    CyFIFuncType("wsock32", "getpeername", getpeernamehook, {NULL}),
    CyFIFuncType("wsock32", "ntohs", ntohshook, {NULL}),
    CyFIFuncType("wsock32", "recv", recvhook, {NULL}),
    CyFIFuncType("wsock32", "accept", accepthook, {NULL}),
    CyFIFuncType("wsock32", "select", selecthook, {NULL}),
    CyFIFuncType("wsock32", "send", sendhook, {NULL}),
    CyFIFuncType("wsock32", "sendto", sendtohook, {NULL}),
    CyFIFuncType("wsock32", "bind", bindhook, {NULL}),
    CyFIFuncType("wsock32", "gethostbyname", gethostbynamehook, {NULL}),
    CyFIFuncType("wsock32", "inet_ntoa", inet_ntoahook, {NULL}),
    CyFIFuncType("wsock32", "inet_ntop", inet_ntophook, {NULL}),


    CyFIFuncType("msvcrt", "fopen", fopenhook, {NULL}),
    CyFIFuncType("msvcrt", "fwrite", fwritehook, {NULL}),
    CyFIFuncType("msvcrt", "fread", freadhook, {NULL}),
    //CyFIFuncType("msvcrt", "fseek", fseekhook, {NULL}),
    CyFIFuncType("msvcrt", "fclose", fclosehook, {NULL}),

    CyFIFuncType("msvcrt", "strstr", strstrhook, {NULL}),
    CyFIFuncType("msvcrt", "_strlwr", _strlwrhook, {NULL}),

    CyFIFuncType("msvcrt", "strrchr", strrchrhook, {NULL}),

    //CyFIFuncType("msvcrt", "rand", randhook, {NULL}),

    CyFIFuncType("kernel32", "Sleep", SleepHook, {NULL}),

    //CyFIFuncType("winmm", "timeGetTime", timeGetTimeHook, {NULL}),

    CyFIFuncType("shlwapi", "StrStrA", StrStrAHook, {NULL}),
    CyFIFuncType("shlwapi", "StrStrW", StrStrWHook, {NULL}),
    CyFIFuncType("shlwapi", "StrStrIA", StrStrIAHook, {NULL}),
    CyFIFuncType("shlwapi", "StrStrIW", StrStrIWHook, {NULL}),

    CyFIFuncType("winhttp", "WinHttpOpen", WinHttpOpenHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpCrackUrl", WinHttpCrackUrlHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpSendRequest", WinHttpSendRequestHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpReceiveResponse", WinHttpReceiveResponseHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpQueryDataAvailable", WinHttpQueryDataAvailableHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpReadData", WinHttpReadDataHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpWriteData", WinHttpWriteDataHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpConnect", WinHttpConnectHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpAddRequestHeaders", WinHttpAddRequestHeadersHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpCloseHandle", WinHttpCloseHandleHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpGetProxyForUrl", WinHttpGetProxyForUrlHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpOpenRequest", WinHttpOpenRequestHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpQueryHeaders", WinHttpQueryHeadersHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpQueryOption", WinHttpQueryOptionHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpResetAutoProxy", WinHttpResetAutoProxyHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpSetCredentials", WinHttpSetCredentialsHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpSetOption", WinHttpSetOptionHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpSetTimeouts", WinHttpSetTimeoutsHook, {NULL}),

    CyFIFuncType("wininet", "InternetConnectA", InternetConnectAHook, {NULL}),
    CyFIFuncType("wininet", "InternetConnectW", InternetConnectWHook, {NULL}),
    CyFIFuncType("wininet", "HttpOpenRequestA", HttpOpenRequestAHook, {NULL}),
    CyFIFuncType("wininet", "HttpOpenRequestW", HttpOpenRequestWHook, {NULL}),
    CyFIFuncType("wininet", "HttpSendRequestA", HttpSendRequestAHook, {NULL}),
    CyFIFuncType("wininet", "HttpSendRequestW", HttpSendRequestWHook, {NULL}),
    CyFIFuncType("wininet", "InternetReadFile", InternetReadFileHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenUrlA", InternetOpenUrlAHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenUrlW", InternetOpenUrlWHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenA", InternetOpenAHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenW", InternetOpenWHook, {NULL}),
    CyFIFuncType("wininet", "InternetCloseHandle", InternetCloseHandleHook, {NULL}),
    CyFIFuncType("wininet", "HttpAddRequestHeadersA", HttpAddRequestHeadersAHook, {NULL}),
    CyFIFuncType("wininet", "HttpAddRequestHeadersW", HttpAddRequestHeadersWHook, {NULL}),
    CyFIFuncType("wininet", "HttpEndRequestA", HttpEndRequestAHook, {NULL}),
    CyFIFuncType("wininet", "HttpEndRequestW", HttpEndRequestWHook, {NULL}),
    CyFIFuncType("wininet", "HttpQueryInfoA", HttpQueryInfoAHook, {NULL}),
    CyFIFuncType("wininet", "HttpQueryInfoW", HttpQueryInfoWHook, {NULL}),
    CyFIFuncType("wininet", "InternetQueryDataAvailable", InternetQueryDataAvailableHook, {NULL}),
    CyFIFuncType("wininet", "InternetQueryOptionA", InternetQueryOptionAHook, {NULL}),
    CyFIFuncType("wininet", "InternetQueryOptionW", InternetQueryOptionWHook, {NULL}),
    CyFIFuncType("wininet", "InternetSetOptionA", InternetSetOptionAHook, {NULL}),
    CyFIFuncType("wininet", "InternetSetOptionW", InternetSetOptionWHook, {NULL}),
    CyFIFuncType("wininet", "InternetWriteFile", InternetWriteFileHook, {NULL}),
    CyFIFuncType("wininet", "InternetGetConnectedState", InternetGetConnectedStateHook, {NULL}),
    CyFIFuncType("wininet", "InternetCheckConnectionA", InternetCheckConnectionAHook, { NULL }),
    CyFIFuncType("wininet", "InternetCheckConnectionW", InternetCheckConnectionWHook, { NULL }),

    CyFIFuncType("Kernel32", "LocalAlloc", LocalAllocHook, {NULL}),
    CyFIFuncType("urlmon.dll", "URLDownloadToFile", URLDownloadToFileHook, {NULL}),
    CyFIFuncType("urlmon.dll", "URLDownloadToFileA", URLDownloadToFileHook, { NULL }),
    CyFIFuncType("urlmon.dll", "URLDownloadToFileW", URLDownloadToFileWHook, {NULL}),
    CyFIFuncType("urlmon.dll", "URLDownloadToCacheFile", URLDownloadToCacheFileAHook, { NULL }),
    CyFIFuncType("urlmon.dll", "URLDownloadToCacheFileA", URLDownloadToCacheFileAHook, {NULL}),
    CyFIFuncType("urlmon.dll", "URLDownloadToCacheFileW", URLDownloadToCacheFileWHook, { NULL }),

    CyFIFuncType("esent.dll", "JetSetSystemParameter", JetSetSystemParameterHook, {NULL}),

    //CyFIFuncType("kernel32", "SetFilePointer", SetFilePointerHook, {NULL}),

    //CyFIFuncType("ntdll", "wcschr", wcschrHook, {NULL}),
    //CyFIFuncType("ntdll", "wcsrchr", wcsrchrHook, {NULL}),
    //CyFIFuncType("ntdll", "wcscmp", wcscmpHook, {NULL}),
    CyFIFuncType("shell32", "ShellExecuteW", ShellExecuteWHook, {NULL}),
    CyFIFuncType("shell32", "ShellExecuteA", ShellExecuteAHook, {NULL}),
    //CyFIFuncType("shell32", "SHFileOperationA", SHFileOperationAHook, { NULL }),
    //CyFIFuncType("User32", "PeekMessageA", PeekMessageAHook, { NULL }),
    //CyFIFuncType("kernel32", "WaitForSingleObject", WaitForSingleObjectHook, { NULL }),


    //CyFIFuncType("User32", "GetKeyboardType", GetKeyboardTypeHook, {NULL}),
    //CyFIFuncType("User32", "GetKeyboardLayout", GetKeyboardLayoutHook, {NULL}),
    //CyFIFuncType("User32", "GetSystemMetrics", GetSystemMetricsHook, {NULL}),
    //CyFIFuncType("User32", "EnumDisplayMonitors", EnumDisplayMonitorsHook, {NULL}),
    //CyFIFuncType("User32", "GetCursorPos", GetCursorPosHook, {NULL}),
    
    //CyFIFuncType("Kernel32", "GetCommandLineA", GetCommandLineAHook, {NULL}),

    //CyFIFuncType("Kernel32", "GetCommandLineA", GetCommandLineAHook, {NULL}),
    //CyFIFuncType("User32", "wsprintfA", wsprintfAHook, {NULL}),
    
    CyFIFuncType("Kernel32", "CreateFileA", CreateFileAHook, {NULL}),
    CyFIFuncType("Kernel32", "DeleteFileA", DeleteFileAHook, {NULL}),
    CyFIFuncType("Kernel32", "DeleteFileW", DeleteFileWHook, {NULL}),
    //CyFIFuncType("Kernel32", "GetFileType", GetFileTypeHook, {NULL}),
    CyFIFuncType("Kernel32", "CreateFileW", CreateFileWHook, {NULL}),
    CyFIFuncType("kernel32", "ReadFile", ReadFileHook, {NULL}),
    CyFIFuncType("kernel32", "WriteFile", WriteFileHook, {NULL}),
    CyFIFuncType("kernel32", "CloseHandle", CloseHandleHook, {NULL}),
    CyFIFuncType("kernel32", "CopyFileA", CopyFileAHook, { NULL }),
    CyFIFuncType("kernel32", "CopyFileW", CopyFileWHook, { NULL }),
    CyFIFuncType("kernel32", "PathFileExistsA", PathFileExistsAHook, { NULL }),
    CyFIFuncType("kernel32", "PathFileExistsW", PathFileExistsWHook, { NULL }),

    CyFIFuncType("kernel32", "CreateProcessA", CreateProcessAHook, {NULL}),
    CyFIFuncType("kernel32", "CreateProcessW", CreateProcessWHook, {NULL}),

    CyFIFuncType("kernel32", "WideCharToMultiByte", WideCharToMultiByteHook, { NULL }),

    // CyFIFuncType("ntdll", "_wtoi", _wtoiHook, { NULL }),

    //CyFIFuncType("kernel32", "GetTickCount", GetTickCountHook, { NULL }),

    CyFIFuncType("kernel32", "GetSystemDefaultLangID", GetSystemDefaultLangIDHook, { NULL }),

    CyFIFuncType("user32", "GetAsyncKeyState", GetAsyncKeyStateHook, { NULL }),
    /* Evasion Techniques*/
    //CyFIFuncType("kernel32", "GetModuleFileNameA", GetModuleFileNameAHook, {NULL}),
    //CyFIFuncType("kernel32", "TlsGetValue", TlsGetValueHook, { NULL }),
    //CyFIFuncType("kernel32", "GetModuleFileNameW", GetModuleFileNameWHook, {NULL}),

    //CyFIFuncType("user32", "GetAsyncKeyState", GetAsyncKeyStateHook, { NULL }),

    /*CyFIFuncType("Kernel32", "GetSystemInfo", GetSystemInfoHook, {NULL}),
    CyFIFuncType("kernel32", "QueryPerformanceCounter", QueryPerformanceCounterHook, {NULL}),
    CyFIFuncType("kernel32", "GetCommandLineW", GetCommandLineWHook, {NULL}),
    CyFIFuncType("kernel32", "IsProcessorFeaturePresent", IsProcessorFeaturePresentHook, {NULL}),
    CyFIFuncType("kernel32", "GetFileType", GetFileTypeHook, {NULL}),
    CyFIFuncType("kernel32", "GetEnvironmentStringsW", GetEnvironmentStringsWHook, {NULL}),
    CyFIFuncType("kernel32", "FreeEnvironmentStringsW", FreeEnvironmentStringsWHook, {NULL}),
    CyFIFuncType("kernel32", "GetSystemTimeAsFileTime", GetSystemTimeAsFileTimeHook, {NULL}),
    CyFIFuncType("advapi32", "RegOpenKeyExA", RegOpenKeyExAHook, {NULL}),
    CyFIFuncType("advapi32", "RegOpenKeyExW", RegOpenKeyExWHook, {NULL}),
    CyFIFuncType("advapi32", "RegCloseKey", RegCloseKeyHook, {NULL}),
    CyFIFuncType("advapi32", "RegGetValueA", RegGetValueAHook, {NULL}),
    CyFIFuncType("kernel32", "RegGetValueA", RegGetValueAHook, {NULL}),
    CyFIFuncType("advapi32", "RegGetValueW", RegGetValueWHook, {NULL}),
    CyFIFuncType("kernel32", "RegGetValueW", RegGetValueWHook, {NULL}),
    CyFIFuncType("advapi32", "RegQueryValueExA", RegQueryValueExAHook, {NULL}),
    CyFIFuncType("kernel32", "RegQueryValueExA", RegQueryValueExAHook, {NULL}),
    CyFIFuncType("advapi32", "RegQueryValueExW", RegQueryValueExWHook, {NULL}),
    CyFIFuncType("kernel32", "RegQueryValueExW", RegQueryValueExWHook, {NULL}),
    CyFIFuncType("kernel32", "GetTickCount", GetTickCountHook, {NULL}),
    CyFIFuncType("kernel32", "GetFileSize", GetFileSizeHook, {NULL}),
    CyFIFuncType("gdi32", "GetDeviceCaps", GetDeviceCapsHook, {NULL}),
    CyFIFuncType("user32", "GetDC", GetDCHook, {NULL}),
    CyFIFuncType("user32", "GetSysColor", GetSysColorHook, {NULL}),
    CyFIFuncType("kernel32", "GetUserDefaultUILanguage", GetUserDefaultUILanguageHook, {NULL}),
    //CyFIFuncType("kernel32", "GetFileAttributesA", GetFileAttributesAHook, {NULL}),
    //CyFIFuncType("kernel32", "GetFileAttributesW", GetFileAttributesWHook, { NULL }),
    CyFIFuncType("kernel32", "GetFullPathNameA", GetFullPathNameAHook, { NULL }),
    // CyFIFuncType("kernel32", "FindClose", FindCloseHook, { NULL }),
    CyFIFuncType("kernel32", "IsDebuggerPresent", IsDebuggerPresentHook, { NULL }),
    CyFIFuncType("kernel32", "CheckRemoteDebuggerPresent", CheckRemoteDebuggerPresentHook, { NULL }),
    //CyFIFuncType("kernel32", "GetLocaleInfoA", GetLocaleInfoAHook, { NULL }),
    CyFIFuncType("kernel32", "GetOEMCP", GetOEMCPHook, { NULL }),
   // CyFIFuncType("kernel32", "GetThreadLocale", GetThreadLocaleHook, { NULL }),
    CyFIFuncType("ntdll", "RtlTimeToSecondsSince1970", RtlTimeToSecondsSince1970Hook, { NULL }),
    CyFIFuncType("user32", "GetLastInputInfo", GetLastInputInfoHook, { NULL }),
    CyFIFuncType("kernel32", "GetFileTime", GetFileTimeHook, { NULL }),
    CyFIFuncType("kernel32", "GetLocalTime", GetLocalTimeHook, { NULL }),
    

    CyFIFuncType("wininet", "InternetAttemptConnect", InternetAttemptConnectHook, { NULL }),
    CyFIFuncType("winhttp", "WinHttpGetIEProxyConfigForCurrentUser", WinHttpGetIEProxyConfigForCurrentUserHook, { NULL }),*/

};


// EasyHook will be looking for this export to support DLL injection. If not
// found then DLL injection will fail
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO*);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo) {
    // Unused
    (void*)inRemoteInfo;

    // Used by the Message function to decide where to write output to
    s2eVersion = S2EGetVersion();

    HINSTANCE hurlmon = LoadLibrary(L"urlmon");

    GetModuleFileNameA(GetModuleHandle(NULL), moduleName, sizeof(moduleName));

    PathStripPathA(moduleName);

    Message("Current module is %s\n", moduleName);

    if (hurlmon == NULL) {
        Message("Failed to load %ld\n",
            GetLastError());
    }

    for (unsigned i = 0; i < sizeof(functionToHook) / sizeof(CyFIFuncType); i++) {
        LPCSTR moduleName = functionToHook[i].lib;
        LPCSTR functionName = functionToHook[i].funcName;

        HMODULE hmodule = GetModuleHandleA(moduleName);

        //Install the hook
        NTSTATUS result = LhInstallHook(GetProcAddress(GetModuleHandleA(moduleName), functionName),
            functionToHook[i].hookFunc,
            NULL,
            &functionToHook[i].hook);

        if (FAILED(result)) {
            Message("Failed to hook %s.%s: %S\n", moduleName, functionName,
                RtlGetLastErrorString());
        }
        else {
            Message("Successfully hooked %s.%s\n", moduleName, functionName);
        }

        // Ensure that all threads _except_ the injector thread will be hooked
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &functionToHook[i].hook);
    }
    RhWakeUpProcess();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        // Don't exit until all child processes have terminated (or a timeout is
        // reached)
    case DLL_PROCESS_DETACH:
        return WaitForChildProcesses(CHILD_PROCESS_TIMEOUT);
    }

    return TRUE;
}

