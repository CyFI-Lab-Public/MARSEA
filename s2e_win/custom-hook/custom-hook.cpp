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

INT s2eVersion = 0;

/// Keep track of thread handles we've created
static std::set<HANDLE> dummyThreadHandles;

/// Keep track of dummy Stream handles that we've created
static std::set<HGLOBAL> dummyStreams;

/// Keep track of base addrs
static std::set<LPVOID> dummyBaseAddrs;

/// Keep track of child processes
static std::set<DWORD> childPids;



///
/// Wait a set timeout (in milliseconds) for all the child processes to
/// terminate.
///
static BOOL WaitForChildProcesses(DWORD timeout) {
    bool retCode = TRUE;

    if (childPids.size() > 0) {
        // Convert the set of PIDS to a list of handles with the appropriate
        // permissions
        std::vector<HANDLE> childHandles;
        for (DWORD pid : childPids) {
            Message("Getting handle to process 0x%x\n", pid);
            HANDLE childHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
                FALSE, pid);
            if (childHandle) {
                childHandles.push_back(childHandle);
            }
            else {
                Message("Unable to open child process 0x%x: 0x%X\n", pid,
                    GetLastError());
                return FALSE;
            }
        }

        // Wait for the processes to terminate
        Message("Waiting %d ms for %d children processes to terminate...\n",
            timeout, childHandles.size());
        DWORD waitRes = WaitForMultipleObjects(childHandles.size(),
            childHandles.data(), TRUE, timeout);
        switch (waitRes) {
        case WAIT_FAILED:
            Message("Failed to wait for child processes: 0x%X\n", GetLastError());
            retCode = FALSE;
            break;
        case WAIT_TIMEOUT:
            Message("Timeout - not all child processes may have terminated\n");
            break;
        }

        // Close all handles
        for (HANDLE handle : childHandles) {
            CloseHandle(handle);
        }
    }

    return retCode;
}


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
    //}
    //else {
        // Explore the program where CreateThread "fails"
    //    Message("[W] CreateThread Failed\n");
    //    return NULL;
    //}
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

static BOOL WINAPI CreateProcessAHook(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    Message("Intercepted CreateProcessA(%s, %s, %p, %p, %d, %d, %p, %s, %p, %p)",
        lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    // Get this DLL's path
    HMODULE hDll = NULL;
    DWORD hModFlags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    if (!GetModuleHandleEx(hModFlags, (LPCTSTR)&Message, &hDll)) {
        Message("Failed to retrive DLL handle: 0x%X\n", GetLastError());
        goto default_create_process;
    }

    WCHAR dllPath[MAX_PATH_LEN];
    if (!GetModuleFileNameW(hDll, dllPath, MAX_PATH_LEN)) {
        Message("Failed to retrive DLL path: 0x%X\n", GetLastError());
        goto default_create_process;
    }

    // Create the new process, but force it to be created in a suspended state
    if (!CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)) {
        Message("Failed to create suspended process: 0x%X\n", GetLastError());
        goto default_create_process;
    }

    // Inject ourselves into the new, suspended process.
    // NativeInjectionEntryPoint will call RhWakeupProcess, which will kick
    // ourselves out of the suspended state
    NTSTATUS result = RhInjectLibrary(lpProcessInformation->dwProcessId,
        lpProcessInformation->dwThreadId, EASYHOOK_INJECT_DEFAULT,
#if defined(_M_IX86)
        dllPath, NULL,
#elif defined(_M_X64)
        NULL, dllPath,
#else
#error "Platform not supported"
#endif
        NULL, 0);

    if (FAILED(result)) {
        Message("RhInjectLibrary failed: %S\n", RtlGetLastErrorString());
        goto default_create_process;
    }

    // Save the handle to the newly-created process
    childPids.insert(lpProcessInformation->dwProcessId);

    Message("Successfully injected %S into %s %s (PID=0x%x)\n", dllPath,
        lpApplicationName, lpCommandLine, lpProcessInformation->dwProcessId);

    return TRUE;

default_create_process:
    return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}


static LPVOID VirtualAllocHook(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) {
    Message("[W] VirtualAlloc (%p, %i, %i, %i, %p)\n", lpAddress, dwSize, flAllocationType, flProtect);
    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    /*
    UINT8 branch = S2ESymbolicChar("lpvResult", 1);
    if (branch) {
        LPVOID lpvResult;
        lpvResult = VirtualAlloc(lpAddress, 1000, flAllocationType, flProtect);
        Message("[W] VirtualAlloc (%p, %i, %i, %i, %p)\n", lpAddress, dwSize, flAllocationType, flProtect, lpvResult);
        //dummyBaseAddrs.insert(lpvResult);
        S2EMakeSymbolic(lpvResult, 18, "CyFi_VirtualAlloc");
        return lpvResult;
    }
    else {
        Message("[W] VirtualAlloc (%p, %i, %i, %i, %p): FAILED\n", lpAddress, dwSize, flAllocationType, flProtect);
        return NULL;
    }*/
}


static BOOL VirtualFreeHook(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
) {
    Message("[W] VirtualFree (%p, %i, %i)\n", lpAddress, dwSize, dwFreeType);
    VirtualFree(lpAddress, dwSize, dwFreeType);
    return TRUE;
    /*
    std::set<LPVOID>::iterator it = dummyBaseAddrs.find(lpAddress);
    if (it == dummyBaseAddrs.end()) {
        return VirtualFree(lpAddress, nSize, dwFreeType);
    }
    else {
        VirtualFree(lpAddress, nSize, dwFreeType);
        free(*it);
        dummyBaseAddrs.erase(it);
        return TRUE;
    }*/
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
        Message("[W] CreateStreamOnHGlobal (%p, %s, %p) Ret:%p\n", hGlobal, fDeleteOnRelease, ppstm, hr);

    }
    catch (int e) {
        Message("[W] CreateStreamOnHGlobal Failed %i\n!", e);

    }
    return hr;

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

static HMODULE LoadLibraryExAHook(
    LPCSTR lpLibFileName,
    HANDLE hFile,
    DWORD  dwFlags
)
{
    Message("[W] LoadLibraryExA (A\"%s\")\n", lpLibFileName);

    return LoadLibraryExA(lpLibFileName, hFile, dwFlags);

}

CyFIFuncType functionToHook[] = {
    CyFIFuncType("Ws2_32", "socket", sockethook, {NULL}),
    CyFIFuncType("Ws2_32", "connect", connecthook, {NULL}),
    CyFIFuncType("Ws2_32", "closesocket", closesockethook, {NULL}),
    CyFIFuncType("Ws2_32", "recv", recvhook, {NULL}),
    CyFIFuncType("Ws2_32", "accept", accepthook, {NULL}),
    CyFIFuncType("Ws2_32", "select", selecthook, {NULL}),
    CyFIFuncType("Ws2_32", "send", sendhook, {NULL}),
    CyFIFuncType("Ws2_32", "sendto", sendtohook, {NULL}),
    CyFIFuncType("msvcrt", "fopen", fopenhook, {NULL}),
    CyFIFuncType("msvcrt", "fwrite", fwritehook, {NULL}),

    CyFIFuncType("kernel32", "Sleep", SleepHook, {NULL}),

    CyFIFuncType("winmm", "timeGetTime", timeGetTimeHook, {NULL}),

    CyFIFuncType("shlwapi", "StrStrA", StrStrAHook, {NULL}),
    CyFIFuncType("shlwapi", "StrStrW", StrStrWHook, {NULL}),

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
    CyFIFuncType("winhttp", "WinHttpResetAutoProxy", WinHttpResetAutoProxyHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpSetCredentials", WinHttpSetCredentialsHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpSetOption", WinHttpSetOptionHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpSetTimeouts", WinHttpSetTimeoutsHook, {NULL}),

    CyFIFuncType("wininet", "InternetConnectA", InternetConnectAHook, {NULL}),
    CyFIFuncType("wininet", "HttpOpenRequestA", HttpOpenRequestAHook, {NULL}),
    CyFIFuncType("wininet", "HttpSendRequestA", HttpSendRequestAHook, {NULL}),
    CyFIFuncType("wininet", "InternetReadFile", InternetReadFileHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenUrlA", InternetOpenUrlAHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenUrlW", InternetOpenUrlWHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenA", InternetOpenAHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenW", InternetOpenWHook, {NULL}),
    CyFIFuncType("wininet", "InternetCloseHandle", InternetCloseHandleHook, {NULL}),
    CyFIFuncType("wininet", "HttpAddRequestHeadersA", HttpAddRequestHeadersAHook, {NULL}),
    CyFIFuncType("wininet", "HttpEndRequestA", HttpEndRequestAHook, {NULL}),
    CyFIFuncType("wininet", "HttpQueryInfoA", HttpQueryInfoAHook, {NULL}),
    CyFIFuncType("wininet", "InternetQueryDataAvailable", InternetQueryDataAvailableHook, {NULL}),
    CyFIFuncType("wininet", "InternetQueryOptionA", InternetQueryOptionAHook, {NULL}),
    CyFIFuncType("wininet", "InternetSetOptionA", InternetSetOptionAHook, {NULL}),
    CyFIFuncType("wininet", "InternetWriteFile", InternetWriteFileHook, {NULL}),

    CyFIFuncType("ole32", "CreateStreamOnHGlobal", CreateStreamOnHGlobalHook, {NULL}),  //->Breaks execution...bad hook


    //CyFIFuncType("ntdll", "wcschr", wcschrHook, {NULL}),
    //CyFIFuncType("ntdll", "wcsrchr", wcsrchrHook, {NULL}),
    //CyFIFuncType("ntdll", "wcscmp", wcscmpHook, {NULL}),

    //CyFIFuncType("Urlmon", "URLDownloadToFile", URLDownloadToFileHook, {NULL}),

    /*CyFIFuncType("User32", "GetKeyboardType", GetKeyboardTypeHook, {NULL}),
    CyFIFuncType("User32", "GetKeyboardLayout", GetKeyboardLayoutHook, {NULL}),
    CyFIFuncType("User32", "GetSystemMetrics", GetSystemMetricsHook, {NULL}),
    CyFIFuncType("User32", "EnumDisplayMonitors", EnumDisplayMonitorsHook, {NULL}),
    CyFIFuncType("User32", "GetCursorPos", GetCursorPosHook, {NULL}),
    CyFIFuncType("Kernel32", "GetCommandLineA", GetCommandLineAHook, {NULL}),*/
    
    //CyFIFuncType("Kernel32", "CreateFileA", CreateFileAHook, {NULL}),
    //CyFIFuncType("Kernel32", "DeleteFileA", DeleteFileAHook, {NULL}),
    //CyFIFuncType("Kernel32", "GetFileType", GetFileTypeHook, {NULL}),
    //CyFIFuncType("Kernel32", "CreateFileW", CreateFileWHook, {NULL}),

    /* Evasion Techniques*/
    /*CyFIFuncType("Kernel32", "GetSystemInfo", GetSystemInfoHook, {NULL}),
    CyFIFuncType("kernel32", "QueryPerformanceCounter", QueryPerformanceCounterHook, {NULL}),
    CyFIFuncType("kernel32", "GetModuleFileNameA", GetModuleFileNameAHook, {NULL}),
    CyFIFuncType("kernel32", "GetModuleFileNameW", GetModuleFileNameWHook, {NULL}),
    CyFIFuncType("kernel32", "GetCommandLineW", GetCommandLineWHook, {NULL}),
    CyFIFuncType("kernel32", "IsProcessorFeaturePresent", IsProcessorFeaturePresentHook, {NULL}),
    CyFIFuncType("kernel32", "GetFileType", GetFileTypeHook, {NULL}),
    CyFIFuncType("kernel32", "GetEnvironmentStringsW", GetEnvironmentStringsWHook, {NULL}),
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
    CyFIFuncType("kernel32", "ReadFile", ReadFileHook, {NULL}),
    CyFIFuncType("kernel32", "GetFileSize", GetFileSizeHook, {NULL}),
    CyFIFuncType("gdi32", "GetDeviceCaps", GetDeviceCapsHook, {NULL}),
    CyFIFuncType("user32", "GetDC", GetDCHook, {NULL}),
    CyFIFuncType("user32", "GetSysColor", GetSysColorHook, {NULL}),
    CyFIFuncType("user32", "GetCursorPos", GetCursorPosHook, {NULL}),
    CyFIFuncType("kernel32", "GetUserDefaultUILanguage", GetUserDefaultUILanguageHook, {NULL}),
    CyFIFuncType("kernel32", "GetFileAttributesA", GetFileAttributesAHook, {NULL}),
    CyFIFuncType("kernel32", "GetFileAttributesW", GetFileAttributesWHook, { NULL }),
    CyFIFuncType("kernel32", "GetFullPathNameA", GetFullPathNameAHook, { NULL }),
    CyFIFuncType("kernel32", "FindClose", FindCloseHook, { NULL }),
    CyFIFuncType("kernel32", "IsDebuggerPresent", IsDebuggerPresentHook, { NULL }),
    CyFIFuncType("kernel32", "CheckRemoteDebuggerPresent", CheckRemoteDebuggerPresentHook, { NULL }),
    CyFIFuncType("kernel32", "GetLocaleInfoA", GetLocaleInfoAHook, { NULL }),
    CyFIFuncType("kernel32", "GetOEMCP", GetOEMCPHook, { NULL }),
    CyFIFuncType("kernel32", "GetThreadLocale", GetThreadLocaleHook, { NULL }),
    CyFIFuncType("wininet", "InternetGetConnectedState", InternetGetConnectedStateHook, { NULL }),
    CyFIFuncType("ntdll", "RtlTimeToSecondsSince1970", RtlTimeToSecondsSince1970Hook, { NULL }),
    CyFIFuncType("user32", "GetLastInputInfo", GetLastInputInfoHook, { NULL }),
    CyFIFuncType("kernel32", "GetFileTime", GetFileTimeHook, { NULL }),
    CyFIFuncType("kernel32", "GetLocalTime", GetLocalTimeHook, { NULL }),
    CyFIFuncType("wininet", "InternetCheckConnectionA", InternetCheckConnectionAHook, { NULL }),
    CyFIFuncType("wininet", "InternetAttemptConnect", InternetAttemptConnectHook, { NULL }),*/

};


// EasyHook will be looking for this export to support DLL injection. If not
// found then DLL injection will fail
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO*);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo) {
    // Unused
    (void*)inRemoteInfo;

    // Used by the Message function to decide where to write output to
    s2eVersion = S2EGetVersion();

    for (unsigned i = 0; i < sizeof(functionToHook) / sizeof(CyFIFuncType); i++) {
        LPCSTR moduleName = functionToHook[i].lib;
        LPCSTR functionName = functionToHook[i].funcName;

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

