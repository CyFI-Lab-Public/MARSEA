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

static VOID* memcpy_ntdll_model(
    void* dst,
    const void* src,
    size_t num
) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_MEMCPY;
    Command.Memcpy.dst = (uint64_t)dst;
    Command.Memcpy.src = (uint64_t)src;
    Command.Memcpy.n = num;

    Message("[W] (ntdll) memcpy (%p, %p, %i)\n", dst, src, num);
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    
    if (Command.Memcpy.symbolic) {
        Message("[W] memcpy received a symbolic src. Symbolizing the dst.\n");
        //return memcpy(dst, src, num);
        //char con[41] = "aHR0cHM6Ly93MHJtLmluL2pvaW4vam9pbi5waHA=";
        //memcpy((void*)dst, con, sizeof(con));
        S2EMakeSymbolic((PVOID)dst, 12, "CyFi_Memcpy");

    }
    else if (Command.needOrigFunc == 1) {
        Message("[W] memcpy: function model failed with concrete params, calling ntdll.memcpy.\n");
        return memcpy(dst, src, num);
    }
    else {
        return (void*)Command.Memcpy.dst;
    }

}

static VOID* memset_ntdll_model(
    void* ptr,
    int value,
    size_t num
) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_MEMSET;
    Command.Memset.ptr = (uint64_t)ptr;
    Command.Memset.value = value;
    Command.Memset.num = (uint64_t)num;

    Message("[W] (ntdll) memset (%p, %i, %i)\n", ptr, value, num);
    //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    return memset(ptr, value, num);

    /*if (Command.Memset.symoblic) {
        S2EMakeSymbolic((PVOID)ptr, 12, "CyFi_Memset");
    }
   
    return memset(ptr, value, num);*/
}

static INT lstrlenA_model(
    LPCSTR lpString
) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_LSTRLENA;
    Command.LstrlenA.lpString = (uint64_t)lpString;

    /*Message("[W] lstrlenA (%s, %p,  %i)\n", lpString, lpString);
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    int ret = S2ESymbolicInt(lpString, 25);
    Message("h1)\n", lpString, lpString);

    return ret;
    if (Command.LstrlenA.symbolic) {
        int ret = S2ESymbolicInt(lpString, 25);
        Message("h1)\n", lpString, lpString);

        return ret;
    }*/
    return lstrlenA(lpString);
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
/*
static INT MultiByteToWideCharHook(
    UINT                              CodePage,
    DWORD                             dwFlags,
    _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
    int                               cbMultiByte,
    LPWSTR                            lpWideCharStr,
    int                               cchWideChar
) {

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_MULTIBYTETOWIDECHAR;
    Command.MultiByteToWideChar.CodePage = (uint64_t)CodePage;
    Command.MultiByteToWideChar.dwFlags = (uint64_t)dwFlags;
    Command.MultiByteToWideChar.lpMultiByteStr = (uint64_t) lpMultiByteStr;
    Command.MultiByteToWideChar.cbMultiByte = cbMultiByte;
    Command.MultiByteToWideChar.lpWideCharStr = (uint64_t)lpWideCharStr;
    Command.MultiByteToWideChar.cchWideChar = cchWideChar;

    Message("[W] MultiByteToWideChar (%i, %i, %p, A\"%s\", %i, %p, %i)\n", CodePage, dwFlags, lpMultiByteStr, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    if (Command.MultiByteToWideChar.symbolic) {
        S2EMakeSymbolic((PVOID)lpMultiByteStr, DEFAULT_MEM_LEN, "CyFi_MultiByteToWideChar");
        Message("[W] MultiByteToWideChar: symbolizing %p.\n", lpWideCharStr);
    }
    if (cchWideChar == 0) {
        // Force success
        cchWideChar = DEFAULT_MEM_LEN;
    }



    return MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}*/

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
    //CyFIFuncType("Ws2_32", "recv", recvhook, {NULL}),
    //CyFIFuncType("Ws2_32", "accept", accepthook, {NULL}),
    //CyFIFuncType("Ws2_32", "select", selecthook, {NULL}),
    //CyFIFuncType("Ws2_32", "send", sendhook, {NULL}),
    //CyFIFuncType("Ws2_32", "sendto", sendtohook, {NULL}),
    //CyFIFuncType("msvcrt", "fopen", fopenhook, {NULL}),
    //CyFIFuncType("msvcrt", "fwrite", fwritehook, {NULL}),
    //CyFIFuncType("kernel32", "Sleep", SleepHook, {NULL}),

    CyFIFuncType("shlwapi", "StrStrA", StrStrAHook, {NULL}),
    CyFIFuncType("shlwapi", "StrStrW", StrStrWHook, {NULL}),

    CyFIFuncType("winhttp", "WinHttpOpen", WinHttpOpenHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpCrackUrl", WinHttpCrackUrlHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpSendRequest", WinHttpSendRequestHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpReceiveResponse", WinHttpReceiveResponseHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpQueryDataAvailable", WinHttpQueryDataAvailableHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpReadData", WinHttpReadDataHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpWriteData", WinHttpWriteDataHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpConnect", WinHttpConnectHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpAddRequestHeaders", WinHttpAddRequestHeadersHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpCloseHandle", WinHttpCloseHandleHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpGetProxyForUrl", WinHttpGetProxyForUrlHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpOpenRequest", WinHttpOpenRequestHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpQueryHeaders", WinHttpQueryHeadersHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpQueryOption", WinHttpQueryOptionHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpResetAutoProxy", WinHttpResetAutoProxyHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpSetCredentials", WinHttpSetCredentialsHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpSetOption", WinHttpSetOptionHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpSetTimeouts", WinHttpSetTimeoutsHook, {NULL}),

    CyFIFuncType("wininet", "InternetConnectA", InternetConnectAHook, {NULL}),
    CyFIFuncType("wininet", "HttpOpenRequestA", HttpOpenRequestAHook, {NULL}),
    CyFIFuncType("wininet", "HttpSendRequestA", HttpSendRequestAHook, {NULL}),
    CyFIFuncType("wininet", "InternetReadFile", InternetReadFileHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenUrlA", InternetOpenUrlAHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenUrlW", InternetOpenUrlWHook, {NULL}),
    CyFIFuncType("wininet", "InternetReadFile", InternetReadFileHook, {NULL}),
    //CyFIFuncType("wininet", "InternetOpenA", InternetOpenAHook, {NULL}),
    //CyFIFuncType("wininet", "InternetOpenW", InternetOpenWHook, {NULL}),
    CyFIFuncType("wininet", "InternetCloseHandle", InternetCloseHandleHook, {NULL}),
    //CyFIFuncType("wininet", "HttpAddRequestHeadersA", HttpAddRequestHeadersAHook, {NULL}),
    //CyFIFuncType("wininet", "HttpEndRequestA", HttpEndRequestAHook, {NULL}),
    //CyFIFuncType("wininet", "HttpQueryInfoA", HttpQueryInfoAHook, {NULL}),
    //CyFIFuncType("wininet", "InternetQueryDataAvailable", InternetQueryDataAvailableHook, {NULL}),
    //CyFIFuncType("wininet", "InternetQueryOptionA", InternetQueryOptionAHook, {NULL}),
    //CyFIFuncType("wininet", "InternetSetOptionA", InternetSetOptionAHook, {NULL}),
    //CyFIFuncType("wininet", "InternetWriteFile", InternetWriteFileHook, {NULL}),

    //CyFIFuncType("ntdll", "wcschr", wcschrHook, {NULL}),
    //CyFIFuncType("ntdll", "wcsrchr", wcsrchrHook, {NULL}),
    //CyFIFuncType("ntdll", "wcscmp", wcscmpHook, {NULL}),

    //CyFIFuncType("Urlmon", "URLDownloadToFileW", URLDownloadToFileWHook, {NULL}),

    //CyFIFuncType("User32", "GetKeyboardType", GetKeyboardTypeHook, {NULL}),
    //CyFIFuncType("User32", "GetKeyboardLayout", GetKeyboardLayoutHook, {NULL}),
    //CyFIFuncType("User32", "GetSystemMetrics", GetSystemMetricsHook, {NULL}),
    //CyFIFuncType("User32", "EnumDisplayMonitors", EnumDisplayMonitorsHook, {NULL}),
    //CyFIFuncType("User32", "GetCursorPos", GetCursorPosHook, {NULL}),

    //CyFIFuncType("Kernel32", "GetCommandLineA", GetCommandLineAHook, {NULL}),

    //CyFIFuncType("ole32", "CreateStreamOnHGlobal", CreateStreamOnHGlobalHook, {NULL}),
    //CyFIFuncType("Kernel32", "LoadLibraryW", LoadLibraryWHook, {NULL}),

    //CyFIFuncType("Kernel32", "CreateFileA", CreateFileAHook, {NULL}),
    //CyFIFuncType("Kernel32", "DeleteFileA", DeleteFileAHook, {NULL}),
    //CyFIFuncType("Kernel32", "GetFileType", GetFileTypeHook, {NULL}),

    //CyFIFuncType("Kernel32", "MultiByteToWideChar", MultiByteToWideCharHook, {NULL}),
    //CyFIFuncType("Kernel32", "lstrlenA", lstrlenA_model, {NULL}),


};


/*HMODULE LoadLibraryAHook(
    LPCSTR lpLibFileName
)
{
    Message("[W] LoadLibraryA (A\"%s\")\n", lpLibFileName);
    for (unsigned i = 0; i < sizeof(functionToHook) / sizeof(CyFIFuncType); i++) {
        LPCSTR moduleName = functionToHook[i].lib;
        LPCSTR functionName = functionToHook[i].funcName;

        //Uninstall previously installed hook
        LhUninstallHook(&functionToHook[i].hook);
        LhWaitForPendingRemovals();

        //Install the hook
        NTSTATUS result = LhInstallHook(GetProcAddress(GetModuleHandleA(moduleName), functionName),
            functionToHook[i].hookFunc,
            NULL,
            &functionToHook[i].hook);

        if (FAILED(result)) {
            Message("Rehooking failed %s.%s: %S\n", moduleName, functionName,
                RtlGetLastErrorString());
        }
        else {
            Message("Rehooking %s.%s\n", moduleName, functionName);
        }

        // Ensure that all threads _except_ the injector thread will be hooked
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &functionToHook[i].hook);
    }
    RhWakeUpProcess();
    return LoadLibraryA(lpLibFileName);

}

HMODULE LoadLibraryWHook(
    LPCWSTR lpLibFileName
)
{
    Message("[W] LoadLibraryW (A\"%ls\")\n", lpLibFileName);
    for (unsigned i = 0; i < sizeof(functionToHook) / sizeof(CyFIFuncType); i++) {
        LPCSTR moduleName = functionToHook[i].lib;
        LPCSTR functionName = functionToHook[i].funcName;

        //Uninstall previously installed hook
        LhUninstallHook(&functionToHook[i].hook);
        LhWaitForPendingRemovals();

        //Install the hook
        NTSTATUS result = LhInstallHook(GetProcAddress(GetModuleHandleA(moduleName), functionName),
            functionToHook[i].hookFunc,
            NULL,
            &functionToHook[i].hook);

        if (FAILED(result)) {
            Message("Rehooking failed %s.%s: %S\n", moduleName, functionName,
                RtlGetLastErrorString());
        }
        else {
            Message("Rehooking %s.%s\n", moduleName, functionName);
        }

        // Ensure that all threads _except_ the injector thread will be hooked
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &functionToHook[i].hook);
    }
    RhWakeUpProcess();
    return LoadLibraryW(lpLibFileName);
}

CyFIFuncType dynamicLinkingFuncsToHook[] = {
    CyFIFuncType("Kernel32", "LoadLibraryA", LoadLibraryAHook, {NULL}),
    CyFIFuncType("Kernel32", "LoadLibraryW", LoadLibraryWHook, {NULL}),
};*/

// EasyHook will be looking for this export to support DLL injection. If not
// found then DLL injection will fail
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO*);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo) {
    // Unused
    (void*)inRemoteInfo;

    // Used by the Message function to decide where to write output to
    s2eVersion = S2EGetVersion();

    /*for (unsigned i = 0; i < sizeof(dynamicLinkingFuncsToHook) / sizeof(CyFIFuncType); i++) {
        LPCSTR moduleName = dynamicLinkingFuncsToHook[i].lib;
        LPCSTR functionName = dynamicLinkingFuncsToHook[i].funcName;

        //Install the hook
        NTSTATUS result = LhInstallHook(GetProcAddress(GetModuleHandleA(moduleName), functionName),
            dynamicLinkingFuncsToHook[i].hookFunc,
            NULL,
            &dynamicLinkingFuncsToHook[i].hook);

        if (FAILED(result)) {
            Message("Failed to hook %s.%s: %S\n", moduleName, functionName,
                RtlGetLastErrorString());
        }
        else {
            Message("Successfully hooked %s.%s\n", moduleName, functionName);
        }

        // Ensure that all threads _except_ the injector thread will be hooked
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &dynamicLinkingFuncsToHook[i].hook);
    }*/

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

