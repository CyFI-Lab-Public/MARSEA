///
/// Copyright (C) 2018, Adrian Herrera
/// All rights reserved.
///
/// 
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <set>
#include <vector>

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

INT s2eVersion = 0;

/// Keep track of thread handles we've created
static std::set<HANDLE> dummyThreadHandles;

/// Keep track of dummy Stream handles that we've created
static std::set<HGLOBAL> dummyStreams;

/// Keep track of base addrs
static std::set<LPVOID> dummyBaseAddrs;

/// Keep track of child processes
static std::set<DWORD> childPids;

LPCWSTR g_unique_handle = 0;

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


/*
    FUNCITON MODELS

    MEMCPY
    MEMSET
    STRSTRA
    LSTRLENA
*/


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

    Message("[HLOG] (ntdll) memcpy (%p, %p, %i)\n", dst, src, num);
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    
    if (Command.Memcpy.symbolic) {
        Message("[HLOG] memcpy received a symbolic src. Symbolizing the dst.\n");
        //return memcpy(dst, src, num);
        //char con[41] = "aHR0cHM6Ly93MHJtLmluL2pvaW4vam9pbi5waHA=";
        //memcpy((void*)dst, con, sizeof(con));
        S2EMakeSymbolic((PVOID)dst, 12, "CyFi_Memcpy");

    }
    else if (Command.needOrigFunc == 1) {
        Message("[HLOG] memcpy: function model failed with concrete params, calling ntdll.memcpy.\n");
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

    Message("[HLOG] (ntdll) memset (%p, %i, %i)\n", ptr, value, num);
    //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    return memset(ptr, value, num);

    /*if (Command.Memset.symoblic) {
        S2EMakeSymbolic((PVOID)ptr, 12, "CyFi_Memset");
    }
   
    return memset(ptr, value, num);*/
}

static PCSTR StrStrA_model(
    PCSTR pszFirst,
    PCSTR pszSrch
) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_STRSTRA;
    Command.StrStrA.pszFirst = (uint64_t) pszFirst;
    Command.StrStrA.pszSrch = (uint64_t) pszSrch;
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    /*
    PCSTR ret = StrStrA(pszFirst, pszSrch);
    if (ret == NULL) {

        char start[7] = "start_";
        size_t len = strlen(pszSrch);
        strncat(start, pszSrch, len);
        char end[5] = "_end";
        len = strlen(end);
        strncat(start, end, len);
        memcpy((void*)pszFirst, start, strlen(start));
        Message("%s, %p, %s", pszFirst, pszFirst, start);
        ret = StrStrA(pszFirst, pszSrch);
        Message("[HLOG] StrStrA A\"%s\", %p, Ret: A\"%s\", %p \n", pszFirst, pszFirst, ret, ret);
    }
    S2EMakeSymbolic((PVOID)ret, 0x80, "CyFi_WinHttpReadData_StrStrA");
    return ret;*/


    if (Command.StrStrA.symbolic) {
        Message("[HLOG] STRSTRA pszFirst is symbolic %s\n", Command.StrStrA.ret);
    }
    //pszFirst = ")))))aHR0cHM6Ly93MHJtLmluL2pvaW4vam9pbi5waHA=";
    //memcpy((void*)pszFirst, (void*)buf, sizeof(buf));
    //memcpy((void*)pszFirst, pszSrch, sizeof(pszFirst));
    //PCSTR ret = StrStrA(pszFirst, pszSrch);
    Message("[HLOG] StrStrA (A\"%s\", A\"%s\", %p, %p, A\"%s\")\n", pszFirst, pszSrch, pszFirst, pszSrch);//, ret);

    S2EMakeSymbolic((PVOID)pszFirst, 13, "CyFi_StrStrA");
    return pszFirst+3;

}

static INT lstrlenA_model(
    LPCSTR lpString
) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_LSTRLENA;
    Command.LstrlenA.lpString = lpString;

    Message("[HLOG] lstrlenA (%s, %p,  %i)\n", lpString, lpString);
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    int ret = S2ESymbolicInt(lpString, 25);
    Message("h1)\n", lpString, lpString);

    return ret;
    if (Command.LstrlenA.symbolic) {
        int ret = S2ESymbolicInt(lpString, 25);
        Message("h1)\n", lpString, lpString);

        return ret;
    }
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
    Message("[HLOG] CreateThread(%p)\n", rHandle);
    return rHandle;
    //}
    //else {
        // Explore the program where CreateThread "fails"
    //    Message("[HLOG] CreateThread Failed\n");
    //    return NULL;
    //}
}

static VOID ExitThreadHook(
    DWORD dwExitCode
)
{
    Message("[HLOG] ExitThread(%i)\n", dwExitCode);

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

    Message("[HLOG] MultiByteToWideChar (%i, %i, %p, %i, %p, %i)\n", CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    if (Command.MultiByteToWideChar.symbolic) {
        S2EMakeSymbolic((PVOID)lpWideCharStr, 25, "CyFi_MultiByteToWideChar");
        Message("[HLOG] MultiByteToWideChar: symbolizing %p.\n", lpWideCharStr);
    }
    MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
    if (cchWideChar == 0) {
        // Force success
        cchWideChar = 0x80;
    }
    return cchWideChar;
}

static LPVOID VirtualAllocHook(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) {
    UINT8 branch = S2ESymbolicChar("lpvResult", 1);
    if (branch) {
        LPVOID lpvResult;
        lpvResult = VirtualAlloc(lpAddress, 1000, flAllocationType, flProtect);
        Message("[HLOG] VirtualAlloc (%p, %i, %i, %i, %p)\n", lpAddress, dwSize, flAllocationType, flProtect, lpvResult);
        //dummyBaseAddrs.insert(lpvResult);
        S2EMakeSymbolic(lpvResult, 18, "CyFi_VirtualAlloc");
        return lpvResult;
    }
    else {
        Message("[HLOG] VirtualAlloc (%p, %i, %i, %i, %p): FAILED\n", lpAddress, dwSize, flAllocationType, flProtect);
        return NULL;
    }
}


static BOOL VirtualFreeHook(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
) {
    Message("[HLOG] VirtualFree (%p, %i, %i)\n", lpAddress, dwSize, dwFreeType);
    VirtualFree(lpAddress, dwSize, dwFreeType);
    return true;
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
        Message("[HLOG] CreateStreamOnHGlobal (%p, %s, %p) Ret:%p\n", hGlobal, fDeleteOnRelease, ppstm, hr);

    }
    catch (int e) {
        Message("[HLOG] CreateStreamOnHGlobal Failed %i\n!", e);

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
    //CyFIFuncType("winhttp", "WinHttpOpenRequest", WinHttpOpenRequestHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpQueryHeaders", WinHttpQueryHeadersHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpQueryOption", WinHttpQueryOptionHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpResetAutoProxy", WinHttpResetAutoProxyHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpSetCredentials", WinHttpSetCredentialsHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpSetOption", WinHttpSetOptionHook, {NULL}),
    //CyFIFuncType("winhttp", "WinHttpSetTimeouts", WinHttpSetTimeoutsHook, {NULL}),
    CyFIFuncType("winhttp", "WinHttpOpen", WinHttpOpenHook, {NULL}),
    CyFIFuncType("wininet", "InternetConnectA", InternetConnectAHook, {NULL}),
    CyFIFuncType("wininet", "HttpOpenRequestA", HttpOpenRequestAHook, {NULL}),
    CyFIFuncType("wininet", "HttpSendRequestA", HttpSendRequestAHook, {NULL}),
    CyFIFuncType("wininet", "InternetReadFile", InternetReadFileHook, {NULL}),
    CyFIFuncType("wininet", "InternetOpenUrlA", InternetOpenUrlAHook, {NULL}),
    CyFIFuncType("wininet", "InternetCloseHandle", InternetCloseHandleHook, {NULL}),
    //CyFIFuncType("wininet", "HttpAddRequestHeadersA", HttpAddRequestHeadersAHook, {NULL}),
    //CyFIFuncType("wininet", "HttpEndRequestA", HttpEndRequestAHook, {NULL}),
    //CyFIFuncType("wininet", "HttpQueryInfoA", HttpQueryInfoAHook, {NULL}),
    //CyFIFuncType("wininet", "InternetQueryDataAvailable", InternetQueryDataAvailableHook, {NULL}),
    //CyFIFuncType("wininet", "InternetQueryOptionA", InternetQueryOptionAHook, {NULL}),
    //CyFIFuncType("wininet", "InternetSetOptionA", InternetSetOptionAHook, {NULL}),
    //CyFIFuncType("wininet", "InternetWriteFile", InternetWriteFileHook, {NULL}),
};

///
/// The names of the functions to hook (and the library that function belongs
/// to)
///
static LPCSTR functionsToHook[][2] = {
    //{ "wininet", "InternetOpenA"},
    { "wininet", "InternetConnectA" },
    { "wininet", "InternetOpenUrlA" },
    { "wininet", "HttpOpenRequestA" },
    { "wininet", "HttpSendRequestA" },
    { "wininet", "InternetReadFile" },
    { "wininet", "InternetCloseHandle" },
    { "kernel32", "CreateProcessA" },
    { "winhttp", "WinHttpOpen" },
    { "winhttp", "WinHttpConnect" },
    { "winhttp", "WinHttpOpenRequest" },
    { "winhttp", "WinHttpSendRequest" },
    { "winhttp", "WinHttpReceiveResponse" },
    { "winhttp", "WinHttpReadData" },
    { "winhttp", "WinHttpCrackUrl" },
    { "winhttp", "WinHttpCloseHandle" },
    { "kernel32_fail", "CreateThread" },
    { "kernel32_fail", "ExitThread" },
    { "Ws2_32", "socket" },
    { "Ws2_32", "connect" },
    { "Ws2_32", "closesocket" },
    //{ "kernel32", "VirtualAlloc" },
    //{ "kernel32", "VirtualFree" },
    { "kernel32", "MultiByteToWideChar" },
    //{ "ole32", "CreateStreamOnHGlobal"},   // comment to fix virustotal hooks...this functin hook breaks the malware


    // MODELS
    //{ "msvcrt", "memcpy" },
    //{ "ntdll", "memcpy" },

    //{ "msvcrt", "memset" },
    { "ntdll", "memset" },

    { "shlwapi", "StrStrA" },
    //{ "kernel32", "lstrlenA"},

    { NULL, NULL },
};


/// The function hooks that we will install
static PVOID hookFunctions[] = {
    //InternetOpenAHook,
    InternetConnectAHook,
    InternetOpenUrlAHook,
    HttpOpenRequestAHook,
    HttpSendRequestAHook,
    InternetReadFileHook,
    InternetCloseHandleHook,
    CreateProcessAHook,
    WinHttpOpenHook,
    WinHttpConnectHook,
    WinHttpOpenRequestHook,
    WinHttpSendRequestHook,
    WinHttpReceiveResponseHook,
    WinHttpReadDataHook,
    WinHttpCrackUrlHook,
    WinHttpCloseHandleHook,
    CreateThreadHook,
    ExitThreadHook,
    sockethook,
    connecthook,
    closesockethook,
    //VirtualAllocHook,
    //VirtualFreeHook,
    MultiByteToWideCharHook,
    //CreateStreamOnHGlobalHook,

    // MODELS
    //memcpy_msvcrt_model,
    //memcpy_ntdll_model,

    //memset_msvcrt_model,
    memset_ntdll_model,

    StrStrA_model,
    //lstrlenA_model
};

/// The actual hooks
static HOOK_TRACE_INFO hooks[] = {
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
    { NULL },
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
 
    //for (unsigned i = 0; functionsToHook[i][0] != NULL; ++i) {
    //    LPCSTR moduleName = functionsToHook[i][0];
    //    LPCSTR functionName = functionsToHook[i][1];

    //    // Install the hook
    //    NTSTATUS result = LhInstallHook(
    //        GetProcAddress(GetModuleHandleA(moduleName), functionName),
    //        hookFunctions[i],
    //        NULL,
    //        &hooks[i]);

    //    if (FAILED(result)) {
    //        Message("Failed to hook %s.%s: %S\n", moduleName, functionName,
    //            RtlGetLastErrorString());
    //    }
    //    else {
    //        Message("Successfully hooked %s.%s\n", moduleName, functionName);
    //    }

    //    // Ensure that all threads _except_ the injector thread will be hooked
    //    ULONG ACLEntries[1] = { 0 };
    //    LhSetExclusiveACL(ACLEntries, 1, &hooks[i]);
    //}

    // The process was started in a suspended state. Wake it up...
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

