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

// We need this header file to make things symbolic and to write to the S2E log
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}
#include <atlbase.h>
#include <commands.h>

/// Maximum timeout to wait for child processes to terminate (in milliseconds).
/// Can also be set to INFINITE.
#define CHILD_PROCESS_TIMEOUT 10 * 1000

/// Maximum message length to write to S2E debug log
#define S2E_MSG_LEN 512

/// Maximum path length
#define MAX_PATH_LEN 256

/// S2E version number, or 0 if not running in S2E mode
static INT s2eVersion = 0;

/// Keep track of dummy Internet handles that we've created
static std::set<HINTERNET> dummyHandles;

/// Keep track of thread handles we've created
static std::set<HANDLE> dummyThreadHandles;

/// Keep track of dummy Stream handles that we've created
static std::set<HGLOBAL> dummyStreams;

/// Keep track of sockets 
static std::set<SOCKET> dummySockets;

/// Keep track of base addrs
static std::set<LPVOID> dummyBaseAddrs;

/// Keep track of child processes
static std::set<DWORD> childPids;

LPCWSTR g_unique_handle = 0;

//////////////////////
// Helper functions //
//////////////////////

///
/// Write a message to the S2E log (or stdout).
///
static void Message(LPCSTR fmt, ...) {
    CHAR message[S2E_MSG_LEN];
    va_list args;

    va_start(args, fmt);
    vsnprintf(message, S2E_MSG_LEN, fmt, args);
    va_end(args);

    if (s2eVersion) {
        S2EMessageFmt("[0x%x|malware-hook] %s", GetCurrentProcessId(),
            message);
    }
    else {
        printf("[0x%x|malware-hook] %s", GetCurrentProcessId(), message);
    }
}


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


/*
    FUNCTION HOOKS

    KERNEL32
        CREATETHREAD
        EXITTHREAD
        CREATEPROCESSA
        MULTIBYTETOWIDECHAR
        VIRTUALALLOC
        VIRTUALFREE

    WINSOCK
        SOCKET
        CONNECT
        CLOSESOCKET

    WININET
        INTERNETCONNECT
        INTERNETREADFILE
        INTERNETCLOSEHANDLE
        INTERNETOPENURLA
        HTTPOPENREQUEST
        HTTPSENDREQEUST

    WINHTTP
        WINHTTPOPEN
        WINHTTPCONNECT
        WINHTTPOPENREQEUST
        WINHTTPSENDREQUEST
        WINHTTPRECEIVEREQUEST
        WINHTTPREADDADA
        WINHTTPCLOSEHANDLE
        WINHTTPCRACKURL


*/

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

////////////////////////////////////////////////////////////////////
//// WINSOCK
////////////////////////////////////////////////////////////////////

static SOCKET WSAAPI sockethook(
    int af,
    int type,
    int protocol
) {
    UINT8 retSocket = S2ESymbolicChar("socket", 1);
    if (retSocket) {
        SOCKET rSocket = (SOCKET)malloc(sizeof(SOCKET));
        dummySockets.insert(rSocket);
        Message("[HLOG] socket(%i, %i, %i) Ret: %i\n",
            af, type, protocol, rSocket);

        return rSocket;
    }
    else {
        return NULL;
    }
}

static INT WSAAPI connecthook(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
) {
    Message("[HLOG] connect(%i)\n", s);
    return 0;
}
static int WSAAPI closesockethook(
    SOCKET s
) {
    Message("[HLOG] closesocket(%p)\n", s);

    std::set<SOCKET>::iterator it = dummySockets.find(s);

    if (it == dummySockets.end()) {
        // The socket is not one of our dummy sockets, so call the original
        // closesocket function
        return closesocket(*it);
    }
    else {
        // The socket is a dummy handle. Free it
        //free(*it);
        dummySockets.erase(it);

        return TRUE;
    }
}

////////////////////////////////////////////////////////////////////
//// WININET
////////////////////////////////////////////////////////////////////

static HINTERNET WINAPI InternetConnectAHook(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
) {
    HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(resourceHandle);

    Message("[HLOG] InternetConnectA(%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p) Ret: %p\n",
        hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, resourceHandle);

    return resourceHandle;
}

static HINTERNET WINAPI HttpOpenRequestAHook(
    HINTERNET hConnect,
    LPCSTR    lpszVerb,
    LPCSTR    lpszObjectName,
    LPCSTR    lpszVersion,
    LPCSTR    lpszReferrer,
    LPCSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(resourceHandle);

    Message("[HLOG] HttpOpenRequestA(%p, A\"%s\", A\"%s\", A\"%s\", A\"%s\", %p, 0x%x, %p) Ret: %p\n",
        hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext, resourceHandle);

    return resourceHandle;
}

static BOOL WINAPI HttpSendRequestAHook(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
) {
    Message("[HLOG] HttpSendRequestA(%p, A\"%s\", 0x%x, %p, 0x%x)\n",
        hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

    return TRUE; //Only consider successful http request sends for now
}

#define INTERNET_READ_FILE_SIZE_OPT 1

static BOOL WINAPI InternetReadFileHook(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    Message("[HLOG] InternetReadFile(%p, %p, 0x%x, %p)\n",
        hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

    DWORD bytesToRead = dwNumberOfBytesToRead;

#ifndef INTERNET_READ_FILE_SIZE_OPT
    S2EMakeSymbolic(&bytesToRead, sizeof(DWORD), "numberOfBytesReadRaw");

    bytesToRead %= (dwNumberOfBytesToRead + 1);

#else
    //Optimization: Read entire buffer or none
    UINT8 readBuf = S2ESymbolicChar("numberOfBytesReadOpt", 0);
    if (readBuf) {
        bytesToRead = dwNumberOfBytesToRead;
    }
    else {
        bytesToRead = 0;
    }
#endif

    if (lpdwNumberOfBytesRead)
        *lpdwNumberOfBytesRead = bytesToRead;

    if (bytesToRead > 0)
        S2EMakeSymbolic(lpBuffer, bytesToRead, "bytesReadBuffer");

    return TRUE;
};

/*
static BOOL WINAPI InternetReadFileHook(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    DWORD bytesToRead = 0;

    //Optimization: Read entire buffer or none
    UINT8 readBuf = S2ESymbolicChar("numberOfBytesReadOpt", 0);
    if (readBuf) {
        bytesToRead = dwNumberOfBytesToRead;
    }VirtualFreeHookm

    if (lpdwNumberOfBytesRead)
        *lpdwNumberOfBytesRead = bytesToRead;

    if (bytesToRead > 0)
        S2EMakeSymbolic(lpBuffer, bytesToRead, "bytesReadBuffer");

    return TRUE;
};
*/

static HINTERNET WINAPI InternetOpenUrlAHook(
    HINTERNET hInternet,
    LPCSTR    lpszUrl,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {


    // Force a fork via a symbolic variable. Since both branches are feasible,
    // both paths are taken
    UINT8 returnResource = S2ESymbolicChar("hInternet", 1);
    if (returnResource) { //Ignore InternetOpenUrlA failure for now
        // Explore the program when InternetOpenUrlA "succeeds" by returning a
        // dummy resource handle. Because we know that the resource handle is
        // never used, we don't have to do anything fancy to create it.
        // However, we will need to keep track of it so we can free it when the
        // handle is closed.
        HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));

        // Record the dummy handle so we can clean up afterwards
        dummyHandles.insert(resourceHandle);

        Message("[HLOG] InternetOpenUrlA(%p,A\"%s\", A\"%s\", 0x%x, 0x%x, %p) Ret: %p\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);

        return resourceHandle;
    }
    else {
        Message("[HLOG] InternetOpenUrlA(%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p)\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);

        // Explore the program when InternetOpenUrlA "fails"
        return NULL;
    }
}

static BOOL WINAPI InternetCloseHandleHook(
    HINTERNET hInternet
) {
    Message("[HLOG] InternetCloseHandle(%p)\n", hInternet);

    std::set<HINTERNET>::iterator it = dummyHandles.find(hInternet);

    if (it == dummyHandles.end()) {
        // The handle is not one of our dummy handles, so call the original
        // InternetCloseHandle function
        return InternetCloseHandle(hInternet);
    }
    else {
        // The handle is a dummy handle. Free it
        free(*it);
        dummyHandles.erase(it);

        return TRUE;
    }
}


////////////////////////////////////////////////////////////////////
//// WINHTTP
////////////////////////////////////////////////////////////////////

static HINTERNET WINAPI WinHttpOpenHook(
    LPCWSTR pszAgentW,
    DWORD dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD dwFlags
) {

    //HINTERNET sessionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    HINTERNET sessionHandle = winhttp::WinHttpOpen(g_unique_handle, NULL, NULL, NULL, NULL);

    std::set<HINTERNET>::iterator it = dummyHandles.find(sessionHandle);

    UINT8 returnSession = S2ESymbolicChar("pszAgentW", 1);
    if (returnSession) {
        if (it == dummyHandles.end()) {
            // The handle is not one of our dummy handles
            dummyHandles.insert(sessionHandle);
        }
        else {
            // The handle is a dummy handle. 
            g_unique_handle += 100;
            HINTERNET sessionHandle = winhttp::WinHttpOpen(g_unique_handle, NULL, NULL, NULL, NULL);
            Message("Needed unique %s", g_unique_handle);
            dummyHandles.insert(sessionHandle);
        }

        Message("[HLOG] WinHttpOpen(A\"%ls\", %i, A\"%ls\", A\"%ls\", %i) Ret: %p\n",
            pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags, sessionHandle);

        return sessionHandle;
    }
    else {
        // Explore when WinHttpOpen fails
        return NULL;
    }
}


static HINTERNET WINAPI WinHttpConnectHook(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved
) {
    HINTERNET connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(connectionHandle);

    Message("[HLOG] WinHttpConnect(%p, A\"%ls\", %i, %i) Ret: %p\n",
        hSession, pswzServerName, nServerPort, dwReserved, connectionHandle);

    if (S2EIsSymbolic(&pswzServerName, 0x1000)) {
        Message("[HLOG] Found symbolic connection...probably a success!\n");
        return NULL;
    }

    return connectionHandle;

}

static HINTERNET WINAPI WinHttpOpenRequestHook(
    HINTERNET hConnect,
    LPCWSTR   pwszVerb,
    LPCWSTR   pwszObjectName,
    LPCWSTR   pwszVersion,
    LPCWSTR   pwszReferrer,
    LPCWSTR* ppwszAcceptTypes,
    DWORD     dwFlags
) {

    HINTERNET requestHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(requestHandle);

    Message("[HLOG] WinHttpOpenRequest(%p, A\"%ls\", A\"%ls\", A\"%ls\", A\"%ls\", %p, %i) Ret: %p\n",
        hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags, requestHandle);

    return requestHandle;

}

static BOOL WINAPI WinHttpSendRequestHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength,
    DWORD     dwTotalLength,
    DWORD_PTR dwContext
) {
    Message("[HLOG] WinHttpSendRequest(%p, A\"%ls\", 0x%x, %p, 0x%x, 0x%x, %p)\n",
        hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);

    return TRUE; //Only consider successful winhttp send requests for now
}

static BOOL WINAPI WinHttpReceiveResponseHook(
    HINTERNET hRequest,
    LPVOID    lpReserved
) {
    Message("[HLOG] WinHttpReceiveResponse(%p, %p)\n",
        hRequest, lpReserved);

    return TRUE; //Only consider successful winhttp responses for now
}

static BOOL WINAPI WinHttpReadDataHook(
    HINTERNET hRequest,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    /*
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_WINHTTPREADDATA;
    Command.WinHttpReadData.hRequest = hRequest;
    Command.WinHttpReadData.lpBuffer = lpBuffer;
    Command.WinHttpReadData.dwNumberOfBytesToRead = dwNumberOfBytesToRead;
    Command.WinHttpReadData.lpdwNumberOfByteRead = lpdwNumberOfBytesRead;
    Command.needOrigFunc = 0;
    */
    //BOOL ret = winhttp::WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    //char buf[19] = "CyFi_Concrete_Read";
    //memcpy(lpBuffer, buf, 46);
    
    Message("[HLOG] WinHttpReadData(%p, A\"%ls\", %p, 0x%x, %p)\n",
        hRequest, lpBuffer, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

    S2EMakeSymbolic(lpBuffer, 0x80, "CyFi_WinHttpReadData");
    *lpdwNumberOfBytesRead = 0x80;
    
    //char buf [46] = ")))))aHR0cHM6Ly93MHJtLmluL2pvaW4vam9pbi5waHA=";
    //memcpy(lpBuffer, buf, 46);
    

    return TRUE;

    //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    //return TRUE;
};


static BOOL WINAPI WinHttpCrackUrlHook(
    LPCWSTR pwszUrl,
    DWORD dwUrlLength,
    DWORD dwFlags,
    winhttp::LPURL_COMPONENTS lpUrlComponents
) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_WINHTTPCRACKURL;
    Command.WinHttpCrackUrl.pwszUrl = (uint64_t) pwszUrl;
    Command.WinHttpCrackUrl.dwUrlLength = (uint64_t) dwUrlLength;
    Command.WinHttpCrackUrl.dwFlags = (uint64_t) dwFlags;
    Command.WinHttpCrackUrl.lpUrlComponets = (uint64_t) lpUrlComponents;
    Message("[HLOG] WinHttpCrackUrl (%p, %i, %i, %i)\n", pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    if (Command.WinHttpCrackUrl.symbolic) {
        Message("[HLOG] WinHttpCrackUrl received a symbolic URL.\n");
        pwszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
        winhttp::WinHttpCrackUrl(pwszUrl, 69, dwFlags, lpUrlComponents);
        Message("[HLOG] WinHttpCrackUrl (%ls, %i, %i, %i)\n", pwszUrl, 69, dwFlags, lpUrlComponents);
        return true;
    }
    else {
        bool ret = winhttp::WinHttpCrackUrl(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
        return ret;
    }

}


static BOOL WINAPI WinHttpCloseHandleHook(
    HINTERNET hInternet
) {
    Message("[HLOG] WinHttpCloseHandle(%p)\n", hInternet);

    std::set<HINTERNET>::iterator it = dummyHandles.find(hInternet);

    if (it == dummyHandles.end()) {
        // The handle is not one of our dummy handles, so call the original
        // InternetCloseHandle function
        return winhttp::WinHttpCloseHandle(hInternet);
    }
    else {
        // The handle is a dummy handle. Free it
        free(*it);
        dummyHandles.erase(it);

        return TRUE;
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
        Message("[HLOG] CreateStreamOnHGlobal (%p, %s, %p) Ret:%p\n", hGlobal, fDeleteOnRelease, ppstm, hr);

    }
    catch (int e) {
        Message("[HLOG] CreateStreamOnHGlobal Failed %i\n!", e);

    }
    return hr;

}


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

    for (unsigned i = 0; functionsToHook[i][0] != NULL; ++i) {
        LPCSTR moduleName = functionsToHook[i][0];
        LPCSTR functionName = functionsToHook[i][1];

        // Install the hook
        NTSTATUS result = LhInstallHook(
            GetProcAddress(GetModuleHandleA(moduleName), functionName),
            hookFunctions[i],
            NULL,
            &hooks[i]);

        if (FAILED(result)) {
            Message("Failed to hook %s.%s: %S\n", moduleName, functionName,
                RtlGetLastErrorString());
        }
        else {
            Message("Successfully hooked %s.%s\n", moduleName, functionName);
        }

        // Ensure that all threads _except_ the injector thread will be hooked
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hooks[i]);
    }

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

