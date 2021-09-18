#include "wininet-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>

static std::set<HINTERNET> dummyHandles;
LPCSTR unique_handle = 0;
LPCWSTR unique_handleW = 0;

HINTERNET WINAPI InternetOpenAHook(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
) {
    HINTERNET sessionHandle = InternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    if (sessionHandle == 0) {
        sessionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    }
    Message("[W] InternetOpenA (A\"%s\", %ld, A\"%s\", A\"%s\", %ld), Ret: %p\n",
        lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags, sessionHandle);
    return sessionHandle;
}

HINTERNET WINAPI InternetOpenWHook(
    LPCWSTR lpszAgent,
    DWORD   dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD   dwFlags
) {
    HINTERNET sessionHandle = InternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    if (sessionHandle == 0) {
        sessionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    }
    Message("[W] InternetOpenW (A\"%ls\", %ld, A\"%ls\", A\"%ls\", %ld), Ret: %p\n",
        lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags, sessionHandle);
    return sessionHandle;
}

HINTERNET WINAPI InternetConnectAHook(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
) {
    if (checkCaller("InternetConnectA")) {
        HINTERNET connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
        dummyHandles.insert(connectionHandle);
        if (S2EIsSymbolic((PVOID)lpszServerName, 0x4)) {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_INTERNETCONNECTA;
            Command.InternetConnectA.hInternet = (uint64_t)hInternet;
            Command.InternetConnectA.lpszServerName = (uint64_t)lpszServerName;
            Command.InternetConnectA.nServerPort = (uint64_t)nServerPort;
            Command.InternetConnectA.lpszUserName = (uint64_t)lpszUserName;
            Command.InternetConnectA.lpszPassword = (uint64_t)lpszPassword;
            Command.InternetConnectA.dwService = (uint64_t)dwService;
            Command.InternetConnectA.dwFlags = (uint64_t)dwFlags;
            Command.InternetConnectA.dwContext = (uint64_t)dwContext;

            std::string symbTag = "";
            Command.InternetConnectA.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.InternetConnectA.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
            Message("[W] InternetConnectA (%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p tag_in: %s\n",
                hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle, (uint32_t)Command.InternetConnectA.symbTag);
           return connectionHandle;
        }
        else {
            Message("[W] InternetConnectA (%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p\n",
                hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle);
            return connectionHandle;
        }
    }
    HINTERNET connectionHandle = InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    Message("[W] InternetConnectA (%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p\n",
        hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle);
    return connectionHandle;
}

HINTERNET WINAPI InternetConnectWHook(
    HINTERNET     hInternet,
    LPCWSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCWSTR        lpszUserName,
    LPCWSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
) {
    if (checkCaller("InternetConnectW")) {
        HINTERNET connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
        dummyHandles.insert(connectionHandle);
        if (S2EIsSymbolic((PVOID)lpszServerName, 0x4)) {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_INTERNETCONNECTW;
            Command.InternetConnectW.hInternet = (uint64_t)hInternet;
            Command.InternetConnectW.lpszServerName = (uint64_t)lpszServerName;
            Command.InternetConnectW.nServerPort = (uint64_t)nServerPort;
            Command.InternetConnectW.lpszUserName = (uint64_t)lpszUserName;
            Command.InternetConnectW.lpszPassword = (uint64_t)lpszPassword;
            Command.InternetConnectW.dwService = (uint64_t)dwService;
            Command.InternetConnectW.dwFlags = (uint64_t)dwFlags;
            Command.InternetConnectW.dwContext = (uint64_t)dwContext;

            std::string symbTag = "";
            Command.InternetConnectW.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.InternetConnectW.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            Message("[W] InternetConnectW (%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p, tag_in: %s\n",
                hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle, (uint32_t)Command.InternetConnectW.symbTag);
            return connectionHandle;
        }
        else {
            Message("[W] InternetConnectW (%p, A\"%ls\", %i, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p\n",
                hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle);
            return connectionHandle;
        }
    }
    HINTERNET connectionHandle = InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    Message("[W] InternetConnectW (%p, A\"%ls\", %i, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p\n",
        hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle);
    return connectionHandle;
}

BOOL WINAPI InternetCrackUrlAHook(
    LPCSTR           pwszUrl,
    DWORD            dwUrlLength,
    DWORD            dwFlags,
    LPURL_COMPONENTSA lpUrlComponents
) {
    if (checkCaller("InternetCrackUrlA")) {
        if (S2EIsSymbolic((PVOID)pwszUrl, 0x4)) {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_INTERNETCRACKURLA;
            Command.InternetCrackUrlA.lpszUrl = (uint64_t)pwszUrl;
            Command.InternetCrackUrlA.dwUrlLength = (uint64_t)dwUrlLength;
            Command.InternetCrackUrlA.dwFlags = (uint64_t)dwFlags;
            Command.InternetCrackUrlA.lpUrlComponents = (uint64_t)lpUrlComponents;
            std::string symbTag = "";
            Command.InternetCrackUrlA.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.InternetCrackUrlA.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            pwszUrl = "http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
            std::string tag = GetTag("InternetCrackUrlA");
            S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
            InternetCrackUrlA(pwszUrl, 52, dwFlags, lpUrlComponents);
            Message("[W] InternetCrackUrlA (%s, %ld, %ld, %p) -> tag_in: %p, tag_out: %s\n", 
                pwszUrl, 52, dwFlags, lpUrlComponents, (uint32_t)Command.InternetCrackUrlA.symbTag, tag.c_str());
            return TRUE;
        }
    }

    Message("[W] InternetCrackUrlA (%p, %ld, %ld, %p)\n", pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
    return InternetCrackUrlA(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
}

BOOL WINAPI InternetCrackUrlWHook(
    LPCWSTR           lpszUrl,
    DWORD             dwUrlLength,
    DWORD             dwFlags,
    LPURL_COMPONENTSW lpUrlComponents
) {
    if (checkCaller("InternetCrackUrlW")) {
        if (S2EIsSymbolic((PVOID)lpszUrl, 0x4)) {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_INTERNETCRACKURLW;
            Command.InternetCrackUrlW.lpszUrl = (uint64_t)lpszUrl;
            Command.InternetCrackUrlW.dwUrlLength = (uint64_t)dwUrlLength;
            Command.InternetCrackUrlW.dwFlags = (uint64_t)dwFlags;
            Command.InternetCrackUrlW.lpUrlComponents = (uint64_t)lpUrlComponents;
            std::string symbTag = "";
            Command.InternetCrackUrlW.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.InternetCrackUrlW.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            lpszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
            std::string tag = GetTag("InternetCrackUrlW");
            S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
            InternetCrackUrlW(lpszUrl, 52, dwFlags, lpUrlComponents);
            Message("[W] InternetCrackUrlW (%s, %ld, %ld, %p) -> tag_in: %p, tag_out: %s\n",
                lpszUrl, 52, dwFlags, lpUrlComponents, (uint32_t)Command.InternetCrackUrlW.symbTag, tag.c_str());
            return TRUE;
        }
    }

    Message("[W] InternetCrackUrlW (%p, %ld, %ld, %p)\n", lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
    return InternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
}

HINTERNET WINAPI HttpOpenRequestAHook(
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

    Message("[W] HttpOpenRequestA (%p, A\"%s\", A\"%s\", A\"%s\", A\"%s\", %p, 0x%x, %p), Ret: %p\n",
        hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext, resourceHandle);

    return resourceHandle;
}

HINTERNET WINAPI HttpOpenRequestWHook(
    HINTERNET hConnect,
    LPCWSTR   lpszVerb,
    LPCWSTR   lpszObjectName,
    LPCWSTR   lpszVersion,
    LPCWSTR   lpszReferrer,
    LPCWSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(resourceHandle);

    Message("[W] HttpOpenRequestW (%p, A\"%ls\", A\"%ls\", A\"%ls\", A\"%ls\", %p, 0x%x, %p), Ret: %p\n",
        hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext, resourceHandle);

    return resourceHandle;
}

BOOL WINAPI HttpSendRequestAHook(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
) {
    Message("[W] HttpSendRequestA (%p, A\"%s\", 0x%x, %p, 0x%x)\n",
        hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

    return TRUE; //Only consider successful http request sends for now
}

BOOL WINAPI HttpSendRequestWHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
) {
    Message("[W] HttpSendRequestW (%p, A\"%ls\", 0x%x, %p, 0x%x)\n",
        hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

    return TRUE; //Only consider successful http request sends for now
}

#define INTERNET_READ_FILE_SIZE_OPT 1

BOOL WINAPI InternetReadFileHook(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    if (dwNumberOfBytesToRead) {
        *lpdwNumberOfBytesRead = min(dwNumberOfBytesToRead, DEFAULT_MEM_LEN);
    }
    std::string tag = GetTag("InternetReadFile");
    S2EMakeSymbolic(lpBuffer, *lpdwNumberOfBytesRead, tag.c_str());
    S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag.c_str());
    Message("[W] InternetReadFile  (%p, %p, 0x%x, %p=0x%x) -> tag_out: %s\n",
        hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead, *lpdwNumberOfBytesRead, tag.c_str());
    return TRUE;


};

HINTERNET WINAPI InternetOpenUrlAHook(
    HINTERNET hInternet,
    LPCSTR    lpszUrl,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    if (checkCaller("InternetOpenUrlA")) {
        HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
        dummyHandles.insert(resourceHandle);
        if (S2EIsSymbolic((PVOID)lpszUrl, 0x4)) {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_INTERNETOPENURLA;
            Command.InternetOpenUrlA.hInternet = (uint64_t)hInternet;
            Command.InternetOpenUrlA.lpszUrl = (uint64_t)lpszUrl;
            Command.InternetOpenUrlA.lpszHeaders = (uint64_t)lpszHeaders;
            Command.InternetOpenUrlA.dwHeadersLength = (uint64_t)dwHeadersLength;
            Command.InternetOpenUrlA.dwFlags = (uint64_t)dwFlags;
            Command.InternetOpenUrlA.dwContext = (uint64_t)dwContext;

            std::string symbTag = "";
            Command.InternetOpenUrlA.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.InternetOpenUrlA.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %s, tag_in: %s\n",
                hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle, (uint32_t)Command.InternetOpenUrlA.symbTag);
            return resourceHandle;
        }
        else {
            Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p\n",
                hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);
            return resourceHandle;
        }
    }
    HINTERNET resourceHandle = InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
    Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p\n",
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);
    return resourceHandle;
}


HINTERNET WINAPI InternetOpenUrlWHook(
    HINTERNET hInternet,
    LPCWSTR   lpszUrl,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    if (checkCaller("InternetOpenUrlW")) {
        HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
        dummyHandles.insert(resourceHandle);
        if (S2EIsSymbolic((PVOID)lpszUrl, 0x4)) {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_INTERNETOPENURLW;
            Command.InternetOpenUrlW.hInternet = (uint64_t)hInternet;
            Command.InternetOpenUrlW.lpszUrl = (uint64_t)lpszUrl;
            Command.InternetOpenUrlW.lpszHeaders = (uint64_t)lpszHeaders;
            Command.InternetOpenUrlW.dwHeadersLength = (uint64_t)dwHeadersLength;
            Command.InternetOpenUrlW.dwFlags = (uint64_t)dwFlags;
            Command.InternetOpenUrlW.dwContext = (uint64_t)dwContext;

            std::string symbTag = "";
            Command.InternetOpenUrlW.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.InternetOpenUrlW.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            Message("[W] InternetOpenUrlW (%p, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p, tag_in: %s\n",
                hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle, (uint32_t)Command.InternetOpenUrlW.symbTag);
            return resourceHandle;
        }
        else {
            Message("[W] InternetOpenUrlW (%p, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p\n",
                hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);
            return resourceHandle;
        }
    }
    HINTERNET resourceHandle = InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);;
    Message("[W] InternetOpenUrlW (%p, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p\n",
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);
    return resourceHandle;
}

BOOL WINAPI HttpAddRequestHeadersAHook(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {
    Message("[W] HttpAddRequestHeaders (%p, A\"%s\", %ld, %ld)\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers);

    return TRUE;
}

BOOL WINAPI HttpAddRequestHeadersWHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {
    Message("[W] HttpAddRequestHeaders (%p, A\"%ls\", %ld, %ld)\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers);

    return TRUE;
}

BOOL WINAPI HttpEndRequestAHook(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
) {
    return TRUE;
}

BOOL WINAPI HttpQueryInfoAHook(
    HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
) {

    if (lpBuffer) {
        std::string tag = GetTag("HttpQueryInfoA");
        S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag.c_str());
        S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
        Message("[W] HttpQueryInfoAHook(%p, %ld, %p, %p, %p) -> tag_out: %s\n",
            hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex, tag.c_str());

    }
    else
    {
        Message("[W] HttpQueryInfoAHook(%p, %ld, %p, %p, %p)\n", hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
    }

    return TRUE;
}

BOOL WINAPI InternetQueryDataAvailableHook(
    HINTERNET hFile,
    LPDWORD   lpdwNumberOfBytesAvailable,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    if (lpdwNumberOfBytesAvailable) {
        S2EMakeSymbolic(lpdwNumberOfBytesAvailable, sizeof(*lpdwNumberOfBytesAvailable), GetTag("InternetQueryDataAvailable").c_str());
    }

    return TRUE;
}

BOOL WINAPI InternetQueryOptionAHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength
) {
    Message("[W] WinHttpQueryOption (%p, %ld, %p, %p)\n", hInternet, dwOption, lpBuffer, lpdwBufferLength);

    if (lpBuffer) {
        std::string tag = GetTag("InternetQueryOptionA");
        S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag.c_str());
        S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
    }

    return TRUE;
}

BOOL WINAPI InternetSetOptionAHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
) {
    // lpBuffer can point to a DWROD, it can also point to a char array
    if (dwBufferLength == 4) {
        Message("[W] InternetSetOptionA(%p, %ld, %ld, %ld)\n", hInternet, dwOption, *(LPDWORD)lpBuffer, dwBufferLength);
    }
    else {
        Message("[W] InternetSetOptionA(%p, %ld, %ls, %ld)\n", hInternet, dwOption, (LPCTSTR)lpBuffer, dwBufferLength);
    }

    return TRUE;
}

BOOL WINAPI InternetWriteFileHook(
    HINTERNET hFile,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
) {
    std::string tag = GetTag("InternetWriteFile");
    S2EMakeSymbolic(lpdwNumberOfBytesWritten, 4, tag.c_str());
    Message("[W] InternetWriteFile(%p, A\"%ls\", 0x%x, %p) -> tag_out: %s\n",
        hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten, tag.c_str());
    return TRUE;
}

BOOL WINAPI InternetGetConnectedStateHook(
    LPDWORD lpdwFlags,
    DWORD   dwReserved
) {
    if(checkCaller("InternetGetConnectedState")) {
        BOOL res = InternetGetConnectedState(lpdwFlags, dwReserved);
        Message("[W] InternetGetConnectedState (%ld, %ld) Ret: %i\n", *lpdwFlags, dwReserved, res);
        return TRUE;
    }
    return InternetGetConnectedState(lpdwFlags, dwReserved);
}

BOOL WINAPI InternetCheckConnectionAHook(
    LPCSTR lpszUrl,
    DWORD  dwFlags,
    DWORD  dwReserved
) {
    if (checkCaller("InternetCheckConnectionA")) {
        Message("[W] InternetCheckConnectionA (%s, %ld, %ld)\n", lpszUrl, dwFlags, dwReserved);
        return TRUE;
    }
    return InternetCheckConnectionA(lpszUrl, dwFlags, dwReserved);
}

BOOL WINAPI InternetCheckConnectionWHook(
    LPCWSTR lpszUrl,
    DWORD   dwFlags,
    DWORD   dwReserved
) {
    if (checkCaller("InternetCheckConnectionW")) {
        Message("[W] InternetCheckConnectionW (%s, %ld, %ld)\n", lpszUrl, dwFlags, dwReserved);
        return TRUE;
    }
    return InternetCheckConnectionW(lpszUrl, dwFlags, dwReserved);
}

DWORD WINAPI InternetAttemptConnectHook(
    DWORD dwReserved
) {
    if (checkCaller("InternetAttemptConnect")) {
        Message("[W] InternetAttemptConnect (%ld)\n", dwReserved);
        return ERROR_SUCCESS;
    }
    return InternetAttemptConnect(dwReserved);
}


BOOL WINAPI InternetCloseHandleHook(
    HINTERNET hInternet
) {
    Message("[W] InternetCloseHandle (%p)\n", hInternet);

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

