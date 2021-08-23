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
    unique_handle += 100;
    HINTERNET sessionHandle = InternetOpenA(unique_handle, NULL, NULL, NULL, NULL);
    dummyHandles.insert(sessionHandle);
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
    unique_handle += 100;
    HINTERNET sessionHandle = InternetOpenW(unique_handleW, NULL, NULL, NULL, NULL);
    dummyHandles.insert(sessionHandle);
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

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    HINTERNET connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(connectionHandle);
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

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    HINTERNET connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(connectionHandle);
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
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_INTERNETCRACKURLA;
    Command.InternetCrackUrlA.pwszUrl = (uint64_t)pwszUrl;
    Command.InternetCrackUrlA.dwUrlLength = (uint64_t)dwUrlLength;
    Command.InternetCrackUrlA.dwFlags = (uint64_t)dwFlags;
    Command.InternetCrackUrlA.lpUrlComponets = (uint64_t)lpUrlComponents;

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    if (Command.InternetCrackUrlA.symbolic) {
        pwszUrl = "http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
        InternetCrackUrlA(pwszUrl, 52, dwFlags, lpUrlComponents);
        Message("[W] InternetCrackUrlA (%s, %ld, %ld, %p)\n", pwszUrl, 52, dwFlags, lpUrlComponents);
        return TRUE;
    }
    else {
        Message("[W] InternetCrackUrlA (%p, %ld, %ld, %p)\n", pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
        bool ret = InternetCrackUrlA(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
        return ret;
    }
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

#define INTERNET_READ_FILE_SIZE_OPT 1

BOOL WINAPI InternetReadFileHook(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    /*CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_INTERNETREADFILE;
    Command.InternetReadFile.hFile = (uint64_t)hFile;
    Command.InternetReadFile.lpBuffer = (uint64_t)lpBuffer;
    Command.InternetReadFile.dwNumberOfBytesToRead = dwNumberOfBytesToRead;
    Command.InternetReadFile.lpdwNumberOfBytesRead = (uint64_t)lpdwNumberOfBytesRead;

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));*/

    if (dwNumberOfBytesToRead) {
        *lpdwNumberOfBytesRead = dwNumberOfBytesToRead;
    }
    else {
        *lpdwNumberOfBytesRead = DEFAULT_MEM_LEN;
    }
    std::string tag = GetTag("InternetReadFile");
    S2EMakeSymbolic(lpBuffer, *lpdwNumberOfBytesRead, tag.c_str());
    //S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag.c_str());
    Message("[W] InternetReadFile  (%p, %p, 0x%x, %p=0x%x) -> tag_out: %s\n", 
        hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead,  *lpdwNumberOfBytesRead, tag.c_str());

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
    // Only consider successes for now
    HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));

    // Record the dummy handle so we can clean up afterwards
    dummyHandles.insert(resourceHandle);

    Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p\n",
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);

    return resourceHandle;
    /*
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

        Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);

        return resourceHandle;
    }
    else {
        Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: Fail\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);

        // Explore the program when InternetOpenUrlA "fails"
        return NULL;
    }*/
}

HINTERNET WINAPI InternetOpenUrlWHook(
    HINTERNET hInternet,
    LPCWSTR   lpszUrl,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    // Record the dummy handle so we can clean up afterwards
    dummyHandles.insert(resourceHandle);

    Message("[W] InternetOpenUrlW (%p, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p\n",
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);

    return resourceHandle;
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

BOOL WINAPI HttpAddRequestHeadersAHook(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
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
    Message("[W] WinHttpSetOption(%p, %ld, %p, %ld)\n", hInternet, dwOption, lpBuffer, dwBufferLength);

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