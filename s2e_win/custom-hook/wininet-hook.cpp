#include "wininet-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>
#include <unordered_map>

static std::set<HINTERNET> dummyHandles;
static std::unordered_map<HINTERNET, DWORD> perHandleBytesToRead;

HINTERNET WINAPI InternetOpenAHook(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
) {
    HINTERNET sessionHandle = InternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    if (sessionHandle == NULL) {
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

    HINTERNET connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(connectionHandle);

    std::string tag = ReadTag((PVOID)lpszServerName);        
    if (tag != "") {
        CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
        Command.Command = DUMP_EXPRESSION;
        Command.dumpExpression.buffer = (uint64_t)lpszServerName;
        S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

        Message("[W] InternetConnectA (%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p tag_in: %s\n",
            hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle, tag.c_str());
        return connectionHandle;
    }
    else {
        Message("[W] InternetConnectA (%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p\n",
            hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle);
        return connectionHandle;
    }
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
    HINTERNET connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(connectionHandle);
    std::string tag = ReadTag((PVOID)lpszServerName);
    if (tag != "") {
        CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
        Command.Command = DUMP_EXPRESSION;
        Command.dumpExpression.buffer = (uint64_t)lpszServerName;
        S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

        Message("[W] InternetConnectW (%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p, tag_in: %s\n",
            hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle, tag.c_str());
        return connectionHandle;
    }
    else {
        Message("[W] InternetConnectW (%p, A\"%ls\", %i, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p\n",
            hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle);
        return connectionHandle;
    }
}

BOOL WINAPI InternetCrackUrlAHook(
    LPCSTR           pwszUrl,
    DWORD            dwUrlLength,
    DWORD            dwFlags,
    LPURL_COMPONENTSA lpUrlComponents
) {
    if (checkCaller("InternetCrackUrlA")) {
        std::string tagIn = ReadTag((PVOID)pwszUrl);
        if (tagIn != "") {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = DUMP_EXPRESSION;
            Command.dumpExpression.buffer = (uint64_t)pwszUrl;
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            pwszUrl = "http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
            std::string tag = GetTag("InternetCrackUrlA");
            S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
            InternetCrackUrlA(pwszUrl, 52, dwFlags, lpUrlComponents);
            Message("[W] InternetCrackUrlA (%s, %ld, %ld, %p) -> tag_in: %p, tag_out: %s\n", 
                pwszUrl, 52, dwFlags, lpUrlComponents, tagIn.c_str(), tag.c_str());
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
        std::string tagIn = ReadTag((PVOID)lpszUrl);
        if (tagIn != "") {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = DUMP_EXPRESSION;
            Command.dumpExpression.buffer = (uint64_t)lpszUrl;
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            lpszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
            std::string tag = GetTag("InternetCrackUrlW");
            S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
            InternetCrackUrlW(lpszUrl, 52, dwFlags, lpUrlComponents);
            Message("[W] InternetCrackUrlW (%s, %ld, %ld, %p) -> tag_in: %p, tag_out: %s\n",
                lpszUrl, 52, dwFlags, lpUrlComponents, tagIn.c_str(), tag.c_str());
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
    std::string header_tag = ReadTag((PVOID)lpszHeaders);
    std::string option_tag = ReadTag((PVOID)lpOptional);

    if (header_tag.length() > 0) {
        Message("[W] HttpSendRequestA (%p, A\"%s\", 0x%x, %p, 0x%x) tag_in: %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, header_tag.c_str());
    }
    else if (option_tag.length() > 0) {
        Message("[W] HttpSendRequestA (%p, A\"%s\", 0x%x, %p, 0x%x) tag_in: %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, option_tag.c_str());
    }
    else {
        Message("[W] HttpSendRequestA (%p, A\"%s\", 0x%x, %p, 0x%x)\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    }

    return TRUE; //Only consider successful http request sends for now
}

BOOL WINAPI HttpSendRequestWHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
) {
    std::string header_tag = ReadTag((PVOID)lpszHeaders);
    std::string option_tag = ReadTag((PVOID)lpOptional);
    if (header_tag.length() > 0) {
        Message("[W] HttpSendRequestW (%p, A\"%ls\", 0x%x, %p, 0x%x) tag_in: %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, header_tag.c_str());
    }
    else if (option_tag.length() > 0) {
        Message("[W] HttpSendRequestW (%p, A\"%ls\", 0x%x, %p, 0x%x) tag_in: %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, option_tag.c_str());
    }
    else {
        Message("[W] HttpSendRequestW (%p, A\"%ls\", 0x%x, %p, 0x%x)\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    }

    return TRUE; //Only consider successful http request sends for now
}

BOOL WINAPI InternetReadFileHook(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    auto it = perHandleBytesToRead.find(hFile);
    if (it == perHandleBytesToRead.end()) {
        perHandleBytesToRead[hFile] = DEFAULT_MEM_LEN;
        it = perHandleBytesToRead.find(hFile);
    }
    DWORD bytes_left = it->second;
    DWORD bytes_read = bytes_left < dwNumberOfBytesToRead ? bytes_left : dwNumberOfBytesToRead;
    it->second -= bytes_read;
    *lpdwNumberOfBytesRead = bytes_read;

    //
    ////std::string data_read = "1BkeGqpo8M5KNVYXW3obmQt1R58zXAqLBQ 11223344 1BkeGqpo8M5KNVYXW3obmQt1R58zXAqLBQ 55667788"; //redaman
    //std::string data_read = "DG8FV-B9TKY-FRT9J-6CRCC-XPQ4G-104A149B245C120D";   //spyanker
    //if (bytes_read < data_read.size()) {
    //    data_read = data_read.substr(0, bytes_read);
    //}
    //if (bytes_read > 0) {
    //    memcpy(lpBuffer, data_read.c_str(), bytes_read);
    //}
    

    std::string tag = GetTag("InternetReadFile");
    Message("[W] InternetReadFile  (%p, %p, 0x%x, %p=0x%x) -> tag_out: %s\n",
        hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead, bytes_read, tag.c_str());

    S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
    S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag.c_str());
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
    // If lpszUrl is not symbolic and is empty, returns NULL
    std::string tag = ReadTag((PVOID)lpszUrl);

    if (tag == "" && lstrlenA(lpszUrl) == 0) {
        Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: NULL\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
        return NULL;
    }

    HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(resourceHandle);
    
    if(tag != ""){
        Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %s, tag_in: %s\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle, tag.c_str());
        return resourceHandle;
    }
    else {
        Message("[W] InternetOpenUrlA (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: %p\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);
        return resourceHandle;
    }
    
}


HINTERNET WINAPI InternetOpenUrlWHook(
    HINTERNET hInternet,
    LPCWSTR   lpszUrl,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    std::string tag = ReadTag((PVOID)lpszUrl);

    if (tag == "" && lstrlenW(lpszUrl) == 0) {
        Message("[W] InternetOpenUrlW (%p, A\"%s\", A\"%s\", 0x%x, 0x%x, %p), Ret: NULL\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
        return NULL;
    }

    HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(resourceHandle);
    
    if (tag != "") {

        Message("[W] InternetOpenUrlW (%p, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p, tag_in: %s\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle, tag.c_str());
        return resourceHandle;
    }
    else {
        Message("[W] InternetOpenUrlW (%p, A\"%ls\", A\"%ls\", 0x%x, 0x%x, %p), Ret: %p\n",
            hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle);
        return resourceHandle;
    }
}

BOOL WINAPI HttpAddRequestHeadersAHook(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {
    std::string header_tag = ReadTag((PVOID)lpszHeaders);
    if (header_tag.length() > 0) {
        Message("[W] HttpAddRequestHeadersA (%p, A\"%s\", %d, %d) tag_in: %s\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers, header_tag.c_str());
    }
    else {
        Message("[W] HttpAddRequestHeadersA (%p, A\"%s\", %d, %d)\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    }
    return TRUE;
}

BOOL WINAPI HttpAddRequestHeadersWHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {
    std::string header_tag = ReadTag((PVOID)lpszHeaders);
    if (header_tag.length() > 0) {
        Message("[W] HttpAddRequestHeadersW (%p, A\"%ls\", %ld, %ld) tag_in: %s\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers, header_tag.c_str());
    }
    else {
        Message("[W] HttpAddRequestHeadersW (%p, A\"%ls\", %ld, %ld)\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    }
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
        // If the info level is 19 - Status Code
        if (dwInfoLevel == 19) {
            // Patch the lpBuffer as HTTP_STATUS_OK then mark it as symbolic
            *(DWORD *)lpBuffer = HTTP_STATUS_OK;
            S2EMakeSymbolic(lpBuffer, 4, tag.c_str());
        }
        else {
            S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag.c_str());
        }
        S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
        Message("[W] HttpQueryInfoA(%p, %ld, %p, %p, %p) -> tag_out: %s\n",
            hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex, tag.c_str());

    }
    else
    {
        Message("[W] HttpQueryInfoA(%p, %ld, %p, %p, %p)\n", hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
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

    std::string read_tag = ReadTag((PVOID)lpBuffer);

    if (read_tag.length() > 0) {
        Message("[W] InternetWriteFile(%p, A\"%ls\", 0x%x, %p) -> tag_in: %s tag_out: %s\n",
            hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten, read_tag.c_str(), tag.c_str());
    }
    else {
        Message("[W] InternetWriteFile(%p, A\"%ls\", 0x%x, %p) -> tag_out: %s\n",
            hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten, tag.c_str());
    }

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
    Message("[W] InternetCheckConnectionA (%s, %ld, %ld)\n", lpszUrl, dwFlags, dwReserved);
    return TRUE;
}

BOOL WINAPI InternetCheckConnectionWHook(
    LPCWSTR lpszUrl,
    DWORD   dwFlags,
    DWORD   dwReserved
) {
    Message("[W] InternetCheckConnectionW (%s, %ld, %ld)\n", lpszUrl, dwFlags, dwReserved);
    return TRUE;
}

DWORD WINAPI InternetAttemptConnectHook(
    DWORD dwReserved
) {
    Message("[W] InternetAttemptConnect (%ld)\n", dwReserved);
    return ERROR_SUCCESS;
}


BOOL WINAPI InternetCloseHandleHook(
    HINTERNET hInternet
) {
    perHandleBytesToRead.erase(hInternet);

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

