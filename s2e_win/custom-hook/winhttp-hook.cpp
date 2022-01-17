#include "winhttp-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>
#include <string>
#include <unordered_map>

static std::set<winhttp::HINTERNET> queryDataHandles;
static std::set<winhttp::HINTERNET> dummyHandles;
static std::unordered_map<winhttp::HINTERNET, DWORD> perHandleBytesToRead;

winhttp::HINTERNET WINAPI WinHttpOpenHook(
    LPCWSTR pszAgentW,
    DWORD dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD dwFlags
) {
    //WinHttpOpen should still succeed w/o network
    winhttp::HINTERNET sessionHandle = winhttp::WinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
    if (sessionHandle == 0) {
        sessionHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
    }
    Message("[W] WinHttpOpen (A\"%ls\", %ld, A\"%ls\", A\"%ls\", %ld), Ret: %p\n",
        pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags, sessionHandle);
    return sessionHandle;
}

BOOL WINAPI WinHttpCrackUrlHook(
	LPCWSTR          pwszUrl,
	DWORD            dwUrlLength,
	DWORD            dwFlags,
	winhttp::LPURL_COMPONENTS lpUrlComponents
) {
    std::string tagin = ReadTag((PVOID)pwszUrl);
    if (tagin != "") {
        CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
        Command.Command = DUMP_EXPRESSION;
        Command.dumpExpression.buffer = (uint64_t)pwszUrl;
        S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

        pwszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
        winhttp::WinHttpCrackUrl(pwszUrl, 52, dwFlags, lpUrlComponents);
        std::string tag = GetTag("WinHttpCrackUrl");
        S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
        Message("[W] WinHttpCrackUrl (%p, %ld, %ld, %p) -> tag_in: %s tag_out: %s\n",
            pwszUrl, dwUrlLength, dwFlags, lpUrlComponents, tagin.c_str(), tag.c_str());
        return TRUE;
    }
    return WinHttpCrackUrl(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
}

winhttp::HINTERNET WINAPI WinHttpConnectHook(
    winhttp::HINTERNET hSession,
    LPCWSTR pswzServerName,
    winhttp::INTERNET_PORT nServerPort,
    DWORD dwReserved
) {
    winhttp::HINTERNET connectionHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
    dummyHandles.insert(connectionHandle);
    std::string tagin = ReadTag((PVOID)pswzServerName);
    if (tagin != "") {
        CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
        Command.Command = DUMP_EXPRESSION;
        Command.dumpExpression.buffer = (uint64_t)pswzServerName;
        S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

        Message("[W] WinHttpConnect (%p, A\"%ls\", %i, %ld),Ret: %p, tag_in: %s\n",
            hSession, pswzServerName, nServerPort, dwReserved, connectionHandle, tagin.c_str());

        // killAnalysis("WinHttpConnect");
        return connectionHandle;
    }
    else {
        Message("[W] WinHttpConnect (%p, A\"%ls\", %i, %ld), Ret: %p\n",
            hSession, pswzServerName, nServerPort, dwReserved, connectionHandle);
        return connectionHandle;
    }
}


BOOL WINAPI WinHttpSendRequestHook(
    winhttp::HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength,
    DWORD     dwTotalLength,
    DWORD_PTR dwContext
) {
    std::string read_header_tag = ReadTag((PVOID)lpszHeaders);
    std::string read_option_tag = "";
    if (lpOptional != WINHTTP_NO_REQUEST_DATA) {
        read_option_tag = ReadTag((PVOID)lpOptional);
    }

    if (read_header_tag.length() > 0) {
        Message("[W] WinHttpSendRequest (%p, A\"%ls\", 0x%x, A\"%s\", 0x%x, 0x%x, %p) tag_in: %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext, read_header_tag.c_str());
    }
    else if (read_option_tag.length() > 0) {
        Message("[W] WinHttpSendRequest (%p, A\"%ls\", 0x%x, A\"%s\", 0x%x, 0x%x, %p) tag_in: %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext, read_option_tag.c_str());
    }
    else {
        Message("[W] WinHttpSendRequest (%p, A\"%ls\", 0x%x, A\"%s\", 0x%x, 0x%x, %p)\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
    }

    return TRUE; //Only consider successful winhttp send requests for now
}

BOOL WINAPI WinHttpQueryDataAvailableHook(
    winhttp::HINTERNET hRequest,
    LPDWORD   lpdwNumberOfBytesAvailable
) {
    if (lpdwNumberOfBytesAvailable) {
        S2EMakeSymbolic(lpdwNumberOfBytesAvailable, sizeof(*lpdwNumberOfBytesAvailable), GetTag("WinHttpQueryDataAvailable").c_str());
    }
    return TRUE;
}

BOOL WINAPI WinHttpReadDataHook(
    winhttp::HINTERNET hRequest,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    auto it = perHandleBytesToRead.find(hRequest);
    if (it == perHandleBytesToRead.end()) {
        perHandleBytesToRead[hRequest] = DEFAULT_MEM_LEN;
        it = perHandleBytesToRead.find(hRequest);
    }
    DWORD bytes_left = it->second;
    DWORD bytes_read = bytes_left < dwNumberOfBytesToRead ? bytes_left : dwNumberOfBytesToRead;
    it->second -= bytes_read;
    *lpdwNumberOfBytesRead = bytes_read;

    /*
    //std::string data_read = "1BkeGqpo8M5KNVYXW3obmQt1R58zXAqLBQ 11223344 1BkeGqpo8M5KNVYXW3obmQt1R58zXAqLBQ 55667788"; //redaman
    std::string data_read = "DG8FV-B9TKY-FRT9J-6CRCC-XPQ4G-104A149B245C120D";   //spyanker
    if (bytes_read < data_read.size()) {
        data_read = data_read.substr(0, bytes_read);
    }
    if (bytes_read > 0) {
        memcpy(lpBuffer, data_read.c_str(), bytes_read);
    }*/


    std::string tag = GetTag("WinHttpReadData");
    S2EMakeSymbolic(lpBuffer, *lpdwNumberOfBytesRead, tag.c_str());
    S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag.c_str());
    Message("[W] WinHttpReadData (%p, %p, %ld, %p=0x%x)-> tag_out: %s\n", hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead, *lpdwNumberOfBytesRead, tag.c_str());
    return TRUE;

}

BOOL WINAPI WinHttpWriteDataHook(
    winhttp::HINTERNET hRequest,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_WINHTTPWRITEDATA;
    Command.WinHttpWriteData.hRequest = (uint64_t)hRequest;
    Command.WinHttpWriteData.lpBuffer = (uint64_t)lpBuffer;
    Command.WinHttpWriteData.dwNumberOfBytesToWrite = dwNumberOfBytesToWrite;
    Command.WinHttpWriteData.lpdwNumberOfBytesWritten = (uint64_t)lpdwNumberOfBytesWritten;

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    std::string tag = GetTag("WinHttpWriteData");
    S2EMakeSymbolic(lpdwNumberOfBytesWritten, 4, tag.c_str());

    std::string read_tag = ReadTag((PVOID)lpBuffer);

    if (read_tag.length() > 0) {
        Message("[W] WinHttpWriteData (%p, A\"%ls\", 0x%x, %p) -> tag_in: %s tag_out: %s\n",
            hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten, read_tag.c_str(), tag.c_str());
    }
    else {
        Message("[W] WinHttpWriteData (%p, A\"%ls\", 0x%x, %p) -> tag_out: %s\n",
            hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten, tag.c_str());
    }
    return TRUE;
}

BOOL WINAPI WinHttpAddRequestHeadersHook(
    winhttp::HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {
    std::string header_tag = ReadTag((PVOID)lpszHeaders);
    if (header_tag.length() > 0) {
        Message("[W] WinHttpAddRequestHeaders (%p, A\"%ls\", 0x%x,  0x%x) tag_in: %s\n",
            hRequest, lpszHeaders, dwHeadersLength, dwModifiers, header_tag);
    }
    else {
        Message("[W] WinHttpAddRequestHeaders (%p, A\"%ls\", 0x%x,  0x%x)\n",
            hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    }

    return TRUE;
}

BOOL WINAPI WinHttpCloseHandleHook(
    winhttp::HINTERNET hInternet
) {
    perHandleBytesToRead.erase(hInternet);

    Message("[W] WinHttpCloseHandle (%p)\n", hInternet);

    std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hInternet);

    if (it == dummyHandles.end()) {
        return winhttp::WinHttpCloseHandle(hInternet);
    }
    else {
        // The handle is a dummy handle. Free it
        free(*it);
        dummyHandles.erase(it);
        return TRUE;
    }
}

BOOL WINAPI WinHttpGetProxyForUrlHook(
    winhttp::HINTERNET                 hSession,
    LPCWSTR                   lpcwszUrl,
    winhttp::WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions,
    winhttp::WINHTTP_PROXY_INFO* pProxyInfo
) {
    Message("[W] WinHttpGetProxyForUrl (%p, A\"%ls\", %p, %p)\n", hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);
    return TRUE;
}

winhttp::HINTERNET WINAPI WinHttpOpenRequestHook(
    winhttp::HINTERNET hConnect,
    LPCWSTR   pwszVerb,
    LPCWSTR   pwszObjectName,
    LPCWSTR   pwszVersion,
    LPCWSTR   pwszReferrer,
    LPCWSTR* ppwszAcceptTypes,
    DWORD     dwFlags
) {

    winhttp::HINTERNET requestHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
    dummyHandles.insert(requestHandle);

    Message("[W] WinHttpOpenRequest (%p, A\"%ls\", A\"%ls\", A\"%ls\", A\"%ls\", %p, %ld), Ret: %p\n",
        hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags, requestHandle);

    return requestHandle;

}

BOOL WINAPI WinHttpQueryHeadersHook(
    winhttp::HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPCWSTR   pwszName,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
) {
    Message("[W] WinHttpQueryHeaders (%p, %ld, A\"%ls\", %p, %p, %p)\n", hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
    // If the buffer exists, symbolize
    if (lpBuffer) {
        std::string tag = GetTag("WinHttpQueryHeaders");
        S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag.c_str()); 
        S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
        Message("[W] WinHttpQueryHeaders (%p, %ld, A\"%ls\", %p, %p, %p) -> tag_out: %s\n", hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex, tag.c_str());

    }
    else {
        Message("[W] WinHttpQueryHeaders (%p, %ld, A\"%ls\", %p, %p, %p)\n", hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
    }

    return TRUE;
}


BOOL WINAPI WinHttpQueryOptionHook(
    winhttp::HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength
) {
    if (lpBuffer) {
        std::string tag = GetTag("WinHttpQueryOption");
        Message("[W] WinHttpQueryOption (%p, %ld, %p, %p) -> tag out:\n", hInternet, dwOption, lpBuffer, lpdwBufferLength);
        S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag.c_str());
        S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
    }
    else {
        Message("[W] WinHttpQueryOption (%p, %ld, %p, %p)\n", hInternet, dwOption, lpBuffer, lpdwBufferLength);
    }

    return TRUE;
}

DWORD WINAPI WinHttpResetAutoProxyHook(
    winhttp::HINTERNET hSession,
    DWORD     dwFlags
) {
    return 0;
}

BOOL WINAPI WinHttpSetCredentialsHook(
    winhttp::HINTERNET hRequest,
    DWORD     AuthTargets,
    DWORD     AuthScheme,
    LPCWSTR   pwszUserName,
    LPCWSTR   pwszPassword,
    LPVOID    pAuthParams
) {
    Message("[W] WinHttpSetCredentials(%p, %ld, %ld, %s, %s)\n", hRequest, AuthTargets, AuthScheme, pwszUserName, pwszPassword);

    return TRUE;
}

BOOL WINAPI WinHttpSetOptionHook(
    winhttp::HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
) {
    // lpBuffer can point to a DWROD, it can also point to a char array
    if (dwBufferLength == 4) {
        Message("[W] WinHttpSetOption(%p, %ld, %ld, %ld)\n", hInternet, dwOption, *(LPDWORD)lpBuffer, dwBufferLength);
    }
    else {
        Message("[W] WinHttpSetOption(%p, %ld, %ls, %ld)\n", hInternet, dwOption, (LPCTSTR)lpBuffer, dwBufferLength);
    }
    
    return TRUE;
}

BOOL WINAPI WinHttpSetTimeoutsHook(
    winhttp::HINTERNET hInternet,
    int       nResolveTimeout,
    int       nConnectTimeout,
    int       nSendTimeout,
    int       nReceiveTimeout
) {
    Message("[W] WinHttpSetTimeouts (%p, %i, %i, %i, %i)\n", hInternet, nResolveTimeout, nConnectTimeout, nSendTimeout, nReceiveTimeout);

    //Call the original function just in case that we will run some functions in the future
    //If it is a valid handle
    std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hInternet);

    if (it == dummyHandles.end()) {
        winhttp::WinHttpSetTimeouts(hInternet, 0, 0, 0, 0);
    }

    return TRUE;
}

BOOL WINAPI WinHttpReceiveResponseHook(
    winhttp::HINTERNET hRequest,
    LPVOID    lpReserved
) {
    Message("[W] WinHttpReceiveResponse (%p, %p)\n",
        hRequest, lpReserved);

    return TRUE; //Only consider successful winhttp responses for now
}


BOOL WINAPI WinHttpGetIEProxyConfigForCurrentUserHook(
    winhttp::WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig
) {
    WinHttpGetIEProxyConfigForCurrentUser(pProxyConfig);
    pProxyConfig->fAutoDetect = TRUE;
    std::string tag = GetTag("WinHttpGetIEProxyConfigForCurrentUser");
    S2EMakeSymbolic(pProxyConfig->lpszAutoConfigUrl, DEFAULT_MEM_LEN, tag.c_str());
    S2EMakeSymbolic(pProxyConfig->lpszProxy, DEFAULT_MEM_LEN, tag.c_str());
    S2EMakeSymbolic(pProxyConfig->lpszProxyBypass, DEFAULT_MEM_LEN, tag.c_str());
    Message("[W] WinHttpGetIEProxyConfigForCurrentUser (%p) -> tag_out: %s\n", pProxyConfig, tag.c_str());
    return TRUE;
}

