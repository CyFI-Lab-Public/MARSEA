#include "winhttp-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>
#include <string>

static std::set<winhttp::HINTERNET> queryDataHandles;
static std::set<winhttp::HINTERNET> dummyHandles;
LPCWSTR g_unique_handle = 0;

BOOL WINAPI WinHttpCrackUrlHook(
	LPCWSTR          pwszUrl,
	DWORD            dwUrlLength,
	DWORD            dwFlags,
	winhttp::LPURL_COMPONENTS lpUrlComponents
) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_WINHTTPCRACKURL;
    Command.WinHttpCrackUrl.pwszUrl = (uint64_t)pwszUrl;
    Command.WinHttpCrackUrl.dwUrlLength = (uint64_t)dwUrlLength;
    Command.WinHttpCrackUrl.dwFlags = (uint64_t)dwFlags;
    Command.WinHttpCrackUrl.lpUrlComponets = (uint64_t)lpUrlComponents;

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    if (Command.WinHttpCrackUrl.symbolic) {
        pwszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
        winhttp::WinHttpCrackUrl(pwszUrl, 52, dwFlags, lpUrlComponents);
        std::string tag = GetTag("WinHttpCrackUrl");
        S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
        Message("[W] WinHttpCrackUrl (%p, %ld, %ld, %p) -> tag_out: %s\n",
            pwszUrl, dwUrlLength, dwFlags, lpUrlComponents, tag.c_str());
        return TRUE;
    }
    else {
        Message("[W] WinHttpCrackUrl (%p, %ld, %ld, %p)\n", pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
        bool ret = winhttp::WinHttpCrackUrl(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
        return ret;
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
    Message("[W] WinHttpSendRequest (%p, A\"%ls\", 0x%x, %p, 0x%x, 0x%x, %p)\n",
        hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);

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

    if (dwNumberOfBytesToRead) {
        dwNumberOfBytesToRead = min(dwNumberOfBytesToRead, DEFAULT_MEM_LEN);
    }
    std::string tag = GetTag("WinHttpReadData");
    S2EMakeSymbolic(lpBuffer, dwNumberOfBytesToRead, tag.c_str());
    S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag.c_str());
    Message("[W] WinHttpReadData (%p, %p, %ld, %p)-> tag_out: %s\n", hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead, tag.c_str());
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
    Message("[W] WinHttpWriteData (%p, A\"%ls\", 0x%x, %p) -> tag_out: %s\n",
        hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten, tag.c_str());
    return TRUE;
}

winhttp::HINTERNET WINAPI WinHttpConnectHook(
    winhttp::HINTERNET hSession,
    LPCWSTR pswzServerName,
    winhttp::INTERNET_PORT nServerPort,
    DWORD dwReserved
) {

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_WINHTTPCONNECT;
    Command.WinHttpConnect.hSession = (uint64_t)hSession;
    Command.WinHttpConnect.pswzServerName = (uint64_t)pswzServerName;
    Command.WinHttpConnect.nServerPort = (uint64_t)nServerPort;
    Command.WinHttpConnect.dwReserved = (uint64_t)dwReserved;

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    winhttp::HINTERNET connectionHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
    dummyHandles.insert(connectionHandle);
    Message("[W] WinHttpConnect (%p, A\"%ls\", i, %ld), Ret: %p\n",
        hSession, pswzServerName, nServerPort, dwReserved, connectionHandle);
    return connectionHandle;
}

BOOL WINAPI WinHttpAddRequestHeadersHook(
    winhttp::HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {
    Message("[W] WinHttpAddRequestHeaders (%p, A\"%ls\", 0x%x,  0x%x)\n",
        hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    return TRUE;
}

BOOL WINAPI WinHttpCloseHandleHook(
    winhttp::HINTERNET hInternet
) {
    Message("[W] WinHttpCloseHandle (%p)\n", hInternet);

    std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hInternet);

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
    Message("[W] WinHttpSetCredentials(%p, %ld, %ld, %s, %s", hRequest, AuthTargets, AuthScheme, pwszUserName, pwszPassword);

    return TRUE;
}

BOOL WINAPI WinHttpSetOptionHook(
    winhttp::HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
) {
    Message("[W] WinHttpSetOption(%p, %ld, %p, %ld", hInternet, dwOption, lpBuffer, dwBufferLength);
    
    return TRUE;
}

BOOL WINAPI WinHttpSetTimeoutsHook(
    winhttp::HINTERNET hInternet,
    int       nResolveTimeout,
    int       nConnectTimeout,
    int       nSendTimeout,
    int       nReceiveTimeout
) {
    Message("[W] WinHttpSetTimeouts (%p, %i, %i, %i, %i)", hInternet, nResolveTimeout, nConnectTimeout, nSendTimeout, nReceiveTimeout);

    //Call the original function just in case that we will run some functions in the future
    //If it is a valid handle
    std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hInternet);

    if (it == dummyHandles.end()) {
        winhttp::WinHttpSetTimeouts(hInternet, 0, 0, 0, 0);
    }

    return TRUE;
}

winhttp::HINTERNET WINAPI WinHttpOpenHook(
    LPCWSTR pszAgentW,
    DWORD dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD dwFlags
) {
    g_unique_handle += 100;
    winhttp::HINTERNET sessionHandle = winhttp::WinHttpOpen(g_unique_handle, NULL, NULL, NULL, NULL);
    dummyHandles.insert(sessionHandle);    
    Message("[W] WinHttpOpen (A\"%ls\", %ld, A\"%ls\", A\"%ls\", %ld), Ret: %p\n",
        pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags, sessionHandle);
    return sessionHandle;
    //std::set<HINTERNET>::iterator it = dummyHandles.find(sessionHandle);

    //UINT8 returnSession = S2ESymbolicChar("pszAgentW", 1);
    //if (returnSession) {
    //    if (it == dummyHandles.end()) {
    //        // The handle is not one of our dummy handles
    //        dummyHandles.insert(sessionHandle);
    //    }
    //    else {
    //        // The handle is a dummy handle. 
    //        g_unique_handle += 100;
    //        HINTERNET sessionHandle = winhttp::WinHttpOpen(g_unique_handle, NULL, NULL, NULL, NULL);
    //        Message("Needed unique %s", g_unique_handle);
    //        dummyHandles.insert(sessionHandle);
    //    }

    //    Message("[W] WinHttpOpen(A\"%ls\", %i, A\"%ls\", A\"%ls\", %i) Ret: %p\n",
    //        pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags, sessionHandle);

    //    return sessionHandle;
    //}
    //else {
    //    // Explore when WinHttpOpen fails
    //    return NULL;
    //}

}

BOOL WINAPI WinHttpReceiveResponseHook(
    winhttp::HINTERNET hRequest,
    LPVOID    lpReserved
) {
    Message("[W] WinHttpReceiveResponse (%p, %p)\n",
        hRequest, lpReserved);

    return TRUE; //Only consider successful winhttp responses for now
}