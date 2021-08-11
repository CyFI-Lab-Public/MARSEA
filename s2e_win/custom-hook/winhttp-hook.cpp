#include "winhttp-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>

static std::set<winhttp::HINTERNET> queryDataHandles;
static std::set<winhttp::HINTERNET> dummyHandles;

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
    Message("[HLOG] WinHttpCrackUrl (%p, %ld, %ld, %p)\n", pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    if (Command.WinHttpCrackUrl.symbolic) {
        Message("[HLOG] WinHttpCrackUrl received a symbolic URL.\n");
        pwszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
        winhttp::WinHttpCrackUrl(pwszUrl, 69, dwFlags, lpUrlComponents);
        Message("[HLOG] WinHttpCrackUrl (%ls, %ld, %ld, %p)\n", pwszUrl, 69, dwFlags, lpUrlComponents);
        return true;
    }
    else {
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
    Message("[HLOG] WinHttpSendRequest(%p, A\"%ls\", 0x%x, %p, 0x%x, 0x%x, %p)\n",
        hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);

    return TRUE; //Only consider successful winhttp send requests for now
}

BOOL WINAPI WinHttpQueryDataAvailableHook(
    winhttp::HINTERNET hRequest,
    LPDWORD   lpdwNumberOfBytesAvailable
) {

    if (lpdwNumberOfBytesAvailable) {
        S2EMakeSymbolic(lpdwNumberOfBytesAvailable, sizeof(*lpdwNumberOfBytesAvailable), GetTag("WinHttpQueryDataAvailable"));
    }

    return TRUE;
}

BOOL WINAPI WinHttpReadDataHook(
    winhttp::HINTERNET hRequest,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
     CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
     Command.Command = WINWRAPPER_WINHTTPREADDATA;
     Command.WinHttpReadData.hRequest = (uint64_t)hRequest;
     Command.WinHttpReadData.lpBuffer = lpBuffer;
     Command.WinHttpReadData.dwNumberOfBytesToRead = dwNumberOfBytesToRead;
     Command.WinHttpReadData.lpdwNumberOfByteRead = lpdwNumberOfBytesRead;
     Command.needOrigFunc = 0;

     S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
 
 //BOOL ret = winhttp::WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
 //char buf[19] = "CyFi_Concrete_Read";
 //memcpy(lpBuffer, buf, 46);

    Message("[HLOG] WinHttpReadData(%p, A\"%ls\", 0x%x, %p)\n",
        hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

    if (dwNumberOfBytesToRead) {
        dwNumberOfBytesToRead = min(dwNumberOfBytesToRead, DEFAULT_MEM_LEN);
    }
    PCSTR tag = GetTag("WinHttpReadData");
    S2EMakeSymbolic(lpBuffer, dwNumberOfBytesToRead, tag);
    S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag);
    //*lpdwNumberOfBytesRead = 0x80;

    //char buf [46] = ")))))aHR0cHM6Ly93MHJtLmluL2pvaW4vam9pbi5waHA=";
    //memcpy(lpBuffer, buf, 46);


    return TRUE;
}

BOOL WINAPI WinHttpWriteDataHook(
    winhttp::HINTERNET hRequest,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
) {
    Message("[HLOG] WinHttpWriteData(%p, A\"%ls\", 0x%x, %p)\n",
        hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_WINHTTPWRITEDATA;
    Command.WinHttpWriteData.hRequest = (uint64_t)hRequest;
    Command.WinHttpWriteData.lpBuffer = lpBuffer;
    Command.WinHttpWriteData.dwNumberOfBytesToWrite = dwNumberOfBytesToWrite;
    Command.WinHttpWriteData.lpdwNumberOfBytesWritten = lpdwNumberOfBytesWritten;

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    S2EMakeSymbolic(lpdwNumberOfBytesWritten, 4, GetTag("WinHttpWriteData"));
    return TRUE;
}

winhttp::HINTERNET WINAPI WinHttpConnectHook(
    winhttp::HINTERNET hSession,
    LPCWSTR pswzServerName,
    winhttp::INTERNET_PORT nServerPort,
    DWORD dwReserved
) {
    winhttp::HINTERNET connectionHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
    dummyHandles.insert(connectionHandle);

    Message("[HLOG] WinHttpConnect(%p, A\"%ls\", %i, %ld) Ret: %p\n",
        hSession, pswzServerName, nServerPort, dwReserved, connectionHandle);

    if (S2EIsSymbolic((PVOID)pswzServerName, 0x1000)) {
        Message("[HLOG] Found symbolic connection...probably a success!\n");
    }

    return connectionHandle;

}

BOOL WINAPI WinHttpAddRequestHeadersHook(
    winhttp::HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {
    Message("[HLOG] WinHttpAddRequestHeaders(%p, A\"%ls\", 0x%x,  0x%x)\n",
        hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    return TRUE;
}

BOOL WINAPI WinHttpCloseHandleHook(
    winhttp::HINTERNET hInternet
) {
    Message("[HLOG] WinHttpCloseHandle(%p)\n", hInternet);

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
    Message("[HLOG] WinHttpCloseHandle(%p, A\"%ls\", %p, %p)\n", hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);
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

    Message("[HLOG] WinHttpOpenRequest(%p, A\"%ls\", A\"%ls\", A\"%ls\", A\"%ls\", %p, %ld) Ret: %p\n",
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
    Message("[HLOG] WinHttpQueryHeaders(%p, %ld, A\"%ls\", %p, %p, %p", hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
    // If the buffer exists, symbolize
    if (lpBuffer) {
        PCSTR tag = GetTag("WinHttpQueryHeaders");
        S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag); 
        S2EMakeSymbolic(lpdwBufferLength, 4, tag);
    }

    return TRUE;
}


BOOL WINAPI WinHttpQueryOptionHook(
    winhttp::HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength
) {
    Message("[HLOG] WinHttpQueryOption(%p, %ld, %p, %p", hInternet, dwOption, lpBuffer, lpdwBufferLength);
    if (lpBuffer) {
        PCSTR tag = GetTag("WinHttpQueryOption");
        S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag);
        S2EMakeSymbolic(lpdwBufferLength, 4, tag);
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
    Message("[HLOG] WinHttpSetCredentials(%p, %ld, %ld, %s, %s", hRequest, AuthTargets, AuthScheme, pwszUserName, pwszPassword);

    return TRUE;
}

BOOL WINAPI WinHttpSetOptionHook(
    winhttp::HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
) {
    Message("[HLOG] WinHttpSetOption(%p, %ld, %p, %ld", hInternet, dwOption, lpBuffer, dwBufferLength);
    
    return TRUE;
}

BOOL WINAPI WinHttpSetTimeoutsHook(
    winhttp::HINTERNET hInternet,
    int       nResolveTimeout,
    int       nConnectTimeout,
    int       nSendTimeout,
    int       nReceiveTimeout
) {
    Message("[HLOG] WinHttpSetTimeouts(%p, %i, %i, %i, %i)", hInternet, nResolveTimeout, nConnectTimeout, nSendTimeout, nReceiveTimeout);

    //Call the original function just in case that we will run some functiosn in the future
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
    //WinHttpOpen should still succeed w/o network
    winhttp::HINTERNET sessionHandle = winhttp::WinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
    Message("[HLOG] WinHttpOpen(A\"%ls\", %ld, A\"%ls\", A\"%ls\", %ld) Ret: %p\n",
        pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags, sessionHandle);
    //HINTERNET sessionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    //HINTERNET sessionHandle = winhttp::WinHttpOpen(g_unique_handle, NULL, NULL, NULL, NULL);

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

    //    Message("[HLOG] WinHttpOpen(A\"%ls\", %i, A\"%ls\", A\"%ls\", %i) Ret: %p\n",
    //        pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags, sessionHandle);

    //    return sessionHandle;
    //}
    //else {
    //    // Explore when WinHttpOpen fails
    //    return NULL;
    //}

    return sessionHandle;
}

BOOL WINAPI WinHttpReceiveResponseHook(
    winhttp::HINTERNET hRequest,
    LPVOID    lpReserved
) {
    Message("[HLOG] WinHttpReceiveResponse(%p, %p)\n",
        hRequest, lpReserved);

    return TRUE; //Only consider successful winhttp responses for now
}