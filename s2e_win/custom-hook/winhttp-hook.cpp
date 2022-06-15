#include "winhttp-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>
#include <string>
#include <unordered_map>

static std::set<winhttp::HINTERNET> queryDataHandles;
static std::set<winhttp::HINTERNET> dummyHandles;
static std::unordered_map<winhttp::HINTERNET, DWORD> perHandleBytesToRead;
static std::unordered_map<winhttp::HINTERNET, DWORD> perHandleBytesRead;

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
        dummyHandles.insert(sessionHandle);
    }
    Message("[W] WinHttpOpen (%ls [|] %ld [|] %ls [|] %ls [|] %ld) ret:%p\n",
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
        pwszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
        winhttp::WinHttpCrackUrl(pwszUrl, 52, dwFlags, lpUrlComponents);
        std::string tag = GetTag("WinHttpCrackUrl");
        S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
        Message("[W] WinHttpCrackUrl (%ls [|] %ld [|] %ld [|] %p) tag_in:%s tag_out:%s\n",
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
    winhttp::HINTERNET connectionHandle;

    std::string tagin = ReadTag((PVOID)pswzServerName);
    if (tagin != "") {
        winhttp::HINTERNET handle = winhttp::WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);

        if (handle == NULL) {
            Message("WinHttpConnect 0\n");
            connectionHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
            dummyHandles.insert(connectionHandle);
        }
        else {
            Message("WinHttpConnect 1\n");
            connectionHandle = handle;
        }

        Message("[W] WinHttpConnect (%p [|] %ls [|] %i [|] %ld) ret:%p tag_in:%s\n",
            hSession, pswzServerName, nServerPort, dwReserved, connectionHandle, tagin.c_str());

        // killAnalysis("WinHttpConnect");
        return connectionHandle;
    }
    else {

        winhttp::HINTERNET handle = winhttp::WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);

        if (handle == NULL) {
            Message("WinHttpConnect 0\n");
            connectionHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
            dummyHandles.insert(connectionHandle);
        }
        else {
            Message("WinHttpConnect 1\n");
            connectionHandle = handle;
        }

        Message("[W] WinHttpConnect (%p [|] %ls [|] %i [|] %ld) ret:%p\n",
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
        if (lpOptional) {
            Message("[W] WinHttpSendRequest (%p [|] %ls [|] 0x%x [|] %s [|] 0x%x [|] 0x%x [|] %p) tag_in:%s\n",
                hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext, read_header_tag.c_str());
        }
        else {
            Message("[W] WinHttpSendRequest (%p [|] %ls [|] 0x%x [|] %p [|] 0x%x [|] 0x%x [|] %p) tag_in:%s\n",
                hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext, read_header_tag.c_str());
        }
        
    }
    else if (read_option_tag.length() > 0) {
        if (lpOptional) {
            Message("[W] WinHttpSendRequest (%p [|] %ls [|] 0x%x [|] %s [|] 0x%x [|] 0x%x [|] %p) tag_in:%s\n",
                hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext, read_option_tag.c_str());
        }
        else {
            Message("[W] WinHttpSendRequest (%p [|] %ls [|] 0x%x [|] %p [|] 0x%x [|] 0x%x [|] %p) tag_in:%s\n",
                hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext, read_option_tag.c_str());
        }
        
    }
    else {
        if (lpOptional) {
            Message("[W] WinHttpSendRequest (%p [|] %ls [|] 0x%x [|] %s [|] 0x%x [|] 0x%x [|] %p)\n",
                hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
        }
        else {
            Message("[W] WinHttpSendRequest (%p [|] %ls [|] 0x%x [|] %p [|] 0x%x [|] 0x%x [|] %p)\n",
                hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
        }
       
    }

    S2EBeginAtomic();
    bool res = winhttp::WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
    S2EEndAtomic();

    if (res) {
        Message("WinHttpSendRequest 1\n");
    }
    else {
        Message("WinHttpSendRequest 0\n");
    }
    return TRUE; //Only consider successful winhttp send requests for now
}

BOOL WINAPI WinHttpQueryDataAvailableHook(
    winhttp::HINTERNET hRequest,
    LPDWORD   lpdwNumberOfBytesAvailable
) {
    std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hRequest);

    bool concrete_res = FALSE;

    if (it == dummyHandles.end()) {
        concrete_res = winhttp::WinHttpQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable);
    }

    if (concrete_res) {
        Message("WinHttpQueryDataAvailable 1\n");
    }
    else {
        auto it = perHandleBytesToRead.find(hRequest);
        if (it == perHandleBytesToRead.end() && lpdwNumberOfBytesAvailable) {
            *lpdwNumberOfBytesAvailable = DEFAULT_MEM_LEN;
        }

        if (it != perHandleBytesToRead.end() && lpdwNumberOfBytesAvailable) {
            *lpdwNumberOfBytesAvailable = 0;
        }
        Message("WinHttpQueryDataAvailable 0\n");
    }

    //if (lpdwNumberOfBytesAvailable) {
    //    S2EMakeSymbolic(lpdwNumberOfBytesAvailable, sizeof(*lpdwNumberOfBytesAvailable), GetTag("WinHttpQueryDataAvailable").c_str());
    //}

    return TRUE;
}

BOOL WINAPI WinHttpReadDataHook(
    winhttp::HINTERNET hRequest,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {

    BOOL read_res = winhttp::WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

    BOOL fake = TRUE;

    if (read_res) {
        // If it reads more than 0 bytes
        if (*lpdwNumberOfBytesRead > 0) {

            auto it = perHandleBytesRead.find(hRequest);

            if (it == perHandleBytesRead.end()) {
                perHandleBytesRead[hRequest] = 1;
            }

            fake = FALSE;

        }
        else {
            // If it reads 0 bytes, check if this handle reads anything before
            auto it = perHandleBytesRead.find(hRequest);

            if (it != perHandleBytesRead.end()) {
                fake = FALSE;
            }
        }
    }

    DWORD bytes_read = 0;

    if (fake) {
        Message("WinHttpReadData 0\n");
        auto it = perHandleBytesToRead.find(hRequest);
        if (it == perHandleBytesToRead.end()) {
            perHandleBytesToRead[hRequest] = DEFAULT_MEM_LEN;
            it = perHandleBytesToRead.find(hRequest);
        }
        DWORD bytes_left = it->second;
        bytes_read = bytes_left < dwNumberOfBytesToRead ? bytes_left : dwNumberOfBytesToRead;
        it->second -= bytes_read;
        *lpdwNumberOfBytesRead = bytes_read;
    }
    else {
        Message("WinHttpReadData 1\n");
        auto it = perHandleBytesToRead.find(hRequest);
        if (it == perHandleBytesToRead.end()) {
            perHandleBytesToRead[hRequest] = DEFAULT_MEM_LEN;
            it = perHandleBytesToRead.find(hRequest);
        }
        DWORD bytes_left = it->second;
        bytes_read = bytes_left < *lpdwNumberOfBytesRead ? bytes_left : *lpdwNumberOfBytesRead;
        it->second -= bytes_read;
    }

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

    Message("[W] WinHttpReadData (%p [|] %p [|] %ld [|] %ld) tag_out:%s\n", hRequest, lpBuffer, dwNumberOfBytesToRead, *lpdwNumberOfBytesRead, tag.c_str());

    S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
    S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag.c_str());

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = TAG_TRACKER;
    Command.tagTracker.tag = (uint64_t)tag.c_str();
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
    
    return TRUE;

}

BOOL WINAPI WinHttpWriteDataHook(
    winhttp::HINTERNET hRequest,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
) {
    //CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    //Command.Command = WINWRAPPER_WINHTTPWRITEDATA;
    //Command.WinHttpWriteData.hRequest = (uint64_t)hRequest;
    //Command.WinHttpWriteData.lpBuffer = (uint64_t)lpBuffer;
    //Command.WinHttpWriteData.dwNumberOfBytesToWrite = dwNumberOfBytesToWrite;
    //Command.WinHttpWriteData.lpdwNumberOfBytesWritten = (uint64_t)lpdwNumberOfBytesWritten;

    //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    *lpdwNumberOfBytesWritten = dwNumberOfBytesToWrite;

    std::string tag = GetTag("WinHttpWriteData");
    S2EMakeSymbolic(lpdwNumberOfBytesWritten, sizeof(DWORD), tag.c_str());

    std::string read_tag = ReadTag((PVOID)lpBuffer);

    if (read_tag.length() > 0) {
        Message("[W] WinHttpWriteData (%p [|] %ls [|] 0x%x [|] %p) tag_in:%s tag_out:%s\n",
            hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten, read_tag.c_str(), tag.c_str());
    }
    else {
        Message("[W] WinHttpWriteData (%p [|] %ls [|] 0x%x [|] %p) tag_out:%s\n",
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
        Message("[W] WinHttpAddRequestHeaders (%p [|] %ls [|] 0x%x [|] 0x%x) tag_in:%s\n",
            hRequest, lpszHeaders, dwHeadersLength, dwModifiers, header_tag);
    }
    else {
        Message("[W] WinHttpAddRequestHeaders (%p [|] %ls [|] 0x%x [|] 0x%x)\n",
            hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    }

    bool con_res = winhttp::WinHttpAddRequestHeaders(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);



    return TRUE;
}

BOOL WINAPI WinHttpCloseHandleHook(
    winhttp::HINTERNET hInternet
) {
    perHandleBytesToRead.erase(hInternet);
    perHandleBytesRead.erase(hInternet);

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
    Message("[W] WinHttpGetProxyForUrl (%p [|] %ls [|] %p [|] %p)\n", hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);
    bool con_res = winhttp::WinHttpGetProxyForUrl(hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);

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

    winhttp::HINTERNET requestHandle = winhttp::WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);

    if (requestHandle == NULL) {

        requestHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
        dummyHandles.insert(requestHandle);
    }


    Message("[W] WinHttpOpenRequest (%p [|] %ls [|] %ls [|] %ls [|] %ls [|] %p [|] %ld) ret:%p\n",
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

    // If the buffer exists, symbolize
    if (lpBuffer) {
        std::string tag = GetTag("WinHttpQueryHeaders");

        Message("[W] WinHttpQueryHeaders (%p [|] %ld [|] %ls [|] %p [|] %p [|] %p) tag_out:%s\n", hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex, tag.c_str());

        std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hRequest);

        BOOL query_res = FALSE;

        if (it == dummyHandles.end()) {
            query_res = winhttp::WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
        }

        if (query_res) {
            Message("WinHttpQueryHeaders 1\n");
            S2EMakeSymbolic(lpBuffer, *lpdwBufferLength, tag.c_str());
        }
        else {
            Message("WinHttpQueryHeaders 0\n");
            S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag.c_str());
            S2EMakeSymbolic(lpdwBufferLength, sizeof(DWORD), tag.c_str());
        }
        
    }
    else {
        std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hRequest);

        BOOL query_res = FALSE;

        if (it == dummyHandles.end()) {
            query_res = winhttp::WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
        }

        if (query_res) {
            Message("WinHttpQueryHeaders 1\n");
        }
        else {
            Message("WinHttpQueryHeaders 0\n");
        }

        Message("[W] WinHttpQueryHeaders (%p [|] %ld [|] %ls [|] %p [|] %p [|] %p)\n", hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
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

        Message("[W] WinHttpQueryOption (%p [|] %ld [|] %p [|] %p) tag out:\n", hInternet, dwOption, lpBuffer, lpdwBufferLength);


        std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hInternet);

        BOOL query_res = FALSE;

        if (it == dummyHandles.end()) {
            query_res = winhttp::WinHttpQueryOption(hInternet, dwOption, lpBuffer, lpdwBufferLength);
        }

        if (query_res) {

            S2EMakeSymbolic(lpBuffer, *lpdwBufferLength, tag.c_str());
        }
        else {

            S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag.c_str());
            S2EMakeSymbolic(lpdwBufferLength, sizeof(DWORD), tag.c_str());
        }
        
    }
    else {

        std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hInternet);

        BOOL query_res = FALSE;

        if (it == dummyHandles.end()) {
            query_res = winhttp::WinHttpQueryOption(hInternet, dwOption, lpBuffer, lpdwBufferLength);
        }



        Message("[W] WinHttpQueryOption (%p [|] %ld [|] %p [|] %p)\n", hInternet, dwOption, lpBuffer, lpdwBufferLength);
    }

    return TRUE;
}

DWORD WINAPI WinHttpResetAutoProxyHook(
    winhttp::HINTERNET hSession,
    DWORD     dwFlags
) {
    winhttp::WinHttpResetAutoProxy(hSession, dwFlags);
    return ERROR_SUCCESS;
}

BOOL WINAPI WinHttpSetCredentialsHook(
    winhttp::HINTERNET hRequest,
    DWORD     AuthTargets,
    DWORD     AuthScheme,
    LPCWSTR   pwszUserName,
    LPCWSTR   pwszPassword,
    LPVOID    pAuthParams
) {
    Message("[W] WinHttpSetCredentials(%p [|] %ld [|] %ld [|] %ls [|] %ls [|] %p)\n", hRequest, AuthTargets, AuthScheme, pwszUserName, pwszPassword);

    winhttp::WinHttpSetCredentials(hRequest, AuthTargets, AuthScheme, pwszUserName, pwszPassword, pAuthParams);

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
        Message("[W] WinHttpSetOption(%p [|] %ld [|] %ld [|] %ld)\n", hInternet, dwOption, *(LPDWORD)lpBuffer, dwBufferLength);
    }
    else {
        Message("[W] WinHttpSetOption(%p [|] %ld [|] %s [|] %ld)\n", hInternet, dwOption, (LPCTSTR)lpBuffer, dwBufferLength);
    }

    bool con_res = winhttp::WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);

    
    return TRUE;
}

BOOL WINAPI WinHttpSetTimeoutsHook(
    winhttp::HINTERNET hInternet,
    int       nResolveTimeout,
    int       nConnectTimeout,
    int       nSendTimeout,
    int       nReceiveTimeout
) {
    Message("[W] WinHttpSetTimeouts (%p [|] %i [|] %i [|] %i [|] %i)\n", hInternet, nResolveTimeout, nConnectTimeout, nSendTimeout, nReceiveTimeout);

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

    // Not sure if this function will block or not. So if it is using dummy handle, dont trigger the real function

    std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hRequest);

    bool concrete_res = FALSE;

    if (it == dummyHandles.end()) {
        concrete_res = winhttp::WinHttpReceiveResponse(hRequest, lpReserved);
    }



    Message("[W] WinHttpReceiveResponse (%p [|] %p)\n",
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
    Message("[W] WinHttpGetIEProxyConfigForCurrentUser (%p) tag_out:%s\n", pProxyConfig, tag.c_str());
    return TRUE;
}

