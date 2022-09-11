#include "winhttp-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>
#include <string>
#include <unordered_map>
#include <atlstr.h>

static std::set<winhttp::HINTERNET> queryDataHandles;
static std::set<winhttp::HINTERNET> dummyHandles;
static std::unordered_map<winhttp::HINTERNET, DWORD> perHandleBytesToRead;
static std::unordered_map<winhttp::HINTERNET, DWORD> perHandleBytesRead;
static std::unordered_map<winhttp::HINTERNET, DWORD> perHandleBytesToQuery;

winhttp::HINTERNET WINAPI WinHttpOpenHook(
    LPCWSTR pszAgentW,
    DWORD dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD dwFlags
) {
    //WinHttpOpen should still succeed w/o network

    /*std::string agent = CW2A(pszAgentW);
    std::string proxy = CW2A(pszProxyW);
    std::string proxybypass = CW2A(pszProxyBypassW);*/
    
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
    bool isTaint = IsTainted((PVOID)pwszUrl);
    std::string tagin = ReadTag((PVOID)pwszUrl);
    if (tagin != "") {

        bool hack = FALSE;

        if (isTaint) {
            S2EDisableForking();
            hack = !winhttp::WinHttpCrackUrl(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
            S2EEnableForking();

            if (!hack) {
                std::string tag = GetTag("WinHttpCrackUrl");
                Message("[W] WinHttpCrackUrl (%ls [|] %ld [|] %ld [|] %p) tag_in:%s tag_out:%s\n",
                    pwszUrl, dwUrlLength, dwFlags, lpUrlComponents, tagin.c_str(), tag.c_str());
                cyfiTaint((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
            }
        }

        if ((!isTaint) || hack) {
            pwszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
            winhttp::WinHttpCrackUrl(pwszUrl, 52, dwFlags, lpUrlComponents);
            std::string tag = GetTag("WinHttpCrackUrl");
            Message("[W] WinHttpCrackUrl (%ls [|] %ld [|] %ld [|] %p) tag_in:%s tag_out:%s\n",
                pwszUrl, dwUrlLength, dwFlags, lpUrlComponents, tagin.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
        }
        
        return TRUE;
    }

    Message("[W] WinHttpCrackUrl (%ls [|] %ld [|] %ld [|] %p)\n",
                pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
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
    bool isTaint = IsTainted((PVOID)pswzServerName);

    if (tagin != "") {

        S2EDisableForking();

        cyfiPrintMemory((PVOID)pswzServerName, wcslen(pswzServerName) * 2);

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

        S2EEnableForking();

        // killAnalysis("WinHttpConnect");
        return connectionHandle;
    }
    else {

        S2EDisableForking();

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

        S2EEnableForking();

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

    S2EDisableForking();

    if (lpOptional) {
        Message("[W] WinHttpSendRequest (%p [|] %ls [|] 0x%x [|] %s [|] 0x%x [|] 0x%x [|] %p) tag_in:%s %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext, read_header_tag.c_str(), read_option_tag.c_str());
    }
    else {
        Message("[W] WinHttpSendRequest (%p [|] %ls [|] 0x%x [|] %p [|] 0x%x [|] 0x%x [|] %p) tag_in:%s %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext, read_header_tag.c_str(), read_option_tag.c_str());
    }

    if (lpszHeaders && read_header_tag != "") {
        Message("Headers Memory: ");
        cyfiPrintMemory((PVOID)lpszHeaders, dwHeadersLength * 2);
    }

    if (lpOptional && read_option_tag != "") {
        Message("Optional Memory: ");
        cyfiPrintMemory((PVOID)lpOptional, dwOptionalLength * 2);
    }

    S2EBeginAtomic();
    bool res = winhttp::WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
    S2EEndAtomic();

    S2EEnableForking();

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

    S2EDisableForking();

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

    std::string tag = GetTag("WinHttpReadData");

    Message("[W] WinHttpReadData (%p [|] %s [|] %ld [|] %ld) tag_out:%s\n", hRequest, lpBuffer, dwNumberOfBytesToRead, *lpdwNumberOfBytesRead, tag.c_str());

    S2EEnableForking();

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
        it->second = it->second < 0 ? 0 : it->second;
        *lpdwNumberOfBytesRead = bytes_read;
        S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
        if (bytes_read != 0) {
            S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag.c_str());
        }
        
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
        it->second = it->second < 0 ? 0 : it->second;
        cyfiTaint(lpBuffer, *lpdwNumberOfBytesRead, tag.c_str());
        cyfiTaint(lpdwNumberOfBytesRead, 4, tag.c_str());
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
    Message("WriteData Memory: ");
    cyfiPrintMemory((PVOID)lpBuffer, dwNumberOfBytesToWrite);

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

    S2EDisableForking();

    std::string header_tag = ReadTag((PVOID)lpszHeaders);

    if (header_tag.length() > 0) {
        Message("[W] WinHttpAddRequestHeaders (%p [|] %ls [|] 0x%x [|] 0x%x) tag_in:%s\n",
            hRequest, lpszHeaders, dwHeadersLength, dwModifiers, header_tag.c_str());
        Message("Header Memory: ");
        cyfiPrintMemory((PVOID)lpszHeaders, dwHeadersLength * 2);
    }
    else {
        Message("[W] WinHttpAddRequestHeaders (%p [|] %ls [|] 0x%x [|] 0x%x)\n",
            hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    }

    bool con_res = winhttp::WinHttpAddRequestHeaders(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);

    S2EEnableForking();

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
    std::string verbTag = ReadTag((PVOID)pwszVerb);
    std::string objectNameTag = ReadTag((PVOID)pwszObjectName);
    std::string versionTag = ReadTag((PVOID)pwszVersion);
    std::string referrerTag = ReadTag((PVOID)pwszReferrer);

    S2EDisableForking();
    winhttp::HINTERNET requestHandle = winhttp::WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);

    if (requestHandle == NULL) {

        requestHandle = (winhttp::HINTERNET)malloc(sizeof(winhttp::HINTERNET));
        dummyHandles.insert(requestHandle);
    }

    if (pwszVerb && verbTag != "") {
        Message("Verb Memory: ");
        cyfiPrintMemory((PVOID)pwszVerb, wcslen(pwszVerb)*2);
    }

    if (pwszObjectName && objectNameTag != "") {
        Message("Object Memory: ");
        cyfiPrintMemory((PVOID)pwszObjectName, wcslen(pwszObjectName) * 2);
    }

    if (pwszVersion && versionTag != "") {
        Message("Version Memory: ");
        cyfiPrintMemory((PVOID)pwszVersion, wcslen(pwszVersion) * 2);
    }

    if (pwszReferrer && referrerTag != "") {
        Message("Referrer Memory: ");
        cyfiPrintMemory((PVOID)pwszReferrer, wcslen(pwszReferrer) * 2);
    }


    Message("[W] WinHttpOpenRequest (%p [|] %ls [|] %ls [|] %ls [|] %ls [|] %p [|] %ld) ret:%p tag_in: %s %s %s %s\n",
        hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags, requestHandle, verbTag.c_str(), objectNameTag.c_str(), versionTag.c_str(), referrerTag.c_str());

    S2EEnableForking();

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

        S2EDisableForking();

        std::string tag = GetTag("WinHttpQueryHeaders");

        Message("[W] WinHttpQueryHeaders (%p [|] %ld [|] %ls [|] %p [|] %p [|] %p) tag_out:%s\n", hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex, tag.c_str());

        std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hRequest);

        BOOL query_res = FALSE;

        if (it == dummyHandles.end()) {
            query_res = winhttp::WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
        }

        S2EEnableForking();

        if (query_res) {
            Message("WinHttpQueryHeaders 1\n");
            cyfiTaint(lpBuffer, *lpdwBufferLength, tag.c_str());
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

        S2EDisableForking();

        std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hInternet);

        BOOL query_res = FALSE;

        if (it == dummyHandles.end()) {
            query_res = winhttp::WinHttpQueryOption(hInternet, dwOption, lpBuffer, lpdwBufferLength);
        }

        Message("[W] WinHttpQueryOption (%p [|] %ld [|] %s [|] %p) tag out:\n", hInternet, dwOption, lpBuffer, lpdwBufferLength);

        if (query_res) {
            cyfiTaint(lpBuffer, *lpdwBufferLength, tag.c_str());
        }
        else {

            auto it = perHandleBytesToQuery.find(hInternet);
            if (it == perHandleBytesToQuery.end()) {
                perHandleBytesToQuery[hInternet] = DEFAULT_MEM_LEN;
                it = perHandleBytesToQuery.find(hInternet);
            }

            DWORD bytes_left = it->second;

            DWORD bytes_read = bytes_left < *lpdwBufferLength ? bytes_left : *lpdwBufferLength;

            S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
            S2EMakeSymbolic(lpdwBufferLength, sizeof(DWORD), tag.c_str());
        }

        S2EEnableForking();
        
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

    std::string userNameTag = ReadTag((PVOID)pwszUserName);
    std::string passwordTag = ReadTag((PVOID)pwszPassword);

    S2EDisableForking();

    if (pwszUserName && userNameTag != "") {
        Message("UserName Memory: ");
        cyfiPrintMemory((PVOID)pwszUserName, wcslen(pwszUserName) * 2);
    }

    if (pwszPassword && passwordTag != "") {
        Message("Password Memory: ");
        cyfiPrintMemory((PVOID)pwszPassword, wcslen(pwszPassword) * 2);
    }

    Message("[W] WinHttpSetCredentials(%p [|] %ld [|] %ld [|] %ls [|] %ls [|] %p) tag_in: %s %s\n", hRequest, AuthTargets, AuthScheme, pwszUserName, pwszPassword, userNameTag.c_str(), passwordTag.c_str());

    winhttp::WinHttpSetCredentials(hRequest, AuthTargets, AuthScheme, pwszUserName, pwszPassword, pAuthParams);

    S2EEnableForking();

    winhttp::WinHttpSetCredentials(hRequest, AuthTargets, AuthScheme, pwszUserName, pwszPassword, pAuthParams);

    return TRUE;
}

BOOL WINAPI WinHttpSetOptionHook(
    winhttp::HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
) {

    S2EDisableForking();
    // lpBuffer can point to a DWROD, it can also point to a char array
    if (dwBufferLength == 4) {
        Message("[W] WinHttpSetOption(%p [|] %ld [|] %ld [|] %ld)\n", hInternet, dwOption, *(LPDWORD)lpBuffer, dwBufferLength);
    }
    else {
        Message("[W] WinHttpSetOption(%p [|] %ld [|] %s [|] %ld)\n", hInternet, dwOption, (LPCTSTR)lpBuffer, dwBufferLength);
    }

    bool con_res = winhttp::WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);

    S2EEnableForking();
    
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

    S2EDisableForking();

    std::set<winhttp::HINTERNET>::iterator it = dummyHandles.find(hRequest);

    bool concrete_res = FALSE;

    if (it == dummyHandles.end()) {
        concrete_res = winhttp::WinHttpReceiveResponse(hRequest, lpReserved);
    }

    Message("[W] WinHttpReceiveResponse (%p [|] %p)\n",
        hRequest, lpReserved);

    S2EEnableForking();

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

