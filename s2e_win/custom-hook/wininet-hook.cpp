#include "wininet-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>
#include <unordered_map>

static std::set<HINTERNET> dummyHandles;
static std::unordered_map<HINTERNET, DWORD> perHandleBytesToRead;
static std::unordered_map<HINTERNET, DWORD> perHandleBytesRead;
static std::unordered_map<HINTERNET, DWORD> perHandleBytesToQuery;

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
        dummyHandles.insert(sessionHandle);
    }
    Message("[W] InternetOpenA (%s [|] %ld [|] %s [|] %s [|] %ld) ret:%p\n",
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
        dummyHandles.insert(sessionHandle);
    }
    Message("[W] InternetOpenW (%ls [|] %ld [|] %ls [|] %ls [|] %ld) ret:%p\n",
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
    // Read tag first in case that InternetConnect silently concretize the server name?
    std::string tag = ReadTag((PVOID)lpszServerName);
    bool isTaint = IsTainted((PVOID)lpszServerName);

    HINTERNET connectionHandle = NULL;
            
    if (tag != "") {

        S2EDisableForking();

        connectionHandle = InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

        if (connectionHandle == NULL) {
            Message("InternetConnectA 0\n");
            connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
            dummyHandles.insert(connectionHandle);
        }
        else {
            Message("InternetConnectA 1\n");
        }

        Message("[W] InternetConnectA (%p [|] %s [|] %i [|] %s [|] %s [|] 0x%x [|] 0x%x [|] %p) ret:%p tag_in:%s\n",
            hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle, tag.c_str());

        Message("ServerName Memory: ");
        cyfiPrintMemory((PVOID)lpszServerName, strlen(lpszServerName));

        S2EEnableForking();

        return connectionHandle;
    }
    else {
       
        S2EDisableForking();

        connectionHandle = InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

        if (connectionHandle == NULL) {
            Message("InternetConnectA 0\n");
            connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
            dummyHandles.insert(connectionHandle);
        }
        else {
            Message("InternetConnectA 1\n");
        }
        Message("[W] InternetConnectA (%p [|] %s [|] %i [|] %s [|] %s [|] 0x%x [|] 0x%x [|] %p) ret:%p\n",
            hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle);

        S2EEnableForking();

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
    std::string tag = ReadTag((PVOID)lpszServerName);

    bool isTaint = IsTainted((PVOID)lpszServerName);

    HINTERNET connectionHandle = NULL;

    if (tag != "") {
       
        S2EDisableForking();

        connectionHandle = InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

        if (connectionHandle == NULL) {
            Message("InternetConnectW 0\n");
            connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
            dummyHandles.insert(connectionHandle);
        }
        else {
            Message("InternetConnectW 1\n");
        }

        Message("[W] InternetConnectW (%p [|] %ls [|] %i [|] %ls [|] %ls [|] 0x%x [|] 0x%x [|] %p) ret:%p tag_in:%s\n",
            hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle, tag.c_str());

        Message("ServerName Memory: ");
        cyfiPrintMemory((PVOID)lpszServerName, wcslen(lpszServerName) * 2);

        S2EEnableForking();

        return connectionHandle;
    }
    else {
        
        S2EDisableForking();

        connectionHandle = InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

        if (connectionHandle == NULL) {
            Message("InternetConnectW 0\n");
            connectionHandle = (HINTERNET)malloc(sizeof(HINTERNET));
            dummyHandles.insert(connectionHandle);
        }
        else {
            Message("InternetConnectW 1\n");
        }

        Message("[W] InternetConnectW (%p [|] %ls [|] %i [|] %ls [|] %ls [|] 0x%x [|] 0x%x [|] %p) ret:%p\n",
            hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, connectionHandle);

        S2EEnableForking();

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

            pwszUrl = "http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
            std::string tag = GetTag("InternetCrackUrlA");
            S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
            InternetCrackUrlA(pwszUrl, 52, dwFlags, lpUrlComponents);
            Message("[W] InternetCrackUrlA (%s [|] %ld [|] %ld [|] %p) tag_in:%s tag_out:%s\n", 
                pwszUrl, 52, dwFlags, lpUrlComponents, tagIn.c_str(), tag.c_str());
            return TRUE;
        }
        else {
            Message("[W] InternetCrackUrlA (%s [|] %ld [|] %ld [|] %p)\n", pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
            return InternetCrackUrlA(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
        }
    }

    Message("[W] InternetCrackUrlA (%s [|] %ld [|] %ld [|] %p)\n", pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
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

            lpszUrl = L"http://cyfi.ece.gatech.edu/assests/img/cyfi_bee.png";
            std::string tag = GetTag("InternetCrackUrlW");
            S2EMakeSymbolic((PVOID)lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength, tag.c_str());
            InternetCrackUrlW(lpszUrl, 52, dwFlags, lpUrlComponents);
            Message("[W] InternetCrackUrlW (%ls, %ld [|] %ld [|] %p) tag_in:%s tag_out:%s\n",
                lpszUrl, 52, dwFlags, lpUrlComponents, tagIn.c_str(), tag.c_str());
            return TRUE;
        }
        else {
            Message("[W] InternetCrackUrlW (%ls [|] %ld [|] %ld [|] %p)\n", lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
            return InternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
        }
    }

    Message("[W] InternetCrackUrlW (%ls [|] %ld [|] %ld [|] %p)\n", lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
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

    std::string verbTag = ReadTag((PVOID)lpszVerb);
    std::string objectNameTag = ReadTag((PVOID)lpszObjectName);
    std::string versionTag = ReadTag((PVOID)lpszVersion);
    std::string referrerTag = ReadTag((PVOID)lpszReferrer);

    S2EDisableForking();

    HINTERNET resourceHandle = HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

    if (resourceHandle == NULL) {
        Message("HttpOpenRequestA 0\n");
        resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
        dummyHandles.insert(resourceHandle);
    }
    else {
        Message("HttpOpenRequestA 1\n");
    }

    if (lpszVerb && verbTag != "") {
        Message("Verb Memory: ");
        cyfiPrintMemory((PVOID)lpszVerb, strlen(lpszVerb));
    }

    if (lpszObjectName && objectNameTag != "") {
        Message("Object Memory: ");
        cyfiPrintMemory((PVOID)lpszObjectName, strlen(lpszObjectName));
    }

    if (lpszVersion && versionTag != "") {
        Message("Version Memory: ");
        cyfiPrintMemory((PVOID)lpszVersion, strlen(lpszVersion));
    }

    if (lpszReferrer && referrerTag != "") {
        Message("Referrer Memory: ");
        cyfiPrintMemory((PVOID)lpszReferrer, strlen(lpszReferrer));
    }

    Message("[W] HttpOpenRequestA (%p [|] %s [|] %s [|] %s [|] %s [|] %p [|] 0x%x [|] %p) ret:%p tag_in: %s %s %s %s\n",
        hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext, resourceHandle, verbTag.c_str(), objectNameTag.c_str(), versionTag.c_str(), referrerTag.c_str());

    S2EEnableForking();

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

    std::string verbTag = ReadTag((PVOID)lpszVerb);
    std::string objectNameTag = ReadTag((PVOID)lpszObjectName);
    std::string versionTag = ReadTag((PVOID)lpszVersion);
    std::string referrerTag = ReadTag((PVOID)lpszReferrer);

    S2EDisableForking();

    HINTERNET resourceHandle = HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

    if (resourceHandle == NULL) {
        Message("HttpOpenRequestW 0\n");
        resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
        dummyHandles.insert(resourceHandle);
    }
    else {
        Message("HttpOpenRequestW 1\n");
    }

    if (lpszVerb && verbTag != "") {
        Message("Verb Memory: ");
        cyfiPrintMemory((PVOID)lpszVerb, wcslen(lpszVerb) * 2);
    }

    if (lpszObjectName && objectNameTag != "") {
        Message("Object Memory: ");
        cyfiPrintMemory((PVOID)lpszObjectName, wcslen(lpszObjectName) * 2);
    }

    if (lpszVersion && versionTag != "") {
        Message("Version Memory: ");
        cyfiPrintMemory((PVOID)lpszVersion, wcslen(lpszVersion) * 2);
    }

    if (lpszReferrer && referrerTag != "") {
        Message("Referrer Memory: ");
        cyfiPrintMemory((PVOID)lpszReferrer, wcslen(lpszReferrer) * 2);
    }

    Message("[W] HttpOpenRequestW (%p [|] %ls [|] %ls [|] %ls [|] %ls [|] %p [|] 0x%x [|] %p) ret:%p tag_in: %s %s %s %s\n",
        hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext, resourceHandle, verbTag.c_str(), objectNameTag.c_str(), versionTag.c_str(), referrerTag.c_str());

    S2EEnableForking();

    return resourceHandle;
}

BOOL WINAPI HttpSendRequestAHook(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
) {
    std::string read_header_tag = ReadTag((PVOID)lpszHeaders);
    std::string read_option_tag = "";
    if (lpOptional != NULL) {
        read_option_tag = ReadTag((PVOID)lpOptional);
    }

    S2EDisableForking();

    if (lpOptional) {
        Message("[W] HttpSendRequestA (%p [|] %s [|] 0x%x [|] %s [|] 0x%x) tag_in: %s %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, read_header_tag.c_str(), read_option_tag.c_str());
    }
    else {
        Message("[W] HttpSendRequestA (%p [|] %s [|] 0x%x [|] %p [|] 0x%x) tag_in: %s %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, read_header_tag.c_str(), read_option_tag.c_str());
    }

    if (lpszHeaders && read_header_tag != "") {
        Message("Headers Memory: ");
        cyfiPrintMemory((PVOID)lpszHeaders, dwHeadersLength);
    }

    if (lpOptional && read_option_tag != "") {
        Message("Optional Memory: ");
        cyfiPrintMemory((PVOID)lpOptional, dwOptionalLength);
    }

    S2EBeginAtomic();
    bool con_res = HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    S2EEndAtomic();

    if (con_res) {
        Message("HttpSendRequestA 1\n");
    }
    else {
        Message("HttpSendRequestA 0\n");
    }

    S2EEnableForking();

    return TRUE; //Only consider successful http request sends for now
}

BOOL WINAPI HttpSendRequestWHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
) {
    std::string read_header_tag = ReadTag((PVOID)lpszHeaders);
    std::string read_option_tag = "";
    if (lpOptional != NULL) {
        read_option_tag = ReadTag((PVOID)lpOptional);
    }

    S2EDisableForking();

    if (lpOptional) {
        Message("[W] HttpSendRequestW (%p [|] %ls [|] 0x%x [|] %s [|] 0x%x) tag_in:%s %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, read_header_tag.c_str(), read_option_tag.c_str());
    }
    else {
        Message("[W] HttpSendRequestW (%p [|] %ls [|] 0x%x [|] %p [|] 0x%x) tag_in:%s %s\n",
            hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, read_header_tag.c_str(), read_option_tag.c_str());
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
    bool con_res = HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    S2EEndAtomic();

    if (con_res) {
        Message("HttpSendRequestW 1\n");
    }
    else {
        Message("HttpSendRequestW 0\n");
    }

    S2EEnableForking();

    return TRUE; //Only consider successful http request sends for now
}

BOOL WINAPI InternetReadFileHook(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {

    S2EDisableForking();

    BOOL fake = TRUE;

    BOOL read_res = InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

    if (read_res) {
        // If it reads more than 0 bytes
        if (*lpdwNumberOfBytesRead > 0) {

            auto it = perHandleBytesRead.find(hFile);

            if (it == perHandleBytesRead.end()) {
                perHandleBytesRead[hFile] = 1;
            }

            fake = FALSE;

        }
        else {
            // If it reads 0 bytes, check if this handle reads anything before
            auto it = perHandleBytesRead.find(hFile);

            if (it != perHandleBytesRead.end()) {
                fake = FALSE;
            }
        }
    }


    DWORD bytes_read;

    std::string tag = GetTag("InternetReadFile");
    Message("[W] InternetReadFile  (%p [|] %s [|] %ld [|] %ld) tag_out:%s\n",
        hFile, lpBuffer, dwNumberOfBytesToRead, *lpdwNumberOfBytesRead, tag.c_str());

    S2EEnableForking();


    if (fake) {
        Message("InternetReadFile 0\n");
        auto it = perHandleBytesToRead.find(hFile);
        if (it == perHandleBytesToRead.end()) {
            perHandleBytesToRead[hFile] = DEFAULT_MEM_LEN;
            it = perHandleBytesToRead.find(hFile);
        }
        DWORD bytes_left = it->second;
        bytes_read = bytes_left < dwNumberOfBytesToRead ? bytes_left : dwNumberOfBytesToRead;
        it->second -= bytes_read;
        *lpdwNumberOfBytesRead = bytes_read;
        S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
        S2EMakeSymbolic(lpdwNumberOfBytesRead, 4, tag.c_str());
    }
    else {
        Message("InternetReadFile 1\n");
        auto it = perHandleBytesToRead.find(hFile);
        if (it == perHandleBytesToRead.end()) {
            perHandleBytesToRead[hFile] = DEFAULT_MEM_LEN;
            it = perHandleBytesToRead.find(hFile);
        }
        DWORD bytes_left = it->second;
        bytes_read = bytes_left < *lpdwNumberOfBytesRead ? bytes_left : *lpdwNumberOfBytesRead;
        it->second -= bytes_read;
        cyfiTaint(lpBuffer, *lpdwNumberOfBytesRead, tag.c_str());
        cyfiTaint(lpdwNumberOfBytesRead, 4, tag.c_str());
    }

    //
    ////std::string data_read = "1BkeGqpo8M5KNVYXW3obmQt1R58zXAqLBQ 11223344 1BkeGqpo8M5KNVYXW3obmQt1R58zXAqLBQ 55667788"; //redaman
    //std::string data_read = "DG8FV-B9TKY-FRT9J-6CRCC-XPQ4G-104A149B245C120D";   //spyanker
    //if (bytes_read < data_read.size()) {
    //    data_read = data_read.substr(0, bytes_read);
    //}
    //if (bytes_read > 0) {
    //    memcpy(lpBuffer, data_read.c_str(), bytes_read);
    //}

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = TAG_TRACKER;
    Command.tagTracker.tag = (uint64_t)tag.c_str();
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

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
    S2EDisableForking();

    std::string url_tag = ReadTag((PVOID)lpszUrl);
    std::string header_tag = ReadTag((PVOID)lpszHeaders);

    HINTERNET resourceHandle = InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);

    if (resourceHandle == NULL) {
        Message("InternetOpenUrlA 0\n");
        resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
        dummyHandles.insert(resourceHandle);
    }
    else {
        Message("InternetOpenUrlA 1\n");
    }

    Message("[W] InternetOpenUrlA (%p [|] %s [|] %s [|] 0x%x [|] 0x%x [|] %p) ret:%s tag_in:%s %s\n",
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle, url_tag.c_str(), header_tag.c_str());

    if (url_tag != "") {
        Message("URL Memory: ");
        cyfiPrintMemory((PVOID)lpszUrl, strlen(lpszUrl));
    }

    if (header_tag != "") {
        Message("Header Memory: ");
        cyfiPrintMemory((PVOID)lpszHeaders, dwHeadersLength);
    }

    S2EEnableForking();

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
    S2EDisableForking();

    std::string url_tag = ReadTag((PVOID)lpszUrl);
    std::string header_tag = ReadTag((PVOID)lpszHeaders);

    HINTERNET resourceHandle = InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);

    if (resourceHandle == NULL) {
        Message("InternetOpenUrlW 0\n");
        resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
        dummyHandles.insert(resourceHandle);
    }
    else {
        Message("InternetOpenUrlW 1\n");
    }

    Message("[W] InternetOpenUrlA (%p [|] %s [|] %s [|] 0x%x [|] 0x%x [|] %p) ret:%s tag_in:%s %s\n",
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext, resourceHandle, url_tag.c_str(), header_tag.c_str());

    if (url_tag != "") {
        Message("URL Memory: ");
        cyfiPrintMemory((PVOID)lpszUrl, wcslen(lpszUrl)* 2);
    }

    if (header_tag != "") {
        Message("Header Memory: ");
        cyfiPrintMemory((PVOID)lpszHeaders, dwHeadersLength * 2);
    }

    S2EEnableForking();

    return resourceHandle;
}

BOOL WINAPI HttpAddRequestHeadersAHook(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {

    S2EDisableForking();

    std::string header_tag = ReadTag((PVOID)lpszHeaders);
    if (header_tag.length() > 0) {
        Message("[W] HttpAddRequestHeadersA (%p [|] %s [|] %d [|] %d) tag_in:%s\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers, header_tag.c_str());
        Message("Header Memory: ");
        cyfiPrintMemory((PVOID)lpszHeaders, dwHeadersLength);
    }
    else {
        Message("[W] HttpAddRequestHeadersA (%p [|] %s [|] %d [|] %d)\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    }

    bool con_res = HttpAddRequestHeadersA(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);

    S2EEnableForking();

    return TRUE;
}

BOOL WINAPI HttpAddRequestHeadersWHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {

    S2EDisableForking();

    std::string header_tag = ReadTag((PVOID)lpszHeaders);
    if (header_tag.length() > 0) {
        Message("[W] HttpAddRequestHeadersW (%p [|] %ls [|] %ld [|] %ld) tag_in:%s\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers, header_tag.c_str());
        Message("Header Memory: ");
        cyfiPrintMemory((PVOID)lpszHeaders, dwHeadersLength * 2);
    }
    else {
        Message("[W] HttpAddRequestHeadersW (%p [|] %ls [|] %ld [|] %ld)\n", hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
    }

    bool con_res = HttpAddRequestHeadersW(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);

    S2EEnableForking();

    return TRUE;
}

BOOL WINAPI HttpEndRequestAHook(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
) {
    HttpEndRequestA(hRequest, lpBuffersOut, dwFlags, dwContext);
    return TRUE;
}

BOOL WINAPI HttpEndRequestWHook(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
) {
    S2EDisableForking();

    HttpEndRequestW(hRequest, lpBuffersOut, dwFlags, dwContext);

    S2EEnableForking();

    return TRUE;
}

BOOL WINAPI HttpQueryInfoAHook(
    HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
) {
    BOOL query_res = FALSE;

        S2EDisableForking();

        std::string tag = GetTag("HttpQueryInfoA");

        std::set<HINTERNET>::iterator it = dummyHandles.find(hRequest);

        if (it == dummyHandles.end()) {
            query_res = HttpQueryInfoA(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
        }

        if (query_res) {
            Message("HttpQueryInfoA 1\n");
            cyfiTaint(lpBuffer, *lpdwBufferLength, tag.c_str());
        }

        else {
            Message("HttpQueryInfoA 0\n");
            // If the info level is 19 - Status Code
            if (dwInfoLevel == 19) {
                // Patch the lpBuffer as HTTP_STATUS_OK then mark it as symbolic
                *(DWORD*)lpBuffer = HTTP_STATUS_OK;
                //S2EMakeSymbolic(lpBuffer, 4, tag.c_str());
            }
            else {
                auto it = perHandleBytesToQuery.find(hRequest);
                if (it == perHandleBytesToQuery.end()) {
                    perHandleBytesToQuery[hRequest] = DEFAULT_MEM_LEN;
                    it = perHandleBytesToQuery.find(hRequest);
                }

                DWORD bytes_left = it->second;

                DWORD bytes_read = bytes_left < *lpdwBufferLength ? bytes_left : *lpdwBufferLength;

                S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
                *lpdwBufferLength = bytes_read;
                S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
            }
            
        }
       
  
        Message("[W] HttpQueryInfoA (%p [|] %ld [|] %s [|] %p [|] %p) tag_out:%s\n",
            hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex, tag.c_str());

        S2EEnableForking();

    return TRUE;
}

BOOL WINAPI HttpQueryInfoWHook(
    HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
) {
    S2EDisableForking();

    BOOL query_res = FALSE;

        std::string tag = GetTag("HttpQueryInfoW");

        std::set<HINTERNET>::iterator it = dummyHandles.find(hRequest);

        if (it == dummyHandles.end()) {
            query_res = HttpQueryInfoW(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
        }

        if (query_res) {
            Message("HttpQueyrInfoW 1\n");
            cyfiTaint(lpBuffer, *lpdwBufferLength, tag.c_str());
        }
        else {
            Message("HttpQueyrInfoW 0\n");
            // If the info level is 19 - Status Code
            if (dwInfoLevel == 19) {
                // Patch the lpBuffer as HTTP_STATUS_OK then mark it as symbolic
                *(DWORD*)lpBuffer = HTTP_STATUS_OK;
                //S2EMakeSymbolic(lpBuffer, 4, tag.c_str());
            }
            else {
                auto it = perHandleBytesToQuery.find(hRequest);
                if (it == perHandleBytesToQuery.end()) {
                    perHandleBytesToQuery[hRequest] = DEFAULT_MEM_LEN;
                    it = perHandleBytesToQuery.find(hRequest);
                }

                DWORD bytes_left = it->second;

                DWORD bytes_read = bytes_left < *lpdwBufferLength ? bytes_left : *lpdwBufferLength;
                it->second -= bytes_read;

                it->second = it->second < 0 ? 0 : it->second;

                S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
                *lpdwBufferLength = bytes_read;
                if (bytes_read != 0) {
                    S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
                }
            }
            
        }

        Message("[W] HttpQueryInfoW (%p [|] %ld [|] %p [|] %p [|] %p) tag_out:%s\n",
            hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex, tag.c_str());

        S2EEnableForking();


    return TRUE;
}

BOOL WINAPI InternetQueryDataAvailableHook(
    HINTERNET hFile,
    LPDWORD   lpdwNumberOfBytesAvailable,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    std::set<HINTERNET>::iterator it = dummyHandles.find(hFile);

    bool con_res = FALSE;

    if (it == dummyHandles.end()) {
        con_res = InternetQueryDataAvailable(hFile, lpdwNumberOfBytesAvailable, dwFlags, dwContext);
    }

    if (con_res) {
        Message("InternetQueryDataAvailable 1\n");
    }
    else {
        Message("InternetQueryDataAvailable 0\n");
        auto it = perHandleBytesToRead.find(hFile);
        if (it == perHandleBytesToRead.end() && lpdwNumberOfBytesAvailable) {
            *lpdwNumberOfBytesAvailable = DEFAULT_MEM_LEN;
        }

        if (it != perHandleBytesToRead.end() && lpdwNumberOfBytesAvailable) {
            *lpdwNumberOfBytesAvailable = 0;
        }

        if (lpdwNumberOfBytesAvailable) {
            S2EMakeSymbolic(lpdwNumberOfBytesAvailable, sizeof(*lpdwNumberOfBytesAvailable), GetTag("InternetQueryDataAvailable").c_str());
        }

    }

    return TRUE;
}

BOOL WINAPI InternetQueryOptionAHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength
) {
    S2EDisableForking();

    std::string tag = GetTag("InternetQueryOptionA");

    std::set<HINTERNET>::iterator it = dummyHandles.find(hInternet);

    BOOL query_res = FALSE;

    if (it == dummyHandles.end()) {
        query_res = InternetQueryOptionA(hInternet, dwOption, lpBuffer, lpdwBufferLength);
    }

    Message("[W] InternetQueryOptionA (%p [|] %ld [|] %s [|] %p)\n", hInternet, dwOption, lpBuffer, lpdwBufferLength);

    if (query_res) {
        Message("InternetQueryOptionA 1\n");
        if (lpBuffer) {
            cyfiTaint(lpBuffer, *lpdwBufferLength, tag.c_str());
        }

    }
    else {
        Message("InternetQueryOptionA 0\n");

        if (lpBuffer) {

            auto it = perHandleBytesToQuery.find(hInternet);
            if (it == perHandleBytesToQuery.end()) {
                perHandleBytesToQuery[hInternet] = DEFAULT_MEM_LEN;
                it = perHandleBytesToQuery.find(hInternet);
            }

            DWORD bytes_left = it->second;

            DWORD bytes_read = bytes_left < *lpdwBufferLength ? bytes_left : *lpdwBufferLength;

            S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
            S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
        }
    }

    S2EEnableForking();

    return TRUE;
}

BOOL WINAPI InternetQueryOptionWHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength
) {
    S2EDisableForking();

    std::string tag = GetTag("InternetQueryOptionW");

    std::set<HINTERNET>::iterator it = dummyHandles.find(hInternet);

    BOOL query_res = FALSE;

    if (it == dummyHandles.end()) {
        query_res = InternetQueryOptionW(hInternet, dwOption, lpBuffer, lpdwBufferLength);
    }

    Message("[W] InternetQueryOptionA (%p [|] %ld [|] %ls [|] %p)\n", hInternet, dwOption, lpBuffer, lpdwBufferLength);

    if (query_res) {
        Message("InternetQueryOptionW 1\n");
        if (lpBuffer) {
            cyfiTaint(lpBuffer, *lpdwBufferLength, tag.c_str());
        }

    }
    else {
        Message("InternetQueryOptionW 0\n");
        if (lpBuffer) {
            auto it = perHandleBytesToQuery.find(hInternet);
            if (it == perHandleBytesToQuery.end()) {
                perHandleBytesToQuery[hInternet] = DEFAULT_MEM_LEN;
                it = perHandleBytesToQuery.find(hInternet);
            }

            DWORD bytes_left = it->second;

            DWORD bytes_read = bytes_left < *lpdwBufferLength ? bytes_left : *lpdwBufferLength;
            S2EMakeSymbolic(lpBuffer, bytes_read, tag.c_str());
            S2EMakeSymbolic(lpdwBufferLength, 4, tag.c_str());
        }
    }

    S2EEnableForking();
    return TRUE;
}

BOOL WINAPI InternetSetOptionAHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
) {
    // lpBuffer can point to a DWROD, it can also point to a char array

    std::string tag_in = ReadTag(lpBuffer);

    S2EDisableForking();

    if (dwBufferLength == 4) {
        Message("[W] InternetSetOptionA (%p [|] %ld [|] %ld [|] %ld) tag_in: %s\n", hInternet, dwOption, *(LPDWORD)lpBuffer, dwBufferLength, tag_in.c_str());
    }
    else {
        Message("[W] InternetSetOptionA (%p [|] %ld [|] %ls [|] %ld) tag_in: %s\n", hInternet, dwOption, (LPCTSTR)lpBuffer, dwBufferLength, tag_in.c_str());
    }

    bool con_res = InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength);

    S2EEnableForking();

    return TRUE;
}

BOOL WINAPI InternetSetOptionWHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
) {
    // lpBuffer can point to a DWROD, it can also point to a char array

    std::string tag_in = ReadTag(lpBuffer);

    S2EDisableForking();

    if (dwBufferLength == 4) {
        Message("[W] InternetSetOptionW (%p [|] %ld [|] %ld [|] %ld) tag_in: %s\n", hInternet, dwOption, *(LPDWORD)lpBuffer, dwBufferLength, tag_in.c_str());
    }
    else {
        Message("[W] InternetSetOptionW (%p [|] %ld [|] %ls [|] %ld) tag_in: %s\n", hInternet, dwOption, lpBuffer, dwBufferLength, tag_in.c_str());
    }

    bool con_res = InternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength);

    S2EEnableForking();

    return TRUE;
}

BOOL WINAPI InternetWriteFileHook(
    HINTERNET hFile,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
) {
    Message("WriteData Memory: ");
    cyfiPrintMemory((PVOID)lpBuffer, dwNumberOfBytesToWrite);

    *lpdwNumberOfBytesWritten = dwNumberOfBytesToWrite;

    std::string tag = GetTag("InternetWriteFile");
    S2EMakeSymbolic(lpdwNumberOfBytesWritten, 4, tag.c_str());

    std::string read_tag = ReadTag((PVOID)lpBuffer);

    if (read_tag.length() > 0) {
        Message("[W] InternetWriteFile(%p [|] %s [|] 0x%x [|] %p) tag_in:%s tag_out:%s\n",
            hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten, read_tag.c_str(), tag.c_str());
    }
    else {
        Message("[W] InternetWriteFile(%p [|] %s [|] 0x%x [|] %p) tag_out:%s\n",
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
        Message("[W] InternetGetConnectedState (%ld [|] %ld) ret:%i\n", *lpdwFlags, dwReserved, res);
        return TRUE;
    }
    return InternetGetConnectedState(lpdwFlags, dwReserved);
}

BOOL WINAPI InternetCheckConnectionAHook(
    LPCSTR lpszUrl,
    DWORD  dwFlags,
    DWORD  dwReserved
) {
    std::string tag_in = ReadTag((LPVOID)lpszUrl);

    Message("[W] InternetCheckConnectionA (%s [|] %ld [|] %ld) tag_in: %s\n", lpszUrl, dwFlags, dwReserved, tag_in.c_str());

    return TRUE;
}

BOOL WINAPI InternetCheckConnectionWHook(
    LPCWSTR lpszUrl,
    DWORD   dwFlags,
    DWORD   dwReserved
) {
    std::string tag_in = ReadTag((LPVOID)lpszUrl);

    Message("[W] InternetCheckConnectionW (%ls [|] %ld [|] %ld) tag_in: %s\n", lpszUrl, dwFlags, dwReserved, tag_in.c_str());
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
    perHandleBytesRead.erase(hInternet);

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

