#include "wininet-hook.h"
#include "utils.h"
#include "commands.h"
#include <set>

static std::set<HINTERNET> dummyHandles;

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
    HINTERNET resourceHandle = (HINTERNET)malloc(sizeof(HINTERNET));
    dummyHandles.insert(resourceHandle);

    Message("[HLOG] InternetConnectA(%p, A\"%s\", %i, A\"%s\", A\"%s\", 0x%x, 0x%x, %p) Ret: %p\n",
        hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext, resourceHandle);

    return resourceHandle;
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

    Message("[HLOG] HttpOpenRequestA(%p, A\"%s\", A\"%s\", A\"%s\", A\"%s\", %p, 0x%x, %p) Ret: %p\n",
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
    Message("[HLOG] HttpSendRequestA(%p, A\"%s\", 0x%x, %p, 0x%x)\n",
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

HINTERNET WINAPI InternetOpenUrlAHook(
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

BOOL WINAPI InternetCloseHandleHook(
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

BOOL WINAPI HttpAddRequestHeadersAHook(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
) {
    Message("[HLOG] HttpAddRequestHeaders(%p, A\"%ls\", %ld, %ld", hRequest, lpszHeaders, dwHeadersLength, dwModifiers);

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
    Message("[HLOG] HttpQueryInfoAHook(%p, %ld, %p, %p, %p)", hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);

    if (lpBuffer) {
        PCSTR tag = GetTag("HttpQueryInfoA");
        S2EMakeSymbolic(lpBuffer, min(*lpdwBufferLength, DEFAULT_MEM_LEN), tag);
        S2EMakeSymbolic(lpdwBufferLength, 4, tag);
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
        S2EMakeSymbolic(lpdwNumberOfBytesAvailable, sizeof(*lpdwNumberOfBytesAvailable), GetTag("WinHttpQueryDataAvailable"));
    }

    return TRUE;
}

BOOL WINAPI InternetQueryOptionAHook(
    HINTERNET hInternet,
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

BOOL WINAPI InternetSetOptionAHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
) {
    Message("[HLOG] WinHttpSetOption(%p, %ld, %p, %ld", hInternet, dwOption, lpBuffer, dwBufferLength);

    return TRUE;
}

BOOL WINAPI InternetWriteFileHook(
    HINTERNET hFile,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten
) {
    Message("[HLOG] InternetWriteFile(%p, A\"%ls\", 0x%x, %p)\n",
        hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_WINHTTPWRITEDATA;
    Command.WinHttpWriteData.hRequest = (uint64_t)hFile;
    Command.WinHttpWriteData.lpBuffer = lpBuffer;
    Command.WinHttpWriteData.dwNumberOfBytesToWrite = dwNumberOfBytesToWrite;
    Command.WinHttpWriteData.lpdwNumberOfBytesWritten = lpdwNumberOfBytesWritten;

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    S2EMakeSymbolic(lpdwNumberOfBytesWritten, 4, GetTag("InternetWriteFile"));
    return TRUE;
}