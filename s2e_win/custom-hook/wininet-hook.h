#pragma once
#include <Windows.h>
#include <WinInet.h>

HINTERNET WINAPI InternetOpenAHook(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
);

HINTERNET WINAPI InternetOpenWHook(
    LPCWSTR lpszAgent,
    DWORD   dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD   dwFlags
);

HINTERNET WINAPI InternetConnectAHook(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI InternetConnectWHook(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET WINAPI HttpOpenRequestAHook(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI HttpSendRequestAHook(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI InternetReadFileHook(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
HINTERNET WINAPI InternetOpenUrlAHook(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI InternetOpenUrlWHook(
    HINTERNET hInternet,
    LPCWSTR   lpszUrl,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
);
BOOL WINAPI InternetCloseHandleHook(HINTERNET hInternet);
BOOL WINAPI HttpAddRequestHeadersAHook(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
BOOL WINAPI HttpEndRequestAHook(HINTERNET hRequest, LPINTERNET_BUFFERSA lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI HttpEndRequestWHook(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
);
BOOL WINAPI HttpQueryInfoAHook(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL WINAPI InternetQueryDataAvailableHook(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI InternetQueryOptionAHook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
BOOL WINAPI InternetSetOptionAHook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL WINAPI InternetWriteFileHook(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
BOOL WINAPI InternetGetConnectedStateHook(
	LPDWORD lpdwFlags,
	DWORD   dwReserved
);

BOOL WINAPI InternetCheckConnectionAHook(
	LPCSTR lpszUrl,
	DWORD  dwFlags,
	DWORD  dwReserved
);
BOOL WINAPI InternetCheckConnectionWHook(
    LPCWSTR lpszUrl,
    DWORD   dwFlags,
    DWORD   dwReserved
);
DWORD WINAPI InternetAttemptConnectHook(
	DWORD dwReserved
);

BOOL WINAPI HttpSendRequestWHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
);

HINTERNET WINAPI HttpOpenRequestWHook(
    HINTERNET hConnect,
    LPCWSTR   lpszVerb,
    LPCWSTR   lpszObjectName,
    LPCWSTR   lpszVersion,
    LPCWSTR   lpszReferrer,
    LPCWSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
);

BOOL WINAPI HttpAddRequestHeadersWHook(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwModifiers
);

BOOL WINAPI HttpQueryInfoWHook(
    HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
);

BOOL WINAPI InternetQueryOptionWHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength
);

BOOL WINAPI InternetSetOptionWHook(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
);