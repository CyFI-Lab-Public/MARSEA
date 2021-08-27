#pragma once
#include <Windows.h>
#include <WinInet.h>

HINTERNET WINAPI InternetConnectAHook(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI HttpOpenRequestAHook(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI HttpSendRequestAHook(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI InternetReadFileHook(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
HINTERNET WINAPI InternetOpenUrlAHook(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI InternetCloseHandleHook(HINTERNET hInternet);
BOOL WINAPI HttpAddRequestHeadersAHook(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
BOOL WINAPI HttpEndRequestAHook(HINTERNET hRequest, LPINTERNET_BUFFERSA lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI HttpQueryInfoAHook(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL WINAPI InternetQueryDataAvailableHook(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI InternetQueryOptionAHook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
BOOL WINAPI InternetSetOptionAHook(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL WINAPI InternetWriteFileHook(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
BOOL InternetGetConnectedStateHook(
	LPDWORD lpdwFlags,
	DWORD   dwReserved
);

BOOL InternetCheckConnectionAHook(
	LPCSTR lpszUrl,
	DWORD  dwFlags,
	DWORD  dwReserved
);

DWORD InternetAttemptConnectHook(
	DWORD dwReserved
);
