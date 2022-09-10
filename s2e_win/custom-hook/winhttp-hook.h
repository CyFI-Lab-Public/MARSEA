#pragma once
#include <Windows.h>
namespace winhttp {

#include <winhttp.h>
}

BOOL WINAPI WinHttpCrackUrlHook(LPCWSTR pwszUrl, DWORD dwUrlLength,DWORD dwFlags,winhttp::LPURL_COMPONENTS lpUrlComponents);
BOOL WINAPI WinHttpSendRequestHook(winhttp::HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
BOOL WINAPI WinHttpReceiveResponseHook(winhttp::HINTERNET hRequest, LPVOID lpReserved);
BOOL WINAPI WinHttpQueryDataAvailableHook(winhttp::HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
BOOL WINAPI WinHttpReadDataHook(winhttp::HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL WINAPI WinHttpWriteDataHook(winhttp::HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
winhttp::HINTERNET WINAPI WinHttpConnectHook(winhttp::HINTERNET hSession, LPCWSTR pswzServerName, winhttp::INTERNET_PORT nServerPort, DWORD dwReserved);
BOOL WINAPI WinHttpAddRequestHeadersHook(winhttp::HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
BOOL WINAPI WinHttpCloseHandleHook(winhttp::HINTERNET hInternet);
BOOL WINAPI WinHttpGetProxyForUrlHook(winhttp::HINTERNET hSession, LPCWSTR lpcwszUrl, winhttp::WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, winhttp::WINHTTP_PROXY_INFO* pProxyInfo);
winhttp::HINTERNET WINAPI WinHttpOpenRequestHook(winhttp::HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags);
BOOL WINAPI WinHttpQueryHeadersHook(winhttp::HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL WINAPI WinHttpQueryOptionHook(winhttp::HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
DWORD WINAPI WinHttpResetAutoProxyHook(winhttp::HINTERNET hSession, DWORD dwFlags);
BOOL WINAPI WinHttpSetCredentialsHook(winhttp::HINTERNET hRequest, DWORD AuthTargets, DWORD AuthScheme, LPCWSTR pwszUserName, LPCWSTR pwszPassword, LPVOID pAuthParams);
BOOL WINAPI WinHttpSetOptionHook(winhttp::HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL WINAPI WinHttpSetTimeoutsHook(winhttp::HINTERNET hInternet, int nResolveTimeout, int nConnectTimeout, int nSendTimeout, int nReceiveTimeout);
winhttp::HINTERNET WINAPI WinHttpOpenHook(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
BOOL WINAPI WinHttpReceiveResponseHook(winhttp::HINTERNET hRequest, LPVOID lpReserved);
BOOL WINAPI WinHttpGetIEProxyConfigForCurrentUserHook(
	winhttp::WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig
);

