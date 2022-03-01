#pragma once
#include <Urlmon.h> 
//#pragma comment(lib, "urlmon.lib")

HRESULT WINAPI URLDownloadToFileWHook(
    LPUNKNOWN            pCaller,
    LPCWSTR              szURL,
    LPCWSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
);

HRESULT WINAPI URLDownloadToFileAHook(
    LPUNKNOWN            pCaller,
    LPCSTR              szURL,
    LPCSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
);

HRESULT WINAPI URLDownloadToFileHook(
    LPUNKNOWN            pCaller,
    LPCTSTR              szURL,
    LPCTSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
);

HRESULT WINAPI URLDownloadToCacheFileAHook(
    LPUNKNOWN           lpUnkcaller,
    LPCSTR              szURL,
    LPTSTR              szFileName,
    DWORD               cchFileName,
    DWORD               dwReserved,
    IBindStatusCallback* pBSC
);

HRESULT WINAPI URLDownloadToCacheFileWHook(
    LPUNKNOWN           lpUnkcaller,
    LPCWSTR              szURL,
    LPWSTR              szFileName,
    DWORD               cchFileName,
    DWORD               dwReserved,
    IBindStatusCallback* pBSC
);