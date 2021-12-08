#pragma once
#include <Urlmon.h> 
#pragma comment(lib, "urlmon.lib")

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

HRESULT WINAPI URLDownloadToCacheFileHook(
    LPUNKNOWN           lpUnkcaller,
    LPCSTR              szURL,
    LPTSTR              szFileName,
    DWORD               cchFileName,
    DWORD               dwReserved,
    IBindStatusCallback* pBSC
);