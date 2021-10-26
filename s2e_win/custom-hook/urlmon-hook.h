#pragma once
#include <urlmon.h>

HRESULT WINAPI URLDownloadToFileHook(
    LPUNKNOWN            pCaller,
    LPCTSTR              szURL,
    LPCTSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
);


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

HRESULT WINAPI URLDownloadToCacheFileHook(
    _In_       LPUNKNOWN           lpUnkcaller,
    _In_       LPCSTR              szURL,
    _Out_      LPTSTR              szFileName,
    _In_       DWORD               cchFileName,
    _Reserved_ DWORD               dwReserved,
    _In_opt_   IBindStatusCallback* pBSC
);