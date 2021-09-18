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