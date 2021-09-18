#include "urlmon-hook.h"
#include "utils.h"
#include "commands.h"


HRESULT WINAPI URLDownloadToFileHook(
    LPUNKNOWN            pCaller,
    LPCTSTR              szURL,
    LPCTSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
) {
    if (checkCaller("URLDownloadToFile")) {
        Message("[W] URLDownloadToFile (%p, A\"%s\", A\"%s\", %ld, %p)\n", pCaller, szURL, szFileName, dwReserved, lpfnCB);
        Message("[W] URLDownloadToFile - Not implemented yet\n");
    }
    return URLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
}

HRESULT WINAPI URLDownloadToFileWHook(
    LPUNKNOWN            pCaller,
    LPCWSTR              szURL,
    LPCWSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
) {
    if (checkCaller("URLDownloadToFileW")) {
        Message("[W] URLDownloadToFileW (%p, A\"%s\", A\"%s\", %ld, %p)\n", pCaller, szURL, szFileName, dwReserved, lpfnCB);
        Message("[W] URLDownloadToFileW - Not implemented yet\n");
    }
    return URLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
}

