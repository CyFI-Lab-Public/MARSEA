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
        std::string tag_in = ReadTag((PVOID)szURL);
        if (tag_in.length() > 0) {
            Message("[W] URLDownloadToFileW (%p, A\"%ls\", A\"%ls\", %ld, %p) tag_in: %s \n", pCaller, szURL, szFileName, dwReserved, lpfnCB, tag_in.c_str());
        }
        else {
            Message("[W] URLDownloadToFileW (%p, A\"%ls\", A\"%ls\", %ld, %p)\n", pCaller, szURL, szFileName, dwReserved, lpfnCB);
        }
        Message("[W] URLDownloadToFileW - Not implemented yet\n");
        return S_OK;
}

HRESULT WINAPI URLDownloadToFileAHook(
    LPUNKNOWN            pCaller,
    LPCSTR              szURL,
    LPCSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
) {
    std::string tag_in = ReadTag((PVOID)szURL);
    if (tag_in.length() > 0) {
        Message("[W] URLDownloadToFileA (%p, A\"%s\", A\"%s\", %ld, %p) tag_in: %s \n", pCaller, szURL, szFileName, dwReserved, lpfnCB, tag_in.c_str());
    }
    else {
        Message("[W] URLDownloadToFileA (%p, A\"%s\", A\"%s\", %ld, %p)\n", pCaller, szURL, szFileName, dwReserved, lpfnCB);
    }
    Message("[W] URLDownloadToFileA - Not implemented yet\n");
    return S_OK;
}

HRESULT WINAPI URLDownloadToCacheFileHook(
    _In_       LPUNKNOWN           lpUnkcaller,
    _In_       LPCSTR              szURL,
    _Out_      LPTSTR              szFileName,
    _In_       DWORD               cchFileName,
    _Reserved_ DWORD               dwReserved,
    _In_opt_   IBindStatusCallback* pBSC
) {
    std::string tag_in = ReadTag((PVOID)szURL);
    if (tag_in.length() > 0) {
        Message("[W] URLDownloadToCacheFileHook (%p, A\"%s\", A\"%s\", %ld, %ld, %p) tag_in: %s \n", lpUnkcaller, szURL, szFileName, cchFileName, dwReserved, pBSC, tag_in.c_str());
    }
    else {
        Message("[W] URLDownloadToCacheFileHook (%p, A\"%s\", A\"%s\", %ld, %ld, %p)\n", lpUnkcaller, szURL, szFileName, cchFileName, dwReserved, pBSC);
    }
    return S_OK;
}

