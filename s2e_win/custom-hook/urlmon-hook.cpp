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
        Message("[W] URLDownloadToFile (%p [|] %s [|] %s [|] %ld [|] %p)\n", pCaller, szURL, szFileName, dwReserved, lpfnCB);
        Message("URLDownloadToFile - Not implemented yet\n");
        return S_OK;
    }
    return URLDownloadToFile(pCaller, szURL, szFileName, dwReserved, lpfnCB);
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
        Message("[W] URLDownloadToFileW (%p [|] %ls [|] %ls [|] %ld [|] %p) tag_in:%s \n", pCaller, szURL, szFileName, dwReserved, lpfnCB, tag_in.c_str());
    }
    else {
        Message("[W] URLDownloadToFileW (%p [|] %ls [|] %ls [|] %ld [|] %p)\n", pCaller, szURL, szFileName, dwReserved, lpfnCB);
    }
    Message("URLDownloadToFileW - Not implemented yet\n");
    return S_OK;
}

HRESULT WINAPI URLDownloadToCacheFileHook(
   LPUNKNOWN           lpUnkcaller,
   LPCSTR              szURL,
   LPTSTR              szFileName,
   DWORD               cchFileName,
   DWORD               dwReserved,
   IBindStatusCallback* pBSC
) {
    std::string tag_in = ReadTag((PVOID)szURL);
    if (tag_in.length() > 0) {
        Message("[W] URLDownloadToCacheFileHook (%p [|] %s [|] %s [|] %ld [|] %ld [|] %p) tag_in:%s \n", lpUnkcaller, szURL, szFileName, cchFileName, dwReserved, pBSC, tag_in.c_str());
    }
    else {
        Message("[W] URLDownloadToCacheFileHook (%p [|] %s [|] %s [|] %ld [|] %ld [|] %p)\n", lpUnkcaller, szURL, szFileName, cchFileName, dwReserved, pBSC);
    }
    return S_OK;
}

