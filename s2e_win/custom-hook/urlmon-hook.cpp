#include "urlmon-hook.h"
#include "utils.h"
#include "commands.h"
#include <Shlwapi.h>


HRESULT WINAPI URLDownloadToFileHook(
    LPUNKNOWN            pCaller,
    LPCTSTR              szURL,
    LPCTSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
) {
    std::string tag_in = ReadTag((PVOID)szURL);
    std::string tag_out = GetTag("URLDownloadToFileA");

    if (tag_in.length() > 0) {
        Message("[W] URLDownloadToFileA (%p [|] %s [|] %s [|] %ld [|] %p) tag_in:%s tag_out:%s\n", pCaller, szURL, szFileName, dwReserved, lpfnCB, tag_in.c_str(), tag_out.c_str());
    }
    else {
        Message("[W] URLDownloadToFileA (%p [|] %s [|] %s [|] %ld [|] %p) tag_out:%s\n", pCaller, szURL, szFileName, dwReserved, lpfnCB, tag_out.c_str());
    }
     
    PTSTR fileNamePointer = PathFindFileName(szFileName);
    std::string fileName = lpcstrToString((LPCSTR)fileNamePointer);
    taintFile[fileName] = tag_out;
    return S_OK;
}


HRESULT WINAPI URLDownloadToFileWHook(
    LPUNKNOWN            pCaller,
    LPCWSTR              szURL,
    LPCWSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
) {
    std::string tag_in = ReadTag((PVOID)szURL);
    std::string tag_out = GetTag("URLDownloadToFileW");

    if (tag_in.length() > 0) {
        Message("[W] URLDownloadToFileW (%p [|] %ls [|] %ls [|] %ld [|] %p) tag_in:%s tag_out:%s\n", pCaller, szURL, szFileName, dwReserved, lpfnCB, tag_in.c_str(), tag_out.c_str());
    }
    else {
        Message("[W] URLDownloadToFileW (%p [|] %ls [|] %ls [|] %ld [|] %p) tag_out:%s\n", pCaller, szURL, szFileName, dwReserved, lpfnCB, tag_out.c_str());
    }

    PTSTR fileNamePointer = PathFindFileName(szFileName);
    std::string fileName = lpcstrToString((LPCSTR)fileNamePointer);
    taintFile[fileName] = tag_out;
    return S_OK;
}

HRESULT WINAPI URLDownloadToCacheFileAHook(
   LPUNKNOWN           lpUnkcaller,
   LPCSTR              szURL,
   LPTSTR              szFileName,
   DWORD               cchFileName,
   DWORD               dwReserved,
   IBindStatusCallback* pBSC
) {
    std::string tag_in = ReadTag((PVOID)szURL);
    if (tag_in.length() > 0) {
        Message("[W] URLDownloadToCacheFileA (%p [|] %s [|] %s [|] %ld [|] %ld [|] %p) tag_in:%s \n", lpUnkcaller, szURL, szFileName, cchFileName, dwReserved, pBSC, tag_in.c_str());
    }
    else {
        Message("[W] URLDownloadToCacheFileA (%p [|] %s [|] %s [|] %ld [|] %ld [|] %p)\n", lpUnkcaller, szURL, szFileName, cchFileName, dwReserved, pBSC);
    }
    return S_OK;
}

HRESULT WINAPI URLDownloadToCacheFileWHook(
    LPUNKNOWN           lpUnkcaller,
    LPCWSTR              szURL,
    LPWSTR              szFileName,
    DWORD               cchFileName,
    DWORD               dwReserved,
    IBindStatusCallback* pBSC
) {
    std::string tag_in = ReadTag((PVOID)szURL);
    if (tag_in.length() > 0) {
        Message("[W] URLDownloadToCacheFileW (%p [|] %ls [|] %ls [|] %ld [|] %ld [|] %p) tag_in:%s \n", lpUnkcaller, szURL, szFileName, cchFileName, dwReserved, pBSC, tag_in.c_str());
    }
    else {
        Message("[W] URLDownloadToCacheFileW (%p [|] %ls [|] %ls [|] %ld [|] %ld [|] %p)\n", lpUnkcaller, szURL, szFileName, cchFileName, dwReserved, pBSC);
    }
    return S_OK;
}

