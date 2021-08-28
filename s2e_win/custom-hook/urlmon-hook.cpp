#include "urlmon-hook.h"
#include "utils.h"
#include "commands.h"


HRESULT URLDownloadToFileHook(
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

