#include "urlmon-hook.h"
#include "utils.h"
#include "commands.h"


HRESULT URLDownloadToFileWHook(
    LPUNKNOWN            pCaller,
    LPCTSTR              szURL,
    LPCTSTR              szFileName,
    _Reserved_ DWORD     dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
) {
    Message("[W] URLDownloadToFileW (%p, A\"%ls\", A\"%ls\", %ld, %p)\n", pCaller, szURL, szFileName, dwReserved, lpfnCB);
    Message("[W] URLDownloadToFileW - Not implemented yet\n");

    return URLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
}