#include "shlwapi-hook.h"
#include "utils.h"
#include "commands.h"
#include <string>
#include <wchar.h>

PCSTR StrStrAHook(
	PCSTR pszFirst,
	PCSTR pszSrch
) {

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_STRSTRA;
    Command.StrStrA.pszFirst = (uint64_t)pszFirst;
    Command.StrStrA.pszSrch = (uint64_t)pszSrch;
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    /*if (Command.StrStrA.symbolic) {
        Message("[W] STRSTRA pszFirst is symbolic %s\n", Command.StrStrA.symbolic);
    }*/
    char start[7] = "start_";
    char end[5] = "_end";
    strcpy((char*)pszFirst, start);
    strcat((char*)pszFirst, pszSrch);
    strcat((char*)pszFirst, end);
    strcat((char*)pszFirst, end);

    PCSTR ret = StrStrA(pszFirst, pszSrch);

    std::string tag = GetTag("StrStrA");
    Message("[W] StrStrA (%p, %p) -> tag_out: %s\n", pszFirst, pszSrch, tag.c_str());
    S2EMakeSymbolic((PVOID)pszFirst, strlen(pszFirst), tag.c_str());
    S2EMakeSymbolic((PVOID)ret, strlen(ret), tag.c_str());
    return ret;
}

PCWSTR StrStrWHook(
    PCWSTR pszFirst,
    PCWSTR pszSrch
) {

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_STRSTRW;
    Command.StrStrW.pszFirst = (uint64_t)pszFirst;
    Command.StrStrW.pszSrch = (uint64_t)pszSrch;
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    /*if (Command.StrStrA.symbolic) {
        Message("[W] STRSTRA pszFirst is symbolic %s\n", Command.StrStrA.symbolic);
    }*/
    wchar_t start[7] = L"start_";
    wchar_t end[5] = L"_end";
    wcscpy((wchar_t*)pszFirst, start);
    wcscat((wchar_t*)pszFirst, pszSrch);
    wcscat((wchar_t*)pszFirst, end);
    wcscat((wchar_t*)pszFirst, end);

    PCWSTR ret = StrStrW(pszFirst, pszSrch);

    std::string tag = GetTag("StrStrW");
    Message("[W] StrStrW (%p, %p) -> tag_out: %s\n", pszFirst, pszSrch, tag.c_str());
    S2EMakeSymbolic((PVOID)pszFirst, wcslen(pszFirst), tag.c_str());
    S2EMakeSymbolic((PVOID)ret, wcslen(ret), tag.c_str());
    return ret;
}