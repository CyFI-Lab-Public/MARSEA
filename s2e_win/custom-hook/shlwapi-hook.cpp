#include "shlwapi-hook.h"
#include "utils.h"
#include "commands.h"
#include <string>

PCSTR StrStrAHook(
	PCSTR pszFirst,
	PCSTR pszSrch
) {

    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = WINWRAPPER_STRSTRA;
    Command.StrStrA.pszFirst = (uint64_t)pszFirst;
    Command.StrStrA.pszSrch = (uint64_t)pszSrch;
    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    if (Command.StrStrA.symbolic) {
        Message("[HLOG] STRSTRA pszFirst is symbolic %s\n", Command.StrStrA.symbolic);
    }

    char start[7] = "start_";
    char end[5] = "_end";
    strcpy((char*)pszFirst, start);
    strcat((char*)pszFirst, pszSrch);
    strcat((char*)pszFirst, end);
    strcat((char*)pszFirst, end);
    Message("%s, %p, %s", pszFirst, pszFirst, start);

    PCSTR ret = StrStrA(pszFirst, pszSrch);
    Message("[HLOG] StrStrA A\"%s\", A\"%s\" , A\"%s\"\n", pszFirst, pszSrch, ret);

    std::string tag = GetTag("StrStrA");
    S2EMakeSymbolic((PVOID)pszFirst, strlen(pszFirst), tag.c_str());
    S2EMakeSymbolic((PVOID)ret, strlen(ret), tag.c_str());
    return ret;
}