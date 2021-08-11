#include "shlwapi-hook.h"
#include "utils.h"
#include "commands.h"

PCSTR StrStrAHook(
	PCSTR pszFirst,
	PCSTR pszSrch
) {

    // If can find the string
    if (StrStrA(pszFirst, pszSrch)) {
        return StrStrA(pszFirst, pszSrch);
    }
    else {
        CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
        Command.Command = WINWRAPPER_STRSTRA;
        Command.StrStrA.pszFirst = (uint64_t)pszFirst;
        Command.StrStrA.pszSrch = (uint64_t)pszSrch;
        S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));
        /*
        PCSTR ret = StrStrA(pszFirst, pszSrch);
        if (ret == NULL) {

            char start[7] = "start_";
            size_t len = strlen(pszSrch);
            strncat(start, pszSrch, len);
            char end[5] = "_end";
            len = strlen(end);
            strncat(start, end, len);
            memcpy((void*)pszFirst, start, strlen(start));
            Message("%s, %p, %s", pszFirst, pszFirst, start);
            ret = StrStrA(pszFirst, pszSrch);
            Message("[HLOG] StrStrA A\"%s\", %p, Ret: A\"%s\", %p \n", pszFirst, pszFirst, ret, ret);
        }
        S2EMakeSymbolic((PVOID)ret, 0x80, "CyFi_WinHttpReadData_StrStrA");
        return ret;*/


        if (Command.StrStrA.symbolic) {
            Message("[HLOG] STRSTRA pszFirst is symbolic %s\n", Command.StrStrA.ret);
        }
        //pszFirst = ")))))aHR0cHM6Ly93MHJtLmluL2pvaW4vam9pbi5waHA=";
        //memcpy((void*)pszFirst, (void*)buf, sizeof(buf));
        //memcpy((void*)pszFirst, pszSrch, sizeof(pszFirst));
        //PCSTR ret = StrStrA(pszFirst, pszSrch);
        Message("[HLOG] StrStrA (A\"%s\", A\"%s\", %p, %p, A\"%s\")\n", pszFirst, pszSrch, pszFirst, pszSrch);//, ret);

        S2EMakeSymbolic((PVOID)pszFirst, 13, "CyFi_StrStrA");
        return pszFirst + 3;
    }
    
}