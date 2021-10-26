#include "shlwapi-hook.h"
#include "utils.h"
#include "commands.h"
#include <string>
#include <wchar.h>

PCSTR StrStrAHook(
    PCSTR pszFirst,
    PCSTR pszSrch
) {
    if (checkCaller("StrStrA")) {
        if (S2EIsSymbolic((PVOID)pszFirst, 0x4)) {
            //CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            //Command.Command = WINWRAPPER_STRSTRA;
            //Command.StrStrA.pszFirst = (uint64_t)pszFirst;
            //Command.StrStrA.pszSrch = (uint64_t)pszSrch;
            //std::string symbTag = "";
            //Command.StrStrA.symbTag = (uint64_t)symbTag.c_str();
            //__s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrA.symbTag);
            //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            std::string symbTag = ReadTag((PVOID)pszFirst);

            char start[7] = "start_";
            char end[5] = "_end";
            strcpy((char*)pszFirst, start);    
            strcat((char*)pszFirst, pszSrch);
            strcat((char*)pszFirst, end);
            strcat((char*)pszFirst, end);

            PCSTR ret = StrStrA(pszFirst, pszSrch);
            std::string tag = GetTag("StrStrA");
            Message("[W] StrStrA (%p, %p) -> tag_in: %s tag_out: %s\n", pszFirst, pszSrch, symbTag.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)pszFirst, strlen(pszFirst), tag.c_str());
            S2EMakeSymbolic((PVOID)ret, strlen(ret), tag.c_str());
            return ret;
        }
    }
    return StrStrA(pszFirst, pszSrch);
}

PCWSTR StrStrWHook(
    PCWSTR pszFirst,
    PCWSTR pszSrch
) {

    if (checkCaller("StrStrW")) {
        if (S2EIsSymbolic((PVOID)pszFirst, 0x4)) {
            //CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            //Command.Command = WINWRAPPER_STRSTRW;
            //Command.StrStrW.pszFirst = (uint64_t)pszFirst;
            //Command.StrStrW.pszSrch = (uint64_t)pszSrch;
            //std::string symbTag = "";
            //Command.StrStrW.symbTag = (uint64_t)symbTag.c_str();
            //__s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrW.symbTag);
            //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            std::string symbTag = ReadTag((PVOID)pszFirst);

            wchar_t start[7] = L"start_";
            wchar_t end[5] = L"_end";
            wcscpy((wchar_t*)pszFirst, start);
            wcscat((wchar_t*)pszFirst, pszSrch);
            wcscat((wchar_t*)pszFirst, end);
            wcscat((wchar_t*)pszFirst, end);

            PCWSTR ret = StrStrW(pszFirst, pszSrch);

            std::string tag = GetTag("StrStrW");
            Message("[W] StrStrW (%p, %p) -> tag_int: %s, tag_out: %s\n", pszFirst, pszSrch, symbTag.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)pszFirst, wcslen(pszFirst), tag.c_str());
            S2EMakeSymbolic((PVOID)ret, wcslen(ret), tag.c_str());
            return ret;
        }
    }
    return StrStrW(pszFirst, pszSrch);
}

PCSTR StrStrIAHook(
    PCSTR pszFirst,
    PCSTR pszSrch
) {
    if (checkCaller("StrStrIA")) {
        if (S2EIsSymbolic((PVOID)pszFirst, 0x4)) {
            // Since we are using the CyFiFunctionModels to extract tags, we can retain the StrStra 
            // in-lieu of creating a new one for StrstrIA
            //CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            //Command.Command = WINWRAPPER_STRSTRA;
            //Command.StrStrA.pszFirst = (uint64_t)pszFirst;
            //Command.StrStrA.pszSrch = (uint64_t)pszSrch;
            //std::string symbTag = "";
            //Command.StrStrA.symbTag = (uint64_t)symbTag.c_str();
            //__s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrA.symbTag);
            //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            std::string symbTag = ReadTag((PVOID)pszFirst);

            char start[7] = "start_";
            char end[5] = "_end";
            strcpy((char*)pszFirst, start);
            strcat((char*)pszFirst, pszSrch);
            strcat((char*)pszFirst, end);
            strcat((char*)pszFirst, end);

            PCSTR ret = StrStrA(pszFirst, pszSrch);
            std::string tag = GetTag("StrStrIA");
            Message("[W] StrStrA (%p, %p) -> tag_in: %s tag_out: %s\n", pszFirst, pszSrch, symbTag.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)pszFirst, strlen(pszFirst), tag.c_str());
            S2EMakeSymbolic((PVOID)ret, strlen(ret), tag.c_str());
            return ret;
        }
    }
    return StrStrIA(pszFirst, pszSrch);
}

PCWSTR StrStrIWHook(
    PCWSTR pszFirst,
    PCWSTR pszSrch
) {

    if (checkCaller("StrStrIW")) {
        if (S2EIsSymbolic((PVOID)pszFirst, 0x4)) {
            //CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            //Command.Command = WINWRAPPER_STRSTRW;
            //Command.StrStrW.pszFirst = (uint64_t)pszFirst;
            //Command.StrStrW.pszSrch = (uint64_t)pszSrch;
            //std::string symbTag = "";
            //Command.StrStrW.symbTag = (uint64_t)symbTag.c_str();
            //__s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrW.symbTag);
            //S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            std::string symbTag = ReadTag((PVOID)pszFirst);

            wchar_t start[7] = L"start_";
            wchar_t end[5] = L"_end";
            wcscpy((wchar_t*)pszFirst, start);
            wcscat((wchar_t*)pszFirst, pszSrch);
            wcscat((wchar_t*)pszFirst, end);
            wcscat((wchar_t*)pszFirst, end);

            PCWSTR ret = StrStrW(pszFirst, pszSrch);

            std::string tag = GetTag("StrStrIW");
            Message("[W] StrStrW (%p, %p) -> tag_int: %s, tag_out: %s\n", pszFirst, pszSrch, symbTag.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)pszFirst, wcslen(pszFirst), tag.c_str());
            S2EMakeSymbolic((PVOID)ret, wcslen(ret), tag.c_str());
            return ret;
        }
    }
    return StrStrIW(pszFirst, pszSrch);
}