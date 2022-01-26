#include "shlwapi-hook.h"
#include "utils.h"
#include "commands.h"
#include <string>
#include <wchar.h>

PCSTR STDAPICALLTYPE StrStrAHook(
    PCSTR pszFirst,
    PCSTR pszSrch
) {
    if (checkCaller("StrStrA")) {

        if (S2EIsSymbolic(&pszFirst, 4)) {
            S2EConcretize(&pszFirst, 4);
        }

        std::string tagin = ReadTag((PVOID)pszFirst);
        if (tagin != "")
        {
            PCSTR temp = NULL;

            char start[7] = "start_";
            char end[5] = "_end";
            strcpy((char*)pszFirst, start);
            strcat((char*)pszFirst, pszSrch);
            strcat((char*)pszFirst, end);
            strcat((char*)pszFirst, end);

            PCSTR ret = StrStrA(pszFirst, pszSrch);

            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_STRSTRA;
            Command.StrStrA.pszFirst = (uint64_t)ret;
            Command.StrStrA.pszSrch = (uint64_t)(&temp);
            std::string symbTag = "";
            Command.StrStrA.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrA.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            std::string tag = GetTag("StrStrA");
            Message("[W] StrStrA (%s [|] %s) tag_in:%s tag_out:%s\n", pszFirst, pszSrch, tagin.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)pszFirst, strlen(pszFirst), tag.c_str());

            return temp;

        }
        return StrStrA(pszFirst, pszSrch);
    }

    return StrStrA(pszFirst, pszSrch);
}

PCWSTR STDAPICALLTYPE StrStrWHook(
    PCWSTR pszFirst,
    PCWSTR pszSrch
) {
    if (checkCaller("StrStrW")) {

        if (S2EIsSymbolic(&pszFirst, 4)) {
            S2EConcretize(&pszFirst, 4);
        }

        std::string tagin = ReadTag((PVOID)pszFirst);
        if (tagin != "")
        {

            PCWSTR temp = NULL;

            wchar_t start[7] = L"start_";
            wchar_t end[5] = L"_end";
            wcscpy((wchar_t*)pszFirst, start);
            wcscat((wchar_t*)pszFirst, pszSrch);
            wcscat((wchar_t*)pszFirst, end);
            wcscat((wchar_t*)pszFirst, end);

            PCWSTR ret = StrStrW(pszFirst, pszSrch);

            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_STRSTRA;
            Command.StrStrA.pszFirst = (uint64_t)ret;
            Command.StrStrA.pszSrch = (uint64_t)(&temp);
            std::string symbTag = "";
            Command.StrStrA.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrA.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            std::string tag = GetTag("StrStrW");
            Message("[W] StrStrW (%ls [|] %ls) tag_in:%s, tag_out:%s\n", pszFirst, pszSrch, tagin.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)pszFirst, wcslen(pszFirst), tag.c_str());
            // S2EMakeSymbolic((PVOID)ret, wcslen(ret), tag.c_str());
            return temp;

        }
        return StrStrW(pszFirst, pszSrch);
    }

    return StrStrW(pszFirst, pszSrch);
}

PCSTR STDAPICALLTYPE StrStrIAHook(
    PCSTR pszFirst,
    PCSTR pszSrch
) {

    if (checkCaller("StrStrIA")) {
        // If the pointer itself is symbolic, concretize it here
        if (S2EIsSymbolic(&pszFirst, 4)) {
            S2EConcretize(&pszFirst, 4);
        }

        std::string tagin = ReadTag((PVOID)pszFirst);
        if (tagin != "")
        {
            PCSTR temp = NULL;
            //S2EMakeSymbolic(&temp, sizeof(temp), "temp");

            char start[7] = "start_";
            char end[5] = "_end";
            strcpy((char*)pszFirst, start);
            strcat((char*)pszFirst, pszSrch);
            strcat((char*)pszFirst, end);
            strcat((char*)pszFirst, end);

            PCSTR ret = StrStrIA(pszFirst, pszSrch);

            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_STRSTRA;
            Command.StrStrA.pszFirst = (uint64_t)ret;
            Command.StrStrA.pszSrch = (uint64_t)(&temp);
            std::string symbTag = "";
            Command.StrStrA.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrA.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            std::string tag = GetTag("StrStrIA");
            Message("[W] StrStrIA (%s [|] %s) tag_in:%s tag_out:%s\n", pszFirst, pszSrch, tagin.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)pszFirst, strlen(pszFirst), tag.c_str());
            // S2EMakeSymbolic((PVOID)ret, strlen(ret), tag.c_str());

            return temp;

        }
        return StrStrIA(pszFirst, pszSrch);
    }

    return StrStrIA(pszFirst, pszSrch);
}

PCWSTR STDAPICALLTYPE StrStrIWHook(
    PCWSTR pszFirst,
    PCWSTR pszSrch
) {

    if (checkCaller("StrStrIW")) {

        if (S2EIsSymbolic(&pszFirst, 4)) {
            S2EConcretize(&pszFirst, 4);
        }

        std::string tagin = ReadTag((PVOID)pszFirst);
        if (tagin != "")
        {
            PCWSTR temp = NULL;

            wchar_t start[7] = L"start_";
            wchar_t end[5] = L"_end";
            wcscpy((wchar_t*)pszFirst, start);
            wcscat((wchar_t*)pszFirst, pszSrch);
            wcscat((wchar_t*)pszFirst, end);
            wcscat((wchar_t*)pszFirst, end);

            PCWSTR ret = StrStrIW(pszFirst, pszSrch);

            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_STRSTRA;
            Command.StrStrA.pszFirst = (uint64_t)ret;
            Command.StrStrA.pszSrch = (uint64_t)(&temp);
            std::string symbTag = "";
            Command.StrStrA.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrA.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            std::string tag = GetTag("StrStrIW");
            Message("[W] StrStIrW (%ls [|] %ls) tag_in:%s tag_out:%s\n", pszFirst, pszSrch, tagin.c_str(), tag.c_str());
            S2EMakeSymbolic((PVOID)pszFirst, wcslen(pszFirst), tag.c_str());
            // S2EMakeSymbolic((PVOID)ret, wcslen(ret), tag.c_str());
            return temp;

        }
        return StrStrIW(pszFirst, pszSrch);
    }

    return StrStrIW(pszFirst, pszSrch);
}