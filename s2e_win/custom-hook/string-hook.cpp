#include "string-hook.h"
#include "utils.h"
#include "commands.h"

char* strtokHook(
	char* strToken,
	const char* strDelimit
){     
    if (checkCaller("strtok")) {
        if (S2EIsSymbolic((PVOID)strToken, 0x4)) {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_STRTOK;
            Command.strtok.strToken = (uint64_t)strToken;
            Command.strtok.strDelimit = (uint64_t)strDelimit;
            std::string symbTag = "";
            Command.strtok.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.strtok.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            char start[7] = "start_";
            char end[5] = "_end";
            strcpy((char*)strToken, start);
            strcat((char*)strToken, strDelimit);
            strcat((char*)strToken, end);
            strcat((char*)strToken, end);

            char* ret = strtok(strToken, strDelimit);
            std::string tag = GetTag("strtok");
            Message("[W] strtok (%p, %p) -> tag_in: %s, tag_out: %s\n", strToken, strDelimit, (uint32_t)Command.strtok.symbTag, tag.c_str());
            S2EMakeSymbolic((PVOID)strToken, strlen(strToken), tag.c_str());
            S2EMakeSymbolic((PVOID)ret, strlen(ret), tag.c_str());
            return ret;
        }
    }
    return strtok(strToken, strDelimit);
}

const char* strstrHook(
    const char* str,
    const char* strSearch
) {
    if (checkCaller("strstr")) {
        if (S2EIsSymbolic((PVOID)str, 0x4)) {
            CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
            Command.Command = WINWRAPPER_STRSTR;
            Command.strstr.str = (uint64_t)str;
            Command.strstr.strSearch = (uint64_t)strSearch;
            std::string symbTag = "";
            Command.strstr.symbTag = (uint64_t)symbTag.c_str();
            __s2e_touch_string((PCSTR)(UINT_PTR)Command.strstr.symbTag);
            S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

            char start[7] = "start_";
            char end[5] = "_end";
            strcpy((char*)str, start);
            strcat((char*)str, strSearch);
            strcat((char*)str, end);
            strcat((char*)str, end);

            const char* ret = strstr(str, strSearch);
            std::string tag = GetTag("strstr");
            Message("[W] strtok (%p, %p) -> tag_in: %s, tag_out: %s\n", str, strSearch, (uint32_t)Command.strstr.symbTag, tag.c_str());
            S2EMakeSymbolic((PVOID)str, strlen(str), tag.c_str());
            S2EMakeSymbolic((PVOID)ret, strlen(ret), tag.c_str());
            return ret;
        }
    }
    return strstr(str, strSearch);
}