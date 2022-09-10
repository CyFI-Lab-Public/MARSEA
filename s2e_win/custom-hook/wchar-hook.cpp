#include "wchar-hook.h"
#include "utils.h"
#include "commands.h"

wchar_t* wcschrHook(
	wchar_t* str,
	wchar_t c)
{
	Message("[W] wcschr (%ls [|] %ls)\n", str, c);

	return wcschr(str, c);
}

wchar_t* wcsrchrHook(
	wchar_t* str,
	wchar_t c
) {
	Message("[W] wcsrchr (%ls [|] %ls)\n", str, c);

	return wcsrchr(str, c);
}


int wcscmpHook(
	const wchar_t* string1,
	const wchar_t* string2
) {
	Message("[W] wcscmp (%ls [|] %ls)\n", string1, string2);

	return wcscmp(string1, string2);
}

char* strstrhook(
	char* str,
	const char* strSearch
) {

	if (checkCaller("strstr")) {

		if (S2EIsSymbolic(&str, 4)) {
			S2EConcretize(&str, 4);
		}

		std::string tagin = ReadTag((PVOID)str);

		if (tagin != "") {

			S2EDisableForking();

			char* temp = NULL;

			char start[7] = "start_";
			char end[5] = "_end";
			strcpy(str, start);
			strcat(str, strSearch);
			strcat(str, end);
			strcat(str, end);

			char* ret = strstr(str, strSearch);

			S2EEnableForking();

			CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
			Command.Command = WINWRAPPER_STRSTRA;
			Command.StrStrA.pszFirst = (uint64_t)ret;
			Command.StrStrA.pszSrch = (uint64_t)(&temp);
			std::string symbTag = "";
			Command.StrStrA.symbTag = (uint64_t)symbTag.c_str();
			__s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrA.symbTag);
			S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

			std::string tag = GetTag("strstr");
			Message("[W] strstr (%p [|] %p) tag_in:%s tag_out:%s\n", str, strSearch, tagin.c_str(), tag.c_str());
			S2EMakeSymbolic((PVOID)str, strlen(str), tag.c_str());

			return temp;

		}

		return strstr(str, strSearch);

	}

	return strstr(str, strSearch);
}

char* _strlwrhook(
	char* str
) {
	if (checkCaller("_strlwr")) {
		std::string tag_in = "";
		bool isTainted = FALSE;
		if (S2EIsSymbolic(str, 4)) {
			tag_in = ReadTag(str);
			isTainted = IsTainted(str);
			// If the str points to a symbolic buffer, concretize it first and then mark it symbolic again
			concretizeAll(str);
			// S2EConcretize(str, strlen(str));
		}

		char* res = _strlwr(str);

		if (tag_in != "") {
			std::string tag_out = GetTag("_strlwr");
			Message("[W] _strlwr(%p) tag_in:%s tag_out:%s", str, tag_in.c_str(), tag_out.c_str());
			if (isTainted) {
				cyfiTaint(str, strlen(str) - 1, tag_out.c_str());
			} else {
				S2EMakeSymbolic(str, strlen(str) - 1, tag_out.c_str());
			}
		}

		return res;
	}

	return _strlwr(str);
	
}

char* strrchrhook(
	char* str,
	int c
) {
	if (checkCaller("strrchr")) {

		if (S2EIsSymbolic(&str, 4)) {
			S2EConcretize(&str, 4);
		}

		std::string tagin = ReadTag(str);

		if (tagin != "") {

			char* temp = NULL;

			char search = c + '0';

			char start[7] = "start_";
			char end[5] = "_end";
			strcpy(str, start);
			strcat(str, &search);
			strcat(str, end);
			strcat(str, end);

			char* ret = strrchr(str, c);

			CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
			Command.Command = WINWRAPPER_STRSTRA;
			Command.StrStrA.pszFirst = (uint64_t)ret;
			Command.StrStrA.pszSrch = (uint64_t)(&temp);
			std::string symbTag = "";
			Command.StrStrA.symbTag = (uint64_t)symbTag.c_str();
			__s2e_touch_string((PCSTR)(UINT_PTR)Command.StrStrA.symbTag);
			S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

			std::string tag = GetTag("strrchr");
			Message("[W] strrchr (%p [|] %c) tag_in:%s tag_out:%s\n", str, c, tagin.c_str(), tag.c_str());
			S2EMakeSymbolic((PVOID)str, strlen(str), tag.c_str());

			return temp;
		}

		return strrchr(str, c);
	}

	return strrchr(str, c);
}

