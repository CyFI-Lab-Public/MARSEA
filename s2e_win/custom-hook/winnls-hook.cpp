#include "winnls-hook.h"
#include "utils.h"

LANGID WINAPI GetUserDefaultUILanguageHook() {
	if (checkCaller("GetUserDefaultUILanguage")) {
		std::string tag = GetTag("GetUserDefaultUILanguage");
		LANGID lan_id = GetUserDefaultUILanguage();
		Message("[W] GetUserDefaultUILanguage() ret:%i tag_out:%s\n", lan_id, tag.c_str());
		S2EMakeSymbolic(&lan_id, sizeof(LANGID), tag.c_str());
		return lan_id;
	}
	return GetUserDefaultUILanguage();
}

int WINAPI GetLocaleInfoAHook(
	LCID   Locale,
	LCTYPE LCType,
	LPSTR  lpLCData,
	int    cchData
) {
	if (checkCaller("GetLocaleInfoA")) {
		GetLocaleInfoA(Locale, LCType, lpLCData, cchData);
		std::string tag = GetTag("GetLocaleInfoA");
		Message("[W] GetLocaleInfoA (%p [|] %p [|] %p [|] %i) tag_out:%s\n", Locale, LCType, lpLCData, cchData, tag.c_str());

		if (lpLCData != NULL && cchData != 0) {
			S2EMakeSymbolic(lpLCData, cchData, tag.c_str());
			return cchData;
		}
	}
	return GetLocaleInfoA(Locale, LCType, lpLCData, cchData);
}

UINT WINAPI GetOEMCPHook() {
	if (checkCaller("GetOEMCP")) {

		std::string tag = GetTag("GetOEMCP");
		UINT ret = GetOEMCP();
		Message("[W] GetOEMCP () ret:%i tag_out:%s\n", ret, tag.c_str());
		S2EMakeSymbolic(&ret, sizeof(UINT), tag.c_str());
		return ret;
	}
	return GetOEMCP();
}

LCID WINAPI GetThreadLocaleHook() {
	if (checkCaller("GetThreadLocale")) {
		LCID ret = GetThreadLocale();
		std::string tag = GetTag("GetThreadLocale");
		Message("[W] GetThreadLocale () ret:%ld tag_out:%s\n", ret, tag.c_str());
		S2EMakeSymbolic(&ret, sizeof(LCID), tag.c_str());
		return ret;
	}
	return GetThreadLocale();
}