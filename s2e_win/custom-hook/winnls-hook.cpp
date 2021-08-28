#include "winnls-hook.h"
#include "utils.h"

LANGID GetUserDefaultUILanguageHook() {
	std::string tag = GetTag("GetUserDefaultUILanguage");
	LANGID lan_id = GetUserDefaultUILanguage();
	Message("[W] GetUserDefaultUILanguage() Ret: %i -> tag_out: %s\n", lan_id, tag.c_str());
	S2EMakeSymbolic(&lan_id, sizeof(LANGID), tag.c_str());
	return lan_id;
}

int GetLocaleInfoAHook(
	LCID   Locale,
	LCTYPE LCType,
	LPSTR  lpLCData,
	int    cchData
) {
	std::string tag = GetTag("GetLocaleInfoA");
	Message("[W] GetLocalInfoA (%p, %p, %p, %i) -> tag_out: %s\n", Locale, LCType, lpLCData, cchData);

	if (lpLCData != NULL && cchData != 0) {
		S2EMakeSymbolic(lpLCData, cchData, tag.c_str());
		return cchData;
	}
	else {
		return GetLocaleInfoAHook(Locale, LCType, lpLCData, cchData);
	}
}

UINT GetOEMCPHook() {
	std::string tag = GetTag("GetOEMCP");
	UINT ret = GetOEMCP();
	Message("[W] GetOEMCP () Ret: %i -> tag_out: %s\n", ret, tag.c_str());
	S2EMakeSymbolic(&ret, sizeof(UINT), tag.c_str());
	return ret;
}

LCID GetThreadLocaleHook() {
	LCID ret = GetThreadLocale();
	std::string tag = GetTag("GetThreadLocale");
	Message("[W] GetThreadLocale () Ret: %ld -> tag_out: %s\n", ret, tag.c_str());
	S2EMakeSymbolic(&ret, sizeof(LCID), tag.c_str());
	return ret;
}