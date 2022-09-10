#include "stdlib-hook.h"
#include "utils.h"
#include "commands.h"

int _wtoiHook(
	const wchar_t* str
) {
	if (checkCaller("_wtoi")) {
		std::string tag_in = ReadTag((PVOID)str);
		if (tag_in.length() > 0) {
			std::string tag_out = GetTag("_wtoi");
			concretizeAll((PVOID)str);
			Message("[W] _wtoi(%p) tag_in:%s tag_out:%s", str, tag_in.c_str(), tag_out.c_str());
			return S2ESymbolicInt(tag_out.c_str(), _wtoi(str));
		}
		return _wtoi(str);
	}
	else {
		return _wtoi(str);
	}
}