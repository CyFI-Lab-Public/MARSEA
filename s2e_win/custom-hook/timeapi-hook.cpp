#include "timeapi-hook.h"
#include "utils.h"


DWORD timeGetTimeHook() {
	if (checkCaller("timeGetTime")) {
		Message("[W] timeGetTime()\n");
		std::string tag = GetTag("timeGetTime");
		return S2ESymbolicInt(tag.c_str(), timeGetTime());
	}
	return timeGetTime();
}
