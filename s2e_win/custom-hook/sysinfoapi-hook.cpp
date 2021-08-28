#include "utils.h"
#include <sysinfoapi.h>


void GetLocalTimeHook(
	LPSYSTEMTIME lpSystemTime
) {
	if (checkCaller("GetLocalTime")) {
		//Get concrete time first
		GetLocalTimeHook(lpSystemTime);
		std::string tag = GetTag("GetLocalTime");
		Message("[W] GetLocalTime (%p) -> tag_out: %s\n", lpSystemTime, tag.c_str());
		S2EMakeSymbolic(lpSystemTime, sizeof(SYSTEMTIME), tag.c_str());
		return;
	}
	return GetLocalTimeHook(lpSystemTime);

}