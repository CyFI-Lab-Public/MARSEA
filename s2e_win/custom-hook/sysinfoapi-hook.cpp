#include "utils.h"
#include <sysinfoapi.h>


void WINAPI GetLocalTimeHook(
	LPSYSTEMTIME lpSystemTime
) {
	//Get concrete time first
	GetLocalTime(lpSystemTime);
	if (checkCaller("GetLocalTime")) {
		std::string tag = GetTag("GetLocalTime");
		Message("[W] GetLocalTime (%p) -> tag_out: %s\n", lpSystemTime, tag.c_str());
		S2EMakeSymbolic(lpSystemTime, sizeof(SYSTEMTIME), tag.c_str());
		return;
	}
	return;
}


/*
  GetSystemInfo, which fills a SYSTEM_INFO structure, whose address is provided by its caller. In this case, only the field
  dwNumberOfProcessors is sometimes used to evade dynamic analysis sandboxes
*/
void WINAPI GetSystemInfoHook(
	LPSYSTEM_INFO lpSystemInfo
) {
	GetSystemInfo(lpSystemInfo);
	if (checkCaller("GetSystemInfo")) {
		Message("[W] GetSystemInfo (%p)\n", lpSystemInfo);
		//S2EMakeSymbolic((PVOID)lpSystemInfo->dwNumberOfProcessors, sizeof(lpSystemInfo), tag.c_str());
		lpSystemInfo->dwNumberOfProcessors = 8;
		return;
	}
	return;

}