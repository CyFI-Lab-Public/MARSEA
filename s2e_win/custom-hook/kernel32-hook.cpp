#include"kernel32-hook.h"
#include "utils.h"
#include <set>

void SleepHook(
	DWORD dwMilliseconds
) {
	Message("[HLOG] Sleep(%ld)", dwMilliseconds);
	return;
}