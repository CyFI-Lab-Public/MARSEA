#include "debugapi-hook.h"
#include "utils.h"

BOOL CheckRemoteDebuggerPresentHook(
	HANDLE hProcess,
	PBOOL  pbDebuggerPresent
) {
	if (checkCaller("CheckRemoteDebuggerPresent")) {
		Message("[W] CheckRemoteDebuggerPresent (%p, %p)\n", hProcess, pbDebuggerPresent);
		*pbDebuggerPresent = FALSE;
		return TRUE;
	}
	return CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
}

BOOL IsDebuggerPresentHook() {
	if (checkCaller("IsDebuggerPresent")) {

		Message("[W] IsDebuggerPresent\n");
		return FALSE;
	}
	return IsDebuggerPresent();
}