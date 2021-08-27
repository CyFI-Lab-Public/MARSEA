#include "debugapi-hook.h"
#include "utils.h"

BOOL CheckRemoteDebuggerPresentHook(
	HANDLE hProcess,
	PBOOL  pbDebuggerPresent
) {
	Message("[W] CheckRemoteDebuggerPresent (%p, %p)\n", hProcess, pbDebuggerPresent);
	*pbDebuggerPresent = FALSE;
	return TRUE;
}

BOOL IsDebuggerPresentHook() {
	Message("[W] IsDebuggerPresent\n");
	return FALSE;
}