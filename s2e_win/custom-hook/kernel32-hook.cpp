#include"kernel32-hook.h"
#include "utils.h"
#include <set>

void SleepHook(
	DWORD dwMilliseconds
) {
	Message("[W] Sleep(%ld)", dwMilliseconds);
	return;
}

LPSTR GetCommandLineAHook()
{
	std::string tag = GetTag("GetCommandLineA");
	LPSTR cmd_line_str = "";
	S2EMakeSymbolic((PVOID)cmd_line_str, DEFAULT_MEM_LEN, tag.c_str());
	Message("[W] GetCommandLineA () -> tag_out: %s\n", tag.c_str());
	return cmd_line_str;
}

HMODULE LoadLibraryWHook(LPCWSTR lpLibFileName)
{
	Message("[W] LoadLibraryW (%ls)", lpLibFileName);
	return LoadLibraryW(lpLibFileName);

}


