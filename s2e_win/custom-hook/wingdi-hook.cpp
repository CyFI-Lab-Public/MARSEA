#include "wingdi-hook.h"
#include "utils.h"

int GetDeviceCapsHook(
	HDC hdc,
	int index
) {
	int data = GetDeviceCaps(hdc, index);
	std::string tag = GetTag("GetDeviceCaps");
	Message("[W] GetDeviceCaps (%p, %i) Ret: %i -> tag_out: %s\n", hdc, index, data, tag.c_str());
	int ret = S2ESymbolicInt(tag.c_str(), data);
	return ret;
}