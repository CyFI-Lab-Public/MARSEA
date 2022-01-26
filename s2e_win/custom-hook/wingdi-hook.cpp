#include "wingdi-hook.h"
#include "utils.h"

int WINAPI GetDeviceCapsHook(
	HDC hdc,
	int index
) {
	if (checkCaller("GetDeviceCaps")) {
		int data = GetDeviceCaps(hdc, index);
		std::string tag = GetTag("GetDeviceCaps");
		Message("[W] GetDeviceCaps (%p [|] %i) ret:%i tag_out:%s\n", hdc, index, data, tag.c_str());
		int ret = S2ESymbolicInt(tag.c_str(), data);
		return ret;
	}
	return GetDeviceCaps(hdc, index);
}