#include "winternl-hook.h"
#include "utils.h"

BOOLEAN RtlTimeToSecondsSince1970Hook(
	PLARGE_INTEGER Time,
	PULONG         ElapsedSeconds
) {
	if (checkCaller("RtlTimeToSecondsSince1970")) {
		std::string tag = GetTag("RtlTimeToSecondsSince1970");
		Message("[W] RtlTimeToSecondsSince1970 (%p, %p) -> tag_out: %s\n", Time, ElapsedSeconds, tag.c_str());
		S2EMakeSymbolic(ElapsedSeconds, sizeof(ULONG), tag.c_str());
		return TRUE;
	}
	return RtlTimeToSecondsSince1970(Time, ElapsedSeconds);
}