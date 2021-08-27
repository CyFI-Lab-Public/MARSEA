#pragma once
#include <Windows.h>
#include <wingdi.h>

int GetDeviceCapsHook(
	HDC hdc,
	int index
);