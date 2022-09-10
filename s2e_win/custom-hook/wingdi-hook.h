#pragma once
#include <Windows.h>
#include <wingdi.h>

int WINAPI GetDeviceCapsHook(
	HDC hdc,
	int index
);