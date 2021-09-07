#include "consoleapi3-hook.h"
#include "utils.h"
#include <set>

static std::set<HWND> dummyHandles;


HWND WINAPI GetConsoleWindowHook(void) {
    HWND consoleHandle = GetConsoleWindow();
    if (checkCaller("GetConsoleWindow")) {

        if (consoleHandle == 0) {
            consoleHandle = (HWND)malloc(sizeof(HWND));
        }
        Message("[W] GetConsoleWindow (), Ret: %p\n",
            consoleHandle);
    }
    return consoleHandle;
}
