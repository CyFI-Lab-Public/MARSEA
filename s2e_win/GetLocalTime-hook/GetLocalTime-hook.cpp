///
/// Copyright (C) 2018, Adrian Herrera
/// All rights reserved.
///

#include <Windows.h>
#include <strsafe.h>

#include <easyhook.h>

// We need this header file to make things symbolic and to write to the S2E log
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}

/// Maximum message length to write to S2E debug log
#define S2E_MSG_LEN 512

/// S2E version number, or 0 if not running in S2E mode
static INT s2eVersion = 0;

//////////////////////
// Helper functions //
//////////////////////

///
/// Write a message to the S2E log (or stdout).
///
static void Message(LPCSTR fmt, ...) {
    CHAR message[S2E_MSG_LEN];
    va_list args;

    va_start(args, fmt);
    vsnprintf(message, S2E_MSG_LEN, fmt, args);
    va_end(args);

    if (s2eVersion) {
        S2EMessageFmt("[malware-hook] %s", message);
    } else {
        printf("[malware-hook] %s", message);
    }
}

////////////////////////
// GetLocalTime hooks //
////////////////////////

static VOID WINAPI GetLocalTimeHook(LPSYSTEMTIME lpSystemTime) {
    Message("Intercepted GetLocalTime\n");

    // Call the original GetLocalTime to get a concrete value
    GetLocalTime(lpSystemTime);

    // Make the value concolic
    S2EMakeSymbolic(lpSystemTime, sizeof(*lpSystemTime), "SystemTime");
}

////////////////////
// Initialisation //
////////////////////

///
/// The names of the functions to hook (and the library that function belongs
/// to)
///
static LPCSTR functionsToHook[][2] = {
    { "kernel32", "GetLocalTime" },
    { NULL, NULL },
};

/// The function hooks that we will install
static PVOID hookFunctions[] = {
    GetLocalTimeHook,
};

/// The actual hooks
static HOOK_TRACE_INFO hooks[] = {
    { NULL },
};

// EasyHook will be looking for this export to support DLL injection. If not
// found then DLL injection will fail
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO *);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO *inRemoteInfo) {
    // Unused
    (void*)inRemoteInfo;

    // Used by the Message function to decide where to write output to
    s2eVersion = S2EGetVersion();

    for (unsigned i = 0; functionsToHook[i][0] != NULL; ++i) {
        LPCSTR moduleName = functionsToHook[i][0];
        LPCSTR functionName = functionsToHook[i][1];

        // Install the hook
        NTSTATUS result = LhInstallHook(
            GetProcAddress(GetModuleHandleA(moduleName), functionName),
            hookFunctions[i],
            NULL,
            &hooks[i]);

        if (FAILED(result)) {
            Message("Failed to hook %s.%s: %S\n", moduleName, functionName,
                RtlGetLastErrorString());
        } else {
            Message("Successfully hooked %s.%s\n", moduleName, functionName);
        }

        // Ensure that all threads _except_ the injector thread will be hooked
        ULONG ACLEntries[1] = { 0 };
        LhSetExclusiveACL(ACLEntries, 1, &hooks[i]);
    }

    // The process was started in a suspended state. Wake it up...
    RhWakeUpProcess();
}
