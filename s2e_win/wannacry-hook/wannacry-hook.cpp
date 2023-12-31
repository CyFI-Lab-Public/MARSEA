///
/// Copyright (C) 2018, Adrian Herrera
/// All rights reserved.
///

#include <set>
#include <vector>

#include <Windows.h>
#include <WinInet.h>
#include <strsafe.h>

#include <easyhook.h>

// We need this header file to make things symbolic and to write to the S2E log
#define USER_APP
extern "C" {
#include <s2e/s2e.h>
}

/// Maximum timeout to wait for child processes to terminate (in milliseconds).
/// Can also be set to INFINITE.
#define CHILD_PROCESS_TIMEOUT 10 * 1000

/// Maximum message length to write to S2E debug log
#define S2E_MSG_LEN 512

/// Maximum path length
#define MAX_PATH_LEN 256

/// S2E version number, or 0 if not running in S2E mode
static INT s2eVersion = 0;

/// Keep track of dummy Internet handles that we've created
static std::set<HINTERNET> dummyHandles;

/// Keep track of child processes
static std::set<DWORD> childPids;

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
        S2EMessageFmt("[0x%x|malware-hook] %s", GetCurrentProcessId(),
            message);
    } else {
        printf("[0x%x|malware-hook] %s", GetCurrentProcessId(), message);
    }
}

///
/// Wait a set timeout (in milliseconds) for all the child processes to
/// terminate.
///
static BOOL WaitForChildProcesses(DWORD timeout) {
    bool retCode = TRUE;

    if (childPids.size() > 0) {
        // Convert the set of PIDS to a list of handles with the appropriate
        // permissions
        std::vector<HANDLE> childHandles;
        for (DWORD pid : childPids) {
            Message("Getting handle to process 0x%x\n", pid);
            HANDLE childHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
                FALSE, pid);
            if (childHandle) {
                childHandles.push_back(childHandle);
            } else {
                Message("Unable to open child process 0x%x: 0x%X\n", pid,
                    GetLastError());
                return FALSE;
            }
        }

        // Wait for the processes to terminate
        Message("Waiting %d ms for %d children processes to terminate...\n",
            timeout, childHandles.size());
        DWORD waitRes = WaitForMultipleObjects(childHandles.size(),
            childHandles.data(), TRUE, timeout);
        switch (waitRes) {
        case WAIT_FAILED:
            Message("Failed to wait for child processes: 0x%X\n", GetLastError());
            retCode = FALSE;
            break;
        case WAIT_TIMEOUT:
            Message("Timeout - not all child processes may have terminated\n");
            break;
        }

        // Close all handles
        for (HANDLE handle : childHandles) {
            CloseHandle(handle);
        }
    }

    return retCode;
}

////////////////////
// WannaCry hooks //
////////////////////

static HINTERNET WINAPI InternetOpenUrlAHook(
    HINTERNET hInternet,
    LPCSTR    lpszUrl,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    Message("Intercepted InternetOpenUrlA(%p [|] %s [|] %s [|] 0x%x [|] 0x%x [|] %p)\n",
        hInternet,lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);

    // Force a fork via a symbolic variable. Since both branches are feasible,
    // both paths are taken
    UINT8 returnResource = S2ESymbolicChar("hInternet", 1);
    if (returnResource) {
        // Explore the program when InternetOpenUrlA "succeeds" by returning a
        // dummy resource handle. Because we know that the resource handle is
        // never used, we don't have to do anything fancy to create it.
        // However, we will need to keep track of it so we can free it when the
        // handle is closed.
        HINTERNET resourceHandle = (HINTERNET) malloc(sizeof(HINTERNET));

        // Record the dummy handle so we can clean up afterwards
        dummyHandles.insert(resourceHandle);

        return resourceHandle;
    } else {
        // Explore the program when InternetOpenUrlA "fails"
        return NULL;
    }
}

static BOOL WINAPI InternetCloseHandleHook(HINTERNET hInternet) {
    Message("Intercepted InternetCloseHandle(%p)\n", hInternet);

    std::set<HINTERNET>::iterator it = dummyHandles.find(hInternet);

    if (it == dummyHandles.end()) {
        // The handle is not one of our dummy handles, so call the original
        // InternetCloseHandle function
        return InternetCloseHandle(hInternet);
    } else {
        // The handle is a dummy handle. Free it
        free(*it);
        dummyHandles.erase(it);

        return TRUE;
    }
}

static BOOL WINAPI CreateProcessAHook(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    Message("Intercepted CreateProcessA(%s [|] %s [|] %p [|] %p [|] %d [|] %d [|] %p [|] %s [|] %p [|] %p)",
        lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    // Get this DLL's path
    HMODULE hDll = NULL;
    DWORD hModFlags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    if (!GetModuleHandleEx(hModFlags, (LPCTSTR)&Message, &hDll)) {
        Message("Failed to retrive DLL handle: 0x%X\n", GetLastError());
        goto default_create_process;
    }

    WCHAR dllPath[MAX_PATH_LEN];
    if (!GetModuleFileNameW(hDll, dllPath, MAX_PATH_LEN)) {
        Message("Failed to retrive DLL path: 0x%X\n", GetLastError());
        goto default_create_process;
    }

    // Create the new process, but force it to be created in a suspended state
    if (!CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)) {
        Message("Failed to create suspended process: 0x%X\n", GetLastError());
        goto default_create_process;
    }

    // Inject ourselves into the new, suspended process.
    // NativeInjectionEntryPoint will call RhWakeupProcess, which will kick
    // ourselves out of the suspended state
    NTSTATUS result = RhInjectLibrary(lpProcessInformation->dwProcessId,
        lpProcessInformation->dwThreadId, EASYHOOK_INJECT_DEFAULT,
#if defined(_M_IX86)
        dllPath, NULL,
#elif defined(_M_X64)
        NULL, dllPath,
#else
#error "Platform not supported"
#endif
        NULL, 0);

    if (FAILED(result)) {
        Message("RhInjectLibrary failed: %S\n", RtlGetLastErrorString());
        goto default_create_process;
    }

    // Save the handle to the newly-created process
    childPids.insert(lpProcessInformation->dwProcessId);

    Message("Successfully injected %S into %s %s (PID=0x%x)\n", dllPath,
        lpApplicationName, lpCommandLine, lpProcessInformation->dwProcessId);

    return TRUE;

default_create_process:
    return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

////////////////////
// Initialisation //
////////////////////

///
/// The names of the functions to hook (and the library that function belongs
/// to)
///
static LPCSTR functionsToHook[][2] = {
    { "wininet", "InternetOpenUrlA" },
    { "wininet", "InternetCloseHandle" },
    { "kernel32", "CreateProcessA" },
    { NULL, NULL },
};

/// The function hooks that we will install
static PVOID hookFunctions[] = {
    InternetOpenUrlAHook,
    InternetCloseHandleHook,
    CreateProcessAHook,
};

/// The actual hooks
static HOOK_TRACE_INFO hooks[] = {
    { NULL },
    { NULL },
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

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    // Don't exit until all child processes have terminated (or a timeout is
    // reached)
    case DLL_PROCESS_DETACH:
        return WaitForChildProcesses(CHILD_PROCESS_TIMEOUT);
    }

    return TRUE;
}
