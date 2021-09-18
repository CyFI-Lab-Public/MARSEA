#include "processthreadsapi-hook.h"
#include "utils.h"
#include <set>
#include <vector>

/// Keep track of child processes
static std::set<DWORD> childPids;


BOOL WINAPI CreateProcessAHook(
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
    if (checkCaller("CreateProcessA")) {
        Message("[W] CreateProcessA (%s, %s, %p, %p, %d, %d, %p, %s, %p, %p)",
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
    }

    else {
        goto default_create_process;
    }

default_create_process:
    return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL WINAPI CreateProcessWHook(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    if (checkCaller("CreateProcessW")) {
        Message("[W] CreateProcessW (%ls, %ls, %p, %p, %ld, %ld, %p, %ls, %p, %p)",
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
        if (!CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
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
    }
    else {
        goto default_create_process;
    }

default_create_process:
    return CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}


BOOL WINAPI WaitForChildProcesses(DWORD timeout) {
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
            }
            else {
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