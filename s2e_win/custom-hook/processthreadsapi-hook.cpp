#include "processthreadsapi-hook.h"
#include "utils.h"
#include <set>
#include <vector>
#include <Shlwapi.h>

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

    if (StrStrA(lpApplicationName, "WerFault")) {
        return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    if (StrStrA(lpCommandLine, "drvctl")) {
        return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    if (StrStrA(lpApplicationName, "s2eput") || StrStrA(lpCommandLine, "s2eput")) {
        return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    std::string app_tag = getFileTag(lpApplicationName);
    std::string cmd_tag = getFileTag(lpCommandLine);

    // BARLAIY
    //LPSTR lpCommandLine = "C:\\s2e\\cyfirundll.exe C:\\Users\\s2e\\AppData\\Roaming\\nx00615.ttf DisPlay 64";
    //LPSTR lpCommandLine = "C:\\s2e\\rundll32-ng.exe C:\\Users\\s2e\\AppData\\Roaming\\nx00615.ttf DisPlay 64";

    if (app_tag.length() > 1) {
        Message("[W] CreateProcessA (%s [|] %s [|] %p [|] %p [|] %i [|] %ld [|] %p [|] %s [|] %p [|] %p) tag_in:%s",
            lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation, app_tag.c_str());
    }
    else if (cmd_tag.length() > 1) {
        Message("[W] CreateProcessA (%s [|] %s [|] %p [|] %p [|] %i [|] %ld [|] %p [|] %s [|] %p [|] %p) tag_in:%s",
            lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation, cmd_tag.c_str());
    }
    else {
        Message("[W] CreateProcessA (%s [|] %s [|] %p [|] %p [|] %i [|] %ld [|] %p [|] %s [|] %p [|] %p)",
            lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

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

    if (StrStrW(lpApplicationName, L"WerFault")) {
        return CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    if (StrStrW(lpCommandLine, L"drvctl")) {
        return CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    if (StrStrW(lpApplicationName, L"s2eput") || StrStrW(lpCommandLine, L"s2eput")) {
        return CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    std::string app_tag = getFileTag(lpApplicationName);
    std::string cmd_tag = getFileTag(lpCommandLine);

    if (app_tag.length() > 1) {
        Message("[W] CreateProcessW (%ls [|] %ls [|] %p [|] %p [|] %i [|] %ld [|] %p [|] %ls [|] %p [|] %p) tag_in:%s\n",
            lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation, app_tag.c_str());
    }
    else if (cmd_tag.length() > 1) {
        Message("[W] CreateProcessW (%ls [|] %ls [|] %p [|] %p [|] %i [|] %ld [|] %p [|] %ls [|] %p [|] %p) tag_in:%s\n",
            lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation, cmd_tag.c_str());
    }
    else {
        Message("[W] CreateProcessW (%ls [|] %ls [|] %p [|] %p [|] %i [|] %ld [|] %p [|] %ls [|] %p [|] %p)",
            lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
            lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

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