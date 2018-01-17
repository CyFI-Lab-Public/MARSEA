///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <fltKernel.h>
#include <s2e/ModuleMap.h>
#include <s2e/KeyValueStore.h>

#include "../adt/strings.h"
#include "../log.h"
#include "apis.h"
#include "faultinj.h"
#include "../utils.h"

BOOLEAN g_faultInjOverApproximate;

BOOLEAN FaultInjectionCreateVarName(
    _In_ PCHAR ModuleName,
    _In_ PCHAR FunctionName,
    _In_ UINT_PTR CallSite,
    _Out_ PCHAR *VarName
)
{
    BOOLEAN Result = FALSE;
    NTSTATUS Status;
    S2E_MODULE_INFO Info;
    CHAR Prefix[128];
    CHAR *BackTraceStr = NULL;

    if (!S2EModuleMapGetModuleInfo(CallSite, 0, &Info)) {
        LOG("Could not read module info for callsite %p\n", (PVOID)CallSite);
        goto err;
    }

    Status = S2EEncodeBackTraceForKnownModules(&BackTraceStr, NULL, 3);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not encode backtrace\n");
        goto err;
    }

    // TODO: do we actually need a separate call site given that we have a backtrace?
    const UINT64 RelativeCallSite = CallSite - Info.RuntimeLoadBase + Info.NativeLoadBase;

    sprintf_s(
        Prefix, sizeof(Prefix), "FaultInjInvokeOrig %s:%llx %s:%s ",
        Info.ModuleName[0] ? Info.ModuleName : "<unknown>",
        RelativeCallSite, ModuleName, FunctionName
    );

    *VarName = StringCat(Prefix, BackTraceStr);
    if (!*VarName) {
        LOG("Could not concatenate string\n");
        goto err;
    }

    Result = TRUE;

err:
    if (BackTraceStr) {
        ExFreePool(BackTraceStr);
    }

    return Result;
}

#define STACK_FRAME_COUNT 32
#define CALL_SITE_ID_SIZE 128

// Compute a hash of the call stack and store it in a global key-value store.
// This ensures that different states don't inject the same faults needlessly.
BOOLEAN FaultInjDecideInjectFault(
    _In_ UINT_PTR CallSite,
    _In_ UINT_PTR TargetFunction
)
{
    S2E_MODULE_INFO Info;
    UINT_PTR ModuleAddress = CallSite;
    PVOID BackTrace[STACK_FRAME_COUNT] = { 0 };
    CHAR CallSiteId[CALL_SITE_ID_SIZE];
    ULONG Hash;
    UINT64 AlreadyExercised = 0;

    UNREFERENCED_PARAMETER(CallSite);
    UNREFERENCED_PARAMETER(TargetFunction);

    if (S2EModuleMapGetModuleInfo(CallSite, 0, &Info)) {
        ModuleAddress = CallSite - (UINT_PTR)Info.RuntimeLoadBase + (UINT_PTR)Info.NativeLoadBase;
    }

    RtlCaptureStackBackTrace(0, STACK_FRAME_COUNT, BackTrace, &Hash);
    sprintf_s(CallSiteId, sizeof(CallSiteId), "%s_%p_%x", Info.ModuleName, (PVOID)ModuleAddress, Hash);
    LOG("CallSiteId: %s\n", CallSiteId);

    if (!S2EKVSGetValue(CallSiteId, &AlreadyExercised)) {
        // Key not found, means that we have no exercised yet
        if (!S2EKVSSetValue(CallSiteId, 1, NULL)) {
            LOG("Could not set key %s\n", CallSiteId);
        }
    }

    LOG("AlreadyExercised: %d\n", AlreadyExercised);

    return !AlreadyExercised;
}

VOID FaultInjectionInit(BOOLEAN OverApproximate)
{
    g_faultInjOverApproximate = OverApproximate;

    LOG("Hooking ExXxx apis...");
    RegisterHooks(g_kernelExHooks);

    LOG("Hooking MmXxx apis...");
    RegisterHooks(g_kernelMmHooks);

    LOG("Hooking PsXxx apis...");
    RegisterHooks(g_kernelPsHooks);

    LOG("Hooking ObXxx apis...");
    RegisterHooks(g_kernelObHooks);

    LOG("Hooking Registry apis...");
    RegisterHooks(g_kernelRegHooks);
}
