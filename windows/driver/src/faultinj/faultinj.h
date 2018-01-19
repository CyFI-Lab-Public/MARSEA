///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

extern BOOLEAN g_faultInjOverApproximate;

VOID FaultInjectionInit(BOOLEAN OverApproximate);

BOOLEAN FaultInjectionCreateVarName(
    _In_ PCHAR FunctionName,
    _Out_ PCHAR *VarName
);

BOOLEAN FaultInjDecideInjectFault(
    _In_ UINT_PTR CallSite,
    _In_ UINT_PTR TargetFunction
);
