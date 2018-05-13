///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>

extern "C"
{
#include <s2e/s2e.h>
#include <s2e/GuestCodeHooking.h>

#include "../log.h"
#include "faultinj.h"
#include "apis.h"
}

#include "faultinj.hpp"

extern "C"
{
    NTSTATUS S2EHook_ZwCreateKey(
        _Out_ PHANDLE KeyHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Reserved_ ULONG TitleIndex,
        _In_opt_ PUNICODE_STRING Class,
        _In_ ULONG CreateOptions,
        _Out_opt_ PULONG Disposition
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "ZwCreateKey", FALSE, STATUS_INSUFFICIENT_RESOURCES, &ZwCreateKey,
            KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition
        );
    }

    NTSTATUS S2EHook_ZwOpenKey(
        _Out_ PHANDLE KeyHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "ZwOpenKey", FALSE, STATUS_INSUFFICIENT_RESOURCES, &ZwOpenKey,
            KeyHandle, DesiredAccess, ObjectAttributes
        );
    }

    NTSTATUS S2EHook_ZwQueryValueKey(
        _In_ HANDLE KeyHandle,
        _In_ PUNICODE_STRING ValueName,
        _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
        _Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
        _In_ ULONG Length,
        _Out_ PULONG ResultLength
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "ZwQueryValueKey", FALSE, STATUS_INSUFFICIENT_RESOURCES, &ZwQueryValueKey,
            KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength
        );
    }

    const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelRegHooks[] = {
        S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ZwCreateKey", S2EHook_ZwCreateKey),
        S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ZwOpenKey", S2EHook_ZwOpenKey),
        S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ZwQueryValueKey", S2EHook_ZwQueryValueKey),
        S2E_KERNEL_FCN_HOOK_END()
    };
}
