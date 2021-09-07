#pragma once

#include <Windows.h>

namespace winreg {
#include <winreg.h>
}
LSTATUS APIENTRY RegOpenKeyExAHook(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);

LSTATUS APIENTRY RegOpenKeyExWHook(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);

LSTATUS APIENTRY RegCloseKeyHook(HKEY hKey);

LSTATUS APIENTRY RegGetValueAHook(HKEY hkey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);

LSTATUS APIENTRY RegGetValueWHook(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);

LSTATUS APIENTRY RegQueryValueExAHook(HKEY hKey, LPCSTR  lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);

LSTATUS APIENTRY RegQueryValueExWHook(HKEY hKey, LPCWSTR  lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);