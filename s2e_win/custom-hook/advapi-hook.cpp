#include "advapi-hook.h"
#include "utils.h"
#include <set>

static std::set<HKEY> dummyHandles;

LSTATUS APIENTRY RegOpenKeyExAHook(
	HKEY   hKey,
	LPCSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
) {
	if (checkCaller("RegOpenKeyExA")) {
		std::string tag = GetTag("RegOpenKeyExA");
		Message("[W] RegOpenKeyExA (%p, %s, %ld, %ld, %p) -> tag_out: %s\n", hKey, lpSubKey, ulOptions, samDesired, phkResult, tag.c_str());
		LSTATUS lResult = RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
		if (lResult == ERROR_SUCCESS) {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else {
			HKEY hackHandle = (HKEY)malloc(sizeof(HKEY));
			*phkResult = hackHandle;
			dummyHandles.insert(hackHandle);
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_FILE_NOT_FOUND);
			return fakeResult;
		}
	}
	return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS APIENTRY RegOpenKeyExWHook(
	HKEY   hKey,
	LPCWSTR lpSubKey,
	DWORD  ulOptions,
	REGSAM samDesired,
	PHKEY  phkResult
) {
	if (checkCaller("RegOpenKeyExW")) {
		std::string tag = GetTag("RegOpenKeyExW");
		Message("[W] RegOpenKeyExW (%p, %s, %ld, %ld, %p) -> tag_out: %s\n", hKey, lpSubKey, ulOptions, samDesired, phkResult, tag.c_str());
		LSTATUS lResult = RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
		if (lResult == ERROR_SUCCESS) {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else {
			HKEY hackHandle = (HKEY)malloc(sizeof(HKEY));
			*phkResult = hackHandle;
			dummyHandles.insert(hackHandle);
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_FILE_NOT_FOUND);
			return fakeResult;
		}
	}
	return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS APIENTRY RegCloseKeyHook(
	HKEY hKey
) {
	if (checkCaller("RegCloseKey")) {
		Message("[W] RegCloseKey (%p)\n", hKey);

		std::set<HKEY>::iterator it = dummyHandles.find(hKey);

		if (it == dummyHandles.end()) {
			return RegCloseKey(hKey);
		}
		else {
			free(*it);
			dummyHandles.erase(it);
			return ERROR_SUCCESS;
		}
	}
	return RegCloseKey(hKey);
}

LSTATUS APIENTRY RegGetValueAHook(
	HKEY    hkey,
	LPCSTR  lpSubKey,
	LPCSTR  lpValue,
	DWORD   dwFlags,
	LPDWORD pdwType,
	PVOID   pvData,
	LPDWORD pcbData
) {
	if (checkCaller("RegGetValueA")) {

		LSTATUS ori_result = RegGetValueA(hkey, lpSubKey, lpValue, dwFlags,
			pdwType, pvData, pcbData);

		std::string tag = GetTag("RegGetValueA");
		Message("[W] RegGetValueA (%p, %s, %s, %ld, %p, %p, %p) -> tag_out: %s\n", hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData, tag.c_str());

		// If it is not a dummy handle, call concretely
		std::set<HKEY>::iterator it = dummyHandles.find(hkey);

		if (it == dummyHandles.end()) {
			LSTATUS lResult = ori_result;
		}
		// if pvData is NULL and pcbData is non-NULL, the malware is trying to get the size first
		if (pvData == NULL && pcbData != NULL) {
			// We need to consider the malware try to read the register value about vm
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else if (pvData == NULL && pcbData == NULL) {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			S2EMakeSymbolic(pvData, *pcbData, tag.c_str());
			return fakeResult;
		}
	}
	return RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
}

LSTATUS APIENTRY RegGetValueWHook(
	HKEY    hkey,
	LPCWSTR  lpSubKey,
	LPCWSTR  lpValue,
	DWORD   dwFlags,
	LPDWORD pdwType,
	PVOID   pvData,
	LPDWORD pcbData
) {
	if (checkCaller("RegGetValueW")) {

		LSTATUS ori_result = RegGetValueW(hkey, lpSubKey, lpValue, dwFlags,
			pdwType, pvData, pcbData);

		std::string tag = GetTag("RegGetValueW");
		Message("[W] RegGetValueW (%p, %s, %s, %ld, %p, %p, %p) -> tag_out: %s\n", hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData, tag.c_str());
		// If it is not a dummy handle, call concretely
		std::set<HKEY>::iterator it = dummyHandles.find(hkey);

		if (it == dummyHandles.end()) {
			LSTATUS lResult = ori_result;
		}
		// if pvData is NULL and pcbData is non-NULL, the malware is trying to get the size first
		if (pvData == NULL && pcbData != NULL) {
			// We need to consider the malware try to read the register value about vm
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else if (pvData == NULL && pcbData == NULL) {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			S2EMakeSymbolic(pvData, *pcbData, tag.c_str());
			return fakeResult;
		}
	}
	return RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
}

LSTATUS APIENTRY RegQueryValueExAHook(
	HKEY    hKey,
	LPCSTR  lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE  lpData,
	LPDWORD lpcbData
) {
	if (checkCaller("RegQueryValueExA")) {

		LSTATUS ori_result = RegQueryValueExA(hKey, lpValueName,
			lpReserved, lpType, lpData, lpcbData);

		std::string tag = GetTag("RegQueryValueExA");
		Message("[W] RegQueryValueExA (%p, %s, %p, %p, %p, %p) -> tag_out: %s\n", hKey, lpValueName, lpReserved, lpType, lpData, lpcbData, tag.c_str());
		// If it is not a dummy handle, call concretely
		std::set<HKEY>::iterator it = dummyHandles.find(hKey);

		if (it == dummyHandles.end()) {
			LSTATUS lResult = ori_result;
		}
		// if pvData is NULL and pcbData is non-NULL, the malware is trying to get the size first
		if (lpData == NULL && lpcbData != NULL) {
			// We need to consider the malware try to read the register value about vm
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else if (lpData == NULL && lpcbData == NULL) {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			S2EMakeSymbolic(lpData, *lpcbData, tag.c_str());
			return fakeResult;
		}
	}
	return RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

LSTATUS APIENTRY RegQueryValueExWHook(
	HKEY    hKey,
	LPCWSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE  lpData,
	LPDWORD lpcbData
) {
	if (checkCaller("RegQueryValueExW")) {

		LSTATUS ori_result = RegQueryValueExW(hKey, lpValueName,
			lpReserved, lpType, lpData, lpcbData);

		std::string tag = GetTag("RegQueryValueExW");
		Message("[W] RegQueryValueExA (%p, %s, %p, %p, %p, %p) -> tag_out: %s\n", hKey, lpValueName, lpReserved, lpType, lpData, lpcbData, tag.c_str());
		// If it is not a dummy handle, call concretely
		std::set<HKEY>::iterator it = dummyHandles.find(hKey);

		if (it == dummyHandles.end()) {
			LSTATUS lResult = ori_result;
		}
		// if pvData is NULL and pcbData is non-NULL, the malware is trying to get the size first
		if (lpData == NULL && lpcbData != NULL) {
			// We need to consider the malware try to read the register value about vm
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else if (lpData == NULL && lpcbData == NULL) {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			return fakeResult;
		}
		else {
			LSTATUS fakeResult = S2ESymbolicInt(tag.c_str(), ERROR_SUCCESS);
			S2EMakeSymbolic(lpData, *lpcbData, tag.c_str());
			return fakeResult;
		}
	}
	return RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}