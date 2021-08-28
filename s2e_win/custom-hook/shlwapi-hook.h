#pragma once
#include <Shlwapi.h>

PCSTR StrStrAHook(PCSTR pszFirst,PCSTR pszSrch);
PCWSTR StrStrWHook(PCWSTR pszFirst, PCWSTR pszSrch);
PCSTR StrStrIAHook(PCSTR pszFirst, PCSTR pszSrch);
PCWSTR StrStrIWHook(PCWSTR pszFirst, PCWSTR pszSrch);
