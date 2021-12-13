#pragma once
#include <Shlwapi.h>

PCSTR STDAPICALLTYPE StrStrAHook(PCSTR pszFirst,PCSTR pszSrch);
PCWSTR STDAPICALLTYPE StrStrWHook(PCWSTR pszFirst, PCWSTR pszSrch);
PCSTR STDAPICALLTYPE StrStrIAHook(PCSTR pszFirst, PCSTR pszSrch);
PCWSTR STDAPICALLTYPE StrStrIWHook(PCWSTR pszFirst, PCWSTR pszSrch);
