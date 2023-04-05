#define USER_APP 1

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shellapi.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <s2e/s2e.h>

//typedef int (WINAPI *CallDLL)(
//    LPWSTR lpwCfgFile
//);

typedef int (WINAPI *CallDLL)(
);

// DuplicateToMultiByte takes a tstring parameter and always returns
// a pointer to a duplicate ansi string.  If nBufferSize is zero,
// the buffer length is the exact size of the string plus the
// terminating null.  If nBufferSize is nonzero, the buffer length
// is equal to nBufferSize.  As with strdup, free should be called
// for the returned string when it is no longer needed.
LPSTR DuplicateToMultiByte(LPCWSTR lpwString, size_t nBufferSize)
{
    LPSTR lpString;
    size_t nStrLen;

    nStrLen = wcslen(lpwString) + 1;
    if (nBufferSize == 0) nBufferSize = nStrLen;

    lpString = (LPSTR)malloc(nBufferSize);
    WideCharToMultiByte(0,0,lpwString,nStrLen,lpString,nBufferSize,0,0);

    return lpString;
}


int WINAPI WinMain(
	HINSTANCE hInstance, 
	HINSTANCE hPrevInstance, 
    	LPSTR lpCmdLine, 
	int nCmdShow)
{
    int nArgs,i,nRetVal;
    LPWSTR *szArglist, lpwDLLname, lpwFuncName, lpwConfigFile, lpwSymbolic;
    LPSTR lpDLLname, lpFuncName;
    size_t nStrLen;
    LPCWSTR CommandLinePtr;
    HMODULE hDLL;
    CallDLL calldll;

    szArglist = CommandLineToArgvW(GetCommandLineW(),&nArgs);

    //Processing Arg1 - the DLL to be loaded
    szArglist++;
    lpwDLLname = *szArglist;

    //Processing Arg2 - the export function from the DLL to be executed
    szArglist++;
    lpwFuncName = *szArglist;

    //Processing Arg3 - if use the symbolic argumnets or not
    szArglist++;
    lpwSymbolic = *szArglist;

    //Convert DLL name to non UNICODE
    nStrLen = wcslen(lpwDLLname);
    lpDLLname = DuplicateToMultiByte(lpwDLLname,nStrLen+2); 

    //Load the DLL
    hDLL = LoadLibraryA(lpDLLname);
    if (!hDLL) {
        DWORD err = GetLastError();
    }
    else {
        //Convert export func name to non-UNICODE
        nStrLen = wcslen(lpwFuncName);
        lpFuncName = DuplicateToMultiByte(lpwFuncName,nStrLen+2);
        calldll = (CallDLL)GetProcAddress(hDLL, lpFuncName);	
        if (!calldll) {
            S2EMessageFmt("ERROR: Failed to load function Crash\n");
        }
	    else {
            S2EMessageFmt("Calling DLL function...\n", lpFuncName);

            if (wcscmp(lpwSymbolic, L"--symbArgs") == 0) {
                int arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10 = 0;
                S2EMakeSymbolic(&arg1, 4, "arg1");
                S2EMakeSymbolic(&arg2, 4, "arg2");
                S2EMakeSymbolic(&arg3, 4, "arg3");
                S2EMakeSymbolic(&arg4, 4, "arg4");
                S2EMakeSymbolic(&arg5, 4, "arg5");
                S2EMakeSymbolic(&arg6, 4, "arg6");
                S2EMakeSymbolic(&arg7, 4, "arg7");
                S2EMakeSymbolic(&arg8, 4, "arg8");
                S2EMakeSymbolic(&arg9, 4, "arg9");
                S2EMakeSymbolic(&arg10, 4, "arg10");
                calldll(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
            }
            else {
                nRetVal = calldll();
            }
	        
	    }	
    }

    return 0;
}
