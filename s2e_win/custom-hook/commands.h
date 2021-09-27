
#ifndef S2E_CYFI_FUNCTION_MODEL_COMMANDS_H
#define S2E_CYFI_FUNCTION_MODEL_COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

    // TODO replace this with a stack frame bound, check for mapped memory page, ...
    static const unsigned MAX_STRLEN = 4096;

    enum CYFI_WINWRAPPER_COMMANDS {
        WINWRAPPER_STRCPY,
        WINWRAPPER_STRNCPY,
        WINWRAPPER_STRLEN,
        WINWRAPPER_STRCMP,
        WINWRAPPER_STRNCMP,
        WINWRAPPER_MEMCPY,
        WINWRAPPER_MEMCMP,
        WINWRAPPER_STRCAT,
        WINWRAPPER_STRNCAT,

        WINWRAPPER_MEMSET,

        WINWRAPPER_STRSTRA,
        WINWRAPPER_STRSTRW,
        WINWRAPPER_STRSTR,
        WINWRAPPER_STRTOK,

        WINWRAPPER_WINHTTPREADDATA,
        WINWRAPPER_WINHTTPCRACKURL,
        WINWRAPPER_WINHTTPCONNECT,
        WINWRAPPER_WINHTTPWRITEDATA,

        WINWRAPPER_INTERNETREADFILE,
        WINWRAPPER_INTERNETCRACKURLA,
        WINWRAPPER_INTERNETCRACKURLW,
        WINWRAPPER_INTERNETCONNECTA,
        WINWRAPPER_INTERNETCONNECTW,
        WINWRAPPER_INTERNETOPENURLA,
        WINWRAPPER_INTERNETOPENURLW,

        WINWRAPPER_WRITEFILE,

        WINWRAPPER_WCSSTR,

        WRAPPER_CRC,

        CHECK_CALLER,

        TAG_COUNTER,

        KILL_ANALYSIS,
    };

    struct CYFI_WINWRAPPER_COMMAND_STRCPY {
        uint64_t dst;
        uint64_t src;
        uint64_t ret;
    };

    struct CYFI_WINWRAPPER_COMMAND_STRNCPY {
        uint64_t dst;
        uint64_t src;
        uint64_t n;
        uint64_t ret;
    };

    struct CYFI_WINWRAPPER_COMMAND_STRLEN {
        uint64_t str;
        size_t ret;
    };

    struct CYFI_WINWRAPPER_COMMAND_STRCMP {
        uint64_t str1;
        uint64_t str2;
        int ret;
    };

    struct CYFI_WINWRAPPER_COMMAND_STRNCMP {
        uint64_t str1;
        uint64_t str2;
        uint64_t n;
        int ret;
    };

    struct CYFI_WINWRAPPER_COMMAND_MEMCPY {
        uint64_t dst;
        uint64_t src;
        uint64_t n;
        uint64_t ret;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_MEMCMP {
        uint64_t str1;
        uint64_t str2;
        uint64_t n;
        int ret;
    };

    struct CYFI_WINWRAPPER_COMMAND_MEMSET {
        uint64_t ptr;
        int value;
        uint64_t num;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_STRCAT {
        uint64_t dst;
        uint64_t src;
        uint64_t ret;
    };

    struct CYFI_WINWRAPPER_COMMAND_STRNCAT {
        uint64_t dst;
        uint64_t src;
        uint64_t n;
        uint64_t ret;
    };

    struct CYFI_WINWRAPPER_COMMAND_STRSTRA {
        uint64_t pszFirst;
        uint64_t pszSrch;
        uint64_t symbTag;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_STRSTR {
        uint64_t str;
        uint64_t strSearch;
        uint64_t symbTag;

    };

    struct CYFI_WINWRAPPER_COMMAND_STRTOK {
        uint64_t strToken;
        uint64_t strDelimit;
        uint64_t symbTag;

    };
    struct CYFI_WINWRAPPER_COMMAND_STRSTRW {
        uint64_t pszFirst;
        uint64_t pszSrch;
        uint64_t symbTag;
        

    };

    struct CYFI_WINWRAPPER_COMMAND_INTERNETREADFILE {
        uint64_t hFile;
        uint64_t lpBuffer;
        uint64_t dwNumberOfBytesToRead;
        uint64_t lpdwNumberOfBytesRead;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_INTERNETCRACKURLA {
        uint64_t lpszUrl;
        uint64_t dwUrlLength;
        uint64_t dwFlags;
        uint64_t lpUrlComponents;
        uint64_t symbTag;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_INTERNETCRACKURLW {
        uint64_t lpszUrl;
        uint64_t dwUrlLength;
        uint64_t dwFlags;
        uint64_t lpUrlComponents;
        uint64_t symbTag;
    };

    struct CYFI_WINWRAPPER_COMMAND_INTERNETCONNECTA {
        uint64_t    hInternet;
        uint64_t    lpszServerName;
        uint64_t    nServerPort;
        uint64_t    lpszUserName;
        uint64_t    lpszPassword;
        uint64_t    dwService;
        uint64_t    dwFlags;
        uint64_t    dwContext;
        uint64_t symbTag;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_INTERNETCONNECTW {
        uint64_t    hInternet;
        uint64_t    lpszServerName;
        uint64_t    nServerPort;
        uint64_t    lpszUserName;
        uint64_t    lpszPassword;
        uint64_t    dwService;
        uint64_t    dwFlags;
        uint64_t    dwContext;
        uint64_t symbTag;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_INTERNETOPENURLA {
        uint64_t hInternet;
        uint64_t lpszUrl;
        uint64_t lpszHeaders;
        uint64_t dwHeadersLength;
        uint64_t dwFlags;
        uint64_t dwContext;
        uint64_t symbTag;
    };

    struct CYFI_WINWRAPPER_COMMAND_INTERNETOPENURLW {
        uint64_t hInternet;
        uint64_t lpszUrl;
        uint64_t lpszHeaders;
        uint64_t dwHeadersLength;
        uint64_t dwFlags;
        uint64_t dwContext;
        uint64_t symbTag;
    };

    struct CYFI_WINWRAPPER_COMMAND_WINHTTPREADDATA {
        uint64_t hRequest;
        uint64_t lpBuffer;
        uint64_t dwNumberOfBytesToRead;
        uint64_t lpdwNumberOfBytesRead;
    };

    struct CYFI_WINWRAPPER_COMMAND_WINHTTPCRACKURL {
        uint64_t pwszUrl;
        uint64_t dwUrlLength;
        uint64_t dwFlags;
        uint64_t lpUrlComponents;
        uint64_t symbTag;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_WINHTTPCONNECT {
        uint64_t hSession;
        uint64_t pswzServerName;
        uint64_t nServerPort;
        uint64_t dwReserved;
        uint64_t symbTag;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_WINHTTPWRITEDATA {
        uint64_t hRequest;
        uint64_t lpBuffer;
        uint64_t dwNumberOfBytesToWrite;
        uint64_t lpdwNumberOfBytesWritten;
    };

    struct CYFI_WINWRAPPER_COMMAND_WCSSTR {
        uint64_t str;
        uint64_t strSearch;
        uint64_t symbTag;
        
    };

    struct CYFI_WINWRAPPER_COMMAND_WRITEFILE {
        uint64_t lpBuffer;
        uint64_t symbTag;
    };

    enum CYFI_WRAPPER_CRC_TYPE { CYFI_WRAPPER_CRC16, CYFI_WRAPPER_CRC32 };

    struct CYFI_WRAPPER_COMMAND_CRC {
        enum CYFI_WRAPPER_CRC_TYPE type;
        // Pointer to the initial CRC value
        uint64_t initial_value_ptr;
        uint64_t xor_result;
        uint64_t buffer;
        uint64_t size;
        uint64_t ret;
    };

    struct CYFI_CHECK_CALLER {
        uint64_t funcName;
        bool isTargetModule;
    };

    struct CYFI_TAG_COUNTER {
        int counter;
    };

    struct CYFI_KILL_ANALYSIS {
        uint64_t funcName;
    };

    struct CYFI_WINWRAPPER_COMMAND {
        enum CYFI_WINWRAPPER_COMMANDS Command;
        union {
            struct CYFI_WINWRAPPER_COMMAND_STRCPY Strcpy;
            struct CYFI_WINWRAPPER_COMMAND_STRNCPY Strncpy;
            struct CYFI_WINWRAPPER_COMMAND_STRLEN Strlen;
            struct CYFI_WINWRAPPER_COMMAND_STRCMP Strcmp;
            struct CYFI_WINWRAPPER_COMMAND_STRNCMP Strncmp;
            struct CYFI_WINWRAPPER_COMMAND_MEMCPY Memcpy;
            struct CYFI_WINWRAPPER_COMMAND_MEMCMP Memcmp;
            struct CYFI_WINWRAPPER_COMMAND_STRCAT Strcat;
            struct CYFI_WINWRAPPER_COMMAND_STRNCAT Strncat;

            struct CYFI_WINWRAPPER_COMMAND_MEMSET Memset;

            struct CYFI_WINWRAPPER_COMMAND_STRSTRA StrStrA;
            struct CYFI_WINWRAPPER_COMMAND_STRSTRW StrStrW;
            struct CYFI_WINWRAPPER_COMMAND_STRSTR strstr;
            struct CYFI_WINWRAPPER_COMMAND_STRTOK strtok;

            struct CYFI_WINWRAPPER_COMMAND_WINHTTPREADDATA WinHttpReadData;
            struct CYFI_WINWRAPPER_COMMAND_WINHTTPCRACKURL WinHttpCrackUrl;
            struct CYFI_WINWRAPPER_COMMAND_WINHTTPCONNECT WinHttpConnect;
            struct CYFI_WINWRAPPER_COMMAND_WINHTTPWRITEDATA WinHttpWriteData;

            struct CYFI_WINWRAPPER_COMMAND_INTERNETREADFILE InternetReadFile;
            struct CYFI_WINWRAPPER_COMMAND_INTERNETCRACKURLA InternetCrackUrlA;
            struct CYFI_WINWRAPPER_COMMAND_INTERNETCRACKURLA InternetCrackUrlW;
            struct CYFI_WINWRAPPER_COMMAND_INTERNETCONNECTA InternetConnectA;
            struct CYFI_WINWRAPPER_COMMAND_INTERNETCONNECTW InternetConnectW;
            struct CYFI_WINWRAPPER_COMMAND_INTERNETOPENURLA InternetOpenUrlA;
            struct CYFI_WINWRAPPER_COMMAND_INTERNETOPENURLW InternetOpenUrlW;

            struct CYFI_WINWRAPPER_COMMAND_WRITEFILE WriteFile;

            struct CYFI_WINWRAPPER_COMMAND_WCSSTR wcsstr;

            struct CYFI_WRAPPER_COMMAND_CRC Crc;

            struct CYFI_CHECK_CALLER CheckCaller;

            struct CYFI_TAG_COUNTER TagCounter;

            struct CYFI_KILL_ANALYSIS KillAnalysis;
        };
        uint64_t needOrigFunc;
    };

#ifdef __cplusplus
}
#endif

#endif
