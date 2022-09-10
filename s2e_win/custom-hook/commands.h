
#ifndef S2E_CYFI_FUNCTION_MODEL_COMMANDS_H
#define S2E_CYFI_FUNCTION_MODEL_COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

    // TODO replace this with a stack frame bound, check for mapped memory page, ...
    static const unsigned MAX_STRLEN = 4096;

    enum CYFI_WINWRAPPER_COMMANDS {
        WINWRAPPER_STRSTRA,
        CHECK_CALLER,
        READ_TAG,
        TAG_COUNTER,
        KILL_ANALYSIS,
        DUMP_EXPRESSION,
        CONCRETIZE_ALL,
        TAG_TRACKER,
        EXPRESSION_DATA,
        TAINT,
        PRINT_MEM
    };

    struct CYFI_WINWRAPPER_COMMAND_STRSTRA {
        uint64_t pszFirst;
        uint64_t pszSrch;
        uint64_t symbTag;

    };

    struct CYFI_CHECK_CALLER {
        uint64_t funcName;
        bool isTargetModule;
    };

    struct CYFI_READ_TAG {
        uint64_t buffer;
        uint64_t symbTag;
    };

    struct CYFI_TAG_COUNTER {
        int counter;
    };

    struct KILL_ANALYSIS {
        uint64_t funcName;
    };

    struct CYFI_DUMP_EXPRESSION {
        uint64_t buffer;
    };

    struct CYFI_CONCRETIZE_ALL {
        uint64_t buffer;
    };

    struct TAG_TRACKER {
        uint64_t tag;
    };

    struct EXPRESSION_DATA {
        uint64_t expr;
        int depth;
        int nodes;
        int kinds;
    };

    struct CYFI_TAINT {
        uint64_t buffer;
        uint64_t size;
        uint64_t tag;
    };

    struct CYFI_PRINT_MEM {
        uint64_t buffer;
        uint64_t size;
        bool remove;
    };


    struct CYFI_WINWRAPPER_COMMAND {
        enum CYFI_WINWRAPPER_COMMANDS Command;
        union {
            struct CYFI_WINWRAPPER_COMMAND_STRSTRA StrStrA;

            struct CYFI_CHECK_CALLER CheckCaller;

            struct CYFI_READ_TAG ReadTag;

            struct CYFI_TAG_COUNTER TagCounter;

            struct KILL_ANALYSIS KillAnalysis;

            struct CYFI_DUMP_EXPRESSION dumpExpression;

            struct CYFI_CONCRETIZE_ALL concretizeAll;

            struct TAG_TRACKER tagTracker;

            struct EXPRESSION_DATA expressionData;

            struct CYFI_TAINT cyfiTaint;

            struct CYFI_PRINT_MEM cyfiPrintMem;
        };
        uint64_t needOrigFunc;
    };

#ifdef __cplusplus
}
#endif

#endif