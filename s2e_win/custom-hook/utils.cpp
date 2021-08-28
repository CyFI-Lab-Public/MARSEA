#include <stdio.h>
#include <iostream>
#include <string>

#include "utils.h"
#include "commands.h"

// Global tag number
static uint64_t tag_number = 0;

//////////////////////
// Helper functions //
//////////////////////

///
/// Write a message to the S2E log (or stdout).
///
void Message(LPCSTR fmt, ...) {
    CHAR message[S2E_MSG_LEN];
    va_list args;

    va_start(args, fmt);
    int written = vsnprintf(message, S2E_MSG_LEN, fmt, args);
    va_end(args);

    //printf("cyfi debug 1 %s", message);

    if (s2eVersion) {
        S2ECyfiMessageFmt("[0x%x|malware-hook] %s written: %d", GetCurrentProcessId(),
            message, written);
        //S2EMessageFmt("[0x%x|malware-hook] %s", GetCurrentProcessId(),
        //    message);
    }
    else {
        printf("[0x%x|malware-hook] %s", GetCurrentProcessId(), message);
    }
}


///
/// Generate unique tag for each symbolic expression
/// 
std::string GetTag(PCSTR funcName) {
    std::string tag = "CyFi_" + std::string(funcName) + std::to_string(tag_number);
    tag_number += 1;
    return tag;
}

bool checkCaller(std::string funcName) {
    CYFI_WINWRAPPER_COMMAND Command = CYFI_WINWRAPPER_COMMAND();
    Command.Command = CHECK_CALLER;
    Command.CheckCaller.funcName = (uint64_t)funcName.c_str();
    //std::string symbTag = "";
    //Command.CheckCaller.symbTag = (uint64_t)symbTag.c_str();

    //__s2e_touch_string((PCSTR)(UINT_PTR)Command.CheckCaller.symbTag);

    S2EInvokePlugin("CyFiFunctionModels", &Command, sizeof(Command));

    //Message("Tag is: %s\n", Command.CheckCaller.symbTag);

    return Command.CheckCaller.isTargetModule;
}