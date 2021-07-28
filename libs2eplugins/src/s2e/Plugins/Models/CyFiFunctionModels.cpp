#include <s2e/cpu.h>
#include <s2e/function_models/cyfi_commands.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>

#include <klee/util/ExprTemplates.h>
#include <llvm/Support/CommandLine.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <algorithm>
#include <iostream>

#include "CyFiFunctionModels.h"
using namespace klee;

namespace s2e {
namespace plugins {
namespace models {

S2E_DEFINE_PLUGIN(CyFiFunctionModels, "Plugin that implements CYFI models for libraries", "", "MemUtils");

void CyFiFunctionModels::initialize() {
    m_memutils = s2e()->getPlugin<MemUtils>();
    ins_tracker = (bool) s2e()->getConfig()->getInt(getConfigKey() + ".instructionTracker");
    func_tracker = (bool) s2e()->getConfig()->getInt(getConfigKey() + ".functionTracker");

    //if (ins_tracker) {
        // This indicates that our plugin is interested in monitoring instruction translation.
        // For this, the plugin registers a callback with the onTranslateInstruction signal.
    s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(
        sigc::mem_fun(*this, &CyFiFunctionModels::onTranslateInstruction));

    //s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
    //    sigc::mem_fun(*this, &CyFiFunctionModels::onTranslateSpecialInstEnd));        
    //}
    // Get an instance of the FunctionMonitor plugin
    /*FunctionMonitor *monitor = s2e()->getPlugin<FunctionMonitor>();

    // Get a notification when a function is called
    monitor->onCall.connect(sigc::mem_fun(*this, &CyFiFunctionModels::onCall));*/
    
}


void CyFiFunctionModels::onTranslateInstruction(ExecutionSignal *signal,
                                                S2EExecutionState *state,
                                                TranslationBlock *tb,
                                                uint64_t pc) {
    // Fix how it reads from the lua...it always reads 0                                                    
    if ((pc >= 0x401af0 && pc <= 0x401cee) || (pc == 0x401d36) || (pc >= 0x4010a0 && pc <= 0x40123d) || (pc >= 0x40112e && pc <= 0x401187) || (pc >= 0x401310 && pc <= 0x401333)) {
        // When we find an interesting address, ask S2E to invoke our callback when the address is actually
        // executed
        signal->connect(sigc::mem_fun(*this, &CyFiFunctionModels::onInstructionExecution));
    }
}

// This callback is called only when the instruction at our address is executed.
// The callback incurs zero overhead for all other instructions
void CyFiFunctionModels::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {

    s2e()->getDebugStream() << "Executing instruction at " << hexval(pc) <<  '\n';
    //if((pc >= 0x401af0 && pc <= 0x401c90) || (pc >= 0x4010a0 && pc <= 0x4011a0) || pc == 401190) {
    if(pc == 401190) {

        uint64_t   eax, edx;
        bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
        //bool ok = state->regs()->read(CPU_OFFSET(regs[R_EBX]), &ebx, sizeof(ebx));
        //ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &ecx, sizeof(ecx));
        ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &edx, sizeof(edx));
       


        if (!ok) {
            getWarningsStream(state) << "couldn't read\n";
            return;
        }
        ref<Expr> data = state->mem()->read(eax, state->getPointerWidth());
        if(!data.isNull()) {
            if (!isa<ConstantExpr>(data)) {
                getDebugStream(state) << "EAX " << data << " at " << hexval(eax) << " is symbolic.\n";
            } else {
                getDebugStream(state) << "EAX " << data << " at " << hexval(eax) << " is concrete.\n";
            }
        }
        /*
        ref<Expr> data = state->mem()->read(ebx, state->getPointerWidth());        
        if(!data.isNull()) {
            if (!isa<ConstantExpr>(data)) {
                getDebugStream(state) << "EBX " << data << " at " << hexval(ebx) << " is symbolic.\n";
            } else {
                getDebugStream(state) << "EBX " << data << " at " << hexval(ebx) << " is concrete.\n";
            }
        }           

        data = state->mem()->read(ecx, state->getPointerWidth());    
        if(!data.isNull()) {
            if (!isa<ConstantExpr>(data)) {
                getDebugStream(state) << "ECX " << data << " at " << hexval(ecx) << " is symbolic.\n";
            } else {
                getDebugStream(state) << "ECX " << data << " at " << hexval(ecx) << " is concrete.\n";
            }
        }

        data = state->mem()->read(cl, state->getPointerWidth());    
        if(!data.isNull()) {
            if (!isa<ConstantExpr>(data)) {
                getDebugStream(state) << "CL " << data << " at " << hexval(cl) << " is symbolic.\n";
            } else {
                getDebugStream(state) << "CL " << data << " at " << hexval(cl) << " is concrete.\n";
            }
        }        */
        

        //std::string nameStr = "<NO NAME>";
        //if (ecx && !state->mem()->readString(ecx, nameStr)) {
        //    getWarningsStream(state) << "Error reading string from the guest\n";
        //}
        //getInfoStream() << "SymbExpression " << nameStr << '\n';

        data = state->mem()->read(edx, state->getPointerWidth());
        if(!data.isNull()) {
            if (!isa<ConstantExpr>(data)) {
                getDebugStream(state) << "EDX " << data << " at " << hexval(edx) << " is symbolic.\n";
            } else {
                getDebugStream(state) << "EDX " << data << " at " << hexval(edx) << " is concrete.\n";
            }
        }   


           
    }

}

void CyFiFunctionModels::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                     const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                     const FunctionMonitor::ReturnSignalPtr &returnSignal) {
    // Filter out functions we don't care about
    if (state->regs()->getPc() != 0x401af0) {
        return;
    }

    // If you do not want to track returns, do not connect a return signal.
    // Here, we pass the program counter to the return handler to identify the function
    // from which execution returns.
    returnSignal->connect(
        sigc::bind(sigc::mem_fun(*this, &CyFiFunctionModels::onRet), 0x401af0));
}

void CyFiFunctionModels::onRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                    const ModuleDescriptorConstPtr &dest, uint64_t returnSite,
                    uint64_t functionPc) {
    getDebugStream(state) << "Execution returned from function " << hexval(functionPc) << "\n";
}




void CyFiFunctionModels::handleStrlen(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t stringAddr = (uint64_t) cmd.Strlen.str;

    // Assemble the string length expression
    size_t len;
    if (strlenHelper(state, stringAddr, len, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void CyFiFunctionModels::handleStrcmp(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strcmp.str1;
    stringAddrs[1] = (uint64_t) cmd.Strcmp.str2;

    // Assemble the string compare expression
    if (strcmpHelper(state, stringAddrs, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void CyFiFunctionModels::handleStrncmp(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strncmp.str1;
    stringAddrs[1] = (uint64_t) cmd.Strncmp.str2;
    size_t nSize = cmd.Strncmp.n;

    // Assemble the string compare expression
    if (strncmpHelper(state, stringAddrs, nSize, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void CyFiFunctionModels::handleStrcpy(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strcpy.dst;
    stringAddrs[1] = (uint64_t) cmd.Strcpy.src;

    // Perform the string copy. We don't use the return expression here because it is just a concrete address
    ref<Expr> retExpr;
    if (strcpyHelper(state, stringAddrs, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void CyFiFunctionModels::handleStrncpy(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strncpy.dst;
    stringAddrs[1] = (uint64_t) cmd.Strncpy.src;
    uint64_t numBytes = cmd.Strncpy.n;

    // Perform the string copy. We don't use the return expression here because it is just a concrete address
    ref<Expr> retExpr;
    if (strncpyHelper(state, stringAddrs, numBytes, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void CyFiFunctionModels::handleMemcpy(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t memAddrs[2];
    memAddrs[0] = (uint64_t) cmd.Memcpy.dst;
    memAddrs[1] = (uint64_t) cmd.Memcpy.src;
    uint64_t numBytes = (int) cmd.Memcpy.n;

    ref<Expr> data = state->mem()->read(memAddrs[1], state->getPointerWidth());
    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            getDebugStream(state) << "Argument " << data << " at " << hexval(memAddrs[1]) << " is symbolic\n";
            cmd.Memcpy.symbolic = true;
        } else {
            cmd.Memcpy.symbolic = false;
        }
    }
    
    // Perform the memory copy. We don't use the return expression here because it is just a concrete address
    ref<Expr> retExpr;
     if (memcpyHelper(state, memAddrs, numBytes, retExpr)){
        cmd.needOrigFunc = 0;
    } else {
        if (cmd.Memcpy.symbolic) {
            cmd.needOrigFunc = 0;
        } else {
            cmd.needOrigFunc = 1;
        }
    }


}

void CyFiFunctionModels::handleMemcmp(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t memAddrs[2];
    memAddrs[0] = (uint64_t) cmd.Memcmp.str1;
    memAddrs[1] = (uint64_t) cmd.Memcmp.str2;
    uint64_t numBytes = (int) cmd.Memcmp.n;

    // Assemble the memory compare expression
    if (memcmpHelper(state, memAddrs, numBytes, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void CyFiFunctionModels::handleMemset(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t memAddrs[2];
    memAddrs[0] = (uint64_t) cmd.Memset.ptr;
    memAddrs[1] = (uint64_t) cmd.Memset.value;
    uint64_t numBytes = (int) cmd.Memset.num;
    
    ref<Expr> retExpr;
    if (memsetHelper(state, memAddrs, numBytes, retExpr)){
        ref<Expr> data = state->mem()->read(memAddrs[0], state->getPointerWidth());
        if(!data.isNull()) {
            if (!isa<ConstantExpr>(data)) {
                getDebugStream(state) << "Argument " << data << " at " << hexval(memAddrs[0]) << " is symbolic\n";
                cmd.Memset.symbolic = true;
            } else {
                cmd.Memset.symbolic = false;
            }
        }
    }
}

void CyFiFunctionModels::handleStrcat(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strcat.dst;
    stringAddrs[1] = (uint64_t) cmd.Strcat.src;

    // Assemble the string concatenation expression. We don't use the return expression here because it is just a
    // concrete address
    ref<Expr> retExpr;
    if (strcatHelper(state, stringAddrs, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void CyFiFunctionModels::handleStrncat(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strncat.dst;
    stringAddrs[1] = (uint64_t) cmd.Strncat.src;
    uint64_t numBytes = (int) cmd.Strncat.n;

    // Assemble the string concatenation expression. We don't use the return expression here because it is just a
    // concrete address
    ref<Expr> retExpr;
    if (strcatHelper(state, stringAddrs, retExpr, true, numBytes)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void CyFiFunctionModels::handleStrStrA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.StrStrA.pszFirst;
    stringAddrs[1] = (uint64_t) cmd.StrStrA.pszSrch;

    if (StrStrAHelper(state, stringAddrs, retExpr)) {
        cmd.StrStrA.symbolic = true;
    } else {
        cmd.StrStrA.symbolic = false;
    }
}

void CyFiFunctionModels::handleLstrlenA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t stringAddr = (uint64_t) cmd.Strlen.str;
    getDebugStream(state) << "Handling LstrlenA.\n";

    ref<Expr> data = state->mem()->read(stringAddr, state->getPointerWidth());
    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            getDebugStream(state) << "Argument " << data << " at " << hexval(stringAddr) << " is symbolic.\n";
            cmd.LstrlenA.symbolic = true;
        } else {
            getDebugStream(state) << "Argument " << data << " at " << hexval(stringAddr) << " is concrete.\n";
            cmd.LstrlenA.symbolic = false;
        }
    }
}

void CyFiFunctionModels::handleWinHttpReadData(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t args[4];
    args[0] = (uint64_t) cmd.WinHttpReadData.hRequest;
    args[1] = (uint64_t) cmd.WinHttpReadData.lpBuffer;
    args[2] = (uint64_t) cmd.WinHttpReadData.dwNumberOfBytesToRead;
    args[3] = (uint64_t) cmd.WinHttpReadData.lpdwNumberOfBytesRead;

    WinHttpReadDataHelper(state, args, retExpr);
}

void CyFiFunctionModels::handleWinHttpCrackUrl(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t args[4];
    args[0] = (uint64_t) cmd.WinHttpCrackUrl.pwszUrl;
    args[1] = (uint64_t) cmd.WinHttpCrackUrl.dwUrlLength;
    args[2] = (uint64_t) cmd.WinHttpCrackUrl.dwFlags;
    args[3] = (uint64_t) cmd.WinHttpCrackUrl.lpUrlComponents;

    getDebugStream(state) << "Handling WinHttpCrackUrl.\n";

    ref<Expr> data = state->mem()->read(args[0], state->getPointerWidth());
    //getDebugStream(state) << "testa " << data << " at " << hexval(args[0]) << " is symbolic\n";

    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            getDebugStream(state) << "Argument " << data << " at " << hexval(args[0]) << " is symbolic\n";
            cmd.WinHttpCrackUrl.symbolic = true;
        } else {
            getDebugStream(state) << "Argument " << data << " at " << hexval(args[0]) << " is concrete\n";
            cmd.WinHttpCrackUrl.symbolic = false;
        }
    }
}

void CyFiFunctionModels::handleMultiByteToWideChar(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t args[6];
    args[0] = (uint64_t) cmd.MultiByteToWideChar.CodePage;
    args[1] = (uint64_t) cmd.MultiByteToWideChar.dwFlags;
    args[2] = (uint64_t) cmd.MultiByteToWideChar.lpMultiByteStr;
    args[3] = cmd.MultiByteToWideChar.cbMultiByte;
    args[4] = (uint64_t) cmd.MultiByteToWideChar.lpWideCharStr;
    args[5] = cmd.MultiByteToWideChar.ccWideChar;

   if (MultiByteToWideCharHelper(state, args)){

       for (int i = 0; i < 10; i++) {
            ref<Expr> data = state->mem()->read(args[2]+i, state->getPointerWidth());
            if(!data.isNull()) {
                if (!isa<ConstantExpr>(data)) {
                    getDebugStream(state) << "Argument " << data << " at " << hexval(args[2]+i) << " is symbolic\n";
                    cmd.MultiByteToWideChar.symbolic = true;
                } else {
                    getDebugStream(state) << "Argument " << data << " at " << hexval(args[2]+i) << " is concrete\n";
                    cmd.MultiByteToWideChar.symbolic = false;
                }
            }
       }
    }
}

void CyFiFunctionModels::handleCrc(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &ret) {

    std::vector<ref<Expr>> buffer;
    cmd.needOrigFunc = 1;
    if (!m_memutils->read(state, buffer, cmd.Crc.buffer, cmd.Crc.size)) {
        return;
    }

    ref<Expr> initialCrc;

    switch (cmd.Crc.type) {
        case CYFI_WRAPPER_CRC16:
            initialCrc = state->mem()->read(cmd.Crc.initial_value_ptr, Expr::Int16);
            getDebugStream(state) << "Handling crc16(" << initialCrc << ", " << hexval(cmd.Crc.buffer) << ", "
                                  << cmd.Crc.size << ")\n";
            if (initialCrc.isNull()) {
                return;
            }

            ret = crc16(initialCrc, buffer);
            break;

        case CYFI_WRAPPER_CRC32:
            initialCrc = state->mem()->read(cmd.Crc.initial_value_ptr, Expr::Int32);
            getDebugStream(state) << "Handling crc32(" << initialCrc << ", " << hexval(cmd.Crc.buffer) << ", "
                                  << cmd.Crc.size << ")\n";
            if (initialCrc.isNull()) {
                return;
            }

            ret = crc32(initialCrc, buffer, cmd.Crc.xor_result);
            break;

        default:
            s2e()->getWarningsStream(state) << "Invalid crc type " << hexval(cmd.Crc.type) << "\n";
            return;
    }

    cmd.needOrigFunc = 0;
}


// TODO: use template
#define UPDATE_RET_VAL(CmdType, cmd)                                         \
    do {                                                                     \
        uint32_t offRet = offsetof(CYFI_WINWRAPPER_COMMAND, CmdType.ret);    \
                                                                             \
        if (!state->mem()->write(guestDataPtr, &cmd, sizeof(cmd))) {         \
            getWarningsStream(state) << "Could not write to guest memory\n"; \
        }                                                                    \
                                                                             \
        if (!state->mem()->write(guestDataPtr + offRet, retExpr)) {          \
            getWarningsStream(state) << "Could not write to guest memory\n"; \
        }                                                                    \
    } while (0)

void CyFiFunctionModels::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    CYFI_WINWRAPPER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "CYFI_WINWRAPPER_COMMAND: "
                                 << "mismatched command structure size " << guestDataSize << " " << sizeof(command) << "\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "CYFI_WINWRAPPER_COMMAND: could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {

        case WINWRAPPER_STRCPY: {
            handleStrcpy(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_STRNCPY: {
            handleStrncpy(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_STRLEN: {
            ref<Expr> retExpr;
            handleStrlen(state, command, retExpr);
            UPDATE_RET_VAL(Strlen, command);
        } break;

        case WINWRAPPER_STRCMP: {
            ref<Expr> retExpr;
            handleStrcmp(state, command, retExpr);
            UPDATE_RET_VAL(Strcmp, command);
        } break;

        case WINWRAPPER_STRNCMP: {
            ref<Expr> retExpr;
            handleStrncmp(state, command, retExpr);
            UPDATE_RET_VAL(Strncmp, command);
        } break;

        case WINWRAPPER_MEMCPY: {
            handleMemcpy(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "MEMCPY: Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_MEMCMP: {
            ref<Expr> retExpr;
            handleMemcmp(state, command, retExpr);
            UPDATE_RET_VAL(Memcmp, command);
        } break;

        case WINWRAPPER_MEMSET: {
            handleMemset(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "MEMSET: Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_STRCAT: {
            handleStrcat(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "STRCAT: Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_STRNCAT: {
            handleStrncat(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "STRNCAT: Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_STRSTRA: {
            ref<Expr> retExpr;
            handleStrStrA(state, command, retExpr);
            //if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
            //    getWarningsStream(state) << "Could not find substring\n";
            //}
            //else {
            UPDATE_RET_VAL(StrStrA, command);
            //}
        } break;        

        case WINWRAPPER_WINHTTPCRACKURL: {
            ref<Expr> retExpr;
            handleWinHttpCrackUrl(state, command, retExpr);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "WinHttpCrackUrl: Could not write to guest memory\n";
            }
        } break;  

        case WINWRAPPER_LSTRLENA: {
            ref<Expr> retExpr;
            handleLstrlenA(state, command, retExpr);
            //UPDATE_RET_VAL(Strlen, command);
        } break;

        case WINWRAPPER_MULTIBYTETOWIDECHAR: {
            handleMultiByteToWideChar(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "MultiByteToWideChar: Could not write to guest memory\n";
            }
        } break;

        case WRAPPER_CRC: {
            ref<Expr> retExpr;
            handleCrc(state, command, retExpr);
            UPDATE_RET_VAL(Crc, command);
        } break;

        default: {
            getWarningsStream(state) << "Invalid command " << hexval(command.Command) << "\n";
            exit(-1);
        }
    }
}

} // namespace models
} // namespace plugins
} // namespace s2e
