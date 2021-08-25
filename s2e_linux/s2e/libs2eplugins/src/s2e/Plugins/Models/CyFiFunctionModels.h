

#ifndef S2E_PLUGINS_CYFI_FUNCTION_MODELS_H
#define S2E_PLUGINS_CYFI_FUNCTION_MODELS_H

#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>

#include "BaseFunctionModels.h"
#include <string>

struct CYFI_WINWRAPPER_COMMAND;

namespace s2e {

class S2E;
class S2EExecutionState;
class ModuleMap;


namespace plugins {
namespace models {

class CyFiFunctionModels : public BaseFunctionModels, public IPluginInvoker {
    S2E_PLUGIN

public:
    CyFiFunctionModels(S2E *s2e) : BaseFunctionModels(s2e) {
    }

   
    void initialize();


    void onTranslateInstruction(ExecutionSignal *signal,
                                S2EExecutionState *state,
                                TranslationBlock *tb,
                                uint64_t pc);

    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);

    std::string getTag(const std::string &sym);


    void onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                        const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                        const FunctionMonitor::ReturnSignalPtr &returnSignal);

    void onRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                        const ModuleDescriptorConstPtr &dest, uint64_t returnSite,
                        uint64_t functionPc);

    void cyfiDump(S2EExecutionState *state, std::string reg);

private:

    bool ins_tracker; 
    bool func_tracker;
    ModuleMap *m_map;


    void handleStrlen(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrcmp(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrncmp(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrcpy(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleStrncpy(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleMemcpy(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleMemcmp(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrcat(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleStrncat(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void handleMemset(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void handleStrStrA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrStrW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleWinHttpReadData(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd,  klee::ref<klee::Expr> &expr);
    void handleWinHttpWriteData(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &retExpr);

    void handleWinHttpCrackUrl(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd,  klee::ref<klee::Expr> &expr);
    void handleWinHttpConnect(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void handleMultiByteToWideChar(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void handleWcsstr(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);


    void handleInternetCrackUrlA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd,  klee::ref<klee::Expr> &expr);
    void handleInternetConnectA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleInternetConnectW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleInternetReadFile(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd); 
    void handleCrc(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &ret);
    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace models
} // namespace plugins
} // namespace s2e

#endif
