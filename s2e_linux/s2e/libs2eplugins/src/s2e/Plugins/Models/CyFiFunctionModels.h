

#ifndef S2E_PLUGINS_CYFI_FUNCTION_MODELS_H
#define S2E_PLUGINS_CYFI_FUNCTION_MODELS_H

#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/ExecutionMonitors/LibraryCallMonitor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include "BaseFunctionModels.h"
#include <string>

struct CYFI_WINWRAPPER_COMMAND;

namespace s2e {

class S2E;
class S2EExecutionState;
class OSMonitor;
class ProcessExecutionDetector;
class ModuleMap;


namespace plugins {
namespace models {


/* Utility class to store a list of uint64_t ranges.
 *
 * Range specifications are of the form "start-end" or "value". Disjoint ranges can be
 * separated using a comma. So an example of a valid range specification could be -
 * "1000-3001,4000,5000-6000"
 * This would create a RangeList that includes the range 1000-3001 (INCLUSIVE), the number
 * 4000, and the range 5000-6000 (INCLUSIVE).
 *
 * Note: This is not the most optimal implementation. The assumption is that the number of
 * disjoint ranges will be quite low. If that assumption is no longer valid, a more optimal
 * datastructure might be required.
 */
class Ranges {
public:
    // Returns a nullptr if the passed string was invalid.
    static std::unique_ptr<Ranges> parse(const std::string& ranges_string);
    // Checks if the provided value is within any specified range.
    bool contains(uint64_t value) const;
    // Recreate the range string (for debugging)
    friend std::ostream& operator<<(std::ostream& os, const Ranges& ranges);

private:
    Ranges() {}
    std::vector<std::pair<uint64_t, uint64_t>> ranges_;
};


class CyFiFunctionModels : public BaseFunctionModels, public IPluginInvoker {
    S2E_PLUGIN

public:
    CyFiFunctionModels(S2E *s2e) : BaseFunctionModels(s2e) {
    }


    void initialize();
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool isStatic, uint64_t staticTarget);
    void onIndirectCallOrJump(S2EExecutionState *state, uint64_t pc, unsigned sourceType);
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
    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName);

private:
    bool instructionMonitor; 
    int func_to_monitor = 0;
    ModuleMap *m_map;
    LibraryCallMonitor *m_libCallMonitor;
    ProcessExecutionDetector *m_procDetector;
    uint64_t moduleId = 0;
    std::string m_moduleName = "";
    std::unique_ptr<Ranges> m_traceRegions = nullptr;

    std::string recent_callee = "";
    int counter = 0;

    Vmi *m_vmi;
    OSMonitor *m_monitor;

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

    void handleStrStrA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleStrStrW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleStrStr(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleStrtok(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);  
    void handleWcsstr(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void handleWinHttpReadData(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd,  klee::ref<klee::Expr> &expr);
    void handleWinHttpWriteData(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &retExpr);
    void handleWinHttpCrackUrl(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd,  klee::ref<klee::Expr> &expr);
    void handleWinHttpConnect(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void handleInternetCrackUrlA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleInternetConnectA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleInternetCrackUrlW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleInternetConnectW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleInternetOpenUrlA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);    
    void handleInternetOpenUrlW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);    
    void handleInternetReadFile(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd); 
    
    void handleWriteFile(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void handleCrc(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &ret);
    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    void checkCaller(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void readTag(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void trackModule(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd); 
    void tagCounter(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void killAnalysis(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void dumpExpression(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void concretizeAll(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
};

} // namespace models
} // namespace plugins
} // namespace s2e

#endif
