

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
#include <unordered_map>
#include <map>
#include <vector>
#include <utility>

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


class Decoders {
    public:
        static std::string indexedVal_UC(unsigned char ** data);
        static std::string indexedVal_C(char * data);
        static std::string indexedVal_S(std::string data);
        static std::string indexedVal_V(std::vector<uint8_t> data);

        static std::string base64(const char* in, size_t source_len);
        static std::string xor_23(std::string x);
        static size_t table_lookup(const char* source, size_t source_len, char* dest, size_t dest_capacity, const char* table, size_t table_size);
        static size_t decode_str_to_le_int32(const char* source, size_t source_len, char* dest, size_t dest_capacity);
        static size_t decode_le_int32_to_str(const char* source, size_t source_len, char* dest, size_t dest_capacity);
        static size_t rot_13(const char* source, size_t source_len, char* dest, size_t dest_capacity);
        static int hexchr2bin(const char hex, char* out);
        static size_t base16(const char* hex, unsigned char** out);

        static const void* cyoBase85NextByte(const void* input, unsigned char* byte, int* padding);
        static  unsigned int cyoBase85Power(unsigned int mult, int count);
        static unsigned char* cyoBase85OutputX4(unsigned char* output, char value);    
        static size_t base85(const char* source, size_t source_len, char* dest, size_t dest_capacity);
            
        static std::pair<std::string, std::string> extractBufferComparators(std::string decoder_type, std::vector<uint8_t> all_contants);

    private:
        Decoders() {}

    
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
    void cyfiDump(S2EExecutionState *state, std::string reg);
    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName);

private:

    std::string trackedTag;
    uint64_t trackedPc;

    bool instructionMonitor; 
    int func_to_monitor = 0;
    int arg_dump = 0;
    ModuleMap *m_map;
    LibraryCallMonitor *m_libCallMonitor;
    ProcessExecutionDetector *m_procDetector;
    uint64_t moduleId = 0;

    typedef std::unordered_set<std::string> StringSet;
    StringSet m_moduleNames;
    std::string m_moduleName = "";
    std::unique_ptr<Ranges> m_traceRegions = nullptr;

    std::string recent_callee = "";
    int counter = 0;

    bool decoderSearch;
    std::map< ref<Expr> , std::map< uint64_t, std::vector<std::pair< std::string, std::string> > > > constantMapping;
    typedef std::map<std::string, std::pair<std::string, std::string> > decoderMap;
    typedef std::vector< std::pair< uint64_t,  decoderMap >> memDataVec;
    std::map<int,  memDataVec> instructionMemData;

    Vmi *m_vmi;
    OSMonitor *m_monitor;
    MemUtils *m_memutils;

    void cyfi_equivalence(S2EExecutionState *state, ref<Expr> a, ref<Expr> b, llvm::raw_ostream &os);
    void copy_expression(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void handleStrStrA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    void checkCaller(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void readTag(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void trackModule(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd); 
    void tagCounter(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void killAnalysis(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);

    void dumpExpression(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void tagTracker(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void expressionData(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);
    void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,unsigned flags);

    void onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> address,
                                                   klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value,
                                                   unsigned flags);
    void findBufferByte(ref<Expr> expr, ref<Expr> &index);
    void evalForDecoders(S2EExecutionState *state, klee::ref<klee::Expr> address);    
    void concretizeAll(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd);                                                   
};

} // namespace models
} // namespace plugins
} // namespace s2e

#endif
