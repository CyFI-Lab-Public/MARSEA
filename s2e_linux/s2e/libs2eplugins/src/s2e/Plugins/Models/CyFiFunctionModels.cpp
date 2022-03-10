#include <s2e/cpu.h>
#include <s2e/function_models/cyfi_commands.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/Searchers/MergingSearcher.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include <klee/util/ExprTemplates.h>
#include <klee/util/ExprUtil.h>

#include <llvm/Support/CommandLine.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <optional>
#include <vector>
#include <utility>
#include <list>
#include <queue>


#include "CyFiFunctionModels.h"

using namespace klee;

namespace s2e {
namespace plugins {
namespace models {

#define PRINT_DOT_GRAPH 1

static constexpr size_t countExprNumBytes = 1;
static bool export_to_s_expr = false;
static std::string dot_graph_name;
static std::string dot_graph_path;
static std::string s_expr_path;

static std::unordered_map<Expr::Kind, double> countExprKinds(const ref<Expr>& data, size_t num_bytes) {
    std::unordered_map<Expr::Kind, double> expr_kind_counts;
    std::function<void(ref<Expr>)> recur = nullptr;
    recur = [&recur, &expr_kind_counts](ref<Expr> node) {
        if (!node.isNull()) {
            expr_kind_counts[node->getKind()] += 1.0;
            for (int i = 0; i < node->getNumKids(); ++i) {
                recur(node->getKid(i));
            }
        }
    };
    recur(data);
    // Divide by num_bytes to get an average
    for (auto it : expr_kind_counts) {
        it.second /= num_bytes;
    }
    return expr_kind_counts;
}

static llvm::raw_ostream& operator<<(llvm::raw_ostream& os, const std::unordered_map<Expr::Kind, double>& data) {
    os << "expr_kind_counts: {\n";
    for (const auto& it : data) {
        os << "  ";
        Expr::printKind(os, it.first);
        os << ": " << it.second << '\n';
    }
    return os << '}';
}

// Write out the expression to a path as an s-expression
static void exprToSexpr(const ref<Expr>& expr) {
    static std::set<std::string> already_written;
    if (!export_to_s_expr || s_expr_path.empty()) {
        std::cerr << "WARNING: S-expr not generated: add exportToSExpr=true and sExprPath in s2e-config.lua\n";
        return;
    }

    std::ostringstream ss;
    ss << expr;
    if (already_written.find(ss.str()) != already_written.end()) {
        return;
    }

    std::string updated_s_expr_path = s_expr_path + "." + std::to_string(already_written.size());
    already_written.insert(ss.str());

    std::function<void(const ref<Expr>, std::optional<size_t>)> recur = nullptr;
    // Open file for writing
    std::error_code ec;
    llvm::raw_fd_ostream os(updated_s_expr_path, ec);
    if (ec) {
        std::cerr << "ERROR: Could not open file for S-expression: " << updated_s_expr_path;
        return;
    }
    // Recurse into expression tree
    recur = [&recur, &os](const ref<Expr> node, std::optional<size_t> indent) {
        if (node.isNull()) {
            return;
        }
        if (indent.has_value()) {
            for (size_t i = 0; i < indent.value(); ++i) {
                os << ' ';
            }
        }
        if (node->getNumKids() == 0) {
            if (node->getKind() == Expr::Constant) {
                node->print(os);
            } else {
                Expr::printKind(os, node->getKind());
            }
            return;
        }
        os << '(';
        Expr::printKind(os, node->getKind());
        for (unsigned i = 0; i < node->getNumKids(); ++i) {
            auto child = node->getKid(i);
            if (indent.has_value()) {
                os << '\n';
                recur(child, indent.value() + 2);
            } else {
                os << ' ';
                recur(child, {});
            }
        }
        os << ')';
    };
    recur(expr, {});
    os << '\n'; 
}

struct depth_nodes {
    int depth, nodes;
};
typedef struct depth_nodes Struct;
static Struct exprData(const ref<Expr>& expr) {
    
    Struct data;
    data.depth = 0;
    data.nodes = 0;
    if (expr.isNull()) {
        return data;
    }
    
    std::queue<ref<Expr>> q;
     
    q.push(expr);
    q.push(NULL);
    while (!q.empty())
    {
        ref<Expr> temp = q.front();
        q.pop();
 
        if (temp == NULL)
            data.depth++;

        if (temp != NULL) {
            data.nodes++;
            for (unsigned i = 0; i < temp->getNumKids(); ++i) {
                auto child = temp->getKid(i);
                q.push(child);
            } 
        }
        else if(!q.empty())
        {
            q.push(NULL);
        }
    }
    return data;
}
       
// Extract a dot graph with the given name for the expression and write out to a path
static void exprToDotGraph(const ref<Expr>& expr) {
    if (dot_graph_name.empty() || dot_graph_path.empty()) {
        std::cerr << "WARNING: Dot graph not generated: add dotGraphName and dotGraphPath in s2e-config.lua\n";
        return;
    }

    std::unordered_map<Expr::Kind, size_t> kind_counts;
    std::function<void(ref<Expr>, std::optional<std::pair<Expr::Kind, size_t>>)> recur = nullptr;
    // Open file for writing
    std::error_code ec;
    llvm::raw_fd_ostream os(dot_graph_path, ec);
    if (ec) {
        std::cerr << "ERROR: Could not open file for dot graph: " << dot_graph_path;
        return;
    }
    // Write beginning of file
    os << "digraph " << dot_graph_name << " {\n";
    // Recurse into expression tree.
    recur = [&recur, &kind_counts, &os](ref<Expr> node, const std::optional<std::pair<Expr::Kind, size_t>>& parent) {
        if (node.isNull()) {
            return;
        }
        auto node_kind = node->getKind();
        size_t index = kind_counts[node_kind]++;
        if (parent.has_value()) {
            const auto& tmp = parent.value();
            os << "  ";
            Expr::printKind(os, tmp.first);
            os << tmp.second << " -> ";
            Expr::printKind(os, node_kind);
            os << index << ";\n";
        }
        for (int i = 0; i < node->getNumKids(); ++i) {
            recur(node->getKid(i), {{ node_kind, index }});
        }
    };
    recur(expr, {});
    os << "}\n";
}

static void dumpExpresisonToFile(const ref<Expr>& expr) {
    if (export_to_s_expr) {
        exprToSexpr(expr);
    } else {
        exprToDotGraph(expr);
    }
}

S2E_DEFINE_PLUGIN(CyFiFunctionModels, "Plugin that implements CYFI models for libraries", "", "MemUtils", "ModuleMap", "Vmi", "LibraryCallMonitor", "OSMonitor", "WindowsMonitor", "ProcessExecutionDetector");

void CyFiFunctionModels::initialize() {
    m_map = s2e()->getPlugin<ModuleMap>();
    m_memutils = s2e()->getPlugin<MemUtils>();
    m_base = s2e()->getPlugin<BaseInstructions>();

    instructionMonitor = s2e()->getConfig()->getBool(getConfigKey() + ".instructionMonitor");
    func_to_monitor = s2e()->getConfig()->getInt(getConfigKey() + ".functionToMonitor");

    arg_dump = s2e()->getConfig()->getInt(getConfigKey()+".dumpArgs", 0);
    
    m_moduleName = s2e()->getConfig()->getString(getConfigKey() + ".moduleName");
	    bool ok;
    ConfigFile::string_list moduleNames = s2e()->getConfig()->getStringList(getConfigKey() + ".moduleNames", ConfigFile::string_list(), &ok); 
    foreach2 (it, m_moduleNames.begin(), m_moduleNames.end()) { m_moduleNames.insert(*it); }
    if (!m_moduleName.empty()) {
	    m_moduleNames.insert(m_moduleName);
    }

    const auto& trace_regions = s2e()->getConfig()->getString(getConfigKey() + ".traceRegions");
    if (!trace_regions.empty()) {
        if (!(m_traceRegions = Ranges::parse(trace_regions))) {
            std::cerr << "Failed to parse trace regions: '" << trace_regions << "'\n";
        } else {
            std::cerr << "Parsed trace regions: '" << *m_traceRegions << "'\n";
        }
    }

    dot_graph_name = s2e()->getConfig()->getString(getConfigKey() + ".dotGraphName");
    dot_graph_path = s2e()->getConfig()->getString(getConfigKey() + ".dotGraphPath");
    export_to_s_expr = s2e()->getConfig()->getBool(getConfigKey() + ".exportToSExpr", false);
    s_expr_path = s2e()->getConfig()->getString(getConfigKey() + ".sExprPath");
    std::cerr << "DEBUG: dotGraphName: " << dot_graph_name <<
        "\n       dotGraphPath: " << dot_graph_path <<
        "\n       exportToSExpr: " << (export_to_s_expr ? "true" : "false") <<
        "\n       sExprPath: " << s_expr_path << '\n';

    decoderSearch = s2e()->getConfig()->getBool(getConfigKey() + ".decoderSearch");
    if(decoderSearch)
        getDebugStream() << "Decoding algorithm search is enabled.\n";

    m_libCallMonitor = s2e()->getPlugin<LibraryCallMonitor>();
    m_vmi = s2e()->getPlugin<Vmi>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    m_monitor->onProcessLoad.connect(sigc::mem_fun(*this, &CyFiFunctionModels::onProcessLoad));
    
    s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(
        sigc::mem_fun(*this, &CyFiFunctionModels::onTranslateInstruction));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &CyFiFunctionModels::onTranslateBlockEnd));

    s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
        sigc::mem_fun(*this, &CyFiFunctionModels::onConcreteDataMemoryAccess));
    
    s2e()->getCorePlugin()->onAfterSymbolicDataMemoryAccess.connect(
        sigc::mem_fun(*this, &CyFiFunctionModels::onAfterSymbolicDataMemoryAccess));


}


void CyFiFunctionModels::findBufferByte(ref<Expr> expr, ref<Expr> &index) {

    std::function<void(const ref<Expr>)> recur = nullptr;
    recur = [&recur, &index](const ref<Expr> expr) {
        if (expr.isNull()) 
            return;

        if (expr->getKind() == Expr::Read)
        {
            const ReadExpr *re = cast<ReadExpr>(expr);
            index = re->getIndex();
            return;
        }

        for (unsigned i = 0; i < expr->getNumKids(); ++i) {
            auto child = expr->getKid(i);
            recur(child);
        } 

    };
    recur(expr);
}

void CyFiFunctionModels::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,
                                              unsigned flags) {
    if(false)
        getDebugStream(state) << "Concrete Data Mem Access: " << hexval(address) << " - " << value << "\n";
}

void CyFiFunctionModels::onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> address,
                                                   klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value,
                                                   unsigned flags) 
{
    if(trackedTag.empty())
        return;


    std::stringstream os;
    os << value;
    if (os.str().find(trackedTag[state->getID()]) == std::string::npos)
        return;

    if(address->getKind() != Expr::Constant)
        return;
    
    // Although /p value represents the symbolic expression contained in /p address,
    // we use the /p address becuase we do not only want the symbolic expression for the 
    // first byte of this memory region, but symbolic expressions from all symbolc bytes
    if(!decoderSearch)
        return;
        
    evalForDecoders(state, address);
}

void CyFiFunctionModels::evalForDecoders(S2EExecutionState *state, klee::ref<klee::Expr> address) {

    //getDebugStream(state) << "DUMP: " << address  << "\n";

    std::vector<uint8_t> all_constants;
    uint64_t addr = dyn_cast<ConstantExpr>(address)->getZExtValue();
    int i = 0;
    while (1){
        TranslationBlock *tb = state->getTb(); 
        if(tb == 0x0)    
            break;
        ref<Expr> e = state->mem()->read(addr + i);
        if(e.isNull() || isa<ConstantExpr>(e))
            break;
        ref<Expr> constant =  state->concolics->evaluate(e);   
        uint8_t val = dyn_cast<ConstantExpr>(constant)->getZExtValue();
        all_constants.push_back(val);
        i++;            
    }

    std::string encoded_indiv = Decoders::indexedVal_V(all_constants);

    // HACK:   buffer must be >= 4 ???
    if(all_constants.size() < 4)
        return;

    /* --------------------- DECODING --------------------- */
    decoderMap DM;
    DM["base16"] = Decoders::extractBufferComparators("base16", all_constants);
    DM["base32"] = Decoders::extractBufferComparators("base32", all_constants);
    DM["base64"] = Decoders::extractBufferComparators("base64", all_constants);  
    DM["base85"] = Decoders::extractBufferComparators("base85", all_constants);
    DM["xor_23"] = Decoders::extractBufferComparators("xor_23", all_constants);
    DM["rot_13"] = Decoders::extractBufferComparators("rot_13", all_constants);
    DM["table_lookup"] = Decoders::extractBufferComparators("table_lookup", all_constants);
    DM["decode_str_to_le_int32"] = Decoders::extractBufferComparators("decode_str_to_le_int32", all_constants);
    DM["decode_le_int32_to_str"] = Decoders::extractBufferComparators("decode_le_int32_to_str", all_constants);

    if(instructionMemData.find(state->getID()) == instructionMemData.end())
    {
        memDataVec input;
        input.push_back(std::make_pair(trackedPc, DM));
        instructionMemData[state->getID()] = input;
    }
    else        
    {
        memDataVec input;
        input = instructionMemData[state->getID()];
        input.push_back(std::make_pair(trackedPc, DM));
        instructionMemData[state->getID()] = input;
    }        

    // try to match current encoded to previous decoded
    if (instructionMemData.size() > 0)
    {
        const bool id_found = instructionMemData.find(state->getID()) != instructionMemData.end();
        if(!id_found)
            return;

        memDataVec srchVec;
        srchVec = instructionMemData[state->getID()];

        int i = 0;
        for (auto it: srchVec){
            uint64_t prev_addr = it.first;
            for (auto item: it.second) {
                std::string decoder_name = item.first;   
                std::string prev_encoded = item.second.first;
                std::string prev_decoded = item.second.second;

                if(encoded_indiv.compare(prev_decoded) == 0) {  

                    // Compute distance...using a set b/c we want to account for loops
                    std::set<uint64_t> unqInst;
                    for(int x = i; x < srchVec.size(); ++ x)
                        unqInst.insert(srchVec[x].first);

                    if ((prev_addr != trackedPc) && prev_decoded.length() > 0)
                    {
                        getDebugStream(state) << "Match: " << decoder_name << ", Distance: " << unqInst.size() << ", Start: " << hexval(prev_addr) << ", End: " << hexval(trackedPc) << "\n"
                                        << "Decoded Results: " << prev_decoded << " == " << encoded_indiv << "\n\n";
                    }
                }
            }
            i++;
        }
    }

}  


void CyFiFunctionModels::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName) {
    
    if (moduleId > 0 && (recent_callee.find("CreateProcess") == 0 || recent_callee.find("ShellExecute") == 0)) {
        getDebugStream(state) << "Tracking " << ImageFileName << " pid: " << hexval(pid) << " from ppid: " << hexval(moduleId) <<  "\n";
	m_moduleNames.insert(ImageFileName);
        m_procDetector->trackModule(state, pid, ImageFileName);
        moduleId = pid;
    }

    if(!m_moduleNames.empty() && m_moduleNames.find(ImageFileName) != m_moduleNames.end()){
	    moduleId = pid;
    }

}

void CyFiFunctionModels::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, bool isStatic, uint64_t staticTarget) {
    // Library calls/jumps are always indirect
    if (tb->se_tb_type == TB_CALL_IND || (tb->se_tb_type == TB_JMP_IND)) {
        signal->connect(
            sigc::bind(sigc::mem_fun(*this, &CyFiFunctionModels::onIndirectCallOrJump), (unsigned) tb->se_tb_type));
    }
}

void CyFiFunctionModels::onIndirectCallOrJump(S2EExecutionState *state, uint64_t pc, unsigned sourceType) {

    auto current_mod = m_map->getModule(state, pc);
    auto mod = m_map->getModule(state);

    if (!mod) {
        return;
    }

    if (!current_mod) {
        return;
    }

    if (mod == current_mod) {
        return;
    }

    //We only care about the target as the caller module
    std::string callerModule = (*current_mod.get()).Name;

    if(m_moduleNames.find(callerModule) == m_moduleNames.end()) {
	    return;
    }

    std::string exportName;

    uint64_t targetAddr = state->regs()->getPc();

    exportName = m_libCallMonitor->get_export_name(state, mod->Pid, targetAddr);

    if (exportName.size() == 0) {
        vmi::Exports exps;
        auto exe = m_vmi->getFromDisk(mod->Path, mod->Name, true);

        if (!exe) {
            return;
        }

        auto pe = std::dynamic_pointer_cast<vmi::PEFile>(exe);

        if (!pe) {
            return;
        }

        auto exports = pe->getExports();
        auto it = exports.find(targetAddr-mod->LoadBase);
        if (it != exports.end()) {
            exportName = (*it).second;
        } else {
            // Did not find any export
            return;
        }
    }

    if (exportName.size() == 0) {
        return;
    }

    if (arg_dump > 0) {

        uint64_t stackAddr = state->regs()->getSp() + 4;
        getDebugStream(state) << "PC Address: " << hexval(targetAddr) << "\n";
        getDebugStream(state) << "Stack Address: " << hexval(stackAddr) << "\n";

        uint64_t arguments[8];

        klee::ref<klee::Expr> result;

        for (int i = 0; i < arg_dump; i++) {
            result = state->mem()->read(stackAddr+i*4, state->getPointerWidth());
            if (!result.isNull()) {

                if (isa<ConstantExpr>(result)) {
                    ConstantExpr *CE = dyn_cast<ConstantExpr>(result);
                    arguments[i] = CE->getZExtValue();
                    getDebugStream(state) << "Get " << i << " argument at " << hexval(stackAddr+i*4) << " " <<  hexval(arguments[i]) << "\n";
                    
                    // Check if buffer is symbolic
                    ref<Expr> data = state->mem()->read(arguments[i], state->getPointerWidth());

                    if (!data.isNull()) {
                        if (!isa<ConstantExpr>(data)) {
                            std::ostringstream ss;
                            ss << data;
                            std::string sym = ss.str();
                            //getDebugStream(state) << "symbolic constraints: " << sym << "\n";
                            std::string symbTag = getTag(sym);
                            getCyfiStream(state) << exportName << " " << i << " Argument Tag: " << symbTag << "\n";
                        }
                    }
                } else {
                    getDebugStream(state) <<  i << " argument at " << hexval(stackAddr+i*4) << " is symbolic \n";
                    // The stack space is symbolic, can be a symbolic int on stack?
                    std::ostringstream ss;
                    ss << result;
                    std::string sym = ss.str();
                    std::string symbTag = getTag(sym);
                    getCyfiStream(state) << exportName << " " << i << " Argument Tag: " << symbTag << "\n";
                }
            }
        }
    }

    recent_callee = exportName;

}

void CyFiFunctionModels::cyfiDump(S2EExecutionState *state, std::string reg) {

    static std::unordered_map<std::string, int> m {
        {"eax", R_EAX},
        {"ebx", R_EBX},
        {"ecx", R_ECX},
        {"edx", R_EDX},
        {"esi", R_ESI},
        {"edi", R_EDI},
        {"ebp", R_EBP},
        {"esp", R_ESP},
    };

    uint32_t temp;

    state->regs()->read(CPU_OFFSET(regs[m[reg]]), &temp, sizeof(temp), false);
    ref<Expr> data = state->mem()->read(temp, state->getPointerWidth());
    if (!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            getDebugStream(state) << reg << " " << data << " at " << hexval(temp) << " is symbolic\n";
        } else {
            std::ostringstream ss;
            ss << data;
            uint32_t addr = std::stoull(ss.str(), nullptr, 16);
             
            ref<Expr> level_one = state->mem()->read(addr, state->getPointerWidth());
            if (!level_one.isNull()) {
                if (!isa<ConstantExpr>(level_one)) {
                    getDebugStream(state) << reg << " " << data << " at " << hexval(temp) << " contains symbolic data: " << level_one << "\n";
                } else {
                    getDebugStream(state) << reg << " "  << data << " at " << hexval(temp) << " contains concrete data: " << level_one << "\n";
                }
            }
            else {
                getDebugStream(state) << reg << " " << data << " at " << hexval(temp) << " is concrete\n";
            }
        }
    }
    else {
        data = state->mem()->read(CPU_OFFSET(regs[m[reg]]), state->getPointerWidth());
        getDebugStream(state) << reg << " " << data <<  " at " << hexval(temp) << "\n";
    }
}

void CyFiFunctionModels::onTranslateInstruction(ExecutionSignal *signal,
                                                S2EExecutionState *state,
                                                TranslationBlock *tb,
                                                uint64_t pc) {

    auto currentMod = m_map->getModule(state, pc);
    if (!currentMod) 
        return;

    uint64_t relative_pc;
    currentMod->ToNativeBase(pc, relative_pc);
    const bool is_in = m_moduleNames.find(currentMod->Name) != m_moduleNames.end();
    if (is_in)
        trackedPc = relative_pc;

    // When we find an interesting address, ask S2E to invoke our callback when the address is
    // actually executed
    if (!instructionMonitor) {
        return;
    }

    // If we've defined ranges to dump within, then use those.
    if (m_traceRegions) {
        uint64_t relative_pc;
        if (currentMod->ToNativeBase(pc, relative_pc) && m_traceRegions->contains(relative_pc)) {
            signal->connect(sigc::mem_fun(*this, &CyFiFunctionModels::onInstructionExecution));
        }
        return;
    }
    // Otherwise, check whether we've specified which module to trace, and if the current
    // module's name match. If the config contains "moduleName", then we can use that info
    // to check if the module that the PC is currently in is the one we're interested in.
    if(m_moduleNames.find(currentMod->Name) != m_moduleNames.end()) {
        signal->connect(sigc::mem_fun(*this, &CyFiFunctionModels::onInstructionExecution));
    }
}
                                            

// This callback is called only when the instruction at our address is executed.
// The callback incurs zero overhead for all other instructions
void CyFiFunctionModels::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {

    auto currentMod = m_map->getModule(state, pc);
    
    if (currentMod) {
        bool ok = true;
        uint64_t relPc;
        ok &= currentMod->ToNativeBase(pc, relPc);
        if(ok){
            s2e()->getDebugStream(state) << "Executed instruction: " << hexval(relPc) <<  '\n';
             std::ostringstream ss;
             state->regs()->dump(ss);
             s2e()->getDebugStream() << ss.str();

             cyfiDump(state, "eax");
             cyfiDump(state, "ebx");
             cyfiDump(state, "ecx");
             cyfiDump(state, "edx");
             cyfiDump(state, "esi");
             cyfiDump(state, "edi");
             cyfiDump(state, "ebp");
             cyfiDump(state, "esp");   
        }
    }   
}

void CyFiFunctionModels::expressionData(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {

    uint64_t exprAddr = (uint64_t) cmd.expressionData.expr;
    ref<Expr> expr = state->mem()->read(exprAddr, state->getPointerWidth());

    auto expr_kind_counts = countExprKinds(expr, 4);
    int count = expr_kind_counts.size();
    cmd.expressionData.kinds =  count;

    Struct data = exprData(expr);
    cmd.expressionData.depth = data.depth;
    cmd.expressionData.nodes = data.nodes;
}

void CyFiFunctionModels::handleStrStrA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.StrStrA.pszFirst;
    stringAddrs[1] = (uint64_t) cmd.StrStrA.pszSrch;

    std::string tag;

    state->mem()->readString(cmd.StrStrA.symbTag, tag);
    
    m_base->makeSymbolic(state, stringAddrs[1], state->getPointerSize(), tag);

    klee::ref<klee::Expr> data = state->mem()->read(stringAddrs[1], state->getPointerWidth());

    klee::ref<klee::Expr> possible_1 = klee::ConstantExpr::create(stringAddrs[0], state->getPointerWidth());

    klee::ref<klee::Expr> possible_2 = klee::ConstantExpr::create(0, state->getPointerWidth());

    klee::ref<klee::Expr> condition = klee::OrExpr::create(klee::EqExpr::create(data, possible_1), klee::EqExpr::create(data, possible_2));

    
    klee::ref<klee::Expr> zero = klee::ConstantExpr::create(0, condition.get()->getWidth());
    klee::ref<klee::Expr> boolExpr = klee::NeExpr::create(condition, zero);

    getDebugStream(state) << "Assuming " << boolExpr << "\n";

    if (!state->addConstraint(boolExpr, true)) {
        s2e()->getExecutor()->terminateState(*state, "Tried to add an invalid constraint");
    }

}

void CyFiFunctionModels::dumpExpression(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
#if PRINT_DOT_GRAPH
    // TODO: update countExprNumberBytes to be dynamic...read each byte until concrete and keep track of how many 
    // to be used in countExprKinds()
    ref<Expr> data = state->mem()->read(cmd.dumpExpression.buffer, countExprNumBytes * 8);
    getDebugStream(state) << "\nDump expr for " << hexval(cmd.dumpExpression.buffer) << ": " << data << "\n";
    auto expr_kind_counts = countExprKinds(data, countExprNumBytes);
    getDebugStream(state) << expr_kind_counts << "\n";
    dumpExpresisonToFile(data);
#endif    
}

std::string CyFiFunctionModels::getTag(const std::string &sym)
{
	size_t pos_end = 0;
	int cnt = 0;

	// find the 3rd isntance of '_'
	while (cnt != 3)
	{
		pos_end += 1;
		pos_end = sym.find("_", pos_end);
		if(pos_end == std::string::npos)
			continue;
		cnt++;
	}
	return std::string(&sym[sym.find("CyFi")], &sym[pos_end]);
}

void CyFiFunctionModels::checkCaller(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {

    std::string funcName;

    state->mem()->readString(cmd.CheckCaller.funcName, funcName);



    if (funcName == recent_callee) {

        cmd.CheckCaller.isTargetModule = true;
    } else {
        cmd.CheckCaller.isTargetModule = false;
    }

}

void CyFiFunctionModels::readTag(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    uint64_t buffer = cmd.ReadTag.buffer;
    
    // Check if buffer is symbolic
    ref<Expr> data = state->mem()->read(buffer, state->getPointerWidth());

    if (!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
            getDebugStream(state) << "symbolic constraints: " << sym << "\n";
            std::string symbTag = getTag(sym);
            state->mem()->write(cmd.ReadTag.symbTag, symbTag.c_str(), symbTag.length()+1);
        }
    }
}

void CyFiFunctionModels::trackModule(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {

    std::string funcName;
    state->mem()->readString(cmd.CheckCaller.funcName, funcName);

}

void CyFiFunctionModels::tagCounter(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    counter = counter + 1;
    cmd.TagCounter.counter = counter;
    s2e()->getWarningsStream(state) << "Tag Counter = " << counter << "\n";
}

void CyFiFunctionModels::killAnalysis(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {

    std::string funcName;
    state->mem()->readString(cmd.CheckCaller.funcName, funcName);
    getInfoStream() << "DDR Found. Killing execution from " << funcName << "\n";
    S2EExecutor *executor = s2e()->getExecutor();
    const klee::StateSet &states = s2e()->getExecutor()->getStates();
    size_t nrStatesToTerminate = (size_t)executor->getStatesCount();
    
    if (nrStatesToTerminate < 1 && executor->getStatesCount() > 0) {
        nrStatesToTerminate = 1; // kill at least one state
    }

    for (auto it = states.begin(); it != states.end() && nrStatesToTerminate > 0; it++, nrStatesToTerminate--) {
        S2EExecutionState *state = dynamic_cast<S2EExecutionState *>(*it);

        // Never kill state 0, because it is used by SeedSearcher
        /*if (state->getID() == 0) {
            continue;
        }*/

        // We might terminate the current state so the executor could throw an exception
        try {
            executor->terminateState(*state);
        } catch (s2e::CpuExitException &) {
        }
        }
}

void CyFiFunctionModels::concretizeAll(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    uint64_t address = (uint64_t) cmd.concretizeAll.buffer;
    unsigned i = 0;

    while (True) {
        klee::ref<klee::Expr> ret = state->mem()->read(address + i);
        if (ret.isNull()) {
            getWarningsStream() << "Could not read address " << hexval(address + i) << "\n";
            break;
        }

        if (!isa<ConstantExpr>(ret)) {
            uint8_t b = 0;
            if (!state->mem()->read<uint8_t>(address + i, &b, VirtualAddress)) {
                getWarningsStream() << "Could not concretize address " << hexval(address + i) << "\n";
                break;
            } 
        } else {
            break;
        }

        i++;
    }

    getDebugStream(state) << "Concretizing buffer " << hexval(address) << " with size " << i << "\n";

    return;
}

void CyFiFunctionModels::tagTracker(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {

    state->mem()->readString(cmd.tagTracker.tag, trackedTag);
    getDebugStream(state) << "Tracking tag: " << trackedTag << "\n";
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


        case WINWRAPPER_STRSTRA: {
            ref<Expr> retExpr;
            handleStrStrA(state, command);     
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }            

        } break;        
    
        case CHECK_CALLER: {
            checkCaller(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case READ_TAG: {
            readTag(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case TAG_COUNTER: {
            tagCounter(state, command);
            if(!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
            getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case KILL_ANALYSIS: {
            killAnalysis(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;
        
        case DUMP_EXPRESSION: {
            dumpExpression(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }        
        } break;
        
        case TAG_TRACKER: {
            tagTracker(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }        
        } break;
        
        case CONCRETIZE_ALL: {
            concretizeAll(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case EXPRESSION_DATA: {
            expressionData(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }        
        } break;

        default: {
            getWarningsStream(state) << "Invalid command " << hexval(command.Command) << "\n";
            exit(-1);
        }
    }
}

// Super inefficient parsing, because this won't be running on the fast path (hopefully).
// If that assumption is no longer valid, update the algorithm.
std::unique_ptr<Ranges> Ranges::parse(const std::string& ranges_string) {
    auto retval = std::unique_ptr<Ranges>(new Ranges());
    std::istringstream iss(ranges_string);
    std::string token;
    try {
        while (std::getline(iss, token, ',')) {
            size_t index = 0;
            uint64_t start = std::stoull(token, &index, 16);
            if (index < token.size()) {
                if (token[index] != '-') {
                    return nullptr;
                }
                auto substr = token.substr(index + 1);
                uint64_t end = std::stoull(substr, &index, 16);
                if (index < substr.size()) {
                    return nullptr;
                }
                if (end < start) {
                    return nullptr;
                }
                retval->ranges_.push_back({ start, end });
            } else {
                retval->ranges_.push_back({ start, start });
            }
        }
    } catch (...) {
        return nullptr;
    }
    return retval;
}

bool Ranges::contains(uint64_t value) const {
    for (const auto& range : ranges_) {
        if (value >= range.first && value <= range.second) {
            return true;
        }
    }
    return false;
}

std::ostream& operator<<(std::ostream& os, const Ranges& ranges) {
    bool first = true;
    std::ios_base::fmtflags f = os.flags();
    os << std::hex;
    for (const auto& range : ranges.ranges_) {
        if (!first) {
            os << ',';
        }
        os << range.first;
        if (range.first != range.second) {
            os << '-' << range.second;
        }
        first = false;
    }
    os.flags(f);
    return os;
}

std::string Decoders::indexedVal_V(std::vector<uint8_t> data)
{
        std::stringstream os;
        for (unsigned i = 0; i < data.size(); ++i) {
            if (i !=0)
                os << ", ";
            os << std::setw(2) << std::setfill('0') << "0x" << std::hex << (unsigned) data[i] << std::dec;
        }
        std::string ret = os.str();
        return ret;
}

std::string Decoders::indexedVal_S(std::string data)
{
        std::stringstream os;
        for (unsigned i = 0; i < data.length(); ++i) {
            if (i !=0)
                os << ", ";
            os << std::setw(2) << std::setfill('0') << "0x" << std::hex << (unsigned) data[i] << std::dec;
        }
        std::string ret = os.str();
        return ret;
}

std::string Decoders::indexedVal_C(char * data)
{
        std::stringstream os;
        for (unsigned i = 0; i < std::strlen(data); ++i) {
            if (i !=0)
                os << ", ";
            os << std::setw(2) << std::setfill('0') << "0x" << std::hex << (unsigned) data[i] << std::dec;
        }
        std::string ret = os.str();
        return ret;
}

std::string Decoders::indexedVal_UC(unsigned char ** data)
{
        std::stringstream os;
        for (unsigned i = 0; i < std::strlen((char*)data); ++i) {
            if (i !=0)
                os << ", ";
            os << std::setw(2) << std::setfill('0') << "0x" << std::hex << data[i] << std::dec;
        }
        std::string ret = os.str();
        return ret;
}

std::string Decoders::base64(const char* in, size_t source_len) {

    std::string out;

    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    const char* pSrc ;
    size_t dwSrcSize = source_len;
    pSrc = in;

    while (dwSrcSize >= 1) {
        unsigned char c = *pSrc++;
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
        dwSrcSize--;
    }
    
    return out;
}

std::string Decoders::xor_23(std::string x) {
    std::stringstream ss;
    for (int i = 0; i < x.length(); i++)
    {
        ss << (x.at(i) ^ 0x23);
    }
    return ss.str();
}

size_t Decoders::rot_13(const char* source, size_t source_len, char* dest, size_t dest_capacity) {
    //assert(dest_capacity >= source_len);
    size_t i;
    for (i = 0; i < source_len && i < dest_capacity; ++i) {
        if (source[i] >= 'A' && source[i] <= 'Z') {
            dest[i] = 'A' + (source[i] - 'A' + 13) % 26;
        }
        else if (source[i] >= 'A' && source[i] <= 'Z') {
            dest[i] = 'a' + (source[i] - 'a' + 13) % 26;
        }
        else {
            // this should be dest[i] = source[i], but that will cause false posiive during comparison
            dest[i] = '-';
        }
    }
    return i;
}

size_t Decoders::table_lookup(const char* source, size_t source_len, char* dest, size_t dest_capacity, const char* table, size_t table_size) {
	size_t j = 0;
	for (size_t i = 0; i < source_len && i < dest_capacity; ++i) {
		char c = source[i];
		if (c >= 1 && c <= table_size) {
			dest[j++] = table[c - 1];
		}
	}
	return j;
}

size_t Decoders::decode_str_to_le_int32(const char* source, size_t source_len, char* dest, size_t dest_capacity) {
	//assert(dest_capacity >= 4);
	unsigned result = 0;
	size_t len = 0;
	if(source_len<4){
	    len=source_len;
	}
	else{
	    len=4;
	}
	for (size_t i = 0; i < len; ++i) {
		result = (result * 10) + (unsigned)(source[i]);
	}
	dest[0] = (char)(result & 0xff);
	dest[1] = (char)((result >> 8) & 0xff);
	dest[2] = (char)((result >> 16) & 0xff);
	dest[3] = (char)((result >> 24) & 0xff);
	return 4;
}

size_t Decoders::decode_le_int32_to_str(const char* source, size_t source_len, char* dest, size_t dest_capacity) {
	//assert(source_len >= 4);
	unsigned result = *(unsigned*)source;
	size_t tmplen = 0;
	char tmp[16] = { 0 };
	while (result > 0) {
		tmp[tmplen++] = '0' + (result % 10);
		result /= 10;
	}
	//assert(dest_capacity >= tmplen);
	size_t len;
	for (len = 0; len < tmplen; ++len) {
		dest[len] = tmp[tmplen - len - 1];
	}
	return len;

}

int Decoders::hexchr2bin(const char hex, char* out)
{
	if (out == NULL)
		return 0;

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	}
	else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	}
	else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	}
	else {
		return 0;
	}

	return 1;
}

size_t Decoders::base16(const char* hex, unsigned char** out)
{
	size_t len;
	char   b1;
	char   b2;
	size_t i;

	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;

	*out = (unsigned char*)malloc(len);
	memset(*out, 'A', len);
	for (i = 0; i < len; i++) {
		if (!hexchr2bin(hex[i * 2], &b1) || !hexchr2bin(hex[i * 2 + 1], &b2)) {
			return 0;
		}
		(*out)[i] = (b1 << 4) | b2;
	}
	return len;
}

const size_t BASE85_INPUT = 5;
const size_t BASE85_OUTPUT = 4;
#define FOLD_ZERO 1 
const void* Decoders::cyoBase85NextByte(const void* input, unsigned char* byte, int* padding)
{
    unsigned char* curr = (unsigned char*)input;
    if (*curr)
    {
        *byte = (*curr - '!');
        return (curr + 1);
    }

    *byte = 84;
    ++* padding;
    return input;
}

unsigned int Decoders::cyoBase85Power(unsigned int mult, int count)
{
    unsigned int total = 1;
    for (int i = 0; i < count; ++i)
        total *= mult;
    return total;
}

unsigned char* Decoders::cyoBase85OutputX4(unsigned char* output, char value)
{
    *output++ = value;
    *output++ = value;
    *output++ = value;
    *output++ = value;
    return output;
}

size_t Decoders::base85(const char* source, size_t source_len, char* dest, size_t dest_capacity) {
    const char* pSrc;
    unsigned char* pDest;
    size_t dwSrcSize;
    size_t dwDestSize;

    if (!dest || !source)
        return 0; /*ERROR - null pointer*/

    pSrc = source;
    pDest = (unsigned char*)dest;
    dwSrcSize = source_len;
    dwDestSize = 0;

    while (dwSrcSize >= 1)
    {
        unsigned char in1, in2, in3, in4, in5;
        int padding, shift;
        unsigned int n;

#if FOLD_ZERO
        if (*pSrc == 'z')
        {
            ++pSrc;
            pDest = cyoBase85OutputX4(pDest, 0);
            dwDestSize += BASE85_OUTPUT;
            continue;
        }
#endif
#if FOLD_SPACES
        if (*pSrc == 'y')
        {
            ++pSrc;
            pDest = cyoBase85OutputX4(pDest, 0x20);
            dwDestSize += BASE85_OUTPUT;
            continue;
        }
#endif

        /* 2-5 input chars */
        padding = 0;
        pSrc = (const char*)cyoBase85NextByte((const void*)pSrc, &in1, &padding);
        if (padding != 0)
            return 0; /*ERROR - insufficient data*/
        pSrc = (const char*)cyoBase85NextByte((const void*)pSrc, &in2, &padding);
        if (padding != 0)
            return 0; /*ERROR - insufficient data*/
        pSrc = (const char*)cyoBase85NextByte((const void*)pSrc, &in3, &padding);
        pSrc = (const char*)cyoBase85NextByte((const void*)pSrc, &in4, &padding);
        pSrc = (const char*)cyoBase85NextByte((const void*)pSrc, &in5, &padding);
        dwSrcSize -= (BASE85_INPUT - padding);

        /* Validate */
        if (in1 >= 85 || in2 >= 85 || in3 >= 85 || in4 >= 85 || in5 >= 85)
            return 0; /*ERROR - invalid base85 character*/

        /* 1-4 output bytes */
        n = (in1 * cyoBase85Power(85, 4))
            + (in2 * cyoBase85Power(85, 3))
            + (in3 * cyoBase85Power(85, 2))
            + (in4 * cyoBase85Power(85, 1))
            + in5;
        shift = 24;
        do
        {
            *pDest++ = (unsigned char)(n >> shift);
            ++dwDestSize;
            shift -= 8;
            ++padding;
        } while (padding <= 3);
    }

    return dwDestSize;
}

#define buf_len 64
std::pair<std::string, std::string> Decoders::extractBufferComparators(std::string decoder_type, std::vector<uint8_t> all_constants)
{
    std::map <std::string, int> translate;
    translate["base16"]=1;
    translate["base32"]=2;
    translate["base64"]=3;
    translate["base85"]=4;
    translate["xor_23"]=5;
    translate["rot_13"]=6;
    translate["table_lookup"]=7;
    translate["decode_str_to_le_int32"]=8;
    translate["decode_le_int32_to_str"]=9;

    std::string encoded (all_constants.begin(), all_constants.end());
    char * enc = &encoded[0];
    std::string encoded_indiv = Decoders::indexedVal_V(all_constants);

    std::string decoded_indiv;
    int typ = translate[decoder_type];
   
    //std::cerr << "TYPE: " << typ << "\n";
    switch (typ)
    {
        case 1: {
            decoded_indiv = "";
            break;
        }

        case 2: {
            decoded_indiv = "";
            break;
        }     

        case 3: {
            std::string  base64_decoded = Decoders::base64(enc, encoded.length());
            decoded_indiv = Decoders::indexedVal_S(base64_decoded);
            break;
        }

        case 4: {
            char base85_decoded[buf_len] = {0};
            Decoders::base85(enc, encoded.length(), base85_decoded, encoded.length());
            decoded_indiv = Decoders::indexedVal_C(base85_decoded);
            break;
        }

        case 5: {
            std::string xor_decoded = Decoders::xor_23(encoded);
            decoded_indiv = Decoders::indexedVal_S(xor_decoded);
            break;
        }

        case 6: {
            char rot_13_decoded[buf_len] = {0};
            Decoders::rot_13(enc, encoded.length(), rot_13_decoded, encoded.length());
            decoded_indiv = Decoders::indexedVal_C(rot_13_decoded);
            break;
        }

        case 7: {
            char table_lookup_decoded[buf_len] = {0};
            Decoders::table_lookup(enc, encoded.length(), table_lookup_decoded, encoded.length(), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 62);
            decoded_indiv = Decoders::indexedVal_C(table_lookup_decoded);
            break;
        }

        case 8: {
            char decode_str_to_le_int32_decoded[buf_len] = {0};
            Decoders::decode_str_to_le_int32(enc, encoded.length(), decode_str_to_le_int32_decoded, encoded.length());
            decoded_indiv = Decoders::indexedVal_C(decode_str_to_le_int32_decoded);
            break;
        }

        case 9: {
            char decode_le_int32_to_str_decoded[buf_len] = {0};
            Decoders::decode_le_int32_to_str(enc, encoded.length(), decode_le_int32_to_str_decoded, encoded.length());
            decoded_indiv = Decoders::indexedVal_C(decode_le_int32_to_str_decoded);
            break;
        }

        default: {
            decoded_indiv = "";
            break;
        }
    }

    return std::make_pair(encoded_indiv, decoded_indiv);

}

} // namespace models
} // namespace plugins
} // namespace s2e
