#include <s2e/cpu.h>
#include <s2e/function_models/cyfi_commands.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/Searchers/MergingSearcher.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include <klee/util/ExprTemplates.h>
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
#include <utility>

#include "CyFiFunctionModels.h"
using namespace klee;

namespace s2e {
namespace plugins {
namespace models {

#define PRINT_DOT_GRAPH 1

static constexpr size_t countExprNumBytes = 8;
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

static std::string exprToSExprString(const ref<Expr>& expr) {
    std::string output;
    llvm::raw_string_ostream os(output);
    std::function<void(const ref<Expr>, std::optional<size_t>)> recur = nullptr;
    // Open file for writing
    std::error_code ec;
    llvm::raw_fd_ostream os(s_expr_path, ec);
    if (ec) {
        std::cerr << "ERROR: Could not open file for S-expression: " << s_expr_path;
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
    return output;
}

// Write out the expression to a path as an s-expression
static void exprToSexpr(const ref<Expr>& expr) {
    static std::set<std::string> already_written;
    if (!export_to_s_expr || s_expr_path.empty()) {
        std::cerr << "WARNING: S-expr not generated: add exportToSExpr=true and sExprPath in s2e-config.lua\n";
        return;
    }
    std::string to_string = exprToSExprString(expr);
    if (already_written.find(to_string) != already_written.end()) {
        return;
    }
    std::string updated_s_expr_path = s_expr_path + "." + std::to_string(already_written.size());
    already_written.insert(to_string);
    // Open file for writing
    std::error_code ec;
    llvm::raw_fd_ostream os(updated_s_expr_path, ec);
    if (ec) {
        std::cerr << "ERROR: Could not open file for S-expression: " << s_expr_path;
        return;
    }
    os << to_string;
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

    instructionMonitor = s2e()->getConfig()->getBool(getConfigKey() + ".instructionMonitor");
    func_to_monitor = s2e()->getConfig()->getInt(getConfigKey() + ".functionToMonitor");
    m_moduleName = s2e()->getConfig()->getString(getConfigKey() + ".moduleName");

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

    m_libCallMonitor = s2e()->getPlugin<LibraryCallMonitor>();
    m_vmi = s2e()->getPlugin<Vmi>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    m_monitor->onProcessLoad.connect(sigc::mem_fun(*this, &CyFiFunctionModels::onProcessLoad));
    
    s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(
        sigc::mem_fun(*this, &CyFiFunctionModels::onTranslateInstruction));

    // Get an instance of the FunctionMonitor plugin
    FunctionMonitor *monitor = s2e()->getPlugin<FunctionMonitor>();

    // Get a notification when a function is called
    monitor->onCall.connect(sigc::mem_fun(*this, &CyFiFunctionModels::onCall));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &CyFiFunctionModels::onTranslateBlockEnd));

}
void CyFiFunctionModels::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName) {
    
    if (moduleId > 0) {
        getDebugStream(state) << "Tracking " << ImageFileName << " pid: " << hexval(pid) << " from ppid: " << hexval(moduleId) <<  "\n";
        m_procDetector->trackModule(state, pid, ImageFileName);
        moduleId = pid;
    }
    if ((m_moduleName != "") && (m_moduleName == ImageFileName)) {
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

    if (callerModule != m_moduleName) {
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
    // When we find an interesting address, ask S2E to invoke our callback when the address is
    // actually executed
    if (!instructionMonitor) {
        return;
    }

    auto currentMod = m_map->getModule(state, pc);
    if (!currentMod) {
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
    if (!m_moduleName.empty()) {
        // If the current module is the one we're looking for, connect to the
        // onInstructionExecution signal.
        if (currentMod->Name == m_moduleName) {
            signal->connect(sigc::mem_fun(*this, &CyFiFunctionModels::onInstructionExecution));
        }
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

void CyFiFunctionModels::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                     const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                     const FunctionMonitor::ReturnSignalPtr &returnSignal) {

    if (func_to_monitor == 0) {
        return;
    }

    // Filter out functions we don't care about
    if (state->regs()->getPc() != func_to_monitor) {
        return;
    }

    // If you do not want to track returns, do not connect a return signal.
    // Here, we pass the program counter to the return handler to identify the function
    // from which execution returns.
    returnSignal->connect(
        sigc::bind(sigc::mem_fun(*this, &CyFiFunctionModels::onRet), func_to_monitor));
}

void CyFiFunctionModels::onRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                    const ModuleDescriptorConstPtr &dest, uint64_t returnSite,
                    uint64_t functionPc) {
    getDebugStream(state) << "Execution returned from function " << hexval(functionPc) << "\n";
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
        }
    }

    // Perform the memory copy. We don't use the return expression here because it is just a concrete address
    ref<Expr> retExpr;
    if (memcpyHelper(state, memAddrs, numBytes, retExpr)){
        cmd.needOrigFunc = 0;
    }
    else {
        cmd.needOrigFunc = 1;

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

void CyFiFunctionModels::handleStrStrA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.StrStrA.pszFirst;
    stringAddrs[1] = (uint64_t) cmd.StrStrA.pszSrch;

    ref<Expr> data = state->mem()->read(stringAddrs[0], state->getPointerWidth());
    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
	    std::string symbTag = getTag(sym);
            state->mem()->write(cmd.StrStrA.symbTag, symbTag.c_str(), symbTag.length()+1);
        }
    }
}

void CyFiFunctionModels::handleStrStrW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.StrStrW.pszFirst;
    stringAddrs[1] = (uint64_t) cmd.StrStrW.pszSrch;

    ref<Expr> data = state->mem()->read(stringAddrs[0], state->getPointerWidth());
    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
	    std::string symbTag = getTag(sym);
            state->mem()->write(cmd.StrStrW.symbTag, symbTag.c_str(), symbTag.length()+1);
        }
    }
}

void CyFiFunctionModels::handleStrStr(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.strstr.str;
    stringAddrs[1] = (uint64_t) cmd.strstr.strSearch;

    ref<Expr> data = state->mem()->read(stringAddrs[0], state->getPointerWidth());
    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
	    std::string symbTag = getTag(sym);
            state->mem()->write(cmd.strstr.symbTag, symbTag.c_str(), symbTag.length()+1);
        }
    }
}

void CyFiFunctionModels::handleStrtok(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.strtok.strToken;
    stringAddrs[1] = (uint64_t) cmd.strtok.strDelimit;

    ref<Expr> data = state->mem()->read(stringAddrs[0], state->getPointerWidth());
    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
	    std::string symbTag = getTag(sym);
            state->mem()->write(cmd.strtok.symbTag, symbTag.c_str(), symbTag.length()+1);
        }
    }
}

void CyFiFunctionModels::handleWcsstr(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.wcsstr.str;
    stringAddrs[1] = (uint64_t) cmd.wcsstr.strSearch;

    ref<Expr> data = state->mem()->read(stringAddrs[0], state->getPointerWidth());
    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
		std::string symbTag = getTag(sym);
            state->mem()->write(cmd.wcsstr.symbTag, symbTag.c_str(), symbTag.length()+1);
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

    getDebugStream(state) << "Handling WinHttpReadData.\n";

    ref<Expr> data = state->mem()->read(args[1], state->getPointerWidth());
    //getDebugStream(state) << "testa " << data << " at " << hexval(args[0]) << " is symbolic\n";

    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            getDebugStream(state) << "Argument " << data << " at " << hexval(args[1]) << " is symbolic\n";
        } else {
            getDebugStream(state) << "Argument " << data << " at " << hexval(args[1]) << " is concrete\n";
        }
    }

    WinHttpReadDataHelper(state, args, retExpr);
}

void CyFiFunctionModels::handleWinHttpConnect(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    ref<Expr> data = state->mem()->read(cmd.WinHttpConnect.pswzServerName, countExprNumBytes * 8);
    auto expr_kind_counts = countExprKinds(data, countExprNumBytes);
    getDebugStream(state) << "WinHttpConnect: pswzServerName: " << expr_kind_counts;

#if PRINT_DOT_GRAPH
    dumpExpresisonToFile(data);
#endif
}

void CyFiFunctionModels::handleWinHttpCrackUrl(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    ref<Expr> data = state->mem()->read(cmd.WinHttpCrackUrl.pwszUrl, countExprNumBytes * 8);
    auto expr_kind_counts = countExprKinds(data, countExprNumBytes);
    getDebugStream(state) << "WinHttpCrackUrl: pwszUrl: " << expr_kind_counts;

#if PRINT_DOT_GRAPH
    dumpExpresisonToFile(data);
#endif
}

void CyFiFunctionModels::handleWriteFile(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    uint64_t lpBuffer = (uint64_t) cmd.WriteFile.lpBuffer;

    ref<Expr> data = state->mem()->read(lpBuffer, state->getPointerWidth());

    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
	        std::string symbTag = getTag(sym);
            state->mem()->write(cmd.WriteFile.symbTag, symbTag.c_str(), symbTag.length()+1);
        }
    }
}

void CyFiFunctionModels::handleWinHttpWriteData(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
  // Read function arguments
  uint64_t args[4];
  args[0] = (uint64_t) cmd.WinHttpWriteData.hRequest;
  args[1] = (uint64_t) cmd.WinHttpWriteData.lpBuffer;
  args[2] = (uint64_t) cmd.WinHttpWriteData.dwNumberOfBytesToWrite;
  args[3] = (uint64_t) cmd.WinHttpWriteData.lpdwNumberOfBytesWritten;

  WinHttpWriteDataHelper(state, args, retExpr);
}


void CyFiFunctionModels::handleInternetConnectA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    ref<Expr> data = state->mem()->read(cmd.InternetConnectA.lpszServerName, countExprNumBytes * 8);
    auto expr_kind_counts = countExprKinds(data, countExprNumBytes);
    getDebugStream(state) << "InternetConnectA: lpszServerName: " << expr_kind_counts;

#if PRINT_DOT_GRAPH
    dumpExpresisonToFile(data);
#endif
}

void CyFiFunctionModels::handleInternetConnectW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    ref<Expr> data = state->mem()->read(cmd.InternetConnectW.lpszServerName, countExprNumBytes * 8);
    auto expr_kind_counts = countExprKinds(data, countExprNumBytes);
    getDebugStream(state) << "InternetConnectW: lpszServerName: " << expr_kind_counts;

#if PRINT_DOT_GRAPH
    dumpExpresisonToFile(data);
#endif
}

void CyFiFunctionModels::handleInternetOpenUrlA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    ref<Expr> data = state->mem()->read(cmd.InternetOpenUrlA.lpszUrl, countExprNumBytes * 8);
    auto expr_kind_counts = countExprKinds(data, countExprNumBytes);
    getDebugStream(state) << "InternetOpenUrlA: lpszUrl: " << expr_kind_counts;

#if PRINT_DOT_GRAPH
    dumpExpresisonToFile(data);
#endif
}

void CyFiFunctionModels::handleInternetOpenUrlW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    ref<Expr> data = state->mem()->read(cmd.InternetOpenUrlW.lpszUrl, countExprNumBytes * 8);
    auto expr_kind_counts = countExprKinds(data, countExprNumBytes);
    getDebugStream(state) << "InternetOpenUrlW: lpszUrl: " << expr_kind_counts;

#if PRINT_DOT_GRAPH
    dumpExpresisonToFile(data);
#endif
}

void CyFiFunctionModels::handleInternetReadFile(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    ref<Expr> data = state->mem()->read(state->regs()->getSp(), state->getPointerWidth());
    getCyfiStream(state) << "InternetreadFile " << data  << "\n";
}

void CyFiFunctionModels::handleInternetCrackUrlA(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t args[4];
    args[0] = (uint64_t) cmd.InternetCrackUrlA.lpszUrl;
    args[1] = (uint64_t) cmd.InternetCrackUrlA.dwUrlLength;
    args[2] = (uint64_t) cmd.InternetCrackUrlA.dwFlags;
    args[3] = (uint64_t) cmd.InternetCrackUrlA.lpUrlComponents;

    ref<Expr> data = state->mem()->read(args[0], state->getPointerWidth());

    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
	        std::string symbTag = getTag(sym);
            state->mem()->write(cmd.InternetCrackUrlA.symbTag, symbTag.c_str(), symbTag.length()+1);
        }
    }
}

void CyFiFunctionModels::handleInternetCrackUrlW(S2EExecutionState *state, CYFI_WINWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t args[4];
    args[0] = (uint64_t) cmd.InternetCrackUrlW.lpszUrl;
    args[1] = (uint64_t) cmd.InternetCrackUrlW.dwUrlLength;
    args[2] = (uint64_t) cmd.InternetCrackUrlW.dwFlags;
    args[3] = (uint64_t) cmd.InternetCrackUrlW.lpUrlComponents;

    ref<Expr> data = state->mem()->read(args[0], state->getPointerWidth());

    if(!data.isNull()) {
        if (!isa<ConstantExpr>(data)) {
            std::ostringstream ss;
            ss << data;
            std::string sym = ss.str();
	        std::string symbTag = getTag(sym);
            state->mem()->write(cmd.InternetCrackUrlW.symbTag, symbTag.c_str(), symbTag.length()+1);
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

        case WINWRAPPER_MEMSET: {
            handleMemset(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "MEMSET: Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_STRSTRA: {
            ref<Expr> retExpr;
            handleStrStrA(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }

        } break;

        case WINWRAPPER_STRSTRW: {
            handleStrStrW(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }

        } break;


        case WINWRAPPER_STRSTR: {
            ref<Expr> retExpr;
            handleStrStr(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }

        } break;


        case WINWRAPPER_STRTOK: {
            ref<Expr> retExpr;
            handleStrtok(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }

        } break;


        case WINWRAPPER_WINHTTPREADDATA: {
            ref<Expr> retExpr;
            handleWinHttpReadData(state, command, retExpr);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_WINHTTPCRACKURL: {
            ref<Expr> retExpr;
            handleWinHttpCrackUrl(state, command, retExpr);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "WinHttpCrackUrl: Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_WINHTTPCONNECT: {
            handleWinHttpConnect(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_WINHTTPWRITEDATA: {
            ref<Expr> retExpr;
            handleWinHttpWriteData(state, command, retExpr);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;


        case WINWRAPPER_INTERNETREADFILE: {
            handleInternetReadFile(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_INTERNETCRACKURLA: {
            ref<Expr> retExpr;
            handleInternetCrackUrlA(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "InternetCrackUrlA: Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_INTERNETCRACKURLW: {
            ref<Expr> retExpr;
            handleInternetCrackUrlW(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "InternetCrackUrlA: Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_INTERNETCONNECTA: {
            handleInternetConnectA(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_INTERNETCONNECTW: {
            handleInternetConnectW(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_INTERNETOPENURLA: {
            handleInternetOpenUrlA(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WINWRAPPER_INTERNETOPENURLW: {
            handleInternetOpenUrlW(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;


        case WINWRAPPER_WCSSTR: {
            handleWcsstr(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }

        } break;

        case WINWRAPPER_WRITEFILE: {
            handleWriteFile(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WRAPPER_CRC: {
            ref<Expr> retExpr;
            handleCrc(state, command, retExpr);
            UPDATE_RET_VAL(Crc, command);
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

} // namespace models
} // namespace plugins
} // namespace s2e
