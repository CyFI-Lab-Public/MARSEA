///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef S2E_PLUGINS_CYFISEARCHER_H
#define S2E_PLUGINS_CYFISEARCHER_H

#include <klee/Searcher.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/Searchers/MultiSearcher.h>
#include <s2e/Plugins/StaticAnalysis/ControlFlowGraph.h>
#include <s2e/Plugins/Support/KeyValueStore.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>

#include "Common.h"

#include <chrono>
#include <memory>
#include <random>
#include <unordered_map>
#include <algorithm>

namespace s2e {
class ModuleMap;
namespace plugins {

class DecreeMonitor;

///
/// \brief CyFiSearcher implements the Class-Uniform Path Analysis (CUPA) algorithm.
///
/// This algorithm groups paths into equivalence classes.
///
/// Consider the following chain of equivalence classes:
///
/// ["pc", "pagedir", "random"]
/// - pc is a class that groups states by program counters at fork
/// - pagedir groups states by the value of their page directory register
/// - random creates one class per state and picks one class at random
///
/// Each group in a class is an independent searcher that manages its own
/// set of paths. In this example, the class "pc" would have groups composed
/// of class "pagedir", and so on recursively.
///
/// The cupa searcher requests a state from the top most
/// class (i.e., "pc"). That class selects a group according to its policy, then
/// recursively asks sub-classes to retrieve a state. The leaf class returns
/// the actual state. An intermediate class could also return a state, not
/// recursing down the chain.
///
/// Adding a state is done similarly to selecting a state. Eventually, searchers
/// form a tree, each level of the tree corresponding to one class.
///
/// Chains of classes are not commutative:
/// "pc", "pagedir", "random" is different from "pagedir", "pc", "random".
///
class CyFiSearcher : public Plugin {
    S2E_PLUGIN

public:
    CyFiSearcher(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();

    klee::Searcher *createSearcher(unsigned level);

    void updateState(S2EExecutionState *state);
    void update(klee::ExecutionState *current, const klee::StateSet &addedStates, const klee::StateSet &removedStates);
    void enable(bool e);

    uint64_t getBatchTime() const {
        return m_batchTime;
    }

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc);
    void onBlockStart(S2EExecutionState *state, uint64_t pc);
    void onBlockEnd(S2EExecutionState *state, uint64_t pc, TranslationBlock *tb);
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                         const std::vector<klee::ref<klee::Expr>> &newConditions);

private:
    enum Classes { SEED, BATCH, PC, PAGEDIR, FORKCOUNT, PRIORITY, READCOUNT, RANDOM, GROUP };

    MultiSearcher *m_searchers;
    ModuleMap *m_map;
    klee::Searcher *m_top;
    std::vector<Classes> m_classes;
    bool m_enabled;

    uint64_t m_batchTime;

    std::string m_moduleName = "";
};

class CyFiSearcherClass : public klee::Searcher {
protected:
    CyFiSearcher *m_plg;
    unsigned m_level;

    // Current CUPA class for each state
    std::unordered_map<klee::ExecutionState *, uint64_t> m_stateClasses;

    // Searchers for each CUPA class
    std::map<uint64_t, std::unique_ptr<klee::Searcher>> m_searchers;

    std::mt19937 m_rnd;

    void doAddState(klee::ExecutionState *state, uint64_t stateClass);
    void doRemoveState(klee::ExecutionState *state);

    llvm::raw_ostream &getDebugStream(S2EExecutionState *state = nullptr) const;

protected:
    virtual std::string getName(){return "";};
    virtual uint64_t getClass(S2EExecutionState *state) = 0;

public:
    CyFiSearcherClass(CyFiSearcher *plugin, unsigned level) : m_plg(plugin), m_level(level){};

    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();
};

/**************************************************************/
/**************************************************************/
/**************************************************************/

class CyFiSearcherPcClass : public CyFiSearcherClass {
private:
    std::vector<S2EExecutionState *> stateOrd;
    std::unordered_map<S2EExecutionState *, uint64_t> stateOldPC;

public:
    CyFiSearcherPcClass(CyFiSearcher *plugin, unsigned level) : CyFiSearcherClass(plugin, level){};

protected:
    virtual std::string getName() {
        return "cyfi_pc";
    }

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates) {

        for (auto removedState : removedStates) {
            S2EExecutionState *s = static_cast<S2EExecutionState *>(removedState);
            stateOrd.erase(std::remove(stateOrd.begin(), stateOrd.end(), s), stateOrd.end());
        }

        CyFiSearcherClass::update(current, addedStates, removedStates);
    }

    virtual uint64_t getClass(S2EExecutionState *state);
    virtual klee::ExecutionState &selectState();

    // void doAddState(klee::ExecutionState *state, uint64_t stateClass);
    // void doRemoveState(klee::ExecutionState *state);
};

class CyFiSearcherPageDirClass : public CyFiSearcherClass {

public:
    CyFiSearcherPageDirClass(CyFiSearcher *plugin, unsigned level) : CyFiSearcherClass(plugin, level){};

protected:
    virtual std::string getName() {
        return "cyfi_pageDir";
    }

    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;

        return state->regs()->getPageDir();
    }
};

///
/// \brief The CyFiSearcherForkCountClass class splits states in two classes:
/// Those that forked more than x times at a given pc, and those that forked less.
/// If possible, prioritize states that forked less.
///
class CyFiSearcherForkCountClass : public CyFiSearcherClass {
private:
    typedef std::pair<uint64_t, uint64_t> pid_pc_t;
    typedef llvm::DenseMap<pid_pc_t, uint64_t> ForkCountMap;

    ForkCountMap m_map;

public:
    CyFiSearcherForkCountClass(CyFiSearcher *plugin, unsigned level) : CyFiSearcherClass(plugin, level){};

protected:
    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;

        auto p = std::make_pair(state->regs()->getPageDir(), state->regs()->getPc());
        uint64_t count = m_map[p];
        m_map[p] = count + 1;

        return count > 10 ? 1 : 0;
    }

    virtual klee::ExecutionState &selectState() {
        unsigned size = m_searchers.size();
        assert(size > 0 && size <= 2);
        (void) size;

        return std::begin(m_searchers)->second->selectState();
    }
};

class CyFiSearcherBatchClass : public CyFiSearcherClass {
public:
    CyFiSearcherBatchClass(CyFiSearcher *plugin, unsigned level) : CyFiSearcherClass(plugin, level) {
        m_state = nullptr;
        m_batchTime = std::chrono::seconds(plugin->getBatchTime());
    }

private:
    virtual std::string getName() {
        return "cyfi_batch";
    }
    klee::ExecutionState *m_state;
    std::chrono::steady_clock::time_point m_lastSelectedTime;
    std::chrono::seconds m_batchTime;

protected:
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates) {
        if (removedStates.count(m_state)) {
            m_state = nullptr;
        }

        CyFiSearcherClass::update(current, addedStates, removedStates);
    }

    virtual uint64_t getClass(S2EExecutionState *state) {
        return 0;
    }

    virtual klee::ExecutionState &selectState() {
        using namespace std::chrono;
        auto t1 = steady_clock::now();
        auto d1 = seconds(m_batchTime);

        if (m_state) {
            if (t1 - m_lastSelectedTime < d1) {
                return *m_state;
            }
        }

        uint64_t allStates = 0;
        uint64_t validStates = 0;
        uint64_t inTargetModuleStates = 0;

        for (auto i: m_stateClasses) {
            allStates++;

            if (i.first->inTargetModule && klee::tbTrace.find((i.first)->startPC) == klee::tbTrace.end()) {
                validStates++;
            }

            if ((i.first)->inTargetModule) {
                inTargetModuleStates++;
            }
        }

        auto elapsed = steady_clock::now() - g_s2e->getRealStartTime();
        auto elapsedSeconds = duration_cast<seconds>(elapsed.time_since_epoch()).count();

        g_s2e->getDebugStream() << "[PLOT] \%ValidState: (" << elapsedSeconds << ", " << getName() << ", " << int(((float)validStates/allStates)*100) << ", " << int(((float)inTargetModuleStates/allStates)*100) << " , " << g_s2e->getExecutor()->getStatesCount() << ")\n";
        unsigned size = m_searchers.size();
        assert(size > 0);
        (void) size;
        m_state = &m_searchers.rbegin()->second->selectState();
        m_lastSelectedTime = t1;
        return *m_state;
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CYFISEARCHER_H
