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

#ifndef S2E_PLUGINS_NewCodeSearcher_H
#define S2E_PLUGINS_NewCodeSearcher_H

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

namespace s2e {
class ModuleMap;
namespace plugins {

class DecreeMonitor;

///
/// \brief NewCodeSearcher implements the Class-Uniform Path Analysis (CUPA) algorithm.
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
class NewCodeSearcher : public Plugin {
    S2E_PLUGIN
    friend class NewCodeSearcherReadCountClass;

public:
    NewCodeSearcher(S2E *s2e) : Plugin(s2e) {
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
    void onBlockStart(S2EExecutionState *state, uint64_t pc);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc);
    void onBlockEnd(S2EExecutionState *state, uint64_t pc, TranslationBlock *tb);
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                         const std::vector<klee::ref<klee::Expr>> &newConditions);

    bool isStateTbExplored(S2EExecutionState *state);
    bool isStateInModule(S2EExecutionState *state);                    

private:
    enum Classes { SEED, BATCH, PC, PAGEDIR, FORKCOUNT, PRIORITY, READCOUNT, RANDOM, GROUP, CYFI };

    MultiSearcher *m_searchers;
    ModuleMap *m_map;
    klee::Searcher *m_top;
    std::vector<Classes> m_classes;
    bool m_enabled;

    uint64_t m_batchTime;

    std::string m_moduleName = "";

    std::unordered_map<const S2EExecutionState*, uint64_t> statePCMap;
    
    std::unordered_map<uint64_t, bool> tbTrace;

};

class NewCodeSearcherClass : public klee::Searcher {
protected:
    NewCodeSearcher *m_plg;
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
    NewCodeSearcherClass(NewCodeSearcher *plugin, unsigned level) : m_plg(plugin), m_level(level){};

    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();
};

/**************************************************************/
/**************************************************************/
/**************************************************************/

class NewCodeSearcherSeedClass : public NewCodeSearcherClass {
public:
    NewCodeSearcherSeedClass(NewCodeSearcher *plugin, unsigned level) : NewCodeSearcherClass(plugin, level){};

protected:
    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state) {
            return 0;
        }

        return state->getID() == 0 ? 0 : 1;
    }

    virtual klee::ExecutionState &selectState();
};

class NewCodeSearcherPcClass : public NewCodeSearcherClass {
public:
    NewCodeSearcherPcClass(NewCodeSearcher *plugin, unsigned level) : NewCodeSearcherClass(plugin, level){};

protected:
    virtual std::string getName() {
        return "pc";
    }

    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;
        return state->regs()->getPc();
    }
};

class NewCodeSearcherPageDirClass : public NewCodeSearcherClass {
public:
    NewCodeSearcherPageDirClass(NewCodeSearcher *plugin, unsigned level) : NewCodeSearcherClass(plugin, level){};

protected:
    virtual std::string getName() {
        return "pageDir";
    }

    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;
        return state->regs()->getPageDir();
    }
};

class NewCodeSearcherRandomClass : public NewCodeSearcherClass {
public:
    NewCodeSearcherRandomClass(NewCodeSearcher *plugin, unsigned level) : NewCodeSearcherClass(plugin, level){};

    virtual klee::ExecutionState &selectState();
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty() {
        return m_states.empty();
    }

private:
    typedef std::set<S2EExecutionState *> StateSet;
    StateSet m_states;

protected:
    virtual std::string getName() {
        return "random";
    }

    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;
        return std::uniform_int_distribution<>(0, m_states.size() - 1)(m_rnd);
    }
};

class NewCodeSearcherReadCountClass : public NewCodeSearcherClass {
public:
    NewCodeSearcherReadCountClass(NewCodeSearcher *plugin, unsigned level);
    virtual ~NewCodeSearcherReadCountClass() {
    }

    virtual klee::ExecutionState &selectState();

private:
    DecreeMonitor *m_monitor;

    static sigc::connection s_read_conn;

    static void onSymbolicRead(S2EExecutionState *state, uint64_t pid, uint64_t fd, uint64_t size,
                               const std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> &data,
                               klee::ref<klee::Expr> sizeExpr);

protected:
    virtual uint64_t getClass(S2EExecutionState *state);
};

///
/// \brief The NewCodeSearcherForkCountClass class splits states in two classes:
/// Those that forked more than x times at a given pc, and those that forked less.
/// If possible, prioritize states that forked less.
///
class NewCodeSearcherForkCountClass : public NewCodeSearcherClass {
private:
    typedef std::pair<uint64_t, uint64_t> pid_pc_t;
    typedef llvm::DenseMap<pid_pc_t, uint64_t> ForkCountMap;

    ForkCountMap m_map;

public:
    NewCodeSearcherForkCountClass(NewCodeSearcher *plugin, unsigned level) : NewCodeSearcherClass(plugin, level){};

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

class NewCodeSearcherPriorityClass : public NewCodeSearcherClass {
private:
    KeyValueStore *m_kvs;

public:
    NewCodeSearcherPriorityClass(NewCodeSearcher *plugin, unsigned level);

protected:
    virtual std::string getName() {
        return "priority";
    }

    virtual uint64_t getClass(S2EExecutionState *state);

    virtual klee::ExecutionState &selectState() {
        unsigned size = m_searchers.size();
        assert(size > 0);
        (void) size;

        return m_searchers.rbegin()->second->selectState();
    }
};

///
/// \brief Split states into groups of equal selection probability
///
/// Split states into groups by property 'group' from KeyValueStore.
/// A uniform distribution is used to select state from groups.
///
class NewCodeSearcherGroupClass : public NewCodeSearcherClass {
private:
    KeyValueStore *m_kvs;

public:
    NewCodeSearcherGroupClass(NewCodeSearcher *plugin, unsigned level);

protected:
    virtual std::string getName() {
        return "searchgroup";
    }

    virtual uint64_t getClass(S2EExecutionState *state);
};

class NewCodeSearcherCyFiClass : public NewCodeSearcherClass {
public:
    NewCodeSearcherCyFiClass (NewCodeSearcher *plugin, unsigned level) :  NewCodeSearcherClass(plugin, level) {};

private:
    std::vector<S2EExecutionState *> stateOrd;

protected:
    virtual std::string getName() {
        return "cyfi new code";
    }

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates) {
        for (auto removedState : removedStates) {
            stateOrd.erase(std::remove(stateOrd.begin(), stateOrd.end(), removedState), stateOrd.end());
        }

        NewCodeSearcherClass::update(current, addedStates, removedStates);
    }

    virtual uint64_t getClass(S2EExecutionState *state);

    virtual klee::ExecutionState &selectState() {
        S2EExecutionState *m_state = nullptr;

        for (std::vector<S2EExecutionState *>::reverse_iterator it = stateOrd.rbegin(), ie = stateOrd.rend(); it != ie; ++it) {
            if (m_plg->isStateInModule(*it) && !m_plg->isStateTbExplored(*it)) {
                m_state = *it;
            }
        }

        if (m_state != nullptr) {
            return *m_state;
        }

        for (std::vector<S2EExecutionState *>::reverse_iterator it = stateOrd.rbegin(), ie = stateOrd.rend(); it != ie; ++it) {
            if (m_plg->isStateInModule(*it)) {
                m_state = *it;
            }
        }

        if (m_state != nullptr) {
            return *m_state;
        }

        unsigned size = m_searchers.size();
        assert(size > 0);
        (void) size;
        return m_searchers.rbegin()->second->selectState();
    }
};

class NewCodeSearcherBatchClass : public NewCodeSearcherClass {
public:
    NewCodeSearcherBatchClass(NewCodeSearcher *plugin, unsigned level) : NewCodeSearcherClass(plugin, level) {
        m_state = nullptr;
        m_batchTime = std::chrono::seconds(plugin->getBatchTime());
    }

private:
    virtual std::string getName() {
        return "batch";
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

        NewCodeSearcherClass::update(current, addedStates, removedStates);
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

#endif // S2E_PLUGINS_NewCodeSearcher_H
