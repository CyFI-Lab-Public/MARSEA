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

#include <s2e/cpu.h>

#include <cxxabi.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/Linux/DecreeMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>

#include <algorithm>
#include <random>

#include "NewCodeSearcher.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(NewCodeSearcher, "CUPA searcher", "", "ModuleExecutionDetector", "MultiSearcher", "ModuleMap");

///
/// \brief Initializes the CUPA Searcher plugin
///
/// Implementation notes
///
/// - Do not use onStateFork event to update states. Only use the standard
///   searcher API (selectState, update). onStateFork is hard to get
///   right and may result in corruption of the searcher state. The symptom
///   is the searcher returning a state that was already killed.
///
///   It is not totally clear why at this moment, so if the problem reappears
///   here are a few hypothesis that were checked:
///
///   1. An execution state might end up in multiple different searcher classes,
///   because getClass() may not be deterministic. In other words, calling
///   it once in onFork, then in updateState might lead to inserting the same
///   state into multiple classes. Later, if the state is deleted, it will only
///   be deleted from one class, potentially leading to selectNextState()
///   returning a stale state pointer that could have already been freed.
///   (XXX: adding doRemove in update() doesn't fix it)
///
///   2. Some plugin in onFork could throw an exception, preventing the CUPA
///   searcher from updating the state properly.
///
void NewCodeSearcher::initialize() {
    m_searchers = s2e()->getPlugin<MultiSearcher>();
    m_map = s2e()->getPlugin<ModuleMap>();

    ConfigFile *cfg = s2e()->getConfig();

    m_batchTime = cfg->getInt(getConfigKey() + ".batchTime", 5);

    m_moduleName = s2e()->getConfig()->getString(getConfigKey() + ".moduleName");

    ConfigFile::string_list classes = cfg->getStringList(getConfigKey() + ".classes");

    if (classes.empty()) {
        getWarningsStream() << "Please specify one or more searcher classes\n";
        exit(-1);
    }

    foreach2 (it, classes.begin(), classes.end()) {
        if (*it == "seed") {
            m_classes.push_back(SEED);
        } else if (*it == "batch") {
            m_classes.push_back(BATCH);
        } else if (*it == "pc") {
            m_classes.push_back(PC);
        } else if (*it == "pagedir") {
            m_classes.push_back(PAGEDIR);
        } else if (*it == "forkcount") {
            m_classes.push_back(FORKCOUNT);
        } else if (*it == "priority") {
            m_classes.push_back(PRIORITY);
        } else if (*it == "readcount") {
            m_classes.push_back(READCOUNT);
        } else if (*it == "random") {
            m_classes.push_back(RANDOM);
        } else if (*it == "group") {
            m_classes.push_back(GROUP);
        } else if (*it == "cyfi") {
            m_classes.push_back(CYFI);
        } else {
            getWarningsStream() << "Unknown class " << *it;
            exit(-1);
        }
    }

    m_top = createSearcher(0);

    m_searchers->registerSearcher("NewCodeSearcher", m_top);

    bool ok;
    m_enabled = cfg->getBool(getConfigKey() + ".enabled", true, &ok);
    if (ok && !m_enabled) {
        getInfoStream() << "NewCodeSearcher is in disabled mode\n";
    } else {
        s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &NewCodeSearcher::onTranslateBlockStart)
        );
        // s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &NewCodeSearcher::onFork));
        s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &NewCodeSearcher::onTranslateBlockEnd)
        );
        enable(true);
    }
}

void NewCodeSearcher::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   TranslationBlock *tb, uint64_t pc) {
    auto currentMod = m_map->getModule(state, pc);

    if (!currentMod) {
        return;
    }

    if (!m_moduleName.empty()) {
        if (currentMod->Name == m_moduleName) {
            signal->connect(sigc::mem_fun(*this, &NewCodeSearcher::onBlockStart));
        }
    }

    return;
}

void NewCodeSearcher::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc) {
    
    auto currentMod = m_map->getModule(state, pc);

    if (!currentMod) {
        return;
    }

    if (!m_moduleName.empty()) {
        if (currentMod->Name == m_moduleName) {
            signal->connect(sigc::bind(sigc::mem_fun(*this, &NewCodeSearcher::onBlockEnd), tb));
        }
    }

    return;
}

void NewCodeSearcher::onBlockStart(S2EExecutionState *state, uint64_t pc) {
    statePCMap[state] = pc;

}

void NewCodeSearcher::onBlockEnd(S2EExecutionState *state, uint64_t pc, TranslationBlock *tb) {
    //getInfoStream() << "Add block " << tb->pc << "\n";
    tbTrace[tb->pc] = True;
    return;
}

bool NewCodeSearcher::isStateTbExplored(S2EExecutionState *state) {

    if (statePCMap.find(state) != statePCMap.end()) {
        uint64_t startPC = statePCMap[state];
        if (tbTrace.find(startPC) == tbTrace.end()) {
            return true;
        }
    }
    return false;
}

bool NewCodeSearcher::isStateInModule(S2EExecutionState *state) {

    auto currentMod = m_map->getModule(state, state->regs()->getPc());

    if (!currentMod) {
        return false;
    }

    if (!m_moduleName.empty()) {
        if (currentMod->Name == m_moduleName) {
            return true;
        }
    }

    return false;

    // if (stateInTarget.find(state) != stateInTarget.end() && stateInTarget[state]) {
    //     return true;
    // }

    // return false;
}

void NewCodeSearcher::enable(bool e) {
    m_enabled = e;
    if (e) {
        m_searchers->selectSearcher("NewCodeSearcher");
        getInfoStream() << "NewCodeSearcher is now active\n";
    } else {
        getInfoStream() << "NewCodeSearcher is now disabled\n";
    }
}

klee::Searcher *NewCodeSearcher::createSearcher(unsigned level) {
    assert(level <= m_classes.size());
    klee::Searcher *searcher;

    if (level < m_classes.size()) {
        switch (m_classes[level]) {
            case SEED:
                searcher = new NewCodeSearcherSeedClass(this, level);
                break;
            case BATCH:
                searcher = new NewCodeSearcherBatchClass(this, level);
                break;
            case PC:
                searcher = new NewCodeSearcherPcClass(this, level);
                break;
            case PAGEDIR:
                searcher = new NewCodeSearcherPageDirClass(this, level);
                break;
            case FORKCOUNT:
                searcher = new NewCodeSearcherForkCountClass(this, level);
                break;
            case PRIORITY:
                searcher = new NewCodeSearcherPriorityClass(this, level);
                break;
            case READCOUNT:
                searcher = new NewCodeSearcherReadCountClass(this, level);
                break;
            case RANDOM:
                searcher = new NewCodeSearcherRandomClass(this, level);
                break;
            case GROUP:
                searcher = new NewCodeSearcherGroupClass(this, level);
                break;
            case CYFI:
                searcher = new NewCodeSearcherCyFiClass(this, level);
                break;
            default:
                abort();
        }
    } else {
        searcher = klee::constructUserSearcher();
    }

    return searcher;
}

void NewCodeSearcher::updateState(S2EExecutionState *state) {
    m_top->removeState(state);
    m_top->addState(state);
}

void NewCodeSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                          const klee::StateSet &removedStates) {
    m_top->update(current, addedStates, removedStates);
}

/**************************************************************/
/**************************************************************/
/**************************************************************/

llvm::raw_ostream &NewCodeSearcherClass::getDebugStream(S2EExecutionState *state) const {
    if (m_plg->getLogLevel() <= LOG_DEBUG) {
        // TODO: find a way to move this to plugin class.
        int status;
        std::string name = typeid(*this).name();
        char *demangled = abi::__cxa_demangle(name.c_str(), 0, 0, &status);
        llvm::raw_ostream &ret = m_plg->getDebugStream(state) << demangled << "(" << hexval(this) << ") - ";
        free(demangled);
        return ret;
    } else {
        return m_plg->getNullStream();
    }
}

void NewCodeSearcherClass::doAddState(klee::ExecutionState *state, uint64_t stateClass) {
    auto searchersIt = m_searchers.find(stateClass);
    if (searchersIt == m_searchers.end()) {
        klee::Searcher *searcher = m_plg->createSearcher(m_level + 1);
        searchersIt = m_searchers.emplace(stateClass, std::unique_ptr<klee::Searcher>(searcher)).first;
    }

    assert(m_stateClasses.find(state) == m_stateClasses.end());
    m_stateClasses[state] = stateClass;
    searchersIt->second->addState(state);
}

void NewCodeSearcherClass::doRemoveState(klee::ExecutionState *state) {
    auto stateClassesIt = m_stateClasses.find(state);
    if (stateClassesIt == m_stateClasses.end()) {
        return;
    }

    uint64_t stateClass = stateClassesIt->second;
    m_stateClasses.erase(stateClassesIt);

    // Remove state from the searcher
    auto searchersIt = m_searchers.find(stateClass);
    assert(searchersIt != m_searchers.end());
    searchersIt->second->removeState(state);

    if (searchersIt->second->empty()) {
        m_searchers.erase(searchersIt);
    }
}

void NewCodeSearcherClass::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                               const klee::StateSet &removedStates) {
    
    for (auto addedState : addedStates) {
        doRemoveState(addedState);
        if (m_stateClasses.count(addedState) == 0) {
            S2EExecutionState *s = static_cast<S2EExecutionState *>(addedState);
            // XXX: removing state here first before re-adding
            // does not solve the problem caused by fork
            // (see implementation notes)
            doAddState(addedState, getClass(s));
        }
    }

    for (auto removedState : removedStates) {
        doRemoveState(removedState);
    }
}

klee::ExecutionState &NewCodeSearcherClass::selectState() {
    assert(!m_searchers.empty());

    int idx = std::uniform_int_distribution<>(0, m_searchers.size() - 1)(m_rnd);
    getDebugStream(nullptr) << "selectState class " << idx << "\n";
    return std::next(std::begin(m_searchers), idx)->second->selectState();
}

bool NewCodeSearcherClass::empty() {
    return m_searchers.empty();
}

/**************************************************************/
/**************************************************************/
/**************************************************************/

struct PriorityClass {
    NewCodeSearcher *cupa;
    sigc::connection s_priority_connection;

    void onLocalPut(S2EExecutionState *state, const std::string &key, const std::string &value, bool success) {
        if (!success || key != "priority") {
            return;
        }

        cupa->getDebugStream(state) << "Updating priority\n";

        cupa->updateState(state);
    }
};

static PriorityClass s_pc;

NewCodeSearcherPriorityClass::NewCodeSearcherPriorityClass(NewCodeSearcher *plugin, unsigned level)
    : NewCodeSearcherClass(plugin, level) {
    m_kvs = plugin->s2e()->getPlugin<KeyValueStore>();
    if (!m_kvs) {
        plugin->getDebugStream() << "KeyValueStore plugin must be enabled for the NewCodeSearcherPriorityClass\n";
        exit(-1);
    }

    if (!s_pc.s_priority_connection.connected()) {
        s_pc.cupa = plugin;
        s_pc.s_priority_connection = m_kvs->onLocalPut.connect(sigc::mem_fun(s_pc, &PriorityClass::onLocalPut));
    }
}

uint64_t NewCodeSearcherPriorityClass::getClass(S2EExecutionState *state) {
    std::string value;
    if (!m_kvs->get(state, "priority", value)) {
        return 0;
    }

    uint64_t p = strtol(value.c_str(), nullptr, 0);
    getDebugStream(state) << "NewCodeSearcherPriorityClass priority " << p << "\n";
    return p;
}

struct GroupClass {
    NewCodeSearcher *cupa;
    sigc::connection s_group_connection;

    void onLocalPut(S2EExecutionState *state, const std::string &key, const std::string &value, bool success) {
        if (!success || key != "group") {
            return;
        }

        cupa->getDebugStream(state) << "Updating group\n";

        cupa->updateState(state);
    }
};

static GroupClass s_gc;

NewCodeSearcherGroupClass::NewCodeSearcherGroupClass(NewCodeSearcher *plugin, unsigned level)
    : NewCodeSearcherClass(plugin, level) {
    m_kvs = plugin->s2e()->getPlugin<KeyValueStore>();
    if (!m_kvs) {
        plugin->getDebugStream() << "KeyValueStore plugin must be enabled for the NewCodeSearcherGroupClass\n";
        exit(-1);
    }

    if (!s_gc.s_group_connection.connected()) {
        s_gc.cupa = plugin;
        s_gc.s_group_connection = m_kvs->onLocalPut.connect(sigc::mem_fun(s_gc, &GroupClass::onLocalPut));
    }
}

uint64_t NewCodeSearcherGroupClass::getClass(S2EExecutionState *state) {
    std::string value;
    if (!m_kvs->get(state, "group", value)) {
        return 0;
    }

    uint64_t group = strtoull(value.c_str(), nullptr, 0);
    getDebugStream(state) << "NewCodeSearcherGroupClass group " << group << "\n";
    return group;
}

klee::ExecutionState &NewCodeSearcherRandomClass::selectState() {
    if (m_states.size() > 0) {
        int idx = std::uniform_int_distribution<>(0, m_states.size() - 1)(m_rnd);
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*std::next(std::begin(m_states), idx));
        getDebugStream(es) << hexval(this) << " selected state " << es->getID() << "\n";
        return *es;
    }
    return NewCodeSearcherClass::selectState();
}

klee::ExecutionState &NewCodeSearcherSeedClass::selectState() {
    /**
     * Never schedule the unique state in the seed class,
     *  unless it's the only state.
     */
    auto it = m_searchers.find(1);
    if (it == m_searchers.end()) {
        return NewCodeSearcherClass::selectState();
    }

    return (*it).second->selectState();
}

void NewCodeSearcherRandomClass::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                                     const klee::StateSet &removedStates) {
    foreach2 (it, addedStates.begin(), addedStates.end()) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*it);
        m_states.insert(es);
    }

    foreach2 (it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*it);
        m_states.erase(es);
    }
}

sigc::connection NewCodeSearcherReadCountClass::s_read_conn;

NewCodeSearcherReadCountClass::NewCodeSearcherReadCountClass(NewCodeSearcher *plugin, unsigned level)
    : NewCodeSearcherClass(plugin, level) {
    m_monitor = plugin->s2e()->getPlugin<DecreeMonitor>();

    if (!s_read_conn.connected()) {
        s_read_conn = m_monitor->onSymbolicRead.connect(sigc::ptr_fun(&NewCodeSearcherReadCountClass::onSymbolicRead));
    }

    getDebugStream() << "Searcher created\n";
}

/**
 * This has to be a static function because we don't know in which bucket the class is.
 * Also, updating the class would require updating all the downstream cupa classes.
 * Need to ask the cupa searcher to reconstruct the chain.
 */
void NewCodeSearcherReadCountClass::onSymbolicRead(
    S2EExecutionState *state, uint64_t pid, uint64_t fd, uint64_t size,
    const std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> &data,
    klee::ref<klee::Expr> sizeExpr) {
    NewCodeSearcher *searcher = g_s2e->getPlugin<NewCodeSearcher>();
    searcher->updateState(state);
}

/**
 * Selects the class with the fewest number of reads first.
 */
klee::ExecutionState &NewCodeSearcherReadCountClass::selectState() {
    assert(!m_searchers.empty());
    return (*m_searchers.begin()).second->selectState();
}

uint64_t NewCodeSearcherReadCountClass::getClass(S2EExecutionState *state) {
    if (!g_s2e_state) {
        return 0;
    }

    return m_monitor->getSymbolicReadsCount(state);
}

uint64_t NewCodeSearcherCyFiClass::getClass(S2EExecutionState *state) {
    if (!g_s2e_state)
        return 0;

    if (m_plg->isStateInModule(state)) {
        stateOrd.erase(std::remove(stateOrd.begin(), stateOrd.end(), state), stateOrd.end());
        stateOrd.push_back(state);
    } else {
        stateOrd.erase(std::remove(stateOrd.begin(), stateOrd.end(), state), stateOrd.end());
    }

    return 0;
}

} // namespace plugins
} // namespace s2e
