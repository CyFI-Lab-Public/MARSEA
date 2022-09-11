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

#include "CyFiSearcher.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(CyFiSearcher, "CyFi searcher", "", "ModuleExecutionDetector", "MultiSearcher", "ModuleMap");

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
void CyFiSearcher::initialize() {
    m_searchers = s2e()->getPlugin<MultiSearcher>();
    m_map = s2e()->getPlugin<ModuleMap>();

    ConfigFile *cfg = s2e()->getConfig();

    m_batchTime = cfg->getInt(getConfigKey() + ".batchTime", 5);

    m_moduleName = s2e()->getConfig()->getString(getConfigKey() + ".moduleName");

    m_classes.push_back(BATCH);
    m_classes.push_back(PAGEDIR);
    m_classes.push_back(PC);
    // ConfigFile::string_list classes = cfg->getStringList(getConfigKey() + ".classes");

    // if (classes.empty()) {
    //     getWarningsStream() << "Please specify one or more searcher classes\n";
    //     exit(-1);
    // }

    // foreach2 (it, classes.begin(), classes.end()) {
    //     if (*it == "seed") {
    //         m_classes.push_back(SEED);
    //     } else if (*it == "batch") {
    //         m_classes.push_back(BATCH);
    //     } else if (*it == "pc") {
    //         m_classes.push_back(PC);
    //     } else if (*it == "pagedir") {
    //         m_classes.push_back(PAGEDIR);
    //     } else if (*it == "forkcount") {
    //         m_classes.push_back(FORKCOUNT);
    //     } else if (*it == "priority") {
    //         m_classes.push_back(PRIORITY);
    //     } else if (*it == "readcount") {
    //         m_classes.push_back(READCOUNT);
    //     } else if (*it == "random") {
    //         m_classes.push_back(RANDOM);
    //     } else if (*it == "group") {
    //         m_classes.push_back(GROUP);
    //     } else {
    //         getWarningsStream() << "Unknown class " << *it;
    //         exit(-1);
    //     }
    // }

    m_top = createSearcher(0);

    m_searchers->registerSearcher("CyFiSearcher", m_top);

    bool ok;
    m_enabled = cfg->getBool(getConfigKey() + ".enabled", true, &ok);
    if (ok && !m_enabled) {
        getInfoStream() << "CyFiSearcher is in disabled mode\n";
    } else {
        s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &CyFiSearcher::onTranslateBlockStart)
        );

        s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &CyFiSearcher::onTranslateBlockEnd)
        );

        s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &CyFiSearcher::onFork));
        enable(true);
    }

}

void CyFiSearcher::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                         const std::vector<klee::ref<klee::Expr>> &newConditions) {
    for(auto i: newStates) {

        // if (i->inTargetModule) {
        //     continue;
        // }

        auto currentMod = m_map->getModule(state, i->startPC);

        if (!currentMod) {
            i->inTargetModule = false;
            continue;
        }

        if (!m_moduleName.empty()) {
            if (currentMod->Name == m_moduleName) {
                // g_s2e->getDebugStream() << "state pc: " << hexval(state->startPC) << " new state pc: " << hexval(i->startPC) << "\n";
                i->inTargetModule = true;
            } else {
                i->inTargetModule = false;
            }
        }
    }
}

void CyFiSearcher::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   TranslationBlock *tb, uint64_t pc) {
    auto currentMod = m_map->getModule(state, pc);

    if (!currentMod) {
        return;
    }

    if (!m_moduleName.empty()) {
        if (currentMod->Name == m_moduleName) {
            signal->connect(sigc::mem_fun(*this, &CyFiSearcher::onBlockStart));
        }
    }

    return;
}


void CyFiSearcher::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc) {
    
    auto currentMod = m_map->getModule(state, pc);

    if (!currentMod) {
        return;
    }

    if (!m_moduleName.empty()) {
        if (currentMod->Name == m_moduleName) {
            signal->connect(sigc::bind(sigc::mem_fun(*this, &CyFiSearcher::onBlockEnd), tb));
        }
    }

    return;
}

void CyFiSearcher::onBlockStart(S2EExecutionState *state, uint64_t pc) {
    state->startPC = pc;

    return;
}

void CyFiSearcher::onBlockEnd(S2EExecutionState *state, uint64_t pc, TranslationBlock *tb) {
    getInfoStream() << "Add blocccck " << tb->pc << "\n";
    klee::tbTrace[tb->pc] = True;
    return;
}

void CyFiSearcher::enable(bool e) {
    m_enabled = e;
    if (e) {
        m_searchers->selectSearcher("CyFiSearcher");
        getInfoStream() << "CyFiSearcher is now active\n";
    } else {
        getInfoStream() << "CyFiSearcher is now disabled\n";
    }
}

klee::Searcher *CyFiSearcher::createSearcher(unsigned level) {
    assert(level <= m_classes.size());
    klee::Searcher *searcher;

    if (level < m_classes.size()) {
        switch (m_classes[level]) {
            case BATCH:
                //g_s2e->getDebugStream() << "Create Batch Searcher\n";
                searcher = new CyFiSearcherBatchClass(this, level);
                break;
            case PC:
                // g_s2e->getDebugStream() << "Create PC Searcher\n";
                searcher = new CyFiSearcherPcClass(this, level);
                break;
            case PAGEDIR:
                //g_s2e->getDebugStream() << "Create PageDir Searcher\n";
                searcher = new CyFiSearcherPageDirClass(this, level);
                break;
            default:
                abort();
        }
    } else {
        searcher = klee::constructUserSearcher();
    }

    return searcher;
}

void CyFiSearcher::updateState(S2EExecutionState *state) {
    m_top->removeState(state);
    m_top->addState(state);
}

void CyFiSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                          const klee::StateSet &removedStates) {
    m_top->update(current, addedStates, removedStates);
}

/**************************************************************/
/**************************************************************/
/**************************************************************/

llvm::raw_ostream &CyFiSearcherClass::getDebugStream(S2EExecutionState *state) const {
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

void CyFiSearcherClass::doAddState(klee::ExecutionState *state, uint64_t stateClass) {
    g_s2e->getDebugStream() << getName() << "\n";
    auto searchersIt = m_searchers.find(stateClass);
    if (searchersIt == m_searchers.end()) {
        klee::Searcher *searcher = m_plg->createSearcher(m_level + 1);
        searchersIt = m_searchers.emplace(stateClass, std::unique_ptr<klee::Searcher>(searcher)).first;
    }
    // g_s2e->getDebugStream() << getName() << "1\n";
    assert(m_stateClasses.find(state) == m_stateClasses.end());
    m_stateClasses[state] = stateClass;
    // g_s2e->getDebugStream() << getName() << "2\n";
    searchersIt->second->addState(state);
    // g_s2e->getDebugStream() << getName() << "3\n";
}

void CyFiSearcherClass::doRemoveState(klee::ExecutionState *state) {
    auto stateClassesIt = m_stateClasses.find(state);
    if (stateClassesIt == m_stateClasses.end()) {
        return;
    }

    // g_s2e->getDebugStream() << "old class: " << hexval(stateClassesIt->second) << "\n";

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

void CyFiSearcherClass::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                               const klee::StateSet &removedStates) {
    
    using namespace std::chrono;
    auto elapsed = steady_clock::now() - g_s2e->getRealStartTime();
    auto elapsedSeconds = duration_cast<seconds>(elapsed.time_since_epoch()).count();

    if (addedStates.size() && (!addedStates.count(current))) {
        g_s2e->getDebugStream() << "[PLOT] #Searchers: (" << elapsedSeconds << ", " << getName() << ", " << m_searchers.size() << "," << g_s2e->getExecutor()->getStatesCount() <<")\n";
    }

    for (auto addedState : addedStates) {
        if (current == addedState) {
            // g_s2e->getDebugStream() << "Updating current state " << hexval(current->startPC) << "\n";
            S2EExecutionState *scurrent = static_cast<S2EExecutionState *>(addedState);
            CyFiSearcher *searcher = g_s2e->getPlugin<CyFiSearcher>();
            searcher->updateState(scurrent);
            continue;

        }
        if (m_stateClasses.count(addedState) == 0) {
            S2EExecutionState *s = static_cast<S2EExecutionState *>(addedState);
            // XXX: removing state here first before re-adding
            // does not solve the problem caused by fork
            // (see implementation notes)
            doAddState(addedState, getClass(s));
        }
    }

    for (auto removedState : removedStates) {
        // g_s2e->getDebugStream() << "Remove " << hexval(removedState->startPC) << "\n";
        doRemoveState(removedState);
    }
    
}

klee::ExecutionState &CyFiSearcherClass::selectState() {
    assert(!m_searchers.empty());

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

    using namespace std::chrono;
    auto elapsed = steady_clock::now() - g_s2e->getRealStartTime();
    auto elapsedSeconds = duration_cast<seconds>(elapsed.time_since_epoch()).count();

    g_s2e->getDebugStream() << "[PLOT] \%ValidState: (" << elapsedSeconds << ", " << getName() << ", " << int(((float)validStates/allStates)*100) << ", " << int(((float)inTargetModuleStates/allStates)*100) << ", " << g_s2e->getExecutor()->getStatesCount() << ")\n";
    int idx = std::uniform_int_distribution<>(0, m_searchers.size() - 1)(m_rnd);
    getDebugStream(nullptr) << "selectState class " << idx << "\n";
    return std::next(std::begin(m_searchers), idx)->second->selectState();
}

bool CyFiSearcherClass::empty() {
    return m_searchers.empty();
}

// void CyFiSearcherPcClass::doAddState(klee::ExecutionState *state, uint64_t stateClass) {
//     g_s2e->getDebugStream() << getName() << "\n";
//     auto searchersIt = m_searchers.find(stateClass);
//     if (searchersIt == m_searchers.end()) {
//         klee::Searcher *searcher = m_plg->createSearcher(m_level + 1);
//         searchersIt = m_searchers.emplace(stateClass, std::unique_ptr<klee::Searcher>(searcher)).first;
//     }
//     g_s2e->getDebugStream() << getName() << "1\n";
//     assert(m_stateClasses.find(state) == m_stateClasses.end());
//     m_stateClasses[state] = stateClass;
//     g_s2e->getDebugStream() << getName() << "2\n";
//     searchersIt->second->addState(state);
//     g_s2e->getDebugStream() << getName() << "3\n";
// }

// void CyFiSearcherPcClass::doRemoveState(klee::ExecutionState *state) {
//     auto stateClassesIt = m_stateClasses.find(state);
//     if (stateClassesIt == m_stateClasses.end()) {
//         return;
//     }

//     uint64_t stateClass = stateClassesIt->second;
//     m_stateClasses.erase(stateClassesIt);

//     // Remove state from the searcher
//     auto searchersIt = m_searchers.find(stateClass);
//     assert(searchersIt != m_searchers.end());
//     searchersIt->second->removeState(state);

//     if (searchersIt->second->empty()) {
//         m_searchers.erase(searchersIt);
//     }
// }


uint64_t CyFiSearcherPcClass::getClass(S2EExecutionState *state) {
    if (!g_s2e_state)
        return 0;

    if (state->inTargetModule) {
        stateOrd.erase(std::remove(stateOrd.begin(), stateOrd.end(), state), stateOrd.end());
        stateOrd.push_back(state);

        // g_s2e->getDebugStream() << "Add " << hexval(state->startPC) << "\n";

        // if (startPcOrdMap.find(state->startPC) != startPcOrdMap.end()) {
        //     startPcOrd.erase(startPcOrd.begin()+startPcOrdMap[state->startPC]);
        // }

        // g_s2e->getDebugStream() << "Add " << hexval(state->startPC) << "\n";

        // startPcOrd.push_back(state->startPC);
        // startPcOrdMap[state->startPC] = startPcOrd.size() - 1;
    }

    if (!state->inTargetModule) {
        // g_s2e->getDebugStream() << "Erase " << hexval(state->startPC) << "\n";
        stateOrd.erase(std::remove(stateOrd.begin(), stateOrd.end(), state), stateOrd.end());
    }

    return state->startPC;
}

klee::ExecutionState &CyFiSearcherPcClass::selectState() {

    //Traverse stateOrd in the reversed order, choose the one to the new code region
    for (std::vector<S2EExecutionState *>::reverse_iterator i = stateOrd.rbegin();
    i != stateOrd.rend(); ++i) {
        if ((*i)->inTargetModule && klee::tbTrace.find((*i)->startPC) == klee::tbTrace.end()) {
            auto searchersIt = m_searchers.find((*i)->startPC);
            assert(searchersIt != m_searchers.end());
            return searchersIt->second->selectState();
        }
    }

    // Traverse the statePcOrd in the reversed order, choose the one with less fork count
    std::map<size_t, std::vector<uint64_t>> in_target_searcher_size_map;
    for (std::vector<S2EExecutionState *>::reverse_iterator i = stateOrd.rbegin();
    i != stateOrd.rend(); ++i) {
        auto searchersIt = m_searchers.find((*i)->startPC);
        if (searchersIt == m_searchers.end()) {
            g_s2e->getDebugStream() << "cant find " << hexval((*i)->startPC) << "\n";
        }
        assert(searchersIt != m_searchers.end());
        in_target_searcher_size_map[searchersIt->second->getSize()].push_back((*i)->startPC);
    }
    // Choose the smallest size and in this size, choose the most recent one
    if (in_target_searcher_size_map.size() > 0) {
        uint64_t chosenPC = *((in_target_searcher_size_map.begin()->second).begin());
        auto searchersIt = m_searchers.find(chosenPC);
        return searchersIt->second->selectState();
    }

    std::map<size_t, std::vector<uint64_t>> searcher_size_map;
    for (auto const& i: m_searchers) {
        searcher_size_map[i.second->getSize()].push_back(i.first);
    }
    uint64_t pc = *((searcher_size_map.begin()->second).begin());
    auto searchersIt = m_searchers.find(pc);
    return searchersIt->second->selectState();

}

} // namespace plugins
} // namespace s2e
