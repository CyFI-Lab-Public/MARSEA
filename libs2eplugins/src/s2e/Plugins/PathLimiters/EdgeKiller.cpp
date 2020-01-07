///
/// Copyright (C) 2011-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <iostream>

#include "EdgeKiller.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(EdgeKiller, "Kills states that encounter a given (start_pc, end_pc) edge", "", "EdgeDetector",
                  "ModuleExecutionDetector");

void EdgeKiller::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_edgeDetector = s2e()->getPlugin<EdgeDetector>();
    m_edgeDetector->readConfig(getConfigKey(), this);
    m_edgeDetector->onEdge.connect(sigc::mem_fun(*this, &EdgeKiller::onEdge));
}

void EdgeKiller::addEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType type) {
    getDebugStream() << "EdgeKiller: adding edge " << moduleName << " " << hexval(start) << " => " << hexval(end)
                     << " type:" << type << "\n";
    m_edgeDetector->addEdge(moduleName, start, end, type);
    m_edges.addEdge(moduleName, start, end, type);
}

void EdgeKiller::onEdge(S2EExecutionState *state, uint64_t sourcePc, EdgeType type) {
    auto md = m_detector->getCurrentDescriptor(state);
    if (!md) {
        return;
    }

    uint64_t relSourcePc, relPc;
    bool ok = true;
    ok &= md->ToNativeBase(sourcePc, relSourcePc);
    ok &= md->ToNativeBase(state->regs()->getPc(), relPc);
    if (!ok) {
        getWarningsStream(state) << "Could not get relative source/dest address\n";
        return;
    }

    if (!m_edges.findEdge(md->Name, relSourcePc, relPc, &type)) {
        return;
    }

    std::string s;
    llvm::raw_string_ostream ss(s);
    ss << "EdgeKiller: " << hexval(sourcePc) << " => " << hexval(state->regs()->getPc()) << "\n";
    ss.flush();
    s2e()->getExecutor()->terminateState(*state, s);
}

} // namespace plugins
} // namespace s2e
