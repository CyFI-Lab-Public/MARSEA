///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <iostream>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <TraceEntries.pb.h>

#include "ModuleTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ModuleTracer, "Module load/unload tracer plugin",
                  "ModuleTracer"
                  "ExecutionTracer",
                  "OSMonitor");

ModuleTracer::ModuleTracer(S2E *s2e) : EventTracer(s2e) {
}

ModuleTracer::~ModuleTracer() {
}

void ModuleTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    OSMonitor *monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ModuleTracer::moduleLoadListener));
    monitor->onModuleUnload.connect(sigc::mem_fun(*this, &ModuleTracer::moduleUnloadListener));
    monitor->onProcessUnload.connect(sigc::mem_fun(*this, &ModuleTracer::processUnloadListener));
}

bool ModuleTracer::initSection(TracerConfigEntry *cfgEntry, const std::string &cfgKey, const std::string &entryId) {
    return true;
}

bool ModuleTracer::moduleToProtobuf(const ModuleDescriptor &module, std::string &data) {
    s2e_trace::PbTraceModuleLoadUnload te;
    te.set_name(module.Name.c_str());
    te.set_path(module.Path.c_str());
    te.set_pid(module.Pid);
    te.set_address_space(module.AddressSpace);

    for (const auto &section : module.Sections) {
        auto s = te.add_sections();
        s->set_name(section.name.c_str());
        s->set_runtime_load_base(section.runtimeLoadBase);
        s->set_native_load_base(section.nativeLoadBase);
        s->set_size(section.size);
        s->set_readable(section.readable);
        s->set_writable(section.writable);
        s->set_executable(section.executable);
    }

    return te.AppendToString(&data);
}

void ModuleTracer::moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module) {

    std::string data;
    if (moduleToProtobuf(module, data)) {
        m_tracer->writeData(state, data.c_str(), data.size(), s2e_trace::TRACE_MOD_LOAD);
    }
}

void ModuleTracer::moduleUnloadListener(S2EExecutionState *state, const ModuleDescriptor &module) {
    std::string data;
    if (moduleToProtobuf(module, data)) {
        m_tracer->writeData(state, data.c_str(), data.size(), s2e_trace::TRACE_MOD_UNLOAD);
    }
}

void ModuleTracer::processUnloadListener(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                         uint64_t returnCode) {
    s2e_trace::PbTraceProcessUnload item;
    item.set_return_code(returnCode);
    m_tracer->writeData(state, item, s2e_trace::TRACE_PROC_UNLOAD);
}
} // namespace plugins
} // namespace s2e
