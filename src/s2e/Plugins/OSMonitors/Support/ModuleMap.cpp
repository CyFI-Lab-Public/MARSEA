///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Lua/Lua.h>
#include <s2e/Plugins/Lua/LuaModuleDescriptor.h>
#include <s2e/Plugins/Lua/LuaS2EExecutionState.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include <list>
#include <unordered_map>

#include "ModuleMap.h"

namespace bmi = boost::multi_index;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ModuleMap, "Tracks loaded modules", "", "OSMonitor");

////////////////////
// ModuleMapState //
////////////////////

namespace {

///
/// Keeps track of loaded modules across states.
///
class ModuleMapState : public PluginState {
public:
    struct pid_t {};
    struct pidname_t {};
    struct pagedir_t {};
    struct pidpc_t {};

    typedef boost::multi_index_container<
        ModuleDescriptorConstPtr,
        bmi::indexed_by<bmi::ordered_non_unique<bmi::tag<pidname_t>, bmi::identity<const ModuleDescriptor>,
                                                ModuleDescriptor::ModuleByPidName>,
                        bmi::ordered_non_unique<bmi::tag<pid_t>,
                                                bmi::member<ModuleDescriptor, const uint64_t, &ModuleDescriptor::Pid>>,
                        bmi::ordered_unique<bmi::tag<pidpc_t>, bmi::identity<const ModuleDescriptor>,
                                            ModuleDescriptor::ModuleByLoadBasePid>>>
        Map;

    typedef Map::index<pid_t>::type ModulesByPid;
    typedef Map::index<pidpc_t>::type ModulesByPidPc;
    typedef Map::index<pidname_t>::type ModulesByPidName;

private:
    // Module-related members
    Map m_modules;

public:
    ModuleMapState() {
    }

    virtual ~ModuleMapState() {
    }

    virtual ModuleMapState *clone() const {
        return new ModuleMapState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ModuleMapState();
    }

    ModuleDescriptorList getModulesByPid(uint64_t pid) {
        ModuleDescriptorList result;
        ModulesByPid &byPid = m_modules.get<pid_t>();

        auto p = byPid.equal_range(pid);

        foreach2 (it, p.first, p.second) { result.push_back(*it); }

        return result;
    }

    ModuleDescriptorConstPtr getModule(uint64_t pid, uint64_t pc) {
        ModuleDescriptor md;
        md.Pid = pid;
        md.LoadBase = pc;
        md.Size = 1;

        ModulesByPidPc &byPidPc = m_modules.get<pidpc_t>();
        ModulesByPidPc::const_iterator it = byPidPc.find(md);
        if (it != byPidPc.end()) {
            return *it;
        }

        return nullptr;
    }

    ModuleDescriptorConstPtr getModule(uint64_t pid, const std::string &name) {
        ModuleDescriptor md;
        md.Pid = pid;
        md.Name = name;

        ModulesByPidName &byPidName = m_modules.get<pidname_t>();
        ModulesByPidName::const_iterator it = byPidName.find(md);
        if (it != byPidName.end()) {
            return *it;
        }

        return nullptr;
    }

    void onModuleLoad(const ModuleDescriptor &module) {
        auto ptr = std::make_shared<const ModuleDescriptor>(module);
        m_modules.insert(ptr);
    }

    void onModuleUnload(const ModuleDescriptor &module) {
        // Remove the module from the map
        ModulesByPidPc &byPidPc = m_modules.get<pidpc_t>();
        ModulesByPidPc::const_iterator it = byPidPc.find(module);
        if (it != byPidPc.end()) {
            assert((*it)->Pid == module.Pid);
            if ((*it)->LoadBase != module.LoadBase) {
                g_s2e->getDebugStream(g_s2e_state) << "ModuleMap::onModuleUnload mismatched base addresses:\n"
                                                   << "  looked for:" << module << "\n"
                                                   << "  found     :" << **it << "\n";
            }

            byPidPc.erase(it);
        }
    }

    void onProcessUnload(uint64_t addressSpace, uint64_t pid, uint64_t returnCode) {
        ModulesByPid &byPid = m_modules.get<pid_t>();
        ModulesByPid::const_iterator it;
        while ((it = byPid.find(pid)) != byPid.end()) {
            byPid.erase(it);
        }
    }

    void dump(llvm::raw_ostream &os) const {
        os << "==========================================\n";
        os << "Dumping loaded modules\n";

        const ModulesByPid &byPid = m_modules.get<pid_t>();
        for (const auto &it : byPid) {
            os << "pid:" << hexval(it->Pid) << " - " << *it << "\n";
        }

        os << "==========================================\n";
    }
};

/////////////////////////////
// ModuleMap Lua Interface //
/////////////////////////////

class LuaModuleMap {
private:
    ModuleMap *m_map;

public:
    static const char className[];
    static Lunar<LuaModuleMap>::RegType methods[];

    LuaModuleMap(lua_State *L) : m_map(nullptr) {
    }

    LuaModuleMap(ModuleMap *plg) : m_map(plg) {
    }

    int getModule(lua_State *L) {
        void *data = luaL_checkudata(L, 1, "LuaS2EExecutionState");
        if (!data) {
            m_map->getWarningsStream() << "Incorrect lua invocation\n";
            return 0;
        }

        LuaS2EExecutionState **ls = reinterpret_cast<LuaS2EExecutionState **>(data);
        auto md = m_map->getModule((*ls)->getState());
        if (!md) {
            return 0;
        }

        LuaModuleDescriptor **c =
            static_cast<LuaModuleDescriptor **>(lua_newuserdata(L, sizeof(LuaModuleDescriptor *)));
        *c = new LuaModuleDescriptor(md);
        luaL_getmetatable(L, "LuaModuleDescriptor");
        lua_setmetatable(L, -2);
        return 1;
    }
};

const char LuaModuleMap::className[] = "LuaModuleMap";

Lunar<LuaModuleMap>::RegType LuaModuleMap::methods[] = {LUNAR_DECLARE_METHOD(LuaModuleMap, getModule), {0, 0}};

} // anonymous namespace

///////////////
// ModuleMap //
///////////////

void ModuleMap::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ModuleMap::onModuleLoad));

    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &ModuleMap::onModuleUnload));

    WindowsMonitor *winmon2 = dynamic_cast<WindowsMonitor *>(m_monitor);
    if (winmon2) {
        winmon2->onMonitorLoad.connect(sigc::mem_fun(*this, &ModuleMap::onMonitorLoad));
    }

    lua_State *L = s2e()->getConfig()->getState();
    Lunar<LuaModuleMap>::Register(L);
}

int ModuleMap::getLuaPlugin(lua_State *L) {
    // lua will manage the LuaExpression** ptr
    LuaModuleMap **c = static_cast<LuaModuleMap **>(lua_newuserdata(L, sizeof(LuaModuleMap *)));
    *c = new LuaModuleMap(this); // we manage this
    luaL_getmetatable(L, "LuaModuleMap");
    lua_setmetatable(L, -2);
    return 1;
}

void ModuleMap::onMonitorLoad(S2EExecutionState *state) {
    WindowsMonitor *winmon2 = dynamic_cast<WindowsMonitor *>(m_monitor);
    if (!winmon2->moduleUnloadSupported()) {
        getDebugStream() << "Guest OS does not support native module unload, using workaround\n";
        winmon2->onNtUnmapViewOfSection.connect(sigc::mem_fun(*this, &ModuleMap::onNtUnmapViewOfSection));
    }
}

void ModuleMap::onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &s) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    if (s.Status) {
        return;
    }

    auto module = plgState->getModule(s.Pid, s.BaseAddress);
    if (!module) {
        return;
    }

    getDebugStream(state) << "Unloading section " << hexval(s.BaseAddress) << " of module " << *module << "\n";
    plgState->onModuleUnload(*module);
}

void ModuleMap::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->onModuleLoad(module);
}

void ModuleMap::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->onModuleUnload(module);
}

void ModuleMap::onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->onProcessUnload(addressSpace, pid, returnCode);
}

ModuleDescriptorList ModuleMap::getModulesByPid(S2EExecutionState *state, uint64_t pid) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    return plgState->getModulesByPid(pid);
}

ModuleDescriptorConstPtr ModuleMap::getModule(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    auto pid = m_monitor->getPid(state);
    auto pc = state->regs()->getPc();
    pid = m_monitor->translatePid(pid, pc);
    return plgState->getModule(pid, pc);
}

ModuleDescriptorConstPtr ModuleMap::getModule(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    auto pid = m_monitor->getPid(state);
    pid = m_monitor->translatePid(pid, pc);
    return plgState->getModule(pid, pc);
}

ModuleDescriptorConstPtr ModuleMap::getModule(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    pid = m_monitor->translatePid(pid, pc);
    return plgState->getModule(pid, pc);
}

ModuleDescriptorConstPtr ModuleMap::getModule(S2EExecutionState *state, uint64_t pid, const std::string &name) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    return plgState->getModule(pid, name);
}

void ModuleMap::dump(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->dump(getDebugStream(state));
}

void ModuleMap::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_MODULE_MAP_COMMAND command;

    // TODO: factor these checks out from all plugins
    // TODO: handleOpcodeInvocation should really return error code
    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_MODULE_MAP_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case GET_MODULE_INFO: {
            DECLARE_PLUGINSTATE(ModuleMapState, state);
            auto module = plgState->getModule(command.ModuleInfo.Pid, command.ModuleInfo.Address);
            if (!module) {
                getWarningsStream(state) << "Could not get module for pid=" << hexval(command.ModuleInfo.Pid)
                                         << " addr=" << hexval(command.ModuleInfo.Address) << "\n";
                break;
            }

            // Caller inits the buffer to 0, so subtract 1 to make it asciiz
            auto maxLen = std::min(command.ModuleInfo.ModuleNameSize - 1, module->Name.size());

            if (!state->mem()->write(command.ModuleInfo.ModuleName, module->Name.c_str(), maxLen)) {
                getWarningsStream(state) << "could not write module name to memory\n";
                break;
            }

            // Init these last, guest will check them for 0 for errors
            command.ModuleInfo.NativeLoadBase = module->NativeBase;
            command.ModuleInfo.RuntimeLoadBase = module->LoadBase;
            command.ModuleInfo.Size = module->Size;

            if (!state->mem()->write(guestDataPtr, &command, guestDataSize)) {
                getWarningsStream(state) << "could not write module info to memory\n";
                break;
            }
        } break;

        default: { getWarningsStream(state) << "unknown command\n"; } break;
    }
}

} // namespace plugins
} // namespace s2e
