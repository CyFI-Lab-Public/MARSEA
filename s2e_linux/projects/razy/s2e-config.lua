--[[
This is the main S2E configuration file
=======================================

This file was automatically generated by s2e-env at 2021-06-08 17:29:26.028499

Changes can be made by the user where appropriate.
]]--

-------------------------------------------------------------------------------
-- This section configures the S2E engine.
s2e = {
    logging = {
        -- Possible values include "all", "debug", "info", "warn" and "none".
        -- See Logging.h in libs2ecore.
        console = "debug",
        logLevel = "debug",
    },

    -- All the cl::opt options defined in the engine can be tweaked here.
    -- This can be left empty most of the time.
    -- Most of the options can be found in S2EExecutor.cpp and Executor.cpp.
    kleeArgs = {
    	"--fork-on-symbolic-address=true",
    	"--verbose-fork-info",
    },
}

-- Declare empty plugin settings. They will be populated in the rest of
-- the configuration file.
plugins = {}
pluginsConfig = {}

-- Include various convenient functions
dofile('library.lua')

-------------------------------------------------------------------------------
-- This plugin contains the core custom instructions.
-- Some of these include s2e_make_symbolic, s2e_kill_state, etc.
-- You always want to have this plugin included.

add_plugin("BaseInstructions")
pluginsConfig.BaseInstructions = {

}

-------------------------------------------------------------------------------
-- This plugin implements "shared folders" between the host and the guest.
-- Use it in conjunction with s2eget and s2eput guest tools in order to
-- transfer files between the guest and the host.

add_plugin("HostFiles")
pluginsConfig.HostFiles = {
    baseDirs = {
        "/home/cyfi/s2e/projects/razy",

    },
    allowWrite = true,
}

-------------------------------------------------------------------------------
-- This plugin provides support for virtual machine introspection and binary
-- formats parsing. S2E plugins can use it when they need to extract
-- information from binary files that are either loaded in virtual memory
-- or stored on the host's file system.

add_plugin("Vmi")
pluginsConfig.Vmi = {
    baseDirs = {
        "/home/cyfi/s2e/projects/razy",


            "/home/cyfi/s2e/images/windows-7sp1pro-i386/guestfs",


    },
}

-------------------------------------------------------------------------------
-- This plugin provides various utilities to read from process memory.
-- In case it is not possible to read from guest memory, the plugin tries
-- to read static data from binary files stored in guestfs.
add_plugin("MemUtils")

-------------------------------------------------------------------------------
-- This plugin collects various execution statistics and sends them to a QMP
-- server that listens on an address:port configured by the S2E_QMP_SERVER
-- environment variable.
--
-- The "s2e run razy" command sets up such a server in order to display
-- stats on the dashboard.
--
-- You may also want to use this plugin to integrate S2E into a larger
-- system. The server could collect information about execution from different
-- S2E instances, filter them, and store them in a database.

add_plugin("WebServiceInterface")
pluginsConfig.WebServiceInterface = {
    statsUpdateInterval = 2
}

-------------------------------------------------------------------------------
-- This is the main execution tracing plugin.
-- It generates the ExecutionTracer.dat file in the s2e-last folder.
-- That files contains trace information in a binary format. Other plugins can
-- hook into ExecutionTracer in order to insert custom tracing data.
--
-- This is a core plugin, you most likely always want to have it.

add_plugin("ExecutionTracer")

-------------------------------------------------------------------------------
-- This plugin records events about module loads/unloads and stores them
-- in ExecutionTracer.dat.
-- This is useful in order to map raw program counters and pids to actual
-- module names.

add_plugin("ModuleTracer")

-------------------------------------------------------------------------------
-- This is a generic plugin that let other plugins communicate with each other.
-- It is a simple key-value store.
--
-- The plugin has several modes of operation:
--
-- 1. local: runs an internal store private to each instance (default)
-- 2. distributed: the plugin interfaces with an actual key-value store server.
-- This allows different instances of S2E to communicate with each other.

add_plugin("KeyValueStore")

-------------------------------------------------------------------------------
-- Records the program counter of executed translation blocks.
-- Generates a json coverage file. This file can be later processed by other
-- tools to generate line coverage information. Please refer to the S2E
-- documentation for more details.

add_plugin("TranslationBlockCoverage")
pluginsConfig.TranslationBlockCoverage = {
    writeCoverageOnStateKill = true,
    writeCoverageOnStateSwitch = true,
}

-------------------------------------------------------------------------------
-- Tracks execution of specific modules.
-- Analysis plugins are often interested only in small portions of the system,
-- typically the modules under analysis. This plugin filters out all core
-- events that do not concern the modules under analysis. This simplifies
-- code instrumentation.
-- Instead of listing individual modules, you can also track all modules by
-- setting configureAllModules = true

add_plugin("ModuleExecutionDetector")
pluginsConfig.ModuleExecutionDetector = {

    mod_0 = {
        moduleName = "razy.exe",
    },

    logLevel="info"
}

-------------------------------------------------------------------------------
-- This plugin controls the forking behavior of S2E.

add_plugin("ForkLimiter")
pluginsConfig.ForkLimiter = {
    -- How many times each program counter is allowed to fork.
    -- -1 for unlimited.
    maxForkCount = -1,

    -- How many seconds to wait before allowing an S2E process
    -- to spawn a child. When there are many states, S2E may
    -- spawn itself into multiple processes in order to leverage
    -- multiple cores on the host machine. When an S2E process A spawns
    -- a process B, A and B each get half of the states.
    --
    -- In some cases, when states fork and terminate very rapidly,
    -- one can see flash crowds of S2E instances. This decreases
    -- execution efficiency. This parameter forces S2E to wait a few
    -- seconds so that more states can accumulate in an instance
    -- before spawning a process.
    processForkDelay = 5,
}

-------------------------------------------------------------------------------
-- This plugin tracks execution of processes.
-- This is the preferred way of tracking execution and will eventually replace
-- ModuleExecutionDetector.

add_plugin("ProcessExecutionDetector")
pluginsConfig.ProcessExecutionDetector = {
    moduleNames = {

        "razy.exe",

    },
}

-------------------------------------------------------------------------------
-- Keeps for each state/process an updated map of all the loaded modules.
add_plugin("ModuleMap")
pluginsConfig.ModuleMap = {
  logLevel = "info"
}


-------------------------------------------------------------------------------
-- Keeps for each process in ProcessExecutionDetector an updated map
-- of memory regions.
add_plugin("MemoryMap")
pluginsConfig.MemoryMap = {
  logLevel = "info"
}



-------------------------------------------------------------------------------
-- MultiSearcher is a top-level searcher that allows switching between
-- different sub-searchers.
add_plugin("MultiSearcher")

-- CUPA stands for Class-Uniform Path Analysis. It is a searcher that groups
-- states into classes. Each time the searcher needs to pick a state, it first
-- chooses a class, then picks a state in that class. Classes can further be
-- subdivided into subclasses.
--
-- The advantage of CUPA over other searchers is that it gives similar weights
-- to different parts of the program. If one part forks a lot, a random searcher
-- would most likely pick a state from that hotspot, decreasing the probability
-- of choosing another state that may have better chance of covering new code.
-- CUPA avoids this problem by grouping similar states together.

add_plugin("CUPASearcher")
pluginsConfig.CUPASearcher = {
    -- The order of classes is important, please refer to the plugin
    -- source code and documentation for details on how CUPA works.
    classes = {


        -- This ensures that states run for a certain amount of time.
        -- Otherwise too frequent state switching may decrease performance.
        "batch",



        -- A program under test may be composed of several binaries.
        -- We want to give equal chance to all binaries, even if some of them
        -- fork a lot more than others.
        "pagedir",

        -- Finally, group states by program counter at fork.
        "pc",
    },
    logLevel="info",
    enabled = true,

    -- Delay (in seconds) before switching states (when used with the "batch" class).
    -- A very large delay becomes similar to DFS (current state keeps running
    -- until it is terminated).
    batchTime = 5
}





-------------------------------------------------------------------------------
-- Function models help drastically reduce path explosion. A model is an
-- expression that efficiently encodes the behavior of a function. In imperative
-- languages, functions often have if-then-else branches and loops, which
-- may cause path explosion. A model compresses this into a single large
-- expression. Models are most suitable for side-effect-free functions that
-- fork a lot. Please refer to models.lua and the documentation for more details.

add_plugin("StaticFunctionModels")

pluginsConfig.StaticFunctionModels = {
  modules = {}
}

g_function_models = {}
safe_load('models.lua')
pluginsConfig.StaticFunctionModels.modules = g_function_models


-------------------------------------------------------------------------------
-- This generates test cases when a state crashes or terminates.
-- If symbolic inputs consist of symbolic files, the test case generator writes
-- concrete files in the S2E output folder. These files can be used to
-- demonstrate the crash in a program, added to a test suite, etc.

add_plugin("TestCaseGenerator")
pluginsConfig.TestCaseGenerator = {
    generateOnStateKill = true,
    generateOnSegfault = true
}





-------------------------------------------------------------------------------
-- The screenshot plugin records a screenshot of the guest into screenshotX.png,
-- where XX is the path number. You can configure the interval here:
add_plugin("Screenshot")
pluginsConfig.Screenshot = {
    period = 5
}





-- ========================================================================= --
-- ============== Target-specific configuration begins here. =============== --
-- ========================================================================= --

-------------------------------------------------------------------------------
-- Monitors Windows events intercepted by the s2e.sys driver.

add_plugin("WindowsMonitor")

-------------------------------------------------------------------------------
-- This plugin is required to intercept some Windows kernel functions.
-- Guest code patching monitors execution and transparently changes
-- the target program counter when it encounters a call instructions.

add_plugin("GuestCodeHooking")
pluginsConfig.GuestCodeHooking = {
  moduleNames = {}
}






-------------------------------------------------------------------------------
-- This plugin monitors kernel crashes and generates WinDbg crash dumps.
-- The dump contains the entire physical memory

add_plugin("BlueScreenInterceptor")
add_plugin("WindowsCrashDumpGenerator")

-------------------------------------------------------------------------------
-- This plugin collects Windows crash events (user and kernel space).
-- It must be used together with s2e.sys and drvctl.exe.

add_plugin("WindowsCrashMonitor")
pluginsConfig.WindowsCrashMonitor = {
    terminateOnCrash = true,

    -- Make this true if you want crash dumps.
    -- Note that crash dumps may be very large (100s of MBs)
    generateCrashDumpOnKernelCrash = false,
    generateCrashDumpOnUserCrash = false,

    -- Limit number of crashes we generate
    maxCrashDumps = 10,

    -- Uncompressed dumps have the same size as guest memory (e.g., 2GB),
    -- you almost always want to compress them.
    compressDumps = true
}



-- ========================================================================= --
-- ============== User-specific scripts begin here ========================= --
-- ========================================================================= --


-------------------------------------------------------------------------------
-- This plugin exposes core S2E engine functionality to LUA scripts.
-- In particular, it provides the g_s2e global variable, which works similarly
-- to C++ plugins.
-------------------------------------------------------------------------------
add_plugin("LuaBindings")

-------------------------------------------------------------------------------
-- Exposes S2E engine's core event.
-- These are similar to events in CorePlugin.h. Please refer to
-- the LuaCoreEvents.cpp source file for a list of availble events.
-------------------------------------------------------------------------------
add_plugin("LuaCoreEvents")

--[[
pluginsConfig.LuaCoreEvents = {
    -- This annotation is called in case of a fork. It should return true
    -- to allow the fork and false to prevent it.
    onStateForkDecide = "onStateForkDecide"
}
function onStateForkDecide(state)
    return true
end--]]
-- This configuration shows an example that kills states if they fork in
-- a specific module.
--[[
pluginsConfig.LuaCoreEvents = {
    -- This annotation is called in case of a fork. It should return true
    -- to allow the fork and false to prevent it.
    onStateForkDecide = "onStateForkDecide"
}

function onStateForkDecide(state)
   mmap = g_s2e:getPlugin("ModuleMap")
   mod = mmap:getModule(state)
   if mod ~= nil then
      name = mod:getName()
      if name == "mymodule" then
          state:kill(0, "forked in mymodule")
      end

      if name == "myothermodule" then
          return false
      end
   end
   return true
end
--]]

add_plugin("CyFiFunctionModels")
pluginsConfig.CyFiFunctionModels = {
    -- Turn on/off instruction tracking
    instrutionTracker = false,  -- strangely, false means on
    functionTracker = true,
}

add_plugin("ControlFlowGraph")
pluginsConfig.ControlFlowGraph = {
	reloadConfig = false,
}

add_plugin("BasicBlockCoverage")

add_plugin("FunctionMonitor")

--[[
MOVZX_ADDR=$(objdump -M intel -d $TARGET | grep movzx | cut -d ':' -f 1 | xargs)
if [ "x$MOVZX_ADDR" = "x" ]; then
    echo "Could not get instruction address for movzx instructions"
    exit 1
fi
--]]
add_plugin("LuaInstructionInstrumentation")
pluginsConfig.LuaInstructionInstrumentation = {
    -- For each instruction to instrument, provide an entry in the "instrumentation" table
    instrumentation = {
        -- Defines an instrumentation called "success"
        success = {
            module_name = "razy.exe",
            name = "on_success",
            pc = 0x540117a,--0x401c0c,
        },

        -- Defines an instrumentation called "failure"
        failure = {
            module_name = "razy.exe",
            name = "on_failure",
            pc = 0x4011fd,
        }
        
        --[[
        skip = {
        	module_name = "razy.exe",
        	name = "skip",
        	pc = 0x401c8e,
        },
        skiip = {
        	module_name = "razy.exe",
        	name = "skip",
        	pc = 0x401c91,
        }     --]]   

    }
}

printf = function(s, ...)
    return io.write(s:format(...))
end

g_platform = "$PLATFORM"

-- An instruction instrumentation takes
-- a LuaS2EExecutionState object and a LuaInstrumentationState object.
function on_success(state, instrumentation_state)
    g_s2e:debug("called lstrlenA instrumentation")
    ptr_size = state:getPointerSize()
    if ptr_size == 4 then
        -- 32-bit calling convention
        sp = state:regs():getSp()
        printf("sp: %#x ptr_size: %d\n", sp, ptr_size)
        -- Compute the stack address that contains the address
        -- to the concrete buffer (second argument of scanf)
        buffer_addr_ptr = sp + ptr_size * 1
        printf("buffer_addr_ptr: %#x\n", buffer_addr_ptr)
        -- Read the pointer to the buffer from the stack
        buffer_addr = state:mem():readPointer(buffer_addr_ptr)
        if buffer_addr == nil then
           g_s2e:debug("Could not read pointer")
           g_s2e:exit(-1)
        end
        printf("buffer_addr: %#x\n", buffer_addr)
    else
        if g_platform == "windows" then
            -- Microsoft x64 calling convention
            -- 2nd parameter is in RDX=2
            buffer_addr = state:regs():read(2 * ptr_size, ptr_size)
        else
            -- System V AMD64 ABI
            -- 2nd parameter is in RSI=6
            buffer_addr = state:regs():read(6 * ptr_size, ptr_size)
        end
    end
    -- Make 30 bytes of that buffer symbolic
    --state:mem():makeSymbolic(buffer_addr, 25, "CyFi_Lua_LstrlenA")
    -- Write 25 to eax. This is an example of what lsrlentA would have returned
    -- if it actually got executed.
    state:regs():write(0, 11, ptr_size)
    state:mem():makeSymbolic(sp-ptr_size, 25, "CyFi_Lua_LstrlenA")
    --state:regs():write(0, 11, ptr_size)
    -- Don't execute the instruction, jump straight to the next one.
    instrumentation_state:skipInstruction(1)
end

function on_failure(state, instrumentation_state)
    -- There is no reason to continue execution any further because any other paths
    -- that will fork from here will not lead to success.
    state:kill(1, "Dead-end path")
end

function skip(state, instrumentation_state)
    instrumentation_state:skipInstruction(1)
end


--[[
add_plugin("MemoryTracer")
pluginsConfig.MemoryTracer = {
    traceMemory = true,
    tracePageFaults = true,
    traceTlbMisses = true,

    -- Restrict tracing to the "test" binary. Note that the modules specified here
    -- must run in the context of the process(es) defined in ProcessExecutionDetector.
    moduleNames = { "razy" }
}


add_plugin("LibraryCallMonitor")
pluginsConfig.LibraryCallMonitor = {
	monitorIndirectJumps = true,

}
--]]

