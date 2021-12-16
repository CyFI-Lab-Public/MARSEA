## Updates

### 16 Dec 2021 (ref 7 Sept updates for context)

#### Invoke the CyFiFunctionModels plugin, add the following to the lua file.

``` 
add_plugin("CyFiFunctionModels")
pluginsConfig.CyFiFunctionModels = {
  moduleNames = {
  	"<project_name>", 
	"rundll32.exe",
	},
}
```

### 8 Sept 2021

Symbolic data may cause state/path explosion. One tailored solution is to prune away paths that do not meet a certain condition.  For instance, if exploration encounters a branch and the path you desire jumps to 0x402010, and not the alternative 0x402da5, you can kill the state that allows exploration to follow 0x402da5. For example, you can put the fllowing code in the ```onInstructionExecution()``` of the **CyFiFunctionModels**.

```
if (relPc == 0x402da5) {
	S2EExecutor *executor = s2e()->getExecutor();
        executor->terminateState(*state);
        return;
}
```

Similarly, 'hooking' *evasive* APIs and updating the return value (or arguments) to include symbolic data can also cause path/state explosion. Along with the solution above, you must also ensure that your hook only affect functions called from the target module (malware sample).  In the function hook, ensure any action is within ```checkCaller()```.

```
int WINAPI GetKeyboardTypeHook(
	int nTypeFlag
) {
	if (checkCaller("GetKeyboardType")) {
	...
```

If it is not called by the target module, you must call the hooked function natively to ensure normal execution continues.

### 7 Sept 2021

All of the recent major changes to the linux S2E code can be invoked from the project-specific ``s2e-config.lua`` file.

If the user wants to invoke CyFiFunctionModels plugin, they can copy `s2e/s2e_linux/s2e` from this repo and overwrite the local `s2e` folder. Or they can cherry pick. But please notice the difference in `libs2eplugins/src/CMakeLists.txt`.

#### Make sure there is FunctionMonitor plugin added

```
add_plugin("FunctionMonitor")
```

#### Invoke the CyFiFunctionModels plugin, add the following to the lua file.

``` 
add_plugin("CyFiFunctionModels")
pluginsConfig.CyFiFunctionModels = {
  moduleName = "<project_name>",   **DEPRECATED. See 16 Dec update.**
}
```
#### Monitor executed instructions (ALL)
``` 
add_plugin("CyFiFunctionModels")
pluginsConfig.CyFiFunctionModels = {
  moduleName = "<project_name>",
  instructionMonitor=true,
}
```
#### Monitor executed instructions (Project only)
``` 
add_plugin("CyFiFunctionModels")
pluginsConfig.CyFiFunctionModels = {
  moduleName = "<project_name>",
  instructionMonitor=true,
  traceRegions="start_addr1-end_addr1,start_addr2-end_addr2,addr3,..."
}
```

*Since our CyFiFunctionModels plugin depends on the LibraryCallMonitor plugin, this must also be enabled.*

Besides changed above, please refer `s2e/s2e_linux/projects/razy/s2e-config.lua` to see if there is anything missing. 

#### Enable the LibraryCallMonitorPlugin
```
add_plugin("LibraryCallMonitor")
pluginsConfig.LibraryCallMonitor = {
	aggressiveOff = true,
	moduleName="netscout.exe",
}
```

*However, you may actually want to monitor library calls, so set `agressiveOff=false`*

Running S2E
===========

The S2E project is now ready to run. You have two ways to start the analysis:

    * cd /home/cyfi/s2e/projects/<project_name> && ./launch-s2e.sh
    * Use the "s2e run" command

The results of the analysis can be found in the s2e-last directory.
You may customize s2e-config.lua, bootstrap.sh, launch-s2e.sh, and others
as needed.

If something does not run as expected, you can troubleshoot like this:

    * Enable graphics output by deleting the -nographic flag from launch-s2e.sh
    * Look at the logs in serial.txt, log.txt, s2e-last/debug.txt, and s2e-last/cyfi.txt
    * Run S2E in GDB using ./launch-s2e.sh debug



S2E Library
===========

This repository contains all the necessary components to build ``libs2e.so``. This shared
library is preloaded in QEMU to enable symbolic execution.

Please refer to the documentation in the ``docs`` directory for build and usage instructions.
You can also find it online on <https://s2e.systems/docs>.
