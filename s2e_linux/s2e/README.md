## Updates

### 7 Sept 2021

All of the recent major changes to the linux S2E code can be invoked from the project-specific ``s2e-config.lua`` file.

#### Invoke the CyFiFunctionModels plugin, add the following to the lua file.

``` 
add_plugin("CyFiFunctionModels")
pluginsConfig.CyFiFunctionModels = {
  moduleName = "<project_name>",
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

*Since our CyFiFunctionModels plugin depends on the LibraryCallMonitor plugin, this must also be enabled*

#### Enable the LibraryCallMonitorPlugin
```
add_plugin("LibraryCallMonitor")
pluginsConfig.LibraryCallMonitor = {
	aggressiveOff = false,
	moduleName="netscout.exe",
}
```

*However, you may actually want monitor any library calls, so set `agressiveOff=true`*.

S2E Library
===========

This repository contains all the necessary components to build ``libs2e.so``. This shared
library is preloaded in QEMU to enable symbolic execution.

Please refer to the documentation in the ``docs`` directory for build and usage instructions.
You can also find it online on <https://s2e.systems/docs>.
