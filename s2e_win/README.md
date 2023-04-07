# MARSEA Windows Deployment

## Recommended System
- Windows 10 22H2. Download the installation media from the official Microsoft [website](https://www.microsoft.com/en-us/software-download/windows10ISO)
- Memory: 16GB
- Number of processors: 4
- Number of cores per processor: 1
- Disk space: 250GB

**Note**: The above recommendations are for system configurations. The setup should work for Windows 7 through Windows 11.

## Building
This section will guide you through the process of generating `custom-hook.dll`.

### Visual Studio 2022 Community Installation

#### Install Visual Studio 2022 Community Edition using the official installer
Find the official installer [here](https://visualstudio.microsoft.com/vs/). For a video tutorial on installation, click [here](https://youtu.be/fWnnu-SQf6U).

#### Visual Studio Configuration
Install the following components using the Visual Studio Installer. Watch the tutorial [here](https://youtu.be/iXpZ-YqH6Nk). The complete list of components to install are:
- Desktop development with C++
- MSVC v141 - VS 2017 C++ x64/x86 build tools (v14.16)
- MSVC v142 - VS 2019 C++ x64/x86 build tools (v14.29-16.11)
- Windows Universal CRT SDK
- C++ Windows XP Support for VS 2017 (v141) tools
- C++ ATL for v141 build tools (x86 & x64)
- Incredibuild - Build Acceleration

#### Install Windows SDK for Windows 8.1
View the video tutorial [here](https://youtu.be/Rg2ed3B7xRw).

### Project Building
Follow the steps in this [video tutorial](https://youtu.be/gg4BdG5HUqY).
1. Open the [solution](s2e.sln) file using Visual Studio. **Do not upgrade/migrate the project's version**.
2. Ensure the Solution Configuration is set to `Release` and the Solution Platforms is set to `Win32`.
3. Build the `custom-hook (Visual Studio 2017)` project.
