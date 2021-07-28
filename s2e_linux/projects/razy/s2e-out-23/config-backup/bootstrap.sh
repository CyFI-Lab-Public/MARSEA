#!/bin/bash
#
# This file was automatically generated by s2e-env at 2021-06-08 17:29:26.028499
#
# This bootstrap script is used to control the execution of the target program
# in an S2E guest VM.
#
# When you run launch-s2e.sh, the guest VM calls s2eget to fetch and execute
# this bootstrap script. This bootstrap script and the S2E config file
# determine how the target program is analyzed.
#

set -x


cd /c/s2e


mkdir -p guest-tools32
TARGET_TOOLS32_ROOT=guest-tools32




TARGET_TOOLS_ROOT=${TARGET_TOOLS32_ROOT}



# To save the hassle of rebuilding guest images every time you update S2E's guest tools,
# the first thing that we do is get the latest versions of the guest tools.
function update_common_tools {
    local OUR_S2EGET

    OUR_S2EGET=${S2EGET}
    OUR_S2ECMD=${S2ECMD}

    # First, download the common tools

    # Windows does not allow s2eget.exe to overwrite itself, so we need a workaround.
    if echo ${COMMON_TOOLS} | grep -q s2eget; then
      OUR_S2EGET=${S2EGET}_old.exe
      mv ${S2EGET} ${OUR_S2EGET}
    fi
    if echo ${COMMON_TOOLS} | grep -q s2ecmd; then
      OUR_S2ECMD=${S2ECMD}_old.exe
      mv ${S2ECMD} ${OUR_S2ECMD}
    fi


    for TOOL in ${COMMON_TOOLS}; do
        ${OUR_S2EGET} ${TARGET_TOOLS_ROOT}/${TOOL}
        if [ ! -f ${TOOL} ]; then
          ${OUR_S2ECMD} kill 0 "Could not get ${TOOL} from the host. Make sure that guest tools are installed properly."
          exit 1
        fi
        chmod +x ${TOOL}
    done
}

function update_target_tools {
    for TOOL in $(target_tools); do
        ${S2EGET} ${TOOL} ${TOOL}
        chmod +x ${TOOL}
    done
}

function prepare_target {
    # Make sure that the target is executable
    chmod +x "$1"
}





function get_ramdisk_root {
  echo 'x:\'
}

function copy_file {
  SOURCE="$1"
  DEST="$2"

  run_cmd "copy /Y ${SOURCE} ${DEST}" > /dev/null

}

# This prepares the symbolic file inputs.
# This function takes as input a seed file name and makes its content symbolic according to the symranges file.
# It is up to the host to prepare all the required symbolic files. The bootstrap file does not make files
# symbolic on its own.
function download_symbolic_file {
  SYMBOLIC_FILE="$1"
  RAMDISK_ROOT="$(get_ramdisk_root)"

  ${S2EGET} "${SYMBOLIC_FILE}"
  if [ ! -f "${SYMBOLIC_FILE}" ]; then
    ${S2ECMD} kill 1 "Could not fetch symbolic file ${SYMBOLIC_FILE} from host"
  fi

  copy_file "${SYMBOLIC_FILE}" "${RAMDISK_ROOT}"

  SYMRANGES_FILE="${SYMBOLIC_FILE}.symranges"

  ${S2EGET} "${SYMRANGES_FILE}" > /dev/null

  # Make the file symbolic
  if [ -f "${SYMRANGES_FILE}" ]; then
     export S2E_SYMFILE_RANGES="${SYMRANGES_FILE}"
  fi


  # The symbolic file will be split into symbolic variables of up to 4k bytes each.
  ${S2ECMD} symbfile 4096 "${RAMDISK_ROOT}${SYMBOLIC_FILE}" > /dev/null

}

function download_symbolic_files {
  for f in "$@"; do
    download_symbolic_file "${f}"
  done
}



# This function executes the target program given in arguments.
#
# There are two versions of this function:
#    - without seed support
#    - with seed support (-s argument when creating projects with s2e_env)
function execute {
    local TARGET

    TARGET="$1"
    shift

    execute_target "${TARGET}" "$@"
}



###############################################################################
# This section contains target-specific code

function make_seeds_symbolic {
    echo 1
}

# This function executes the target program.
# You can customize it if your program needs special invocation,
# custom symbolic arguments, etc.
function execute_target {
    ./malware-inject.exe --dll "./custom-hook.dll" --app $1
    #run_cmd "$@" > /dev/null 2> /dev/null
}

# In 64-bit mode, it is important to run commands using the 64-bit cmd.exe,
# otherwise most changes will be confined to the SysWow64 environment.
# This function takes care of calling the right cmd.exe depending on the guest OS.
function run_cmd {
    local PREFIX
    local CMD
    CMD="$1"
    shift


    PREFIX=


    ${PREFIX}cmd.exe '\/c' "${CMD}" $*
}

function install_driver {
    local PREFIX
    local DRIVER
    DRIVER="$1"

    run_cmd "rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 ${DRIVER}"
}

function target_init {
    # Set FaultInjectionEnabled to 1 if you want to test a driver for proper error recovery
    # This only initializes fault injection infrastructure. Actual activation will be done
    # later when needed using drvctl.exe.
    run_cmd "reg add HKLM\\Software\\S2E /v FaultInjectionEnabled /t REG_DWORD /d  0  /f"

    # Start the s2e.sys WindowsMonitor driver
    install_driver 'c:\s2e\s2e.inf'
    sc start s2e

    # Create ram disk
    imdisk -a -s 2M -m X: -p "/fs:fat /q /y"
    drvctl.exe register_debug
    drvctl.exe wait
}

function target_tools {
    echo ""
}

# This function converts an msys path into a Windows path
function win_path {
  local dir="$(dirname "$1")"
  local fn="$(basename "$1")"
  echo "$(cd "$dir"; echo "$(pwd -W)/$fn")" | sed 's|/|\\|g';
}

S2ECMD=./s2ecmd.exe
S2EGET=./s2eget.exe
S2EPUT=./s2eput.exe
COMMON_TOOLS="s2ecmd.exe s2eget.exe s2eput.exe s2e.sys s2e.inf drvctl.exe tickler.exe"

COMMON_TOOLS="${COMMON_TOOLS} libs2e32.dll"


###############################################################################


update_common_tools
update_target_tools



target_init

# Download the target file to analyze
${S2EGET} "razy.exe"
${S2EGET} "EasyHook32.dll"
${S2EGET} "custom-hook.dll"
${S2EGET} "malware-inject.exe"


download_symbolic_files



# Run the analysis



    TARGET_PATH='razy.exe'




prepare_target "${TARGET_PATH}"





execute "${TARGET_PATH}"
