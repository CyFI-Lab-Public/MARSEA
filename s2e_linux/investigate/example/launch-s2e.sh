#!/bin/bash
#
# This file was automatically generated by s2e-env at 2021-10-2911:36:21.551988
#
# This script is used to run the S2E analysis. Additional QEMU command line
# arguments can be passed to this script at run time.
#

ENV_DIR="/home/cyfi/s2e"
INSTALL_DIR="$ENV_DIR/install"
BUILD_DIR="$ENV_DIR/build"
BUILD=debug

# Either s2e for symbolic execution support or s2e_sp for single-path mode
S2E_MODE=s2e

if [ "x$GUI" != "x1" ]; then
  GRAPHICS=-nographic
fi

if [ "x$1" = "xdebug" ]; then
  DEBUG=1
  shift
fi

IMAGE_PATH="$ENV_DIR/images/windows-7sp1pro-i386/image.raw.s2e"
IMAGE_JSON="$(dirname $IMAGE_PATH)/image.json"

if [ ! -f "$IMAGE_PATH" -o ! -f "$IMAGE_JSON" ]; then
    echo "$IMAGE_PATH and/or $IMAGE_JSON do not exist. Please check that your images are build properly."
    exit 1
fi

QEMU_EXTRA_FLAGS=$(jq -r '.qemu_extra_flags' "$IMAGE_JSON")
QEMU_MEMORY=$(jq -r '.memory' "$IMAGE_JSON")
QEMU_SNAPSHOT=$(jq -r '.snapshot' "$IMAGE_JSON")
QEMU_DRIVE="-drive file=$IMAGE_PATH,format=s2e,cache=writeback"

export S2E_CONFIG=s2e-config.lua
export S2E_SHARED_DIR=$INSTALL_DIR/share/libs2e
export S2E_MAX_PROCESSES=24
export S2E_UNBUFFERED_STREAM=1

if [ $S2E_MAX_PROCESSES -gt 1 ]; then
    # Multi-threaded mode does not support graphics output, so we override
    # whatever settings were there before.
    export GRAPHICS=-nographic
fi

if [ "x$DEBUG" != "x" ]; then

    if [ ! -d "$BUILD_DIR/qemu-$BUILD" ]; then
        echo "No debug build found in $BUILD_DIR/qemu-$BUILD. Please run \`\`s2e build -g\`\`"
        exit 1
    fi

    QEMU="$BUILD_DIR/qemu-$BUILD/i386-softmmu/qemu-system-i386"
    LIBS2E="$BUILD_DIR/libs2e-$BUILD/i386-$S2E_MODE-softmmu/libs2e.so"

    rm -f gdb.ini

    echo handle SIGUSR1 noprint >> gdb.ini
    echo handle SIGUSR2 noprint >> gdb.ini
    echo set disassembly-flavor intel >> gdb.ini
    echo set print pretty on >> gdb.ini
    echo set environment S2E_CONFIG=$S2E_CONFIG >> gdb.ini
    echo set environment S2E_SHARED_DIR=$S2E_SHARED_DIR >> gdb.ini
    echo set environment LD_PRELOAD=$LIBS2E >> gdb.ini
    echo set environment S2E_UNBUFFERED_STREAM=1 >> gdb.ini
    # echo set environment LIBCPU_LOG_LEVEL=in_asm,int,exec >> gdb.ini
    # echo set environment LIBCPU_LOG_FILE=/tmp/log.txt >> gdb.ini
    # echo set environment S2E_QMP_SERVER=127.0.0.1:3322 >> gdb.ini
    echo set python print-stack full >> gdb.ini

    GDB="gdb  --init-command=gdb.ini --args"

    # Useful options:
    # - Display debug output from the BIOS:
    #    -chardev stdio,id=seabios -device isa-debugcon,iobase=0x402,chardev=seabios

    $GDB $QEMU $QEMU_DRIVE \
	-name fea7a448b1987dffd751b4b82623832719a534320406234fc8daf78a4c402f99 \
        -k en-us $GRAPHICS -monitor null -m $QEMU_MEMORY -enable-kvm \
        -serial file:serial.txt $QEMU_EXTRA_FLAGS \
        -loadvm $QEMU_SNAPSHOT $*

else
    QEMU="$INSTALL_DIR/bin/qemu-system-i386"
    LIBS2E="$INSTALL_DIR/share/libs2e/libs2e-i386-$S2E_MODE.so"

    LD_PRELOAD=$LIBS2E $QEMU $QEMU_DRIVE \
	-name fea7a448b1987dffd751b4b82623832719a534320406234fc8daf78a4c402f99 \
        -k en-us $GRAPHICS -monitor null -m $QEMU_MEMORY -enable-kvm \
        -serial file:serial.txt $QEMU_EXTRA_FLAGS \
        -loadvm $QEMU_SNAPSHOT $* &

    CHILD_PID=$!
    trap "kill $CHILD_PID" SIGINT
    wait $CHILD_PID
fi
