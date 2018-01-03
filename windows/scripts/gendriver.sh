#!/bin/sh
# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

# This script automatically extracts kernels from Windows ISO images
# and generates the winmonitor_gen.c file that is used by the S2E kernel
# driver in order to parse internal Windows data structures.
#
# Run this script if you want to add support for a new Windows version.
# After the script is done, rebuild the driver.

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/windows/iso/folder"
    exit 1
fi

ISO_DIR="$1"
CUR_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname $0)" && pwd)"
BASE_DIR="$SCRIPT_DIR/../"
OUTPUT_DIR="$BASE_DIR/kernels"
KB_DIR="$BASE_DIR/kb"

WGET="wget --no-use-server-timestamps -O"
DRIVER_OUTPUT="$BASE_DIR/driver/src/winmonitor_gen.c"
PDBPARSER="$CUR_DIR/x64/Release/pdbparser.exe"

if [ ! -f "$PDBPARSER" ]; then
    echo "$PDBPARSER does not exist."
    echo "Please build the s2e.sln solution with Visual Studio in release mode."
    exit 1
fi

if [ ! -d $ISO_DIR ]; then
    echo "$ISO_DIR does not exist"
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$KB_DIR"

download_patch()
{
    local URL="$1"
    local FILE="$(basename $URL)"
    local DEST_FILE="$KB_DIR/$FILE"
    if [ -f "$DEST_FILE" ]; then
        echo "$DEST_FILE already exists, skipping."
    else
        $WGET "$DEST_FILE" "$URL"
    fi
}

# Download patches for driver signature checks
download_patch https://download.microsoft.com/download/C/8/7/C87AE67E-A228-48FB-8F02-B2A9A1238099/Windows6.1-KB3033929-x64.msu
download_patch https://download.microsoft.com/download/3/7/4/37473F39-5728-4153-9A25-64C09DE9ED52/Windows6.1-KB3033929-x86.msu

# Extract kernels from KBs first
./scripts/extract_kernels.py  --iso-dir "$KB_DIR" -o "$OUTPUT_DIR"

# Extract ISOs
./scripts/extract_kernels.py  --iso-dir "$ISO_DIR" -o "$OUTPUT_DIR"

cd "$OUTPUT_DIR"
for f in *.exe; do
    PDB_FILE="$(basename "${f%.*}.pdb")"
    if [ ! -f "$PDB_FILE" ]; then
        echo "Getting PDB for $f"
        $SCRIPT_DIR/symchk.py "$f"
    fi
done

cd "$CUR_DIR"
./scripts/gendriver.py -d "$OUTPUT_DIR" -p "$PDBPARSER" -o "$DRIVER_OUTPUT"

echo "The S2E driver file $DRIVER_OUTPUT has been updated. Please rebuild the solution."
