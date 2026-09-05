#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# AEGIS DevKit - QEMU Launcher
#
# Custom QEMU configuration for AEGIS kernel testing.
# This script boots the AEGIS kernel with a minimal developer OS.
#
# Usage: ./launch.sh [options]
#
# Options:
#   --gui          Launch with graphical window (default: nographic)
#   --gdb          Launch with GDB stub on port 1234
#   --smp N        Number of CPU cores (default: 2)
#   --mem N        Memory in MB (default: 2048)
#   --debug        Enable kernel debug output (more verbose)
#   --serial FILE  Redirect serial output to file
#

set -e

# ======================== Configuration ========================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL="${AEGIS_KERNEL:-${SCRIPT_DIR}/../linux-aegis/arch/x86/boot/bzImage}"
INITRD="${SCRIPT_DIR}/initramfs.cpio.gz"

# Default settings
SMP=2
MEM=2048
DISPLAY_MODE="nographic"
GDB_ENABLED=0
SERIAL_FILE=""
APPEND_EXTRA=""

# ======================== Colors ========================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ======================== Functions ========================

print_banner() {
    echo -e "${YELLOW}"
    echo "    ╔══════════════════════════════════════════════════╗"
    echo "    ║                                                  ║"
    echo "    ║       🛡️  AEGIS DevKit  v1.0.0                 ║"
    echo "    ║       QEMU Launcher                            ║"
    echo "    ║                                                  ║"
    echo "    ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_files() {
    if [ ! -f "$KERNEL" ]; then
        echo -e "${RED}ERROR: Kernel not found at $KERNEL${NC}"
        echo "Build the kernel first: cd ../linux-aegis && make -j\$(nproc)"
        exit 1
    fi

    if [ ! -f "$INITRD" ]; then
        echo -e "${RED}ERROR: Initramfs not found at $INITRD${NC}"
        echo "Build the initramfs first: make initramfs"
        exit 1
    fi

    echo -e "${GREEN}✅ Kernel: $KERNEL${NC}"
    echo -e "${GREEN}✅ Initramfs: $INITRD${NC}"
    echo ""
}

# ======================== Parse Arguments ========================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gui)
            DISPLAY_MODE="gtk"
            shift
            ;;
        --gdb)
            GDB_ENABLED=1
            shift
            ;;
        --smp)
            SMP="$2"
            shift 2
            ;;
        --mem)
            MEM="$2"
            shift 2
            ;;
        --debug)
            APPEND_EXTRA="debug earlyprintk=serial console=ttyS0,115200n8"
            shift
            ;;
        --serial)
            SERIAL_FILE="$2"
            shift 2
            ;;
        --help|-h)
            print_banner
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --gui          Launch with graphical window (default: nographic)"
            echo "  --gdb          Launch with GDB stub on port 1234"
            echo "  --smp N        Number of CPU cores (default: 2)"
            echo "  --mem N        Memory in MB (default: 2048)"
            echo "  --debug        Enable kernel debug output"
            echo "  --serial FILE  Redirect serial output to file"
            echo ""
            echo "Examples:"
            echo "  $0                    # Basic nographic launch"
            echo "  $0 --gui              # Launch with GUI window"
            echo "  $0 --gdb --debug      # Debug mode with GDB"
            echo "  $0 --smp 4 --mem 4096 # 4 cores, 4GB RAM"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Try '$0 --help' for usage."
            exit 1
            ;;
    esac
done

# ======================== Launch ========================

print_banner
check_files

echo -e "${CYAN}Configuration:${NC}"
echo "  Kernel:      $(basename $KERNEL)"
echo "  Initramfs:   $(basename $INITRD)"
echo "  CPUs:        $SMP"
echo "  Memory:      ${MEM}MB"
echo "  Display:     $DISPLAY_MODE"
echo "  GDB:         $([ $GDB_ENABLED -eq 1 ] && echo "port 1234" || echo "disabled")"
echo "  Debug:       $([ -n "$APPEND_EXTRA" ] && echo "enabled" || echo "disabled")"
echo ""

# Build kernel command line
KERNEL_CMD="console=ttyS0,115200n8 root=/dev/ram0 rw quiet loglevel=4 aegis.force_shield=1"
if [ -n "$APPEND_EXTRA" ]; then
    KERNEL_CMD="$KERNEL_CMD $APPEND_EXTRA"
fi

# Build QEMU command
QEMU_CMD="qemu-system-x86_64"
QEMU_ARGS=(
    -kernel "$KERNEL"
    -initrd "$INITRD"
    -append "$KERNEL_CMD"
    -m "${MEM}M"
    -smp "$SMP"
    -cpu "host,migratable=on,+sse4.1,+sse4.2,+ssse3"
    -enable-kvm
    -nographic
    -serial mon:stdio
    -no-reboot
    -no-shutdown
)

# Add GDB stub if enabled
if [ $GDB_ENABLED -eq 1 ]; then
    QEMU_ARGS+=(-s -S)
fi

# Add serial file redirect if specified
if [ -n "$SERIAL_FILE" ]; then
    QEMU_ARGS+=(-serial "file:$SERIAL_FILE")
fi

# Add display mode
if [ "$DISPLAY_MODE" != "nographic" ]; then
    QEMU_ARGS+=(-display "$DISPLAY_MODE")
    # Remove nographic and mon:stdio if GUI
    QEMU_ARGS=("${QEMU_ARGS[@]/-nographic/}")
    QEMU_ARGS=("${QEMU_ARGS[@]/-serial mon:stdio/}")
fi

echo -e "${YELLOW}Launching QEMU...${NC}"
echo -e "${CYAN}Command:${NC} $QEMU_CMD ${QEMU_ARGS[*]}"
echo ""

# Execute QEMU
exec "$QEMU_CMD" "${QEMU_ARGS[@]}"
