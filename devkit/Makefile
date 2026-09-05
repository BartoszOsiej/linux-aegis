# SPDX-License-Identifier: GPL-2.0
#
# AEGIS DevKit Makefile
#
# Builds the complete AEGIS developer OS:
#   - Static init binary
#   - aegisctl tool
#   - Busybox (if available)
#   - Initramfs image
#   - QEMU launch
#

# ======================== Configuration ========================

CC := gcc
CFLAGS := -static -O2 -Wall -Wextra -Werror -D_GNU_SOURCE
STRIP := strip

KERNEL_DIR ?= ../linux-aegis
INITRAMFS_DIR := initramfs
BUILD_DIR := build
SRC_DIR := src

# ======================== Targets ========================

.PHONY: all clean initramfs init aegisctl qemu help

all: initramfs

help:
	@echo ""
	@echo "  ╔══════════════════════════════════════════╗"
	@echo "  ║     AEGIS DevKit Build System            ║"
	@echo "  ╠══════════════════════════════════════════╣"
	@echo "  ║                                          ║"
	@echo "  ║  make init     - Build init binary       ║"
	@echo "  ║  make aegisctl - Build aegisctl tool     ║"
	@echo "  ║  make initramfs - Build initramfs image  ║"
	@echo "  ║  make all       - Build everything       ║"
	@echo "  ║  make qemu      - Launch in QEMU        ║"
	@echo "  ║  make clean     - Clean build artifacts  ║"
	@echo "  ║                                          ║"
	@echo "  ╚══════════════════════════════════════════╝"
	@echo ""

# ======================== Build Init ========================

init: $(BUILD_DIR)/aegis_init

$(BUILD_DIR)/aegis_init: $(SRC_DIR)/init/aegis_init.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<
	$(STRIP) $@
	@echo "  INIT    $@"

# ======================== Build aegisctl ========================

aegisctl: $(BUILD_DIR)/aegisctl

$(BUILD_DIR)/aegisctl: $(SRC_DIR)/aegisctl.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<
	$(STRIP) $@
	@echo "  CTL     $@"

# ======================== Build Initramfs ========================

initramfs: $(BUILD_DIR)/aegis_init $(BUILD_DIR)/aegisctl
	@echo ""
	@echo "  Building initramfs..."
	@echo ""

	# Clean old initramfs
	rm -rf $(INITRAMFS_DIR)
	mkdir -p $(INITRAMFS_DIR)/{bin,sbin,etc,proc,sys,dev,tmp,run}
	mkdir -p $(INITRAMFS_DIR)/usr/{bin,sbin,lib}
	mkdir -p $(INITRAMFS_DIR)/dev/pts
	mkdir -p $(INITRAMFS_DIR)/root

	# Copy init
	cp $(BUILD_DIR)/aegis_init $(INITRAMFS_DIR)/init
	chmod +x $(INITRAMFS_DIR)/init

	# Copy aegisctl
	cp $(BUILD_DIR)/aegisctl $(INITRAMFS_DIR)/usr/bin/aegisctl
	chmod +x $(INITRAMFS_DIR)/usr/bin/aegisctl

	# Create busybox symlinks (if busybox available)
	@if command -v busybox >/dev/null 2>&1; then \
		cp $$(which busybox) $(INITRAMFS_DIR)/bin/busybox; \
		chmod +x $(INITRAMFS_DIR)/bin/busybox; \
		for cmd in sh ash bash ls cat echo mkdir mount umount ps top \
		           grep find vi vim nano head tail wc df du uname \
		           insmod rmmod modprobe lsmod sysctl dmesg; do \
			ln -sf /bin/busybox $(INITRAMFS_DIR)/bin/$$cmd; \
		done; \
		echo "  BUSYBOX Added busybox with applets"; \
	else \
		echo "  BUSYBOX Not found, building minimal shell"; \
		$(CC) $(CFLAGS) -o $(INITRAMFS_DIR)/bin/sh $(SRC_DIR)/init/aegis_init.c 2>/dev/null || true; \
	fi

	# Create minimal shell if no busybox
	@test -f $(INITRAMFS_DIR)/bin/sh || \
	$(CC) $(CFLAGS) -DSHELL_ONLY -o $(INITRAMFS_DIR)/bin/sh $(SRC_DIR)/init/aegis_init.c 2>/dev/null

	# Create symlinks for common commands
	@for cmd in sbin/init sbin/modprobe usr/sbin/insmod usr/sbin/rmmod; do \
		mkdir -p $(INITRAMFS_DIR)/$$(dirname $$cmd); \
		test -f $(INITRAMFS_DIR)/$$cmd || \
			ln -sf /bin/sh $(INITRAMFS_DIR)/$$cmd 2>/dev/null; \
	done

	# Create /etc files
	echo "aegis-dev" > $(INITRAMFS_DIR)/etc/hostname
	echo "root:x:0:0:root:/root:/bin/sh" > $(INITRAMFS_DIR)/etc/passwd
	echo "root:x:0:" > $(INITRAMFS_DIR)/etc/group
	echo "::1:     localhost" > $(INITRAMFS_DIR)/etc/hosts
	echo "aegis-dev" > $(INITRAMFS_DIR)/etc/HOSTNAME
	echo "AEGIS DevKit v1.0.0" > $(INITRAMFS_DIR)/etc/issue

	# Build cpio image
	cd $(INITRAMFS_DIR) && \
		find . -print0 | cpio --null -o --format=newc 2>/dev/null | \
		gzip -9 > ../initramfs.cpio.gz

	@echo ""
	@ls -lh $(BUILD_DIR)/initramfs.cpio.gz 2>/dev/null || \
		ls -lh initramfs.cpio.gz 2>/dev/null
	@echo ""
	@echo "  ✅ initramfs built successfully"
	@echo ""

# ======================== QEMU Launch ========================

qemu: initramfs
	@bash scripts/launch.sh

qemu-gui: initramfs
	@bash scripts/launch.sh --gui

qemu-debug: initramfs
	@bash scripts/launch.sh --debug --gdb

# ======================== Clean ========================

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(INITRAMFS_DIR)
	rm -f initramfs.cpio.gz
	@echo "  Cleaned"
