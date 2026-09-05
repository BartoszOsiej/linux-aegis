#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# apply.sh - Reproduce the AEGIS kernel from a pristine upstream tree.
#
# Builds the AEGIS Linux Security Module against a clean checkout of
# the exact kernel revision it was developed on:
#
#   https://github.com/torvalds/linux @ 4d7d9486c04d917265f64c55bd23b2cc4fe7749c
#
# Result: a bootable bzImage with CONFIG_LOCALVERSION="-aegis" plus a
# stripped config committed under build/aegis.config.
#
# Usage:
#   ./apply.sh                 # configure + build the whole kernel
#   ./apply.sh --prepare-only  # configure and prepare, skip full build
#
# Requirements: git, make, gcc, flex, bison, bc, libelf, openssl headers,
#               and the usual kernel build toolchain.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="4d7d9486c04d917265f64c55bd23b2cc4fe7749c"
UPSTREAM="https://github.com/torvalds/linux.git"
WORK="${1:-/tmp/aegis-build}"
KERNEL_DIR="${WORK}/linux"
PREPARE_ONLY="${2:-}"

echo "==> AEGIS apply script"
echo "    base commit : ${BASE}"
echo "    work dir    : ${WORK}"
echo

if [ ! -d "${KERNEL_DIR}/.git" ]; then
	mkdir -p "${WORK}"
	echo "==> Cloning upstream kernel..."
	git clone --single-branch --branch master "${UPSTREAM}" "${KERNEL_DIR}"
else
	echo "==> Reusing existing clone at ${KERNEL_DIR}"
fi

cd "${KERNEL_DIR}"
git checkout -q "${BASE}"

echo "==> Installing AEGIS module source"
rm -rf security/aegis
cp -r "${SCRIPT_DIR}/aegis" security/aegis

echo "==> Applying integration patches"
git apply --check "${SCRIPT_DIR}"/patches/*.patch
git apply "${SCRIPT_DIR}"/patches/*.patch

echo "==> Copying build configuration"
cp "${SCRIPT_DIR}/build/aegis.config" .config
make olddefconfig >/dev/null

if [ "${PREPARE_ONLY}" = "--prepare-only" ]; then
	echo "==> Preparing build tree (no full build)"
	make -j"$(nproc)" prepare
	echo "==> AEGIS tree ready at ${KERNEL_DIR}"
	exit 0
fi

echo "==> Building kernel (this takes a while)..."
make -j"$(nproc)"

echo
echo "==> Done."
echo "    Kernel    : ${KERNEL_DIR}/arch/x86/boot/bzImage"
echo "    Version   : $(make -s kernelversion)-aegis"
echo "    Next step : cd devkit && make qemu"