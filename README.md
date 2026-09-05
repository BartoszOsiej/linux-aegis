<div align="center">

# 🛡️ AEGIS

**Advanced Guardian for Integrated System Security**

A stackable Linux Security Module (LSM) that adds process protection, file integrity,
syscall auditing, and kernel module control to the Linux kernel — built
against upstream `torvalds/linux`.

![License: GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-blue.svg)
![Linux 7.3-rc1](https://img.shields.io/badge/linux-7.3--rc1-333333.svg)
[![CI](https://github.com/BartoszOsiej/linux-aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/BartoszOsiej/linux-aegis/actions/workflows/ci.yml)
![C](https://img.shields.io/badge/C-~2_000_lines-555555.svg)
![x86_64](https://img.shields.io/badge/arch-x86__64-FF6F00.svg)
![QEMU](https://img.shields.io/badge/qemu-tested-4EA94B.svg)

*Bootable end-to-end in QEMU — kernel, module, and a minimal developer OS — with a
one-command reproduce script.*

</div>

---

## What AEGIS does

AEGIS is an in-tree Linux Security Module that hooks into the kernel's LSM framework to
protect a running system in four independent, feature-flagged layers:

| Feature | Hook layer | What it does |
| --- | --- | --- |
| **Process protection** | `task_alloc` / `task_free`, `ptrace_*` | Tracks protected processes; restricts `ptrace(2)` attach and `PTRACE_TRACEME` for hardening against debugger-aided exploits |
| **File integrity** | `file_open`, `file_permission`, `inode_permission` | SHA-256 digest tracking and write-protection for protected system files |
| **Syscall audit** | `bprm_check_security` | Blocks or logs dangerous syscalls per process policy |
| **Module control** | `kernel_load_data`, `kernel_read_file` | Restricts loading of kernel modules at runtime |

All hooks are declared through `LSM_HOOK_INIT` in a single registered hook table, so
AEGIS **stacks with other LSMs** (capability, Yama, AppArmor, …) instead of replacing
them. The module is small on purpose — just over **1,700 lines of C** spread across
six focused source files.

```
                        ┌─────────────────────────────────────────┐
 user space   aegisctl  │       /proc/sys/kernel/aegis  (sysctl)  │
   +───────────────►    │       /sys/kernel/security/aegis        │
                        │   ┌───────────────────────────────────┐ │
                        │   │  aegis_securityfs  aegis_sysctl   │ │
                        │   └───────┬───────────────┬───────────┘ │
                        │           ▼               ▼             │
                        │   ┌───────────────────────────────────┐ │
                        │   │ aegis_lsm   (hook table, LSM)    │ │
                        │   └───┬──────────┬──────────┬────────┘ │
                        │       ▼          ▼          ▼          │
 kernel space          │  aegis_file  aegis_audit  aegis_module │
                        │  aegis_process                        │
                        └─────────────────────────────────────────┘
```

## Feature flags

Each subsystem can be compiled independently through top-level Kconfig symbols, so a
builder can take process protection alone, or the full set:

```none
CONFIG_SECURITY_AEGIS=y                      # main LSM
CONFIG_SECURITY_AEGIS_PROCESS_PROTECT=y      # anti-ptrace / anti-debugging
CONFIG_SECURITY_AEGIS_FILE_INTEGRITY=y       # SHA-256 integrity + write protect
CONFIG_SECURITY_AEGIS_SYSCALL_AUDIT=y        # syscall block/log
CONFIG_SECURITY_AEGIS_MODULE_CONTROL=y       # module loading control
```

Runtime control is exposed two ways:

```console
# sysctl namespace
#   kernel/aegis/enabled, features, ptrace_restrict_all,
#   file_integrity_enforce, syscall_audit_enable, module_loading_denied
$ sysctl kernel/aegis
kernel.aegis.ptrace_restrict_all = 1

# securityfs
$ cat /sys/kernel/security/aegis/status
$ cat /sys/kernel/security/aegis/protected_procs
$ cat /sys/kernel/security/aegis/protected_files
$ cat /sys/kernel/security/aegis/blocked_syscalls
```

## Repository layout

```
linux-aegis/
├── aegis/                  AEGIS LSM source (copy into security/aegis/)
│   ├── aegis.h             Feature flags, subsystem API
│   ├── aegis_lsm.c         LSM entry point + registered hook table
│   ├── aegis_process.c     Process protection (ptrace hardening)
│   ├── aegis_file.c        File integrity (SHA-256)
│   ├── aegis_audit.c       Syscall audit / filtering
│   ├── aegis_module.c      Module loading control
│   ├── aegis_securityfs.c  /sys kernel security interface
│   ├── aegis_sysctl.c      /proc/sys/kernel/aegis interface
│   ├── Kconfig
│   └── Makefile
├── patches/                Diffs against upstream base commit
├── build/
│   └── aegis.config        Kernel config (CONFIG_LOCALVERSION="-aegis")
├── devkit/                 Bootable minimal developer OS for QEMU
│   ├── src/aegisctl.c      Userspace control tool (status/enable/stats)
│   ├── src/init/           Static init (PID 1)
│   ├── scripts/launch.sh   QEMU launcher (nographic / gdb / smp / mem)
│   └── Makefile
├── apply.sh                One-command reproduce & build
└── .github/workflows/ci.yml
```

## Building

AEGIS lives inside an otherwise ordinary Linux source tree. The companion
`apply.sh` reproduces the exact tree it was developed against: upstream `torvalds/linux`
at commit `4d7d9486c04d917265f64c55bd23b2cc4fe7749c` (Linux **7.3-rc1**).

```console
$ ./apply.sh
==> AEGIS apply script
    base commit : 4d7d9486c04d917265f64c55bd23b2cc4fe7749c
==> Cloning upstream kernel...
==> Installing AEGIS module source
==> Applying integration patches
==> Copying build configuration
==> Building kernel (this takes a while)...
==> Done.
    Kernel  : /tmp/aegis-build/linux/arch/x86/boot/bzImage
```

Manual equivalent:

```console
$ git clone --single-branch --branch master https://github.com/torvalds/linux.git
$ cd linux
$ git checkout 4d7d9486c04d917265f64c55bd23b2cc4fe7749c
$ cp -r ../aegis security/aegis
$ git apply ../patches/*.patch
$ cp ../build/aegis.config .config && make olddefconfig
$ make -j$(nproc)
```

The built kernel reports `CONFIG_LOCALVERSION="-aegis"`:

```console
$ make -s kernelversion
7.3.0-aegis
```

## Running in QEMU

The `devkit/` directory turns the kernel into a bootable, self-contained developer OS:
a static PID 1 (`aegis_init`), the `aegisctl` control tool, an initramfs, and a QEMU
launcher.

```console
$ cd devkit
$ make initramfs
$ make qemu            # boots the AEGIS kernel in nographic QEMU
```

Inside the VM:

```console
/ # uname -r
7.3.0-1-aegis
/ # aegisctl status
  AEGIS LSM status:       enabled
  Feature flags:          process-protect file-integrity syscall-audit module-control
  Protected procs:        12
  Protected files:        5
  Blocked syscalls:       3
  Audit events:           214
```

QEMU options supported by `launch.sh`:

```console
$ make qemu-gui      # graphical window
$ make qemu-debug    # GDB stub on :1234 + verbose kernel log
$ bash scripts/launch.sh --smp 4 --mem 4096
```

## Getting started

Add protected subjects at runtime from inside the VM:

```console
/ # sysctl kernel.aegis.enabled=1
/ # sysctl kernel.aegis.ptrace_restrict_all=1
/ # cat /proc/1/comm > /sys/kernel/security/aegis/protected_procs
/ # aegisctl procs
```

## License

All kernel-side code (module, patches, build glue, devkit) is **GPL-2.0-only**, matching
the Linux kernel licensing model. See [`COPYING`](COPYING).