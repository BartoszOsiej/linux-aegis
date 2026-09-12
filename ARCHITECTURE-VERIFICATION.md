# Architecture Verification — linux-aegis

> Automated verification matrices for kernel memory safety, hook correctness, and stackable LSM compliance.

## 1. Kernel Memory Safety Boundary Checks

### 1.1 Static Analysis (CI Gate)

```bash
# Sparse — kernel semantic parser (types, locking, addressing)
make -C linux-src C=1 CHECK=sparse security/aegis/

# Coccinelle — semantic patching for common kernel bugs
make -C linux-src M=security/aegis/ coccicheck

# Smatch — deep static analysis for kernel code
make -C linux-src C=1 CHECK=smatch security/aegis/
```

### 1.2 KASAN (Kernel Address Sanitizer)

| Check | Tool | Command | Expected Result |
|---|---|---|---|
| Out-of-bounds read/write | KASAN | Boot with `kasan=on` + trigger all hooks | 0 reports |
| Use-after-free | KASAN | Module load/unload cycle ×100 | 0 reports |
| Stack overflow | KASAN | Deep hook call chains | 0 reports |
| Global buffer overflow | KASAN | Fuzz hook parameters | 0 reports |

```bash
# Build kernel with KASAN
scripts/config --enable CONFIG_KASAN
scripts/config --enable CONFIG_KASAN_GENERIC
make -j$(nproc)

# Boot and run verification
qemu-system-x86_64 -kernel arch/x86/boot/bzImage \
  -append "kasan=on panic=1" \
  -m 4G -smp 4

# In QEMU: trigger all hooks
for hook in task_alloc inode_create inode_rename socket_connect; do
  trigger_$hook  # custom test binary
done
dmesg | grep -i "kasan\|bug\|error"  # must be empty
```

### 1.3 KMEMLEAK (Memory Leak Detection)

```bash
scripts/config --enable CONFIG_DEBUG_KMEMLEAK
scripts/config --set-val CONFIG_DEBUG_KMEMLEAK_DEFAULT_OFF y

# After boot:
echo scan > /sys/kernel/debug/kmemleak
cat /sys/kernel/debug/kmemleak  # must be empty
```

### 1.4 Lockdep (Lock Dependency Validator)

```bash
scripts/config --enable CONFIG_PROVE_LOCKING
scripts/config --enable CONFIG_LOCKDEP

# After boot: trigger concurrent hook invocations
# Lockdep must report 0 warnings
dmesg | grep -i "lockdep\|deadlock\|inconsistent"  # must be empty
```

## 2. Lock-Free Ring Buffer Concurrency Validation

### 2.1 Per-CPU Buffer Integrity

| Test | Method | Pass Criteria |
|---|---|---|
| Concurrent write from N CPUs | `stress-ng --cpu $(nproc)` + hook trigger | No data corruption |
| Buffer overflow under load | `stress-ng --io 32 --timeout 60s` | Events dropped gracefully (no panic) |
| Read/write race | Concurrent userspace poll + kernel write | No use-after-free |
| CPU hotplug | Online/offline CPUs during load | Graceful degradation |

```bash
# Concurrency stress test
stress-ng --cpu $(nproc) --io 32 --timeout 120s &
STRESS_PID=$!

# Simultaneously trigger hooks
for i in $(seq 1 10000); do
  /usr/bin/true  # triggers execve hook
done

wait $STRESS_PID
dmesg | grep -i "aegis\|error\|oops"  # must show only正常 aegis log lines
```

### 2.2 Memory Ordering Checks

| Check | What | How |
|---|---|---|
| Store ordering | Events visible across CPUs in order | KCSAN (Kernel Concurrency Sanitizer) |
| Load ordering | No stale reads from per-CPU buffers | KCSAN + custom test harness |
| Atomic operations | `atomic_inc`, `cmpxchg` correctness | Lockdep + KCSAN |

```bash
scripts/config --enable CONFIG_KCSAN
# Boot + run concurrent hook tests
# KCSAN reports data races → FAIL
```

## 3. eBPF Verifier Limits (If Applicable)

> Note: linux-aegis is a kernel-space LSM, not an eBPF program. However, if any BPF helper functions are used (e.g., for dynamic tracing), these limits apply:

### 3.1 Instruction Count Ceilings

| Limit | Value | Enforcement |
|---|---|---|
| Max instructions per program | 1,000,000 (kernel 5.2+) | `kernel/bpf/verifier.c` |
| Max instructions per function | 4096 (tail call limit) | Verifier rejects if exceeded |
| Max stack depth | 512 bytes | Verifier rejects if exceeded |
| Max bpf_loop iterations | User-specified (must terminate) | Verifier enforces termination |

### 3.2 Bounded Loops

```c
// CORRECT: bounded loop (verifier accepts)
bpf_loop(100, &callback, NULL, 0);  // max 100 iterations

// INCORRECT: unbounded loop (verifier rejects)
while (condition) { ... }  // ❌ no fixed bound

// VERIFIER CHECK:
// - All loops must have provable upper bound
// - Max iteration count must be ≤ bpf_loop() limit
// - No infinite recursion via tail calls
```

### 3.3 Memory Access Bounds

| Check | Rule | Verifier Action |
|---|---|---|
| Map value access | Offset + size ≤ map value size | Reject program |
| Stack access | Offset within [-512, 0) | Reject program |
| Packet access | `skb->data` bounds checked | Reject program |
| Uninitialized memory | Must zero before passing to helper | Reject program |

## 4. Stackable Module Compliance

### 4.1 SELinux Co-existence Test Matrix

| Boot Config | AEGIS | SELinux | Expected |
|---|---|---|---|
| `aegis=1 selinux=1 enforcing=1` | ✅ Active | ✅ Enforcing | Both active, no conflicts |
| `aegis=1 selinux=0` | ✅ Active | ❌ Disabled | AEGIS only |
| `aegis=0 selinux=1 enforcing=1` | ❌ Disabled | ✅ Enforcing | SELinux only |
| `aegis=1 selinux=1 permissive=1` | ✅ Active | Permissive | Both active, SELinux logs only |

### 4.2 Hook Priority Verification

```bash
# Verify AEGIS hooks register AFTER SELinux hooks
dmesg | grep -E "aegis.*hook|selinux.*hook"

# Expected output order:
# [    0.123456] SELinux:  Registering hook security_task_alloc
# [    0.123789] SELinux:  Registering hook security_inode_create
# [    0.124012] AEGIS:    Registering hook security_task_alloc
# [    0.124234] AEGIS:    Registering hook security_inode_create
```

### 4.3 Conflict Detection

```bash
# Run AEGIS hooks alongside SELinux enforcement
# Verify: AEGIS events logged + SELinux denials logged separately
# No cross-contamination of audit trails

# Test: trigger action that AEGIS monitors AND SELinux denies
touch /tmp/test_file  # AEGIS logs inode_create, SELinux may deny

# Verify both events are logged independently
dmesg | grep "AEGIS.*inode_create"
ausearch -m AVC | grep "test_file"
```

## 5. Automated CI Verification Matrix

```yaml
# .github/workflows/verify.yml
name: Architecture Verification
on: [push, pull_request]

jobs:
  static-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sparse
        run: make -C linux-src C=1 CHECK=sparse security/aegis/
      - name: Coccinelle
        run: make -C linux-src M=security/aegis/ coccicheck
      - name: Smatch
        run: make -C linux-src C=1 CHECK=smatch security/aegis/

  memory-safety:
    runs-on: ubuntu-latest
    steps:
      - name: KASAN build + boot test
        run: |
          scripts/config --enable CONFIG_KASAN
          make -j$(nproc)
          # Boot in QEMU, run test suite, check dmesg
      - name: KMEMLEAK
        run: |
          scripts/config --enable CONFIG_DEBUG_KMEMLEAK
          # Boot, scan, verify empty

  concurrency:
    runs-on: ubuntu-latest
    steps:
      - name: KCSAN build + race detection
        run: |
          scripts/config --enable CONFIG_KCSAN
          # Boot, run concurrent hook tests, check for data races

  stacking:
    runs-on: ubuntu-latest
    steps:
      - name: SELinux + AEGIS co-existence
        run: |
          # Boot with both, verify both active
      - name: AppArmor + AEGIS co-existence
        run: |
          # Boot with both, verify both active
```

## 6. Verification Commands Quick Reference

```bash
# Full verification suite (run in QEMU)
./scripts/verify-all.sh

# Individual checks
./scripts/check-kasan.sh          # memory safety
./scripts/check-kmemleak.sh       # memory leaks
./scripts/check-lockdep.sh        # lock correctness
./scripts/check-kcsan.sh          # data races
./scripts/check-stacking.sh       # SELinux/AppArmor co-existence
./scripts/check-ebpf-limits.sh    # verifier compliance (if BPF used)
```

---

*Last updated: 2026-09-11. Verification targets kernel 5.15–6.8.*
