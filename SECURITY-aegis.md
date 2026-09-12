# Security Policy — linux-aegis

> **AEGIS is a Linux Security Module.** Vulnerabilities in AEGIS can compromise the security of every system running it. We treat security reports with the highest priority.

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch (latest) | ✅ Active |
| Older releases | ⚠️ Best-effort (30-day fix window) |

## Vulnerability Disclosure Policy

### Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, use **one** of these channels (in order of preference):

1. **Encrypted email** (preferred):
   ```
   thethreadcalls@outlook.com
   Subject: [SECURITY] linux-aegis — <brief description>
   ```
   Encrypt your report using the quantum-shield public key:
   ```bash
   # Fetch the public key
   curl -s https://bartoszosiej.github.io/quantum-shield/KEYS | quantum-shield decrypt --verify-only
   ```
   Or use PGP if you have the maintainer's key:
   ```
   Fingerprint: (publish after first key exchange)
   ```

2. **GitHub Security Advisories** (private):
   Go to https://github.com/BartoszOsiej/linux-aegis/security/advisories/new
   This creates a private advisory visible only to maintainers.

3. **Direct message** to `@BartoszOsiej` on GitHub (for urgent issues only).

### What to Include

Your report **must** include:

- **Description**: Clear, concise description of the vulnerability
- **Type**: Buffer overflow, use-after-free, privilege escalation, information leak, DoS, etc.
- **Affected components**: Which LSM hooks, which kernel versions, which AEGIS layers
- **Reproduction steps**: Minimal steps to trigger the vulnerability
- **Impact assessment**: What an attacker could achieve (RCE, privilege escalation, bypass, DoS)
- **Suggested fix** (if any): Proposed mitigation

### Optional: CVSS v3.1 Score

If you can provide a CVSS v3.1 score, it helps us prioritize:

| Severity | CVSS Range | Response SLA |
|---|---|---|
| **Critical** | 9.0–10.0 | **24 hours** initial response |
| **High** | 7.0–8.9 | **48 hours** initial response |
| **Medium** | 4.0–6.9 | **72 hours** initial response |
| **Low** | 0.1–3.9 | **7 days** initial response |
| **Informational** | 0.0 | Best-effort |

## Response SLAs

| Phase | SLA |
|---|---|
| **Initial acknowledgment** | Within 24–72 hours (severity-dependent) |
| **Triage & impact assessment** | Within 72 hours of acknowledgment |
| **Fix development** | Critical: 7 days / High: 14 days / Medium: 30 days / Low: 90 days |
| **Public disclosure** | 90 days after fix (or after upstream kernel patch, whichever is later) |
| **CVE assignment** | If accepted, CVE requested within 14 days of triage |

### SLA Details

1. **Triage (72 hours)**: We confirm the vulnerability, assess impact, and assign severity.
2. **Fix development**: We develop and test a patch. For kernel-level issues, we coordinate with upstream Linux security team if the bug is in shared code.
3. **Disclosure**: We publish a security advisory on GitHub with the fix, CVE (if applicable), and credits. We request 90-day coordinated disclosure.
4. **Backport**: For supported older versions, we backport the fix within 7 days of the main branch fix.

## Scope

### In Scope

- Memory safety violations in AEGIS code (buffer overflows, use-after-free, double-free)
- eBPF verifier bypasses that allow loading malicious BPF programs
- Privilege escalation through AEGIS hooks
- Information leaks via AEGIS interfaces (dmesg, netlink, procfs)
- Denial of service against the kernel via AEGIS
- Logic bugs that allow bypassing AEGIS security checks
- Race conditions in hook registration/deregistration
- Incorrect stackable module interaction with SELinux/AppArmor

### Out of Scope

- Vulnerabilities in the upstream Linux kernel (report to kernel security team)
- Vulnerabilities in eBPF verifier itself (report to kernel security team)
- Issues requiring physical access to the machine
- Social engineering attacks
- Issues in third-party dependencies (report upstream)

## Security Design Principles

AEGIS follows these principles to minimize attack surface:

1. **Minimal hook set**: Only 4 LSM hooks are registered (task_alloc, inode_create, inode_rename, socket_connect). Fewer hooks = smaller attack surface.
2. **No userspace communication by default**: Events are logged to kernel ring buffer (dmesg). Netlink interface is opt-in.
3. **Read-only data paths**: Configuration is read from a shared BPF map. The BPF side never writes to userspace memory.
4. **Stackable isolation**: AEGIS hooks run independently of other LSMs. A bug in AEGIS cannot corrupt SELinux/AppArmor state.
5. **KASAN-compatible**: All AEGIS code is compatible with Kernel Address Sanitizer for automated memory safety testing.

## Bug Bounty

We do not currently operate a bug bounty program. However, we recognize security researchers who report valid vulnerabilities:

- **Public credit** in the security advisory (unless you prefer anonymity)
- **Hall of fame** in `SECURITY_HALL_OF_FAME.md`
- **Letter of recognition** for academic/research purposes

## Contact

| Channel | Details |
|---|---|
| Encrypted email | thethreadcalls@outlook.com |
| GitHub Advisory | https://github.com/BartoszOsiej/linux-aegis/security/advisories |
| maintainer | @BartoszOsiej |
| Entity Home | https://bartoszosiej.github.io/ |

## PGP Key

```
(To be published after first key exchange with a reporter)
```

---

*This security policy is modeled after industry best practices (OpenSSF, Linux kernel security, CNCF). Last updated: 2026-09-11.*
