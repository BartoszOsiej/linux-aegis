/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AEGIS - Advanced Guardian for Integrated System Security
 *
 * A Linux Security Module providing comprehensive kernel-level protection:
 *   - Process protection (anti-ptrace, anti-debugging)
 *   - File integrity monitoring
 *   - Syscall auditing and filtering
 *   - Kernel module loading control
 *
 * Copyright (C) 2026 AEGIS Security Project
 *
 * Author: AEGIS Development Team
 */

#ifndef _AEGIS_H
#define _AEGIS_H

#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/crypto.h>
#include <linux/hash.h>

/* ===================== Configuration Constants ======================== */

#define AEGIS_VERSION		"1.0.0"
#define AEGIS_NAME		"aegis"
#define AEGIS_DESCRIPTION	"Advanced Guardian for Integrated System Security"

/* Maximum length of process names to protect */
#define AEGIS_MAX_PROTECTED_PROCS	64
#define AEGIS_MAX_PROTECTED_FILES	128
#define AEGIS_MAX_BLOCKED_SYSCALLS	256
#define AEGIS_COMM_LEN			16
#define AEGIS_PATH_LEN			256

/* File integrity hash algorithm */
#define AEGIS_HASH_ALGO		"sha256"
#define AEGIS_HASH_SIZE		SHA256_DIGEST_SIZE

/* ======================== Feature Flags ============================== */

/* Enable/disable individual AEGIS subsystems */
#define AEGIS_FEATURE_PROCESS_PROTECT	(1 << 0)
#define AEGIS_FEATURE_FILE_INTEGRITY	(1 << 1)
#define AEGIS_FEATURE_SYSCALL_AUDIT	(1 << 2)
#define AEGIS_FEATURE_MODULE_CONTROL	(1 << 3)
#define AEGIS_FEATURE_PTRACE_RESTRICT	(1 << 4)
#define AEGIS_FEATURE_FULL_SHIELD	(1 << 5)

/* All features enabled by default */
#define AEGIS_FEATURE_ALL		(AEGIS_FEATURE_PROCESS_PROTECT | \
					 AEGIS_FEATURE_FILE_INTEGRITY | \
					 AEGIS_FEATURE_SYSCALL_AUDIT | \
					 AEGIS_FEATURE_MODULE_CONTROL | \
					 AEGIS_FEATURE_PTRACE_RESTRICT)

/* ======================== Global State =============================== */

struct aegis_config {
	/* Master switch */
	bool enabled;

	/* Feature bitmask */
	u32 features;

	/* Process protection */
	bool ptrace_restrict_all;	/* Restrict ALL ptrace operations */
	int ptrace_scope;		/* 0=disabled, 1=restricted, 2=blocked */

	/* File integrity */
	bool file_integrity_enforce;	/* Deny modifications to protected files */
	bool file_integrity_log;	/* Log all access to protected files */

	/* Syscall auditing */
	bool syscall_audit_enable;	/* Enable syscall auditing */
	bool syscall_deny_unlisted;	/* Deny syscalls not in the allow list */

	/* Module control */
	bool module_loading_denied;	/* Deny all module loading */
	bool module_force_loading;	/* Deny forced module loading */

	/* Statistics counters (read-only) */
	atomic64_t ptrace_blocked;
	atomic64_t file_violations;
	atomic64_t syscall_violations;
	atomic64_t module_violations;
	atomic64_t total_events;
};

/* Protected process entry */
struct aegis_protected_proc {
	char comm[AEGIS_COMM_LEN];
	pid_t pid;
	struct list_head list;
};

/* Protected file entry */
struct aegis_protected_file {
	char path[AEGIS_PATH_LEN];
	u8 hash[AEGIS_HASH_SIZE];
	bool hash_valid;
	struct list_head list;
};

/* Blocked syscall entry */
struct aegis_blocked_syscall {
	int syscall_nr;
	struct list_head list;
};

/* ======================== Global Externals =========================== */

extern struct aegis_config aegis_cfg;

/* ======================== Function Declarations ====================== */

/* aegis_lsm.c - Core LSM hooks */
void aegis_init_hooks(void);

/* aegis_process.c - Process protection subsystem */
int aegis_process_init(void);
void aegis_process_exit(void);
int aegis_protect_process_add(const char *comm, pid_t pid);
int aegis_protect_process_del(const char *comm, pid_t pid);
bool aegis_is_process_protected(struct task_struct *task);
void aegis_protected_process_show(struct seq_file *m);

/* aegis_file.c - File integrity subsystem */
int aegis_file_init(void);
void aegis_file_exit(void);
int aegis_protected_file_add(const char *path);
int aegis_protected_file_del(const char *path);
int aegis_compute_file_hash(struct file *file, u8 *hash_out);
bool aegis_is_file_protected(const char *path);
void aegis_protected_file_show(struct seq_file *m);

/* aegis_audit.c - Syscall auditing subsystem */
int aegis_audit_init(void);
void aegis_audit_exit(void);
int aegis_syscall_block_add(int syscall_nr);
int aegis_syscall_block_del(int syscall_nr);
bool aegis_is_syscall_blocked(int syscall_nr);
void aegis_blocked_syscall_show(struct seq_file *m);

/* aegis_module.c - Module loading control */
int aegis_module_init(void);
void aegis_module_exit(void);

/* aegis_securityfs.c - Securityfs interface */
int aegis_securityfs_init(void);
void aegis_securityfs_exit(void);

/* aegis_sysctl.c - Sysctl interface */
int aegis_sysctl_init(void);
void aegis_sysctl_exit(void);

/* ======================== Utility Macros ============================= */

#define AEGIS_FEATURE_CHECK(feature) \
	(aegis_cfg.enabled && (aegis_cfg.features & (feature)))

#define AEGIS_STAT_INC(counter) \
	atomic64_inc(&aegis_cfg.counter)

#define AEGIS_LOG(level, fmt, ...) \
	printk(level "aegis: " fmt "\n", ##__VA_ARGS__)

#define AEGIS_WARN(fmt, ...) \
	AEGIS_LOG(KERN_WARNING, fmt, ##__VA_ARGS__)

#define AEGIS_INFO(fmt, ...) \
	AEGIS_LOG(KERN_INFO, fmt, ##__VA_ARGS__)

#define AEGIS_ERR(fmt, ...) \
	AEGIS_LOG(KERN_ERR, fmt, ##__VA_ARGS__)

#define AEGIS_AUDIT(fmt, ...) \
	AEGIS_LOG(KERN_WARNING, fmt, ##__VA_ARGS__)

#endif /* _AEGIS_H */
