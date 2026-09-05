// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS - Securityfs Interface
 *
 * Provides /sys/kernel/security/aegis/ interface for:
 *   - Status display (status)
 *   - Protected processes list (protected_procs)
 *   - Protected files list (protected_files)
 *   - Blocked syscalls list (blocked_syscalls)
 *   - Statistics (stats)
 *
 * Copyright (C) 2026 AEGIS Security Project
 */

#define pr_fmt(fmt) "AEGIS-fs: " fmt

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/security.h>

#include "aegis.h"

/* ===================== Securityfs Inodes ============================ */

static struct dentry *aegis_dir;

/* ===================== Seq File Operations ========================== */

/**
 * aegis_status_show - Display AEGIS status
 */
static int aegis_status_show(struct seq_file *m, void *v)
{
	seq_printf(m, "==============================================\n");
	seq_printf(m, "  AEGIS v%s - Advanced Guardian for\n", AEGIS_VERSION);
	seq_printf(m, "  Integrated System Security\n");
	seq_printf(m, "==============================================\n");
	seq_printf(m, "\n");
	seq_printf(m, "  Status:        %s\n",
		   aegis_cfg.enabled ? "ACTIVE" : "DISABLED");
	seq_printf(m, "  Features:      0x%08x\n", aegis_cfg.features);
	seq_printf(m, "\n");
	seq_printf(m, "  Process Protection:   %s\n",
		   AEGIS_FEATURE_CHECK(AEGIS_FEATURE_PROCESS_PROTECT) ?
		   "ON" : "OFF");
	seq_printf(m, "  File Integrity:       %s\n",
		   AEGIS_FEATURE_CHECK(AEGIS_FEATURE_FILE_INTEGRITY) ?
		   "ON" : "OFF");
	seq_printf(m, "  Syscall Audit:        %s\n",
		   AEGIS_FEATURE_CHECK(AEGIS_FEATURE_SYSCALL_AUDIT) ?
		   "ON" : "OFF");
	seq_printf(m, "  Module Control:       %s\n",
		   AEGIS_FEATURE_CHECK(AEGIS_FEATURE_MODULE_CONTROL) ?
		   "ON" : "OFF");
	seq_printf(m, "  Ptrace Restrict:      %s\n",
		   AEGIS_FEATURE_CHECK(AEGIS_FEATURE_PTRACE_RESTRICT) ?
		   "ON" : "OFF");
	seq_printf(m, "\n");
	seq_printf(m, "  Ptrace All Restrict:  %s\n",
		   aegis_cfg.ptrace_restrict_all ? "ON" : "OFF");
	seq_printf(m, "  File Integrity Enf:   %s\n",
		   aegis_cfg.file_integrity_enforce ? "ON" : "OFF");
	seq_printf(m, "  Module Loading Deny:  %s\n",
		   aegis_cfg.module_loading_denied ? "ON" : "OFF");
	seq_printf(m, "\n");
	return 0;
}

static int aegis_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, aegis_status_show, NULL);
}

static const struct file_operations aegis_status_fops = {
	.owner		= THIS_MODULE,
	.open		= aegis_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/**
 * aegis_stats_show - Display AEGIS statistics
 */
static int aegis_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "AEGIS Event Statistics:\n");
	seq_printf(m, "=======================\n");
	seq_printf(m, "  Ptrace blocked:       %lld\n",
		   atomic64_read(&aegis_cfg.ptrace_blocked));
	seq_printf(m, "  File violations:      %lld\n",
		   atomic64_read(&aegis_cfg.file_violations));
	seq_printf(m, "  Syscall violations:   %lld\n",
		   atomic64_read(&aegis_cfg.syscall_violations));
	seq_printf(m, "  Module violations:    %lld\n",
		   atomic64_read(&aegis_cfg.module_violations));
	seq_printf(m, "  Total events:         %lld\n",
		   atomic64_read(&aegis_cfg.total_events));
	seq_printf(m, "\n");
	return 0;
}

static int aegis_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, aegis_stats_show, NULL);
}

static const struct file_operations aegis_stats_fops = {
	.owner		= THIS_MODULE,
	.open		= aegis_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/**
 * aegis_protected_procs_show - Display protected processes
 */
static int aegis_protected_procs_show(struct seq_file *m, void *v)
{
	aegis_protected_process_show(m);
	return 0;
}

static int aegis_protected_procs_open(struct inode *inode, struct file *file)
{
	return single_open(file, aegis_protected_procs_show, NULL);
}

static const struct file_operations aegis_protected_procs_fops = {
	.owner		= THIS_MODULE,
	.open		= aegis_protected_procs_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/**
 * aegis_protected_files_show - Display protected files
 */
static int aegis_protected_files_show(struct seq_file *m, void *v)
{
	aegis_protected_file_show(m);
	return 0;
}

static int aegis_protected_files_open(struct inode *inode, struct file *file)
{
	return single_open(file, aegis_protected_files_show, NULL);
}

static const struct file_operations aegis_protected_files_fops = {
	.owner		= THIS_MODULE,
	.open		= aegis_protected_files_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/**
 * aegis_blocked_syscalls_show - Display blocked syscalls
 */
static int aegis_blocked_syscalls_show(struct seq_file *m, void *v)
{
	aegis_blocked_syscall_show(m);
	return 0;
}

static int aegis_blocked_syscalls_open(struct inode *inode, struct file *file)
{
	return single_open(file, aegis_blocked_syscalls_show, NULL);
}

static const struct file_operations aegis_blocked_syscalls_fops = {
	.owner		= THIS_MODULE,
	.open		= aegis_blocked_syscalls_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* ===================== Initialization =============================== */

/**
 * aegis_securityfs_init - Create the /sys/kernel/security/aegis/ tree
 */
int aegis_securityfs_init(void)
{
	aegis_dir = securityfs_create_dir(AEGIS_NAME, NULL);
	if (IS_ERR(aegis_dir)) {
		AEGIS_ERR("Failed to create securityfs directory: %ld",
			  PTR_ERR(aegis_dir));
		return PTR_ERR(aegis_dir);
	}

	/* Create status file */
	securityfs_create_file("status", 0444, aegis_dir,
			       NULL, &aegis_status_fops);

	/* Create stats file */
	securityfs_create_file("stats", 0444, aegis_dir,
			       NULL, &aegis_stats_fops);

	/* Create protected processes file */
	securityfs_create_file("protected_procs", 0444, aegis_dir,
			       NULL, &aegis_protected_procs_fops);

	/* Create protected files file */
	securityfs_create_file("protected_files", 0444, aegis_dir,
			       NULL, &aegis_protected_files_fops);

	/* Create blocked syscalls file */
	securityfs_create_file("blocked_syscalls", 0444, aegis_dir,
			       NULL, &aegis_blocked_syscalls_fops);

	AEGIS_INFO("Securityfs interface created at /sys/kernel/security/aegis/");
	return 0;
}

/**
 * aegis_securityfs_exit - Remove the /sys/kernel/security/aegis/ tree
 */
void aegis_securityfs_exit(void)
{
	if (aegis_dir && !IS_ERR(aegis_dir))
		securityfs_remove(aegis_dir);
}
