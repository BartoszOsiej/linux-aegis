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
static struct dentry *aegis_status_d;
static struct dentry *aegis_stats_d;
static struct dentry *aegis_protected_procs_d;
static struct dentry *aegis_protected_files_d;
static struct dentry *aegis_blocked_syscalls_d;

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
 *
 * MUST run as a late initcall: securityfs_create_dir() requires the VFS
 * mount machinery, which is not initialized while LSM initcalls run.
 * Calling this directly from aegis_init() null-derefs and panics the boot
 * (the same reason Landlock sets up its securityfs in late_initcall).
 */
int aegis_securityfs_init(void)
{
	int ret = 0;

	aegis_dir = securityfs_create_dir(AEGIS_NAME, NULL);
	if (IS_ERR(aegis_dir)) {
		ret = PTR_ERR(aegis_dir);
		aegis_dir = NULL;
		AEGIS_ERR("Failed to create securityfs directory: %d", ret);
		return ret;
	}

	/* Create status file */
	aegis_status_d = securityfs_create_file("status", 0444, aegis_dir,
					       NULL, &aegis_status_fops);
	if (IS_ERR(aegis_status_d)) {
		ret = PTR_ERR(aegis_status_d);
		goto err;
	}

	/* Create stats file */
	aegis_stats_d = securityfs_create_file("stats", 0444, aegis_dir,
					       NULL, &aegis_stats_fops);
	if (IS_ERR(aegis_stats_d)) {
		ret = PTR_ERR(aegis_stats_d);
		goto err;
	}

	/* Create protected processes file */
	aegis_protected_procs_d = securityfs_create_file("protected_procs", 0444,
							 aegis_dir, NULL,
							 &aegis_protected_procs_fops);
	if (IS_ERR(aegis_protected_procs_d)) {
		ret = PTR_ERR(aegis_protected_procs_d);
		goto err;
	}

	/* Create protected files file */
	aegis_protected_files_d = securityfs_create_file("protected_files", 0444,
							 aegis_dir, NULL,
							 &aegis_protected_files_fops);
	if (IS_ERR(aegis_protected_files_d)) {
		ret = PTR_ERR(aegis_protected_files_d);
		goto err;
	}

	/* Create blocked syscalls file */
	aegis_blocked_syscalls_d = securityfs_create_file("blocked_syscalls", 0444,
							  aegis_dir, NULL,
							  &aegis_blocked_syscalls_fops);
	if (IS_ERR(aegis_blocked_syscalls_d)) {
		ret = PTR_ERR(aegis_blocked_syscalls_d);
		goto err;
	}

	/* Write-side control endpoints (CAP_MAC_ADMIN gated) */
	ret = aegis_control_init(aegis_dir);
	if (ret)
		goto err;

	AEGIS_INFO("Securityfs interface created at /sys/kernel/security/aegis/");
	return 0;

err:
	aegis_securityfs_exit();
	AEGIS_ERR("Failed to create securityfs entry: %d", ret);
	return ret;
}

/**
 * aegis_securityfs_exit - Remove the /sys/kernel/security/aegis/ tree
 */
void aegis_securityfs_exit(void)
{
	/* Write-side endpoints first, then read files, then the directory */
	aegis_control_exit();

	/* Files must be removed individually, then the directory */
	if (!IS_ERR_OR_NULL(aegis_status_d))
		securityfs_remove(aegis_status_d);
	if (!IS_ERR_OR_NULL(aegis_stats_d))
		securityfs_remove(aegis_stats_d);
	if (!IS_ERR_OR_NULL(aegis_protected_procs_d))
		securityfs_remove(aegis_protected_procs_d);
	if (!IS_ERR_OR_NULL(aegis_protected_files_d))
		securityfs_remove(aegis_protected_files_d);
	if (!IS_ERR_OR_NULL(aegis_blocked_syscalls_d))
		securityfs_remove(aegis_blocked_syscalls_d);
	if (!IS_ERR_OR_NULL(aegis_dir))
		securityfs_remove(aegis_dir);

	aegis_status_d = NULL;
	aegis_stats_d = NULL;
	aegis_protected_procs_d = NULL;
	aegis_protected_files_d = NULL;
	aegis_blocked_syscalls_d = NULL;
	aegis_dir = NULL;
}

/**
 * aegis_securityfs_late_init - deferred securityfs setup
 *
 * Registered below; runs after the VFS is fully alive.
 */
static int __init aegis_securityfs_late_init(void)
{
	int ret = aegis_securityfs_init();
	if (ret)
		AEGIS_ERR("securityfs init deferred call failed: %d", ret);
	return ret;
}
late_initcall(aegis_securityfs_late_init);
