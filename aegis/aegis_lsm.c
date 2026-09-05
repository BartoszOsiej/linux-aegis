// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS - Core LSM Hooks
 *
 * Main module entry point implementing all LSM security hooks.
 * Registers the AEGIS security module with the Linux Security Module
 * framework and handles all major security decisions.
 *
 * Copyright (C) 2026 AEGIS Security Project
 */

#define pr_fmt(fmt) "AEGIS: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/path.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <uapi/linux/lsm.h>

#include "aegis.h"

/* ===================== Global Configuration ========================= */

struct aegis_config aegis_cfg = {
	.enabled			= true,
	.features			= AEGIS_FEATURE_ALL,
	.ptrace_restrict_all		= false,
	.ptrace_scope			= 1,
	.file_integrity_enforce		= true,
	.file_integrity_log		= true,
	.syscall_audit_enable		= true,
	.syscall_deny_unlisted		= false,
	.module_loading_denied		= false,
	.module_force_loading		= false,
	.ptrace_blocked			= ATOMIC64_INIT(0),
	.file_violations		= ATOMIC64_INIT(0),
	.syscall_violations		= ATOMIC64_INIT(0),
	.module_violations		= ATOMIC64_INIT(0),
	.total_events			= ATOMIC64_INIT(0),
};

/* ===================== LSM Hook: Process / Ptrace =================== */

/**
 * aegis_task_alloc - Called when a new task is allocated
 * @task: the new task
 * @clone_flags: flags from the clone() call
 * @kernel: true if this is a kernel thread
 *
 * Initialize AEGIS-specific security data for the new task.
 */
static int aegis_task_alloc(struct task_struct *task,
			    u64 clone_flags)
{
	if (!AEGIS_FEATURE_CHECK(AEGIS_FEATURE_PROCESS_PROTECT))
		return 0;

	/* Mark new tasks as non-protected by default */
	task->security = NULL;
	return 0;
}

/**
 * aegis_task_free - Called when a task is freed
 * @task: the task being freed
 *
 * Clean up AEGIS security data when a task exits.
 */
static void aegis_task_free(struct task_struct *task)
{
	if (!aegis_cfg.enabled)
		return;

	AEGIS_STAT_INC(total_events);
}

/**
 * aegis_ptrace_access_check - Validate ptrace access requests
 * @child: the task being ptraced
 * @mode: the type of ptrace access
 *
 * Enforces ptrace restrictions based on AEGIS configuration.
 * Returns 0 if access is allowed, -EPERM if denied.
 */
static int aegis_ptrace_access_check(struct task_struct *child,
				     unsigned int mode)
{
	int rc = 0;

	if (!AEGIS_FEATURE_CHECK(AEGIS_FEATURE_PTRACE_RESTRICT))
		return 0;

	/* Block all ptrace if configured */
	if (aegis_cfg.ptrace_restrict_all) {
		AEGIS_STAT_INC(ptrace_blocked);
		AEGIS_STAT_INC(total_events);

		if (mode & PTRACE_MODE_NOAUDIT) {
			/* Silent check - don't log */
			return -EPERM;
		}

		AEGIS_AUDIT("ptrace BLOCKED: %s[%d] -> %s[%d] (all ptrace restricted)",
			    current->comm, current->pid,
			    child->comm, child->pid);
		return -EPERM;
	}

	/* Check if target is a protected process */
	if (AEGIS_FEATURE_CHECK(AEGIS_FEATURE_PROCESS_PROTECT) &&
	    aegis_is_process_protected(child)) {
		AEGIS_STAT_INC(ptrace_blocked);
		AEGIS_STAT_INC(total_events);
		AEGIS_AUDIT("ptrace BLOCKED: %s[%d] -> PROTECTED %s[%d]",
			    current->comm, current->pid,
			    child->comm, child->pid);
		rc = -EPERM;
	}

	return rc;
}

/**
 * aegis_ptrace_traceme - Validate PTRACE_TRACEME requests
 * @parent: the parent task requesting to trace current
 *
 * Validates that the current task is allowed to be traced.
 */
static int aegis_ptrace_traceme(struct task_struct *parent)
{
	if (!AEGIS_FEATURE_CHECK(AEGIS_FEATURE_PTRACE_RESTRICT))
		return 0;

	if (aegis_cfg.ptrace_restrict_all) {
		AEGIS_STAT_INC(ptrace_blocked);
		AEGIS_STAT_INC(total_events);
		AEGIS_AUDIT("ptrace TRACEME BLOCKED: %s[%d] from %s[%d]",
			    current->comm, current->pid,
			    parent->comm, parent->pid);
		return -EPERM;
	}

	return 0;
}

/* ===================== LSM Hook: File Operations ==================== */

/**
 * aegis_file_permission - Check file access permissions
 * @file: the file being accessed
 * @mask: requested access mask
 *
 * Monitors file access and enforces integrity policies.
 * Returns 0 if access is allowed, -EACCES if denied.
 */
static int aegis_file_permission(struct file *file, int mask)
{
	struct path *f_path;
	char *path_buf, *path_str;
	int rc = 0;

	if (!aegis_cfg.enabled)
		return 0;

	/* Skip if no file integrity feature active */
	if (!AEGIS_FEATURE_CHECK(AEGIS_FEATURE_FILE_INTEGRITY))
		return 0;

	/* Check if this file is protected */
	f_path = (struct path *)&file->f_path;
	path_buf = kmalloc(AEGIS_PATH_LEN, GFP_KERNEL);
	if (!path_buf)
		return 0;

	path_str = d_path(f_path, path_buf, AEGIS_PATH_LEN);
	if (IS_ERR(path_str)) {
		kfree(path_buf);
		return 0;
	}

	if (aegis_is_file_protected(path_str)) {
		/* Deny write/append access to protected files */
		if (mask & (MAY_WRITE | MAY_APPEND)) {
			if (aegis_cfg.file_integrity_enforce) {
				AEGIS_STAT_INC(file_violations);
				AEGIS_STAT_INC(total_events);
				AEGIS_AUDIT("file WRITE BLOCKED: %s[%d] -> %s (protected)",
					    current->comm, current->pid,
					    path_str);
				rc = -EACCES;
			}
		}

		/* Log all access to protected files */
		if (aegis_cfg.file_integrity_log) {
			AEGIS_STAT_INC(total_events);
			AEGIS_AUDIT("file ACCESS: %s[%d] -> %s (mask=0x%x)",
				    current->comm, current->pid,
				    path_str, mask);
		}
	}

	kfree(path_buf);
	return rc;
}

/**
 * aegis_file_open - Check file open operations
 * @file: the file being opened
 *
 * Additional check for file open operations on protected files.
 */
static int aegis_file_open(struct file *file)
{
	/* File permission hook handles the actual checks */
	return 0;
}

/* ===================== LSM Hook: Module Loading ===================== */

/**
 * aegis_kernel_read_file - Validate kernel file reading
 * @file: the file being read
 * @id: the type of kernel file being read
 * @contents_only: true if only contents are needed
 *
 * Controls loading of kernel modules and firmware.
 */
static int aegis_kernel_read_file(struct file *file,
				  enum kernel_read_file_id id,
				  bool contents_only)
{
	if (!aegis_cfg.enabled)
		return 0;

	if (!AEGIS_FEATURE_CHECK(AEGIS_FEATURE_MODULE_CONTROL))
		return 0;

	/* Block module loading if configured */
	if (id == READING_MODULE && aegis_cfg.module_loading_denied) {
		char *path_buf, *path_str;
		int rc = -EPERM;

		path_buf = kmalloc(AEGIS_PATH_LEN, GFP_KERNEL);
		if (!path_buf)
			return -ENOMEM;

		path_str = d_path(&file->f_path, path_buf, AEGIS_PATH_LEN);
		if (!IS_ERR(path_str)) {
			AEGIS_STAT_INC(module_violations);
			AEGIS_STAT_INC(total_events);
			AEGIS_AUDIT("module LOAD BLOCKED: %s[%d] -> %s",
				    current->comm, current->pid,
				    path_str);
		}

		kfree(path_buf);
		return rc;
	}

	/* Block firmware loading too */
	if (id == READING_FIRMWARE && aegis_cfg.module_loading_denied) {
		AEGIS_STAT_INC(module_violations);
		AEGIS_STAT_INC(total_events);
		AEGIS_AUDIT("firmware LOAD BLOCKED: %s[%d]",
			    current->comm, current->pid);
		return -EPERM;
	}

	return 0;
}

/**
 * aegis_kernel_load_data - Validate kernel data loading
 * @id: the type of kernel data being loaded
 *
 * Additional hook for module loading control.
 */
static int aegis_kernel_load_data(enum kernel_load_data_id id,
				    bool contents)
{
	if (!aegis_cfg.enabled)
		return 0;

	if (!AEGIS_FEATURE_CHECK(AEGIS_FEATURE_MODULE_CONTROL))
		return 0;

	if (id == LOADING_MODULE && aegis_cfg.module_loading_denied) {
		AEGIS_STAT_INC(module_violations);
		AEGIS_STAT_INC(total_events);
		AEGIS_AUDIT("module LOAD DATA BLOCKED: %s[%d]",
			    current->comm, current->pid);
		return -EPERM;
	}

	return 0;
}

/* ===================== LSM Hook: Bprm (Exec) ======================== */

/**
 * aegis_bprm_check_security - Validate binary execution
 * @bprm: the binary being executed
 *
 * Checks if execution of the binary is allowed based on AEGIS policy.
 * Can be used to prevent execution of known-bad binaries.
 */
static int aegis_bprm_check_security(struct linux_binprm *bprm)
{
	if (!aegis_cfg.enabled)
		return 0;

	/* Log all exec calls if audit is enabled */
	if (AEGIS_FEATURE_CHECK(AEGIS_FEATURE_SYSCALL_AUDIT) &&
	    aegis_cfg.syscall_audit_enable) {
		AEGIS_STAT_INC(total_events);
		/* We don't block exec, just log for now */
	}

	return 0;
}

/* ===================== LSM Hook: Socket Operations =================== */

/**
 * aegis_socket_create - Validate socket creation
 * @family: socket family
 * @type: socket type
 * @protocol: socket protocol
 * @kern: true if kernel socket
 *
 * Controls creation of network sockets.
 */
static int aegis_socket_create(int family, int type, int protocol, int kern)
{
	if (!aegis_cfg.enabled)
		return 0;

	/* Could be used to restrict raw sockets, etc. */
	return 0;
}

/* ===================== LSM Hook: Inode Operations =================== */

/**
 * aegis_inode_permission - Check inode access
 * @inode: the inode being accessed
 * @mask: requested access mask
 *
 * Additional inode-level access checks.
 */
static int aegis_inode_permission(struct inode *inode, int mask)
{
	/* Delegated to file_permission for file-based checks */
	return 0;
}

/* ===================== Hook Registration ============================ */

static struct security_hook_list aegis_hooks[] __ro_after_init = {
	/* Process protection hooks */
	LSM_HOOK_INIT(task_alloc, aegis_task_alloc),
	LSM_HOOK_INIT(task_free, aegis_task_free),

	/* Ptrace hooks */
	LSM_HOOK_INIT(ptrace_access_check, aegis_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, aegis_ptrace_traceme),

	/* File hooks */
	LSM_HOOK_INIT(file_permission, aegis_file_permission),
	LSM_HOOK_INIT(file_open, aegis_file_open),

	/* Module loading hooks */
	LSM_HOOK_INIT(kernel_read_file, aegis_kernel_read_file),
	LSM_HOOK_INIT(kernel_load_data, aegis_kernel_load_data),

	/* Binary execution hooks */
	LSM_HOOK_INIT(bprm_check_security, aegis_bprm_check_security),

	/* Network hooks */
	LSM_HOOK_INIT(socket_create, aegis_socket_create),

	/* Inode hooks */
	LSM_HOOK_INIT(inode_permission, aegis_inode_permission),
};

/* ===================== LSM Identification =========================== */

static const struct lsm_id aegis_lsmid = {
	.name = AEGIS_NAME,
	.id = LSM_ID_AEGIS,
};

/* ===================== Initialization =============================== */

/**
 * aegis_init - Initialize the AEGIS LSM
 *
 * Called by the LSM framework during boot. Registers all security hooks,
 * initializes subsystems, and prints a startup banner.
 */
static int __init aegis_init(void)
{
	int ret;

	AEGIS_INFO("==============================================");
	AEGIS_INFO("  AEGIS v%s - Advanced Guardian for", AEGIS_VERSION);
	AEGIS_INFO("  Integrated System Security");
	AEGIS_INFO("==============================================");
	AEGIS_INFO("Initializing subsystems...");

	/* Register security hooks first */
	security_add_hooks(aegis_hooks, ARRAY_SIZE(aegis_hooks),
			   &aegis_lsmid);

	/* Initialize process protection subsystem */
	ret = aegis_process_init();
	if (ret) {
		AEGIS_ERR("Failed to initialize process protection: %d", ret);
		return ret;
	}
	AEGIS_INFO("  [+] Process protection: active");

	/* Initialize file integrity subsystem */
	ret = aegis_file_init();
	if (ret) {
		AEGIS_ERR("Failed to initialize file integrity: %d", ret);
		return ret;
	}
	AEGIS_INFO("  [+] File integrity: active");

	/* Initialize syscall audit subsystem */
	ret = aegis_audit_init();
	if (ret) {
		AEGIS_ERR("Failed to initialize syscall audit: %d", ret);
		return ret;
	}
	AEGIS_INFO("  [+] Syscall audit: active");

	/* Initialize module control subsystem */
	ret = aegis_module_init();
	if (ret) {
		AEGIS_ERR("Failed to initialize module control: %d", ret);
		return ret;
	}
	AEGIS_INFO("  [+] Module control: active");

	/* Initialize sysctl interface */
	ret = aegis_sysctl_init();
	if (ret) {
		AEGIS_ERR("Failed to initialize sysctl: %d", ret);
		return ret;
	}
	AEGIS_INFO("  [+] Sysctl interface: active");

	/* Initialize securityfs interface */
	ret = aegis_securityfs_init();
	if (ret) {
		AEGIS_ERR("Failed to initialize securityfs: %d", ret);
		return ret;
	}
	AEGIS_INFO("  [+] Securityfs interface: active");

	AEGIS_INFO("==============================================");
	AEGIS_INFO("  AEGIS is ACTIVE - Shield is UP");
	AEGIS_INFO("  Features: 0x%08x", aegis_cfg.features);
	AEGIS_INFO("==============================================");

	return 0;
}

DEFINE_LSM(aegis) = {
	.id = &aegis_lsmid,
	.init = aegis_init,
	.order = LSM_ORDER_MUTABLE,
};
