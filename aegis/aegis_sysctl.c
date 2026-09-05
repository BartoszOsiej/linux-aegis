// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS - Sysctl Interface
 *
 * Provides /proc/sys/kernel/aegis/ interface for runtime configuration:
 *   - enabled: master switch
 *   - features: feature bitmask
 *   - ptrace_restrict_all: restrict all ptrace
 *   - file_integrity_enforce: enforce file integrity
 *   - module_loading_denied: deny module loading
 *
 * Copyright (C) 2026 AEGIS Security Project
 */

#define pr_fmt(fmt) "AEGIS-sysctl: " fmt

#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/seq_file.h>

#include "aegis.h"

/* ===================== Sysctl Variables ============================= */

static int aegis_enabled = 1;
static int aegis_features_val = AEGIS_FEATURE_ALL;
static int aegis_ptrace_restrict_all = 0;
static int aegis_file_integrity_enforce = 1;
static int aegis_module_loading_denied = 0;
static int aegis_syscall_audit_enable = 1;

/* ===================== Sysctl Handlers ============================== */

/**
 * aegis_proc_enable - Handle /proc/sys/kernel/aegis/enabled
 */
static int aegis_proc_enable(const struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		aegis_cfg.enabled = (aegis_enabled != 0);
		AEGIS_INFO("AEGIS %s",
			   aegis_cfg.enabled ? "ENABLED" : "DISABLED");
	}

	return ret;
}

/**
 * aegis_proc_features - Handle /proc/sys/kernel/aegis/features
 */
static int aegis_proc_features(const struct ctl_table *table, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		aegis_cfg.features = (u32)aegis_features_val;
		AEGIS_INFO("Features updated: 0x%08x", aegis_cfg.features);
	}

	return ret;
}

/* ===================== Sysctl Table ================================ */

static struct ctl_table aegis_sysctl_table[] = {
	{
		.procname	= "enabled",
		.data		= &aegis_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= aegis_proc_enable,
	},
	{
		.procname	= "features",
		.data		= &aegis_features_val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= aegis_proc_features,
	},
	{
		.procname	= "ptrace_restrict_all",
		.data		= &aegis_ptrace_restrict_all,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "file_integrity_enforce",
		.data		= &aegis_file_integrity_enforce,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "module_loading_denied",
		.data		= &aegis_module_loading_denied,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "syscall_audit_enable",
		.data		= &aegis_syscall_audit_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,		},
};

/* ===================== Initialization =============================== */

static struct ctl_table_header *aegis_sysctl_header;

/**
 * aegis_sysctl_init - Register the sysctl interface
 */
int aegis_sysctl_init(void)
{
	aegis_sysctl_header = register_sysctl("kernel/aegis",
					      aegis_sysctl_table);
	if (!aegis_sysctl_header) {
		AEGIS_ERR("Failed to register sysctl interface");
		return -ENOMEM;
	}

	AEGIS_INFO("Sysctl interface created at /proc/sys/kernel/aegis/");
	return 0;
}

/**
 * aegis_sysctl_exit - Unregister the sysctl interface
 */
void aegis_sysctl_exit(void)
{
	if (aegis_sysctl_header)
		unregister_sysctl_table(aegis_sysctl_header);
}
