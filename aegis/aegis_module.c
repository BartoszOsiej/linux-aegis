// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS - Module Loading Control Subsystem
 *
 * Provides control over kernel module loading:
 *   - Deny all module loading
 *   - Deny forced module loading
 *   - Audit module load attempts
 *
 * Copyright (C) 2026 AEGIS Security Project
 */

#define pr_fmt(fmt) "AEGIS-mod: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#include "aegis.h"

/* ===================== Public API =================================== */

/**
 * aegis_module_init - Initialize the module control subsystem
 */
int aegis_module_init(void)
{
	return 0;
}

/**
 * aegis_module_exit - Cleanup the module control subsystem
 */
void aegis_module_exit(void)
{
	/* Nothing to clean up */
}
