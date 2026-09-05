// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS - Syscall Auditing Subsystem
 *
 * Provides syscall monitoring and filtering:
 *   - Blocked syscall list management
 *   - Syscall access validation
 *   - Audit logging for denied syscalls
 *
 * Copyright (C) 2026 AEGIS Security Project
 */

#define pr_fmt(fmt) "AEGIS-audit: " fmt

#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>

#include "aegis.h"

/* ===================== Internal Data Structures ===================== */

static LIST_HEAD(blocked_syscalls);
static DEFINE_SPINLOCK(blocked_syscalls_lock);
static int blocked_syscall_count;

/* ===================== Public API =================================== */

/**
 * aegis_audit_init - Initialize the syscall auditing subsystem
 */
int aegis_audit_init(void)
{
	spin_lock_init(&blocked_syscalls_lock);
	blocked_syscall_count = 0;

	/* Add some dangerous syscalls to the block list by default */
	aegis_syscall_block_add(__NR_kexec_load);
	aegis_syscall_block_add(__NR_kexec_file_load);
	aegis_syscall_block_add(__NR_init_module);
	aegis_syscall_block_add(__NR_finit_module);
	aegis_syscall_block_add(__NR_delete_module);

	return 0;
}

/**
 * aegis_audit_exit - Cleanup the syscall auditing subsystem
 */
void aegis_audit_exit(void)
{
	struct aegis_blocked_syscall *entry, *tmp;

	spin_lock(&blocked_syscalls_lock);
	list_for_each_entry_safe(entry, tmp, &blocked_syscalls, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	blocked_syscall_count = 0;
	spin_unlock(&blocked_syscalls_lock);
}

/**
 * aegis_syscall_block_add - Add a syscall to the blocked list
 * @syscall_nr: syscall number to block
 *
 * Returns 0 on success, -ENOMEM on allocation failure, -EEXIST if already
 * blocked, -EINVAL on invalid arguments.
 */
int aegis_syscall_block_add(int syscall_nr)
{
	struct aegis_blocked_syscall *sc;

	if (syscall_nr < 0)
		return -EINVAL;

	/* Check if already blocked */
	spin_lock(&blocked_syscalls_lock);
	list_for_each_entry(sc, &blocked_syscalls, list) {
		if (sc->syscall_nr == syscall_nr) {
			spin_unlock(&blocked_syscalls_lock);
			return -EEXIST;
		}
	}
	spin_unlock(&blocked_syscalls_lock);

	sc = kmalloc(sizeof(*sc), GFP_KERNEL);
	if (!sc)
		return -ENOMEM;

	sc->syscall_nr = syscall_nr;

	spin_lock(&blocked_syscalls_lock);
	list_add_tail(&sc->list, &blocked_syscalls);
	blocked_syscall_count++;
	spin_unlock(&blocked_syscalls_lock);

	AEGIS_INFO("Blocked syscall added: %d", syscall_nr);
	return 0;
}

/**
 * aegis_syscall_block_del - Remove a syscall from the blocked list
 * @syscall_nr: syscall number to unblock
 *
 * Returns 0 on success, -ENOENT if not found.
 */
int aegis_syscall_block_del(int syscall_nr)
{
	struct aegis_blocked_syscall *entry, *tmp;
	bool found = false;

	spin_lock(&blocked_syscalls_lock);
	list_for_each_entry_safe(entry, tmp, &blocked_syscalls, list) {
		if (entry->syscall_nr == syscall_nr) {
			list_del(&entry->list);
			kfree(entry);
			blocked_syscall_count--;
			found = true;
			break;
		}
	}
	spin_unlock(&blocked_syscalls_lock);

	if (!found)
		return -ENOENT;

	AEGIS_INFO("Blocked syscall removed: %d", syscall_nr);
	return 0;
}

/**
 * aegis_is_syscall_blocked - Check if a syscall is blocked
 * @syscall_nr: syscall number to check
 *
 * Returns true if the syscall is blocked, false otherwise.
 */
bool aegis_is_syscall_blocked(int syscall_nr)
{
	struct aegis_blocked_syscall *entry;
	bool blocked = false;

	if (!AEGIS_FEATURE_CHECK(AEGIS_FEATURE_SYSCALL_AUDIT))
		return false;

	if (!aegis_cfg.syscall_audit_enable)
		return false;

	spin_lock(&blocked_syscalls_lock);
	list_for_each_entry(entry, &blocked_syscalls, list) {
		if (entry->syscall_nr == syscall_nr) {
			blocked = true;
			break;
		}
	}
	spin_unlock(&blocked_syscalls_lock);

	return blocked;
}

/**
 * aegis_blocked_syscall_show - Display blocked syscalls
 * @m: seq_file to write to
 */
void aegis_blocked_syscall_show(struct seq_file *m)
{
	struct aegis_blocked_syscall *entry;

	seq_printf(m, "AEGIS Blocked Syscalls (%d entries):\n",
		   blocked_syscall_count);
	seq_printf(m, "%8s %s\n", "NR", "NAME");
	seq_printf(m, "%8s %s\n", "--", "----");

	spin_lock(&blocked_syscalls_lock);
	list_for_each_entry(entry, &blocked_syscalls, list) {
		seq_printf(m, "%8d\n", entry->syscall_nr);
	}
	spin_unlock(&blocked_syscalls_lock);
}
