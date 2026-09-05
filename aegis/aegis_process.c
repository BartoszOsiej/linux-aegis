// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS - Process Protection Subsystem
 *
 * Provides process-level protection including:
 *   - Protected process list (by name or PID)
 *   - Anti-ptrace restrictions
 *   - Anti-debugging measures
 *   - Process ancestry validation
 *
 * Copyright (C) 2026 AEGIS Security Project
 */

#define pr_fmt(fmt) "AEGIS-proc: " fmt

#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/kernel.h>

#include "aegis.h"

/* ===================== Internal Data Structures ===================== */

static LIST_HEAD(protected_procs);
static DEFINE_SPINLOCK(protected_procs_lock);
static int protected_proc_count;

/* ===================== Public API =================================== */

/**
 * aegis_process_init - Initialize the process protection subsystem
 */
int aegis_process_init(void)
{
	spin_lock_init(&protected_procs_lock);
	protected_proc_count = 0;

	/* Add some default protected processes */
	aegis_protect_process_add("sshd", 0);
	aegis_protect_process_add("init", 1);
	aegis_protect_process_add("systemd", 1);

	return 0;
}

/**
 * aegis_process_exit - Cleanup the process protection subsystem
 */
void aegis_process_exit(void)
{
	struct aegis_protected_proc *entry, *tmp;

	spin_lock(&protected_procs_lock);
	list_for_each_entry_safe(entry, tmp, &protected_procs, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	protected_proc_count = 0;
	spin_unlock(&protected_procs_lock);
}

/**
 * aegis_protect_process_add - Add a process to the protected list
 * @comm: process name to protect (NULL for any)
 * @pid: specific PID to protect (0 for name-based only)
 *
 * Adds a process to the protected list. If comm is provided, all processes
 * matching that name will be protected. If pid is non-zero, only that
 * specific PID is protected.
 *
 * Returns 0 on success, -ENOMEM on allocation failure, -EEXIST if already
 * protected, -EINVAL on invalid arguments.
 */
int aegis_protect_process_add(const char *comm, pid_t pid)
{
	struct aegis_protected_proc *proc;

	if (!comm)
		return -EINVAL;

	/* Check if already protected */
	spin_lock(&protected_procs_lock);
	list_for_each_entry(proc, &protected_procs, list) {
		if (proc->pid == pid && strncmp(proc->comm, comm, AEGIS_COMM_LEN) == 0) {
			spin_unlock(&protected_procs_lock);
			return -EEXIST;
		}
	}
	spin_unlock(&protected_procs_lock);

	proc = kmalloc(sizeof(*proc), GFP_KERNEL);
	if (!proc)
		return -ENOMEM;

	memset(proc->comm, 0, AEGIS_COMM_LEN);
	strscpy(proc->comm, comm, AEGIS_COMM_LEN);
	proc->pid = pid;

	spin_lock(&protected_procs_lock);
	list_add_tail(&proc->list, &protected_procs);
	protected_proc_count++;
	spin_unlock(&protected_procs_lock);

	AEGIS_INFO("Protected process added: %s (pid=%d)", comm, pid);
	return 0;
}

/**
 * aegis_protect_process_del - Remove a process from the protected list
 * @comm: process name to unprotect
 * @pid: specific PID to unprotect (0 for name-based only)
 *
 * Returns 0 on success, -ENOENT if not found.
 */
int aegis_protect_process_del(const char *comm, pid_t pid)
{
	struct aegis_protected_proc *entry, *tmp;
	bool found = false;

	if (!comm)
		return -EINVAL;

	spin_lock(&protected_procs_lock);
	list_for_each_entry_safe(entry, tmp, &protected_procs, list) {
		if (entry->pid == pid &&
		    strncmp(entry->comm, comm, AEGIS_COMM_LEN) == 0) {
			list_del(&entry->list);
			kfree(entry);
			protected_proc_count--;
			found = true;
			break;
		}
	}
	spin_unlock(&protected_procs_lock);

	if (!found)
		return -ENOENT;

	AEGIS_INFO("Protected process removed: %s (pid=%d)", comm, pid);
	return 0;
}

/**
 * aegis_is_process_protected - Check if a task is protected
 * @task: the task to check
 *
 * Checks both by process name and PID.
 *
 * Returns true if the process is protected, false otherwise.
 */
bool aegis_is_process_protected(struct task_struct *task)
{
	struct aegis_protected_proc *entry;
	bool protected = false;

	if (!task || !AEGIS_FEATURE_CHECK(AEGIS_FEATURE_PROCESS_PROTECT))
		return false;

	rcu_read_lock();
	spin_lock(&protected_procs_lock);

	list_for_each_entry(entry, &protected_procs, list) {
		/* Check by PID if specified */
		if (entry->pid != 0 && entry->pid == task->pid) {
			protected = true;
			break;
		}

		/* Check by comm (process name) */
		if (entry->pid == 0 &&
		    strncmp(entry->comm, task->comm, AEGIS_COMM_LEN) == 0) {
			protected = true;
			break;
		}

		/* Check group leader's comm */
		if (entry->pid == 0 &&
		    strncmp(entry->comm,
			    task->group_leader->comm,
			    AEGIS_COMM_LEN) == 0) {
			protected = true;
			break;
		}
	}

	spin_unlock(&protected_procs_lock);
	rcu_read_unlock();

	return protected;
}

/**
 * aegis_protected_process_show - Display protected processes
 * @m: seq_file to write to
 */
void aegis_protected_process_show(struct seq_file *m)
{
	struct aegis_protected_proc *entry;

	seq_printf(m, "AEGIS Protected Processes (%d entries):\n",
		   protected_proc_count);
	seq_printf(m, "%-20s %8s\n", "COMM", "PID");
	seq_printf(m, "%-20s %8s\n", "----", "---");

	spin_lock(&protected_procs_lock);
	list_for_each_entry(entry, &protected_procs, list) {
		seq_printf(m, "%-20s %8d\n",
			   entry->comm, entry->pid);
	}
	spin_unlock(&protected_procs_lock);
}
