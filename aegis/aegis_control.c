// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS - Userspace Control Interface (write side)
 *
 * Write-only securityfs files used by aegisctl to mutate policy:
 *
 *   protected_files_add   0200   one path per write, e.g. "/etc/passwd"
 *   protected_files_del   0200   one path per write
 *   protected_procs_add   0200   "comm" or "comm pid" per write
 *   protected_procs_del   0200   "comm" or "comm pid" per write
 *   blocked_syscalls_add  0200   one syscall number per write
 *   blocked_syscalls_del  0200   one syscall number per write
 *
 * Every handler requires CAP_MAC_ADMIN (checked by securityfs file mode
 * 0200 AND an explicit capability check — file modes alone are not a
 * security boundary for kernel policy).
 *
 * Copyright (C) 2026 AEGIS Security Project
 */

#define pr_fmt(fmt) "AEGIS-ctl: " fmt

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/errno.h>

#include "aegis.h"

/* ===================== Shared helpers ================================ */

static bool aectl_authorized(void)
{
	return capable(CAP_MAC_ADMIN);
}

/* Copy at most @max-1 bytes, NUL-terminate, reject embedded NULs. */
static int aectl_get_string(const char __user *ubuf, size_t len,
			    char *out, size_t max)
{
	size_t n = min(len, max - 1);

	if (copy_from_user(out, ubuf, n))
		return -EFAULT;
	out[n] = '\0';
	if (strnlen(out, n) != n)
		return -EINVAL; /* embedded NUL — reject */

	/* strip trailing newline */
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
		out[--n] = '\0';

	return (int)n;
}

static ssize_t aectl_write_op(const char __user *ubuf, size_t len,
			      int (*op)(const char *))
{
	char *buf;
	ssize_t ret;

	if (!aectl_authorized())
		return -EPERM;
	if (len == 0 || len > AEGIS_PATH_LEN)
		return -EINVAL;

	buf = kmalloc(AEGIS_PATH_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = aectl_get_string(ubuf, len, buf, AEGIS_PATH_LEN);
	if (ret <= 0)
		goto out;

	ret = op(buf);
	if (ret == 0)
		ret = (ssize_t)len;
out:
	kfree(buf);
	return ret;
}

/* ===================== Protected files =============================== */

static ssize_t aectl_files_add_write(struct file *file,
				     const char __user *ubuf,
				     size_t len, loff_t *off)
{
	return aectl_write_op(ubuf, len, aegis_protected_file_add);
}

static ssize_t aectl_files_del_write(struct file *file,
				     const char __user *ubuf,
				     size_t len, loff_t *off)
{
	return aectl_write_op(ubuf, len, aegis_protected_file_del);
}

static const struct file_operations aectl_files_add_fops = {
	.owner		= THIS_MODULE,
	.write		= aectl_files_add_write,
};

static const struct file_operations aectl_files_del_fops = {
	.owner		= THIS_MODULE,
	.write		= aectl_files_del_write,
};

/* ===================== Protected processes =========================== */

/*
 * Format: "comm" (name-based, all processes with that name) or
 * "comm pid" (single PID). The pid part is optional.
 */
static ssize_t aectl_procs_add_write(struct file *file,
				     const char __user *ubuf,
				     size_t len, loff_t *off)
{
	char buf[AEGIS_PATH_LEN];
	char comm[AEGIS_COMM_LEN];
	int pid = 0;
	int n, ret;

	if (!aectl_authorized())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;

	n = aectl_get_string(ubuf, len, buf, sizeof(buf));
	if (n <= 0)
		return n;

	/* "comm" or "comm pid" */
	if (sscanf(buf, "%15s %d", comm, &pid) < 1)
		return -EINVAL;

	ret = aegis_protect_process_add(comm, pid);
	return ret == 0 ? (ssize_t)len : ret;
}

static ssize_t aectl_procs_del_write(struct file *file,
				     const char __user *ubuf,
				     size_t len, loff_t *off)
{
	char buf[AEGIS_PATH_LEN];
	char comm[AEGIS_COMM_LEN];
	int pid = 0;
	int n, ret;

	if (!aectl_authorized())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;

	n = aectl_get_string(ubuf, len, buf, sizeof(buf));
	if (n <= 0)
		return n;

	if (sscanf(buf, "%15s %d", comm, &pid) < 1)
		return -EINVAL;

	ret = aegis_protect_process_del(comm, pid);
	return ret == 0 ? (ssize_t)len : ret;
}

static const struct file_operations aectl_procs_add_fops = {
	.owner		= THIS_MODULE,
	.write		= aectl_procs_add_write,
};

static const struct file_operations aectl_procs_del_fops = {
	.owner		= THIS_MODULE,
	.write		= aectl_procs_del_write,
};

/* ===================== Blocked syscalls ============================== */

static ssize_t aectl_syscalls_add_write(struct file *file,
					const char __user *ubuf,
					size_t len, loff_t *off)
{
	char buf[16];
	int nr, n, ret;

	if (!aectl_authorized())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;

	n = aectl_get_string(ubuf, len, buf, sizeof(buf));
	if (n <= 0)
		return n;

	if (kstrtoint(buf, 10, &nr) || nr < 0)
		return -EINVAL;

	ret = aegis_syscall_block_add(nr);
	return ret == 0 ? (ssize_t)len : ret;
}

static ssize_t aectl_syscalls_del_write(struct file *file,
					const char __user *ubuf,
					size_t len, loff_t *off)
{
	char buf[16];
	int nr, n, ret;

	if (!aectl_authorized())
		return -EPERM;
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;

	n = aectl_get_string(ubuf, len, buf, sizeof(buf));
	if (n <= 0)
		return n;

	if (kstrtoint(buf, 10, &nr) || nr < 0)
		return -EINVAL;

	ret = aegis_syscall_block_del(nr);
	return ret == 0 ? (ssize_t)len : ret;
}

static const struct file_operations aectl_syscalls_add_fops = {
	.owner		= THIS_MODULE,
	.write		= aectl_syscalls_add_write,
};

static const struct file_operations aectl_syscalls_del_fops = {
	.owner		= THIS_MODULE,
	.write		= aectl_syscalls_del_write,
};

/* ===================== Securityfs wiring ============================= */

struct aectl_entry {
	const char *name;
	const struct file_operations *fops;
	struct dentry **dentry_p;
};

static struct dentry *aectl_dentries[6];

static const struct aectl_entry aectl_entries[] = {
	{ "protected_files_add",  &aectl_files_add_fops,    &aectl_dentries[0] },
	{ "protected_files_del",  &aectl_files_del_fops,    &aectl_dentries[1] },
	{ "protected_procs_add",  &aectl_procs_add_fops,    &aectl_dentries[2] },
	{ "protected_procs_del",  &aectl_procs_del_fops,    &aectl_dentries[3] },
	{ "blocked_syscalls_add", &aectl_syscalls_add_fops, &aectl_dentries[4] },
	{ "blocked_syscalls_del", &aectl_syscalls_del_fops, &aectl_dentries[5] },
};

int aegis_control_init(struct dentry *parent)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(aectl_entries); i++) {
		struct dentry *d;

		d = securityfs_create_file(aectl_entries[i].name, 0200, parent,
					   NULL, aectl_entries[i].fops);
		if (IS_ERR(d))
			return PTR_ERR(d);
		*aectl_entries[i].dentry_p = d;
	}

	AEGIS_INFO("Control interface ready (6 write endpoints, CAP_MAC_ADMIN)");
	return 0;
}

void aegis_control_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(aectl_dentries); i++) {
		if (!IS_ERR_OR_NULL(aectl_dentries[i]))
			securityfs_remove(aectl_dentries[i]);
		aectl_dentries[i] = NULL;
	}
}
