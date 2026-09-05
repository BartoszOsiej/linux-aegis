// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS - File Integrity Subsystem
 *
 * Provides file integrity monitoring and enforcement:
 *   - Protected file list management
 *   - SHA-256 hash computation for files
 *   - Write/append access control
 *   - Audit logging for protected file access
 *
 * Copyright (C) 2026 AEGIS Security Project
 */

#define pr_fmt(fmt) "AEGIS-file: " fmt

#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/spinlock.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>

#include "aegis.h"

/* ===================== Internal Data Structures ===================== */

static LIST_HEAD(protected_files);
static DEFINE_SPINLOCK(protected_files_lock);
static int protected_file_count;

/* ===================== Hash Computation ============================= */

/**
 * aegis_compute_file_hash - Compute SHA-256 hash of a file's contents
 * @file: the file to hash
 * @hash_out: output buffer for the hash (must be >= AEGIS_HASH_SIZE)
 *
 * Reads the entire file and computes its SHA-256 hash.
 *
 * Returns 0 on success, negative error code on failure.
 */
int aegis_compute_file_hash(struct file *file, u8 *hash_out)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	ssize_t bytes_read;
	loff_t pos = 0;
	char *buf;
	int ret;

	if (!file || !hash_out)
		return -EINVAL;

	tfm = crypto_alloc_shash(AEGIS_HASH_ALGO, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_shash_setkey(tfm, NULL, 0);
	if (ret)
		goto out_tfm;

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
		       GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_tfm;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out_desc;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_desc;
	}

	/* Read file in chunks and update hash */
	while ((bytes_read = kernel_read(file, buf, PAGE_SIZE, &pos)) > 0) {
		ret = crypto_shash_update(desc, buf, bytes_read);
		if (ret)
			goto out_buf;
	}

	if (bytes_read < 0) {
		ret = bytes_read;
		goto out_buf;
	}

	ret = crypto_shash_final(desc, hash_out);

out_buf:
	kfree(buf);
out_desc:
	kfree(desc);
out_tfm:
	crypto_free_shash(tfm);
	return ret;
}

/**
 * aegis_file_init - Initialize the file integrity subsystem
 */
int aegis_file_init(void)
{
	spin_lock_init(&protected_files_lock);
	protected_file_count = 0;

	/*
	 * Note: Default protected files are NOT added here because
	 * kern_path() is not available during early security init.
	 * Files can be added later via securityfs or sysctl.
	 */

	return 0;
}

/**
 * aegis_file_exit - Cleanup the file integrity subsystem
 */
void aegis_file_exit(void)
{
	struct aegis_protected_file *entry, *tmp;

	spin_lock(&protected_files_lock);
	list_for_each_entry_safe(entry, tmp, &protected_files, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	protected_file_count = 0;
	spin_unlock(&protected_files_lock);
}

/**
 * aegis_protected_file_add - Add a file to the protected list
 * @path: file path to protect
 *
 * Returns 0 on success, -ENOMEM on allocation failure, -EEXIST if already
 * protected, -EINVAL on invalid arguments.
 */
int aegis_protected_file_add(const char *path)
{
	struct aegis_protected_file *file;
	struct path fpath;
	struct file *f;
	int ret;

	if (!path)
		return -EINVAL;

	/* Check if already protected */
	spin_lock(&protected_files_lock);
	list_for_each_entry(file, &protected_files, list) {
		if (strncmp(file->path, path, AEGIS_PATH_LEN) == 0) {
			spin_unlock(&protected_files_lock);
			return -EEXIST;
		}
	}
	spin_unlock(&protected_files_lock);

	file = kmalloc(sizeof(*file), GFP_KERNEL);
	if (!file)
		return -ENOMEM;

	memset(file->path, 0, AEGIS_PATH_LEN);
	strscpy(file->path, path, AEGIS_PATH_LEN);
	file->hash_valid = false;

	/* Try to compute initial hash */
	ret = kern_path(path, LOOKUP_FOLLOW, &fpath);
	if (ret == 0) {
		f = dentry_open(&fpath, O_RDONLY, current_cred());
		path_put(&fpath);
		if (!IS_ERR(f)) {
			if (aegis_compute_file_hash(f, file->hash) == 0)
				file->hash_valid = true;
			fput(f);
		}
	}

	spin_lock(&protected_files_lock);
	list_add_tail(&file->list, &protected_files);
	protected_file_count++;
	spin_unlock(&protected_files_lock);

	AEGIS_INFO("Protected file added: %s (hash=%s)",
		   path, file->hash_valid ? "valid" : "pending");
	return 0;
}

/**
 * aegis_protected_file_del - Remove a file from the protected list
 * @path: file path to unprotect
 *
 * Returns 0 on success, -ENOENT if not found.
 */
int aegis_protected_file_del(const char *path)
{
	struct aegis_protected_file *entry, *tmp;
	bool found = false;

	if (!path)
		return -EINVAL;

	spin_lock(&protected_files_lock);
	list_for_each_entry_safe(entry, tmp, &protected_files, list) {
		if (strncmp(entry->path, path, AEGIS_PATH_LEN) == 0) {
			list_del(&entry->list);
			kfree(entry);
			protected_file_count--;
			found = true;
			break;
		}
	}
	spin_unlock(&protected_files_lock);

	if (!found)
		return -ENOENT;

	AEGIS_INFO("Protected file removed: %s", path);
	return 0;
}

/**
 * aegis_is_file_protected - Check if a file path is protected
 * @path: the file path to check
 *
 * Returns true if the file is protected, false otherwise.
 */
bool aegis_is_file_protected(const char *path)
{
	struct aegis_protected_file *entry;
	bool protected = false;

	if (!path || !AEGIS_FEATURE_CHECK(AEGIS_FEATURE_FILE_INTEGRITY))
		return false;

	spin_lock(&protected_files_lock);
	list_for_each_entry(entry, &protected_files, list) {
		if (strncmp(entry->path, path, AEGIS_PATH_LEN) == 0) {
			protected = true;
			break;
		}
	}
	spin_unlock(&protected_files_lock);

	return protected;
}

/**
 * aegis_protected_file_show - Display protected files
 * @m: seq_file to write to
 */
void aegis_protected_file_show(struct seq_file *m)
{
	struct aegis_protected_file *entry;

	seq_printf(m, "AEGIS Protected Files (%d entries):\n",
		   protected_file_count);
	seq_printf(m, "%-40s %s\n", "PATH", "HASH");
	seq_printf(m, "%-40s %s\n", "----", "----");

	spin_lock(&protected_files_lock);
	list_for_each_entry(entry, &protected_files, list) {
		char hash_str[AEGIS_HASH_SIZE * 2 + 1];
		int i;

		for (i = 0; i < AEGIS_HASH_SIZE && entry->hash_valid; i++)
			snprintf(hash_str + i * 2, 3, "%02x", entry->hash[i]);

		if (!entry->hash_valid)
			snprintf(hash_str, sizeof(hash_str), "<pending>");

		seq_printf(m, "%-40s %s\n", entry->path, hash_str);
	}
	spin_unlock(&protected_files_lock);
}
