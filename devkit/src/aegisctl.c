// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS DevKit - aegisctl: Userspace control tool
 *
 * Manages the AEGIS LSM from userspace:
 *   aegisctl status    - Show AEGIS status and statistics
 *   aegisctl enable    - Enable AEGIS
 *   aegisctl disable   - Disable AEGIS
 *   aegisctl stats     - Show event counters
 *   aegisctl procs     - Show protected processes
 *   aegisctl files     - Show protected files
 *   aegisctl symlist   - Show blocked syscalls
 *   aegisctl help      - Show help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/klog.h>

/* Defined in <sys/syslog.h>; not exported by the glibc klog.h header. */
#ifndef SYSLOG_ACTION_READ_ALL
#define SYSLOG_ACTION_READ_ALL 3
#endif

#define AEGIS_SECURITYFS "/sys/kernel/security/aegis"
#define AEGIS_SYSCTL     "/proc/sys/kernel/aegis"
#define MAX_BUF          4096

static int write_secfs(const char *file, const char *value)
{
	char path[512];
	int fd, ret;

	snprintf(path, sizeof(path), "%s/%s", AEGIS_SECURITYFS, file);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		printf("❌ %s: %s\n", path, strerror(errno));
		printf("   (need root + AEGIS loaded)\n");
		return -1;
	}

	ret = (int)write(fd, value, strlen(value));
	close(fd);
	if (ret < 0) {
		printf("❌ write %s: %s\n", path, strerror(errno));
		return -1;
	}
	printf("✅ %s <- %s\n", file, value);
	return 0;
}

struct cmd {
	const char *name;
	const char *endpoint;   /* securityfs write file */
	const char *usage;
};

static const struct cmd write_cmds[] = {
	{ "file-add",      "protected_files_add",  "file-add <path>       protect a file (deny writes)" },
	{ "file-del",      "protected_files_del",  "file-del <path>       unprotect a file" },
	{ "proc-add",      "protected_procs_add",  "proc-add <comm> [pid] protect a process name (optionally one pid)" },
	{ "proc-del",      "protected_procs_del",  "proc-del <comm> [pid] unprotect a process" },
	{ "syscall-add",   "blocked_syscalls_add", "syscall-add <nr>      block a syscall number" },
	{ "syscall-del",   "blocked_syscalls_del", "syscall-del <nr>      unblock a syscall number" },
};

static void cmd_write(int argc, char **argv)
{
	size_t i;

	if (argc < 3) {
		printf("usage: aegisctl <command> <arg>\n\nWrite commands:\n");
		for (i = 0; i < sizeof(write_cmds) / sizeof(write_cmds[0]); i++)
			printf("  %s\n", write_cmds[i].usage);
		return;
	}

	for (i = 0; i < sizeof(write_cmds) / sizeof(write_cmds[0]); i++) {
		if (strcmp(argv[1], write_cmds[i].name) == 0) {
			write_secfs(write_cmds[i].endpoint, argv[2]);
			return;
		}
	}

	printf("unknown command: %s\n", argv[1]);
}

static void print_file(const char *path)
{
	int fd;
	char buf[MAX_BUF];
	ssize_t n;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("  ❌ Cannot open %s: %s\n", path, strerror(errno));
		return;
	}

	n = read(fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		printf("%s", buf);
	} else {
		printf("  (empty)\n");
	}
	close(fd);
}

static int write_sysctl(const char *key, const char *value)
{
	char path[256];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", AEGIS_SYSCTL, key);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		printf("❌ Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	if (write(fd, value, strlen(value)) < 0) {
		printf("❌ Cannot write to %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	printf("✅ %s = %s\n", key, value);
	return 0;
}

static void cmd_status(void)
{
	printf("\n");
	printf("╔══════════════════════════════════════════╗\n");
	printf("║     AEGIS Security Module Status         ║\n");
	printf("╚══════════════════════════════════════════╝\n\n");

	print_file(AEGIS_SECURITYFS "/status");
}

static void cmd_stats(void)
{
	printf("\n");
	printf("╔══════════════════════════════════════════╗\n");
	printf("║     AEGIS Event Statistics               ║\n");
	printf("╚══════════════════════════════════════════╝\n\n");

	print_file(AEGIS_SECURITYFS "/stats");
}

static void cmd_procs(void)
{
	printf("\n");
	printf("╔══════════════════════════════════════════╗\n");
	printf("║     AEGIS Protected Processes            ║\n");
	printf("╚══════════════════════════════════════════╝\n\n");

	print_file(AEGIS_SECURITYFS "/protected_procs");
}

static void cmd_files(void)
{
	printf("\n");
	printf("╔══════════════════════════════════════════╗\n");
	printf("║     AEGIS Protected Files                ║\n");
	printf("╚══════════════════════════════════════════╝\n\n");

	print_file(AEGIS_SECURITYFS "/protected_files");
}

static void cmd_symlist(void)
{
	printf("\n");
	printf("╔══════════════════════════════════════════╗\n");
	printf("║     AEGIS Blocked Syscalls               ║\n");
	printf("╚══════════════════════════════════════════╝\n\n");

	print_file(AEGIS_SECURITYFS "/blocked_syscalls");
}

#define AUDIT_BUF_SIZE (256 * 1024)

/* aegisctl audit [N] — show the last N AEGIS events from the kernel ring
 * buffer (default 20). Every blocked ptrace/write/syscall/module load is
 * logged with the "aegis:" prefix by the LSM hooks; this command turns
 * that stream into a readable incident log without piping dmesg by hand. */
static void cmd_audit(int argc, char **argv)
{
	char *buf;
	long n;
	int want = 20;
	int total = 0, shown = 0;
	char *line, *saveptr = NULL;

	if (argc >= 3) {
		want = atoi(argv[2]);
		if (want <= 0) {
			printf("usage: aegisctl audit [N]  (N = number of events, default 20)\n");
			return;
		}
	}

	buf = malloc(AUDIT_BUF_SIZE);
	if (!buf) {
		printf("❌ out of memory\n");
		return;
	}

	n = klogctl(SYSLOG_ACTION_READ_ALL, buf, AUDIT_BUF_SIZE - 1);
	if (n < 0) {
		printf("❌ cannot read kernel log: %s\n", strerror(errno));
		printf("   (need root, or dmesg_restrict=0)\n");
		free(buf);
		return;
	}
	buf[n] = '\0';

	/* Count matching lines first so we know where to start printing. */
	for (line = buf; (line = strstr(line, "aegis:")) != NULL; line++)
		total++;

	printf("\n");
	printf("╔══════════════════════════════════════════╗\n");
	printf("║     AEGIS Audit Log (last %d events)      \n", want);
	printf("╚══════════════════════════════════════════╝\n\n");

	if (total == 0) {
		printf("  (no AEGIS events in the kernel ring buffer)\n\n");
		free(buf);
		return;
	}

	int skip = total > want ? total - want : 0;
	int idx = 0;
	for (line = strtok_r(buf, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
		char *tag = strstr(line, "aegis:");
		if (!tag)
			continue;
		if (idx++ < skip)
			continue;
		printf("  %s\n", tag);
		shown++;
	}

	printf("\n  %d of %d AEGIS events shown\n\n", shown, total);
	free(buf);
}

static void cmd_enable(void)
{
	printf("Enabling AEGIS...\n");
	write_sysctl("enabled", "1");
}

static void cmd_disable(void)
{
	printf("⚠️  Disabling AEGIS (requires reboot to fully re-enable)...\n");
	write_sysctl("enabled", "0");
}

static void cmd_help(void)
{
	printf("\n");
	printf("╔══════════════════════════════════════════════════╗\n");
	printf("║         AEGIS Control Tool v1.0.0               ║\n");
	printf("║     Advanced Guardian for Integrated System     ║\n");
	printf("║                Security                         ║\n");
	printf("╚══════════════════════════════════════════════════╝\n\n");
	printf("Usage: aegisctl <command>\n\n");
	printf("Commands:\n");
	printf("  status        Show AEGIS status and configuration\n");
	printf("  stats         Show event statistics\n");
	printf("  procs         Show protected processes list\n");
	printf("  files         Show protected files list\n");
	printf("  symlist       Show blocked syscalls list\n");
	printf("  audit [N]     Show last N AEGIS events from kernel log (default 20)\n");
	printf("  enable        Enable AEGIS (via sysctl)\n");
	printf("  disable       Disable AEGIS (via sysctl)\n");
	printf("  file-add      Protect a file:           aegisctl file-add /etc/passwd\n");
	printf("  file-del      Unprotect a file:         aegisctl file-del /etc/passwd\n");
	printf("  proc-add      Protect a process:        aegisctl proc-add sshd\n");
	printf("  proc-del      Unprotect a process:      aegisctl proc-del sshd\n");
	printf("  syscall-add   Block a syscall:          aegisctl syscall-add 101\n");
	printf("  syscall-del   Unblock a syscall:        aegisctl syscall-del 101\n");
	printf("  help          Show this help message\n\n");
	printf("Files:\n");
	printf("  /sys/kernel/security/aegis/status\n");
	printf("  /sys/kernel/security/aegis/stats\n");
	printf("  /sys/kernel/security/aegis/protected_procs\n");
	printf("  /sys/kernel/security/aegis/protected_files\n");
	printf("  /sys/kernel/security/aegis/blocked_syscalls\n");
	printf("  /proc/sys/kernel/aegis/enabled\n");
	printf("  /proc/sys/kernel/aegis/features\n\n");
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		cmd_help();
		return 0;
	}

	if (strcmp(argv[1], "status") == 0)
		cmd_status();
	else if (strcmp(argv[1], "stats") == 0)
		cmd_stats();
	else if (strcmp(argv[1], "procs") == 0)
		cmd_procs();
	else if (strcmp(argv[1], "files") == 0)
		cmd_files();
	else if (strcmp(argv[1], "symlist") == 0)
		cmd_symlist();
	else if (strcmp(argv[1], "audit") == 0)
		cmd_audit(argc, argv);
	else if (strcmp(argv[1], "enable") == 0)
		cmd_enable();
	else if (strcmp(argv[1], "disable") == 0)
		cmd_disable();
	else if (strcmp(argv[1], "file-add") == 0 ||
		 strcmp(argv[1], "file-del") == 0 ||
		 strcmp(argv[1], "proc-add") == 0 ||
		 strcmp(argv[1], "proc-del") == 0 ||
		 strcmp(argv[1], "syscall-add") == 0 ||
		 strcmp(argv[1], "syscall-del") == 0)
		cmd_write(argc, argv);
	else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0)
		cmd_help();
	else {
		printf("Unknown command: %s\n", argv[1]);
		printf("Try 'aegisctl help' for usage.\n");
		return 1;
	}

	return 0;
}
