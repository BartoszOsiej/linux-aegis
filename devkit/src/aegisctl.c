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

#define AEGIS_SECURITYFS "/sys/kernel/security/aegis"
#define AEGIS_SYSCTL     "/proc/sys/kernel/aegis"
#define MAX_BUF          4096

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
	printf("  status      Show AEGIS status and configuration\n");
	printf("  stats       Show event statistics\n");
	printf("  procs       Show protected processes list\n");
	printf("  files       Show protected files list\n");
	printf("  symlist     Show blocked syscalls list\n");
	printf("  enable      Enable AEGIS (via sysctl)\n");
	printf("  disable     Disable AEGIS (via sysctl)\n");
	printf("  help        Show this help message\n\n");
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
	else if (strcmp(argv[1], "enable") == 0)
		cmd_enable();
	else if (strcmp(argv[1], "disable") == 0)
		cmd_disable();
	else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0)
		cmd_help();
	else {
		printf("Unknown command: %s\n", argv[1]);
		printf("Try 'aegisctl help' for usage.\n");
		return 1;
	}

	return 0;
}
