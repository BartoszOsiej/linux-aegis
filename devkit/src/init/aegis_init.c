// SPDX-License-Identifier: GPL-2.0-only
/*
 * AEGIS DevKit - Custom /init for minimal developer OS
 *
 * Minimal init process that:
 *   1. Mounts essential filesystems (proc, sys, dev, tmpfs)
 *   2. Creates device nodes
 *   3. Prints AEGIS system banner
 *   4. Drops to an interactive shell
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/sysmacros.h>

#define AEGIS_BANNER \
"\n" \
"    ╔══════════════════════════════════════════════════╗\n" \
"    ║                                                  ║\n" \
"    ║       🛡️  AEGIS DevKit  v1.0.0                 ║\n" \
"    ║       Advanced Guardian for                     ║\n" \
"    ║       Integrated System Security                ║\n" \
"    ║                                                  ║\n" \
"    ║       Kernel: 7.3.0-rc1-aegis                   ║\n" \
"    ║       Userspace: Minimal Developer OS           ║\n" \
"    ║                                                  ║\n" \
"    ╚══════════════════════════════════════════════════╝\n" \
"\n"

#define AEGIS_COLORS \
"\033[1;33m"  /* bold yellow */ \
"  [AEGIS] " \
"\033[0m"      /* reset */

static const char *mounts[][3] = {
	{"proc",     "/proc",    "proc"},
	{"sysfs",    "/sys",     "sysfs"},
	{"tmpfs",    "/tmp",     "tmpfs"},
	{"devtmpfs", "/dev",     "devtmpfs"},
	{"debugfs",  "/sys/kernel/debug", "debugfs"},
	{NULL, NULL, NULL}
};

static void print_msg(const char *msg)
{
	write(STDOUT_FILENO, AEGIS_COLORS, sizeof(AEGIS_COLORS) - 1);
	write(STDOUT_FILENO, msg, strlen(msg));
	write(STDOUT_FILENO, "\n", 1);
}

static void print_msg_raw(const char *msg)
{
	write(STDOUT_FILENO, msg, strlen(msg));
}

static int do_mount(const char *source, const char *target,
		    const char *fstype, unsigned long flags,
		    const void *data)
{
	mkdir(target, 0755);
	if (mount(source, target, fstype, flags, data) == 0) {
		print_msg(target);
		return 0;
	}
	return -1;
}

static void setup_filesystems(void)
{
	print_msg("Mounting filesystems...");

	for (int i = 0; mounts[i][0] != NULL; i++) {
		do_mount(mounts[i][0], mounts[i][1], mounts[i][2],
			 MS_NOEXEC | MS_NOSUID, NULL);
	}

	/* Mount /proc with nosuid/nodev */
	mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

	/* Mount /sys */
	mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

	/* Mount /dev/pts for proper terminal */
	mkdir("/dev/pts", 0755);
	mount("devpts", "/dev/pts", "devpts", MS_NOEXEC | MS_NOSUID, NULL);

	/* Mount /run for runtime data */
	mkdir("/run", 0755);
	mount("tmpfs", "/run", "tmpfs", MS_NOEXEC | MS_NOSUID, "size=64M,mode=0755");

	print_msg("Filesystems mounted");
}

static void create_device_nodes(void)
{
	print_msg("Creating device nodes...");

	/* Standard device nodes */
	mknod("/dev/null",    0666, makedev(1, 3));
	mknod("/dev/zero",    0666, makedev(1, 5));
	mknod("/dev/full",    0666, makedev(1, 7));
	mknod("/dev/random",  0666, makedev(1, 8));
	mknod("/dev/urandom", 0666, makedev(1, 9));
	mknod("/dev/tty",     0666, makedev(5, 0));
	mknod("/dev/console", 0600, makedev(5, 1));
	mknod("/dev/ptmx",    0666, makedev(5, 2));

	/* Virtual console devices */
	for (int i = 1; i <= 6; i++) {
		char path[32];
		snprintf(path, sizeof(path), "/dev/tty%d", i);
		mknod(path, 0620, makedev(4, i));
	}

	print_msg("Device nodes created");
}

static void setup_environment(void)
{
	print_msg("Setting up environment...");

	setenv("HOME", "/root", 1);
	setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", 1);
	setenv("TERM", "linux", 1);
	setenv("PS1", "\\033[1;32mAEGIS\\033[0m:\\w\\$ ", 1);
	setenv("LANG", "en_US.UTF-8", 1);
	setenv("SHELL", "/bin/sh", 1);
	setenv("AEGIS_VERSION", "1.0.0", 1);
	setenv("AEGIS_KERNEL", "7.3.0-rc1-aegis", 1);

	/* Set hostname */
	sethostname("aegis-dev", 9);

	print_msg("Environment ready");
}

static void check_aegis(void)
{
	int fd;
	char buf[1024];
	ssize_t n;

	print_msg("Checking AEGIS status...");

	/* Read /proc/sys/kernel/lsm to check if AEGIS is active */
	fd = open("/proc/sys/kernel/lsm", O_RDONLY);
	if (fd >= 0) {
		n = read(fd, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			/* Check if aegis is in the LSM list */
			if (strstr(buf, "aegis")) {
				print_msg("✅ AEGIS is ACTIVE in kernel LSM chain");
				printf("  LSM chain: %s\n", buf);
			} else {
				print_msg("⚠️  AEGIS not found in LSM chain");
				printf("  LSM chain: %s\n", buf);
			}
		}
		close(fd);
	} else {
		print_msg("⚠️  Cannot read /proc/sys/kernel/lsm");
	}

	/* Read AEGIS securityfs status */
	fd = open("/sys/kernel/security/aegis/status", O_RDONLY);
	if (fd >= 0) {
		n = read(fd, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			printf("\n%s\n", buf);
		}
		close(fd);
	} else {
		print_msg("ℹ️  /sys/kernel/security/aegis/ not available (AEGIS may not be compiled in)");
	}
}

static void show_system_info(void)
{
	FILE *fp;
	char buf[256];

	print_msg("System information:");

	/* Kernel version */
	fp = popen("uname -a", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp))
			printf("  %s", buf);
		pclose(fp);
	}

	/* Memory */
	fp = popen("cat /proc/meminfo | head -5", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp))
			printf("  %s", buf);
		pclose(fp);
	}
}

static void run_shell(void)
{
	const char *shell = "/bin/sh";

	print_msg("Starting AEGIS development shell...");
	print_msg_raw("\033[1;33m  Type 'help' for AEGIS commands\033[0m\n\n");

	/* Launch shell */
	execlp(shell, shell, "--login", NULL);

	/* Fallback: try sh */
	execlp("/bin/sh", "sh", NULL);

	perror("Failed to exec shell");
}

static void sig_handler(int sig)
{
	(void)sig;
	/* Ignore signals during init */
}

int main(void)
{
	/* Install signal handlers */
	signal(SIGCHLD, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Print banner */
	print_msg_raw(AEGIS_BANNER);

	/* Phase 1: Mount filesystems */
	setup_filesystems();

	/* Phase 2: Create device nodes */
	create_device_nodes();

	/* Phase 3: Set up environment */
	setup_environment();

	/* Phase 4: Check AEGIS */
	check_aegis();

	/* Phase 5: Show system info */
	show_system_info();

	/* Phase 6: Shell */
	run_shell();

	return 0;
}
