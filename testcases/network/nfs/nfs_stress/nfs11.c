// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 SUSE LLC <mdoucha@suse.cz>
 */
/*\
 * Test for use-after-free race condition between NFS unmount and read
 * from NFSD client info procfile.
 */

#include "tst_test.h"
#include "tst_safe_macros.h"
#include "tst_netdevice.h"
#include "tst_fuzzy_sync.h"
#include "lapi/if_addr.h"
#include "lapi/mount.h"
#include "lapi/sched.h"

#define REMOTE_DIR "remote_dir"
#define MNTPOINT "mntpoint"
#define BUFSIZE 4096
#define BASE_OPTS "addr=%s,clientaddr=%s,"

#define LTPNET 0xfa444e00 /* 250.68.78.0 */
#define SRCADDR 0xfa444e01 /* 250.68.78.1 */
#define DSTADDR 0xfa444e02 /* 250.68.78.2 */
#define NETMASK 24

static struct tst_fzsync_pair fzsync_pair;
static int fd = -1;
static int parentns = -1, childns = -1;
static char *nfs_opts_arg = "proto=tcp,vers=4.0";
static char nfs_uri[PATH_MAX + INET_ADDRSTRLEN];
static char client_path[PATH_MAX];
static char *nfs_opts;
static char *remote_path;

static void tst_exportfs(const char *export_path, int fsid)
{
	char buf[PATH_MAX + 128];

	sprintf(buf, "exportfs -i -o fsid=%d,no_root_squash,rw *:%s",
		tst_getpid() + fsid, export_path);
	tst_res(TINFO, "Calling NFS export command: %s", buf);

	if (tst_system(buf))
		tst_brk(TBROK, "Failed to export \"%s\"", export_path);
}

static void tst_unexportfs(const char *export_path)
{
	char buf[PATH_MAX + 128];

	sprintf(buf, "exportfs -u *:%s", export_path);
	tst_res(TINFO, "Calling NFS unexport command: %s", buf);

	if (tst_system(buf))
		tst_res(TWARN, "Failled to unexport \"%s\"", export_path);
}

static int find_client_path(void)
{
	DIR *procdir;
	struct dirent *ent;

	/* FIXME: Search by client IP address */
	procdir = SAFE_OPENDIR("/proc/fs/nfsd/clients");

	while ((ent = SAFE_READDIR(procdir))) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(client_path, PATH_MAX, "/proc/fs/nfsd/clients/%s/info",
			ent->d_name);
		client_path[PATH_MAX - 1] = '\0';
		SAFE_CLOSEDIR(procdir);
		return 1;
	}

	SAFE_CLOSEDIR(procdir);
	return 0;
}

static void setup(void)
{
	char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
	struct in_addr addr;

	addr.s_addr = htonl(SRCADDR);
	inet_ntop(AF_INET, &addr, srcbuf, sizeof(srcbuf));
	addr.s_addr = htonl(DSTADDR);
	inet_ntop(AF_INET, &addr, dstbuf, sizeof(dstbuf));
	nfs_opts = SAFE_MALLOC(strlen(BASE_OPTS) + strlen(nfs_opts_arg) +
		2 * INET_ADDRSTRLEN);
	sprintf(nfs_opts, BASE_OPTS, dstbuf, srcbuf);
	strcat(nfs_opts, nfs_opts_arg);

	SAFE_MKDIR(REMOTE_DIR, 0755);
	SAFE_MKDIR(MNTPOINT, 0755);

	sprintf(nfs_uri, "%s:", dstbuf);
	remote_path = nfs_uri + strlen(nfs_uri);
	SAFE_REALPATH(REMOTE_DIR, remote_path);
	tst_exportfs(remote_path, 0);

	parentns = SAFE_OPEN("/proc/self/ns/net", O_RDONLY);

	/* Configure parent namespace */
	CREATE_VETH_PAIR("ltp_veth1", "ltp_veth2");
	NETDEV_ADD_ADDRESS_INET("ltp_veth2", htonl(DSTADDR), NETMASK,
		IFA_F_NOPREFIXROUTE);
	NETDEV_SET_STATE("ltp_veth2", 1);
	NETDEV_ADD_ROUTE_INET("ltp_veth2", 0, 0, htonl(LTPNET), NETMASK, 0);

	SAFE_UNSHARE(CLONE_NEWNET);

	/* Do NOT close this FD, or both interfaces will be destroyed */
	childns = SAFE_OPEN("/proc/self/ns/net", O_RDONLY);
	SAFE_SETNS(parentns, CLONE_NEWNET);

	/* Configure child namespace */
	NETDEV_CHANGE_NS_FD("ltp_veth1", childns);
	SAFE_SETNS(childns, CLONE_NEWNET);
	NETDEV_ADD_ADDRESS_INET("ltp_veth1", htonl(SRCADDR), NETMASK,
		IFA_F_NOPREFIXROUTE);
	NETDEV_SET_STATE("ltp_veth1", 1);
	NETDEV_ADD_ROUTE_INET("ltp_veth1", 0, 0, htonl(LTPNET), NETMASK, 0);
	SAFE_FILE_PRINTF("/proc/sys/net/ipv4/conf/ltp_veth1/forwarding", "1");

	fzsync_pair.exec_loops = 10000;
	tst_fzsync_pair_init(&fzsync_pair);
}

static void *thread_run(void *arg)
{
	char buf[BUFSIZE];

	while (tst_fzsync_run_b(&fzsync_pair)) {
		tst_fzsync_wait_b(&fzsync_pair);
		fd = SAFE_OPEN(client_path, O_RDONLY);

		tst_fzsync_start_race_b(&fzsync_pair);
		SAFE_READ(0, fd, buf, BUFSIZE);
		tst_fzsync_end_race_b(&fzsync_pair);

		SAFE_CLOSE(fd);
	}

	return arg;
}

static void run(void)
{
	tst_fzsync_pair_reset(&fzsync_pair, thread_run);

	while (tst_fzsync_run_a(&fzsync_pair)) {
		TEST(mount(nfs_uri, MNTPOINT, "nfs", 0, nfs_opts));

		if (TST_RET == -1)
			tst_brk(TBROK | TTERRNO, "mount(%s) failed", nfs_uri);

		if (TST_RET) {
			tst_brk(TBROK | TTERRNO,
				"Invalid mount(%s) return value", nfs_uri);
		}

		if (!find_client_path())
			tst_brk(TBROK, "Client info procfile not found");

		tst_fzsync_wait_a(&fzsync_pair);

		tst_fzsync_start_race_a(&fzsync_pair);
		TEST(umount(MNTPOINT));
		tst_fzsync_end_race_a(&fzsync_pair);

		if (TST_RET == -1)
			tst_brk(TBROK | TTERRNO, "umount(%s) failed", MNTPOINT);

		if (TST_RET) {
			tst_brk(TBROK | TTERRNO,
				"Invalid umount(%s) return value", MNTPOINT);
		}

		if (tst_taint_check()) {
			tst_res(TFAIL, "Triggered NFS use after free");
			return;
		}
	}

	tst_res(TPASS, "Nothing bad happened");
}

static void cleanup(void)
{
	tst_fzsync_pair_cleanup(&fzsync_pair);

	free(nfs_opts);

	if (fd >= 0)
		SAFE_CLOSE(fd);

	if (tst_is_mounted(MNTPOINT))
		SAFE_UMOUNT(MNTPOINT);

	if (parentns >= 0) {
		SAFE_SETNS(parentns, CLONE_NEWNET);
		SAFE_CLOSE(parentns);
	}

	if (childns >= 0)
		SAFE_CLOSE(childns);

	tst_unexportfs(remote_path);
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.needs_tmpdir = 1,
	.needs_root = 1,
	.runtime = 180,
	.taint_check = TST_TAINT_W | TST_TAINT_D,
	.options = (struct tst_option[]) {
		{"o:", &nfs_opts_arg, "NFS mount options"},
		{}
	}

};
