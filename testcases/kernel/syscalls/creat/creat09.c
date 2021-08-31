// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2021 SUSE LLC <mdoucha@suse.cz>
 */
/*\
 * [Description]
 *
 * CVE-2018-13405
 *
 * Check for possible privilege escalation through creating files with setgid
 * bit set inside a setgid directory owned by a group which the user does not
 * belong to.
 *
 * Fixed in:
 *
 *  commit 0fa3ecd87848c9c93c2c828ef4c3a8ca36ce46c7
 *  Author: Linus Torvalds <torvalds@linux-foundation.org>
 *  Date:   Tue Jul 3 17:10:19 2018 -0700
 *
 *  Fix up non-directory creation in SGID directories
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include "tst_test.h"
#include "tst_uid.h"

#define MODE_RWX        0777
#define MODE_SGID       (S_ISGID|0777)

#define WORKDIR		"testdir"
#define CREAT_FILE	WORKDIR "/creat.tmp"
#define OPEN_FILE	WORKDIR "/open.tmp"

#define MAX_GROUPS 32768

static gid_t free_gid, supgroups[MAX_GROUPS];
static int fd = -1;

static void setup(void)
{
	struct stat buf;
	struct passwd *ltpuser = SAFE_GETPWNAM("nobody");
	struct tst_cap_user_header caphdr = {
		.version = 0x20080522,
		.pid = 0
	};
	struct tst_cap_user_data capdata = {0};

	tst_res(TINFO, "User nobody: uid = %d, gid = %d", (int)ltpuser->pw_uid,
		(int)ltpuser->pw_gid);
	free_gid = tst_get_free_gid(ltpuser->pw_gid);

	/* Create directories and set permissions */
	SAFE_MKDIR(WORKDIR, MODE_RWX);
	SAFE_CHOWN(WORKDIR, ltpuser->pw_uid, free_gid);
	SAFE_CHMOD(WORKDIR, MODE_SGID);
	SAFE_STAT(WORKDIR, &buf);

	if (!(buf.st_mode & S_ISGID))
		tst_brk(TBROK, "%s: Setgid bit not set", WORKDIR);

	if (buf.st_gid != free_gid) {
		tst_brk(TBROK, "%s: Incorrect group, %u != %u", WORKDIR,
			buf.st_gid, free_gid);
	}

	/* Switch user */
	tst_capget(&caphdr, &capdata);
	tst_res(TINFO,
		"Process capabilities: eff = %X, perm = %X, inherit = %X",
		capdata.effective, capdata.permitted, capdata.inheritable);
	SAFE_SETGID(ltpuser->pw_gid);
	SAFE_SETREUID(-1, ltpuser->pw_uid);
}

static void file_test(const char *name)
{
	struct stat buf;

	SAFE_STAT(name, &buf);

	if (buf.st_gid != free_gid) {
		tst_res(TFAIL, "%s: Incorrect group, %u != %u", name,
			buf.st_gid, free_gid);
	} else {
		tst_res(TPASS, "%s: Owned by correct group", name);
	}

	if (buf.st_mode & S_ISGID)
		tst_res(TFAIL, "%s: Setgid bit is set", name);
	else
		tst_res(TPASS, "%s: Setgid bit not set", name);
}

static void run(void)
{
	struct tst_cap_user_header caphdr = {
		.version = 0x20080522,
		.pid = 0
	};
	struct tst_cap_user_data capdata = {0};
	int i, gcount;

	tst_res(TINFO, "Switched to euid %d, egid %d", geteuid(), getegid());
	tst_res(TINFO, "Process belongs to group %d: %d", (int)free_gid,
		group_member(free_gid));
	errno = 0;
	gcount = getgroups(MAX_GROUPS, supgroups);
	tst_capget(&caphdr, &capdata);
	tst_res(TINFO,
		"Process capabilities: eff = %X, perm = %X, inherit = %X",
		capdata.effective, capdata.permitted, capdata.inheritable);

	if (gcount < 0) {
		tst_res(TWARN | TERRNO, "Supplemental group query failed");
		return;
	} else if (!gcount) {
		tst_res(TINFO, "Test process has no supplemental groups");
		return;
	}

	tst_res(TINFO, "Test process supplemental groups:");

	for (i = 0; i < gcount; i++)
		printf("%d ", (int)supgroups[i]);

	printf("\n");

	fd = SAFE_CREAT(CREAT_FILE, MODE_SGID);
	SAFE_CLOSE(fd);
	file_test(CREAT_FILE);

	fd = SAFE_OPEN(OPEN_FILE, O_CREAT | O_EXCL | O_RDWR, MODE_SGID);
	file_test(OPEN_FILE);
	SAFE_CLOSE(fd);

	/* Cleanup between loops */
	tst_purge_dir(WORKDIR);
}

static void cleanup(void)
{
	if (fd >= 0)
		SAFE_CLOSE(fd);
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.needs_root = 1,
	.needs_tmpdir = 1,
	.tags = (const struct tst_tag[]) {
		{"linux-git", "0fa3ecd87848"},
		{"CVE", "2018-13405"},
		{}
	},
};
