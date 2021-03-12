// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2017 Cyril Hrubis <chrubis@suse.cz>
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/wait.h>

#define TST_NO_DEFAULT_MAIN
#include "tst_test.h"
#include "tst_fs.h"

static const char *const fs_type_whitelist[] = {
	"ext2",
	"ext3",
	"ext4",
	"xfs",
	"btrfs",
	"vfat",
	"exfat",
	"ntfs",
	NULL
};

static const char *fs_types[ARRAY_SIZE(fs_type_whitelist)];

static int has_mkfs(const char *fs_type)
{
	char buf[128];
	int ret;

	sprintf(buf, "mkfs.%s >/dev/null 2>&1", fs_type);

	ret = tst_system(buf);

	if (WEXITSTATUS(ret) == 127) {
		tst_res(TINFO, "mkfs.%s does not exist", fs_type);
		return 0;
	}

	tst_res(TINFO, "mkfs.%s does exist", fs_type);
	return 1;
}

int tst_fs_in_skiplist(const char *fs_type, const char *const *skiplist)
{
	unsigned int i;

	if (!skiplist)
		return 0;

	for (i = 0; skiplist[i]; i++) {
		if (!strcmp(fs_type, skiplist[i]))
			return 1;
	}

	return 0;
}

static int has_kernel_support(const char *fs_type)
{
	static int fuse_supported = -1;
	const char *tmpdir = getenv("TMPDIR");
	char buf[128];
	int ret;

	if (!tmpdir)
		tmpdir = "/tmp";

	mount("/dev/zero", tmpdir, fs_type, 0, NULL);
	if (errno != ENODEV) {
		tst_res(TINFO, "Kernel supports %s", fs_type);
		return TST_FS_NATIVE;
	}

	/* Is FUSE supported by kernel? */
	if (fuse_supported == -1) {
		ret = open("/dev/fuse", O_RDWR);
		if (ret < 0) {
			fuse_supported = 0;
		} else {
			fuse_supported = 1;
			SAFE_CLOSE(ret);
		}
	}

	if (!fuse_supported)
		return 0;

	/* Is FUSE implementation installed? */
	sprintf(buf, "mount.%s >/dev/null 2>&1", fs_type);

	ret = tst_system(buf);
	if (WEXITSTATUS(ret) == 127) {
		tst_res(TINFO, "Filesystem %s is not supported", fs_type);
		return 0;
	}

	tst_res(TINFO, "FUSE does support %s", fs_type);
	return TST_FS_FUSE;
}

int tst_fs_is_supported(const char *fs_type)
{
	if (has_mkfs(fs_type))
		return has_kernel_support(fs_type);

	return 0;
}

const char **tst_get_supported_fs_types(const char *const *skiplist)
{
	unsigned int ret, skip_fuse, i, j = 0;

	skip_fuse = tst_fs_in_skiplist("fuse", skiplist);

	for (i = 0; fs_type_whitelist[i]; i++) {
		if (tst_fs_in_skiplist(fs_type_whitelist[i], skiplist))
			continue;

		ret = tst_fs_is_supported(fs_type_whitelist[i]);

		if (ret == TST_FS_FUSE && skip_fuse) {
			tst_res(TINFO, "Skipping FUSE as requested by test");
			continue;
		}

		if (ret)
			fs_types[j++] = fs_type_whitelist[i];
	}

	return fs_types;
}
