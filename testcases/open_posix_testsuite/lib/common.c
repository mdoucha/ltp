// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 SUSE LLC <mdoucha@suse.cz>
 *
 * OpenPOSIX test bootstrap
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include "posixtest.h"

#define LIVEPATCH_MAGIC "-lp-"

int test_main(int argc, char **argv);

static void handle_sigusr1(int signum PTS_ATTRIBUTE_UNUSED)
{

}

static int check_livepatch_status(void)
{
	const char *patch, *libc_version = gnu_get_libc_version();

	if (!libc_version) {
		printf("Glibc version is NULL\n");
		return -1;
	}

	printf("Glibc version: %s\n", libc_version);
	patch = strstr(libc_version, LIVEPATCH_MAGIC);

	if (patch) {
		patch += strlen(LIVEPATCH_MAGIC);
		printf("Found Glibc livepatch version: %s\n", patch);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--livepatch")) {
			int status;

			if (check_livepatch_status())
				return PTS_FAIL;

			signal(SIGUSR1, handle_sigusr1);
			pause();
			errno = 0;

			if (check_livepatch_status() <= 0)
				return PTS_FAIL;

			/* Drop the --livepatch argument */
			argc--;

			for (; i < argc; i++)
				argv[i] = argv[i + 1];

			argv[argc] = NULL;
			break;
		}
	}

	return test_main(argc, argv);
}
