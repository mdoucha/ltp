// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 SUSE LLC <mdoucha@suse.cz>
 */

/*\
 * Verify that various timeout values don't get misinterpreted as infinity
 */

#include <sys/epoll.h>

#include "tst_test.h"
#include "tst_timer.h"
#include "epoll_pwait_var.h"

static int efd;

static void run(void)
{
	struct timespec timeout = {};
	struct epoll_event e = {};
	int ret;

	e.events = EPOLLIN;

	TST_FD_FOREACH(fd_in) {
		switch (fd_in.type) {
		case TST_FD_FILE:
		case TST_FD_PATH:
		case TST_FD_DIR:
		case TST_FD_DEV_ZERO:
		case TST_FD_PROC_MAPS:
		case TST_FD_FSOPEN:
		case TST_FD_FSPICK:
		case TST_FD_OPEN_TREE:
		case TST_FD_MEMFD:
		case TST_FD_MEMFD_SECRET:
			continue;
		default:
			break;
		}

		tst_res(TINFO, "%s", tst_fd_desc(&fd_in));
		ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd_in.fd, &e);
		timeout.tv_nsec = 1000000000;

		if (ret)
			tst_brk(TBROK | TERRNO, "epoll_ctl(EPOLL_CTL_ADD)");

		do {
			alarm(1);
			timeout.tv_nsec /= 10;
			do_epoll_pwait(efd, &e, 1, &timeout, NULL);
			alarm(0);
		} while (timeout.tv_nsec);

		if (epoll_ctl(efd, EPOLL_CTL_DEL, fd_in.fd, &e))
			tst_brk(TBROK | TERRNO, "epoll_ctl(EPOLL_CTL_DEL)");
	}

	tst_res(TPASS, "Timeout works correctly");
}

static void setup(void)
{
	epoll_pwait_init();

	efd = epoll_create(1);
	if (efd == -1)
		tst_brk(TBROK | TERRNO, "epoll_create()");
}

static void cleanup(void)
{
	if (efd > 0)
		SAFE_CLOSE(efd);
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.test_variants = TEST_VARIANTS,
};
