// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Linux Test Project, 2009-2019
 * Copyright (C) 2009, Ngie Cooper
 * Copyright (c) 2023 Wei Gao <wegao@suse.com>
 */

/*\
 * This test ptraces itself as per arbitrarily specified signals,
 * over 0 to SIGRTMAX range.
 */

#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "lapi/signal.h"
#include "tst_test.h"

static int expect_stop;

static void test_signal(int signum)
{
	int status;
	pid_t child;

	child = SAFE_FORK();

	if (!child) {
		child = getpid();
		TST_EXP_PASS_SILENT(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
		tst_res(TDEBUG, "[child %d] Sending kill(.., %s)", child, tst_strsig(signum));
		SAFE_KILL(getpid(), signum);
		tst_res(TDEBUG, "[child %d] Exiting", child);
		exit(0);
	}

	tst_res(TINFO, "Testing signal %s", tst_strsig(signum));
	SAFE_WAITPID(child, &status, 0);

	switch (signum) {
	case 0:
		if (WIFEXITED(status)
				&& WEXITSTATUS(status) == 0) {
			tst_res(TPASS,
					"kill(.., 0) exited with 0, as expected.");
		} else {
			tst_res(TFAIL,
					"kill(.., 0) exited with unexpected %s.", tst_strstatus(status));
		}
		break;
	case SIGKILL:
		if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
			tst_res(TPASS, "Child killed by SIGKILL");
		else
			tst_res(TFAIL, "Child %s", tst_strstatus(status));
		break;
		/* All other processes should be stopped. */
	default:
		if (WIFSTOPPED(status)) {
			tst_res(TDEBUG, "Stopped as expected");
		} else {
			tst_res(TFAIL, "Didn't stop as expected. Child %s", tst_strstatus(status));
			expect_stop++;
		}
		break;
	}

	if (signum != 0 && signum != SIGKILL)
		SAFE_PTRACE(PTRACE_CONT, child, NULL, NULL);
}

static void run(void)
{
	int signum = 0, retries = 0, wstatus;
	int wflags = WNOHANG | WUNTRACED | WCONTINUED;
	pid_t pid;

	for (signum = 0; signum <= SIGRTMAX; signum++) {
		if (signum >= __SIGRTMIN && signum < SIGRTMIN)
			continue;
		test_signal(signum);
	}

	tst_res(TINFO, "Test finished");
	usleep(100000);

	for (pid = waitpid(-1, &wstatus, wflags); pid >= 0;
		pid = waitpid(-1, &wstatus, wflags)) {
		if (!pid) {
			if (retries++ <= SIGRTMAX) {
				tst_res(TFAIL, "A child is stuck");
				kill(0, SIGCONT);
				usleep(10000);
				continue;
			}

			kill(-getpid(), SIGKILL);
			tst_brk(TBROK, "Stuck children did not wake up");
		}

		if (WIFCONTINUED(wstatus)) {
			tst_res(TINFO, "Child %d resumed execution\n", pid);
			continue;
		}

		if (WIFSTOPPED(wstatus)) {
			tst_res(TFAIL, "Child %d was stopped by signal %s",
				pid, tst_strsig(WSTOPSIG(wstatus)));
			SAFE_PTRACE(PTRACE_CONT, pid, NULL, NULL);
			usleep(10000);
		} else if (WIFEXITED(wstatus)) {
			tst_res(TINFO, "Child %d exited normally", pid);
		} else {
			tst_res(TFAIL, "Child %d changed status: 0x%x",
				pid, (unsigned int)wstatus);
			kill(pid, SIGKILL);
		}
	}

	if (errno != ECHILD)
		tst_res(TFAIL | TERRNO, "Final wait() failed");
}

static struct tst_test test = {
	.test_all = run,
	.forks_child = 1,
};
