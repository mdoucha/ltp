// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright 2023 Mike Galbraith <efault-AT-gmx.de> */
/* Copyright 2023 Wei Gao <wegao@suse.com> */
/*\
 *
 * [Description]
 *
 * Thread starvation test. On fauluty kernel the test timeouts.
 *
 * Original reproducer taken from:
 * https://lore.kernel.org/lkml/9fd2c37a05713c206dcbd5866f67ce779f315e9e.camel@gmx.de/
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sched.h>

#include "tst_test.h"

static char *str_loop;
static long loop = 2000000;
static volatile long sigcount;
static char *str_timeout;
static int timeout = 240;

static void setup(void)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);

	CPU_SET(0, &mask);

	TST_EXP_POSITIVE(sched_setaffinity(0, sizeof(mask), &mask));

	if (tst_parse_long(str_loop, &loop, 1, LONG_MAX))
		tst_brk(TBROK, "Invalid number of loop number '%s'", str_loop);

	if (tst_parse_int(str_timeout, &timeout, 1, INT_MAX))
		tst_brk(TBROK, "Invalid number of timeout '%s'", str_timeout);

	tst_set_max_runtime(timeout);
}

static void handler(int sig LTP_ATTRIBUTE_UNUSED)
{
	sigcount++;
}

static void child(void)
{
	long i;
	pid_t ppid = getppid();

	TST_CHECKPOINT_WAIT(0);

	for (i = 0; i < loop; i++)
		SAFE_KILL(ppid, SIGUSR1);

	exit(0);
}

static void do_test(void)
{
	long intr_count = 0;
	pid_t child_pid;

	child_pid = SAFE_FORK();

	if (!child_pid)
		child();

	SAFE_SIGNAL(SIGUSR1, handler);
	TST_CHECKPOINT_WAKE(0);

	do {
		TEST(waitpid(child_pid, NULL, 0));
		intr_count++;
	} while (TST_RET < 0 && TST_ERR == EINTR);

	tst_res(TPASS, "waitpid() interrupted %ld times", intr_count - 1);
	tst_res(TPASS, "Received %ld signals", sigcount);
}

static struct tst_test test = {
	.test_all = do_test,
	.setup = setup,
	.forks_child = 1,
	.options = (struct tst_option[]) {
		{"l:", &str_loop, "Number of loops (default 2000000)"},
		{"t:", &str_timeout, "Max timeout (default 240s)"},
		{}
	},
	.needs_checkpoints = 1,
};
