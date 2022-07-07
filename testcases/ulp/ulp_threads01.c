// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 SUSE LLC <mdoucha@suse.cz>
 */
/*\
 * [Description]
 *
 * Create a large number of threads and wait for the process to be livepatched.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/resource.h>
#include <gnu/libc-version.h>

#include "tst_test.h"
#include "tst_safe_pthread.h"

#define LIVEPATCH_MAGIC "-lp-"

#define SAFETY_MARGIN 4096
#define TESTDATA_SIZE 256
#define THREAD_LIMIT_PATH "/proc/sys/kernel/threads-max"

#define CHECK_PTHREAD(SCALL)						\
	do {								\
		TST_ERR = SCALL;					\
									\
		if (TST_ERR)						\
			tst_brk(TBROK | TTERRNO, #SCALL " failed");	\
	} while (0)

static char *thcount_str, *delay_str, *patchinfo;
static long th_count = 16, delay_ms;
static volatile int quit;
static pthread_t *tid_list;
static pthread_barrier_t barrier;
static int barrier_init;
static unsigned char testdata[TESTDATA_SIZE];
static struct timespec delay;

void handle_sigusr1(int sig LTP_ATTRIBUTE_UNUSED)
{
	quit = 1;
}

static const char *get_livepatch_version(void)
{
	const char *ret, *libc_version = gnu_get_libc_version();

	if (!libc_version)
		tst_brk(TBROK, "Glibc version is NULL");

	tst_res(TINFO, "Glibc version: %s", libc_version);
	ret = strstr(libc_version, LIVEPATCH_MAGIC);
	return ret ? ret + strlen(LIVEPATCH_MAGIC) : NULL;
}

void setup(void)
{
	struct rlimit lim;
	long i, max_threads;

	if (thcount_str && tst_parse_long(thcount_str, &th_count, 1, LONG_MAX))
		tst_brk(TBROK, "Invalid thread count: %s", thcount_str);

	if (delay_str && tst_parse_long(delay_str, &delay_ms, 0, LONG_MAX))
		tst_brk(TBROK, "Invalid delay value: %s", delay_str);

	delay.tv_sec = delay_ms / 1000;
	delay.tv_nsec = (delay_ms % 1000) * 1000000;
	SAFE_FILE_SCANF(THREAD_LIMIT_PATH, "%ld", &max_threads);
	SAFE_GETRLIMIT(RLIMIT_NPROC, &lim);

	if (th_count + SAFETY_MARGIN > max_threads) {
		if (access(THREAD_LIMIT_PATH, W_OK)) {
			tst_brk(TCONF | TERRNO,
				"Cannot increase max thread count to %ld",
				th_count + SAFETY_MARGIN);
		}

		SAFE_FILE_PRINTF(THREAD_LIMIT_PATH, "%ld",
			th_count + SAFETY_MARGIN);
	}

	if (th_count + SAFETY_MARGIN > (long)lim.rlim_cur) {
		if (th_count + SAFETY_MARGIN > (long)lim.rlim_max)
			lim.rlim_max = th_count + SAFETY_MARGIN;

		lim.rlim_cur = lim.rlim_max;
		SAFE_SETRLIMIT(RLIMIT_NPROC, &lim);
	}

	CHECK_PTHREAD(pthread_barrier_init(&barrier, NULL, th_count + 1));
	barrier_init = 1;

	for (i = 0; i < TESTDATA_SIZE; i++)
		testdata[i] = i;
}

void *thread_main(void *arg)
{
	unsigned char *buf;
	int i;

	pthread_barrier_wait(&barrier);

	while (!quit) {
		buf = SAFE_MALLOC(TESTDATA_SIZE * sizeof(char));
		memcpy(buf, arg, TESTDATA_SIZE * sizeof(char));

		for (i = 0; i < TESTDATA_SIZE; i++) {
			if (buf[i] != (unsigned char)i) {
				tst_brk(TBROK, "Wrong testdata value: %u != %u",
					buf[i], (unsigned char)i);
			}
		}

		free(buf);

		if (delay_ms)
			nanosleep(&delay, NULL);
	}

	return arg;
}

void run(void)
{
	long i;
	pthread_attr_t attr;
	const char *patchver;

	if (get_livepatch_version())
		tst_brk(TBROK, "Glibc is already livepatched");

	/* Minimize performance impact on system */
	CHECK_PTHREAD(pthread_attr_init(&attr));
	CHECK_PTHREAD(pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN));

	if (setpriority(PRIO_PROCESS, 0, 19))
		tst_brk(TBROK | TERRNO, "setpriority() failed");

	tid_list = SAFE_MALLOC(th_count * sizeof(pthread_t));

	for (i = 0; i < th_count; i++)
		SAFE_PTHREAD_CREATE(tid_list + i, &attr, thread_main, testdata);

	pthread_attr_destroy(&attr);
	signal(SIGUSR1, handle_sigusr1);
	tst_res(TINFO, "PID %d ready, waiting for signal SIGUSR1", getpid());
	pthread_barrier_wait(&barrier);

	for (i = 0; i < th_count; i++)
		SAFE_PTHREAD_JOIN(tid_list[i], NULL);

	tst_res(TPASS, "All threads terminated successfully");
	free(tid_list);
	tid_list = NULL;
	patchver = get_livepatch_version();

	if (patchver)
		tst_res(TPASS, "Glibc livepatch version: %s", patchver);
	else
		tst_res(TFAIL, "No Glibc livepatch found");
}

void cleanup(void)
{
	free(tid_list);
	free(patchinfo);

	if (barrier_init)
		CHECK_PTHREAD(pthread_barrier_destroy(&barrier));
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.needs_root = 1,
	.max_runtime = TST_UNLIMITED_RUNTIME,
	.options = (struct tst_option[]) {
		{"s:", &delay_str,
			"Thread sleep length in milliseconds (default: 0ms)"},
		{"t:", &thcount_str,
			"Number of threads to create (default: 16)"},
		{}
	},
	.save_restore = (const struct tst_path_val[]){
		{"/proc/sys/kernel/threads-max", NULL,
			TST_SR_TCONF_MISSING | TST_SR_SKIP_RO},
		{}
	}
};
