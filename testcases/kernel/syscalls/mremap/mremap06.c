// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 SUSE LLC <mdoucha@suse.cz>
 */

/*
 * CVE-2018-18281
 *
 * Check for race condition between mremap() and ftruncate() which may lead
 * to temporary memory protection bypass because the TLB wasn't properly
 * flushed. Race fixed in:
 *
 *  commit eb66ae030829605d61fbef1909ce310e29f78821
 *  Author: Linus Torvalds <torvalds@linux-foundation.org>
 *  Date:   Fri Oct 12 15:22:59 2018 -0700
 *
 *  mremap: properly flush TLB before releasing the page
 */

#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>

#include "tst_test.h"
#include "tst_fuzzy_sync.h"

#define BUF_SIZE 4096

static int quit, fd = -1, ctl_fd = -1;
static void *baseaddr, *mem_ptr;
static struct tst_fzsync_pair fzsync_pair;
static char buf[BUF_SIZE];

static void setup(void)
{
	fd = SAFE_OPEN("/dev/shm/ltp_mremap06", O_RDWR|O_CREAT|O_TRUNC, 0600);
	ctl_fd = SAFE_OPEN("/proc/sys/vm/compact_memory", O_WRONLY);
	memset(buf, 0x42, BUF_SIZE);
	SAFE_WRITE(1, fd, buf, BUF_SIZE);
	baseaddr = SAFE_MMAP(NULL, BUF_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	mem_ptr = baseaddr;

	fzsync_pair.exec_loops = 100000;
	tst_fzsync_pair_init(&fzsync_pair);

	/* The read thread will segfault. A lot. */
	signal(SIGSEGV, SIG_IGN);
	signal(SIGBUS, SIG_IGN);
}

static void *read_task(void *arg)
{
	unsigned long expval, curval;
	volatile unsigned long *readptr = baseaddr;

	memset(&expval, 0x42, sizeof(expval));
	for (curval = expval; !quit && curval == expval; curval = *readptr);
	quit = 1;

	if (curval == expval)
		return arg;

	tst_res(TFAIL, "Base address contains unexpected value %lx", curval);
	return arg;
}

static void *ftruncate_task(void *arg)
{
	while (tst_fzsync_run_b(&fzsync_pair)) {
		tst_fzsync_start_race_b(&fzsync_pair);
		SAFE_FTRUNCATE(fd, 0);
		SAFE_WRITE(1, ctl_fd, "1", 1);
		tst_fzsync_end_race_b(&fzsync_pair);
	}

	return arg;
}

static void run(void)
{
	void *ret;
	pthread_t read_thread;

	SAFE_PTHREAD_CREATE(&read_thread, NULL, read_task, NULL);
	tst_fzsync_pair_reset(&fzsync_pair, ftruncate_task);

	while (!quit && tst_fzsync_run_a(&fzsync_pair)) {
		tst_fzsync_start_race_a(&fzsync_pair);
		ret = mremap(mem_ptr, BUF_SIZE, BUF_SIZE,
			MREMAP_FIXED | MREMAP_MAYMOVE, baseaddr + 2 * BUF_SIZE);
		tst_fzsync_end_race_a(&fzsync_pair);

		if (ret != MAP_FAILED)
			mem_ptr = ret;

		usleep(10);
		SAFE_LSEEK(fd, 0, SEEK_SET);
		SAFE_WRITE(1, fd, buf, BUF_SIZE);
		SAFE_MUNMAP(mem_ptr, BUF_SIZE);
		mem_ptr = SAFE_MMAP(baseaddr, BUF_SIZE, PROT_READ,
			MAP_SHARED | MAP_FIXED, fd, 0);

		if (mem_ptr == MAP_FAILED) {
			quit = 1;
			SAFE_PTHREAD_JOIN(read_thread, &ret);
			tst_brk(TBROK, "Cannot recreate mapping for next race");
		}
	}

	if (!quit)
		tst_res(TPASS, "Cannot reproduce bug");

	quit = 1;
	SAFE_PTHREAD_JOIN(read_thread, &ret);
}

static void cleanup(void)
{
	tst_fzsync_pair_cleanup(&fzsync_pair);

	if (ctl_fd >= 0)
		SAFE_CLOSE(ctl_fd);

	if (mem_ptr != MAP_FAILED)
		SAFE_MUNMAP(mem_ptr, BUF_SIZE);

	if (fd >= 0) {
		SAFE_CLOSE(fd);
	}
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.tags = (const struct tst_tag[]) {
		{"linux-git", "eb66ae030829"},
		{"CVE", "2018-18281"},
		{}
	}
};
