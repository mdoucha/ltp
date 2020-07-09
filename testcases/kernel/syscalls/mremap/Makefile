# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) International Business Machines  Corp., 2001

top_srcdir		?= ../../../..

LTPLIBS = ltpipc

include $(top_srcdir)/include/mk/testcases.mk

mremap04: LDLIBS  += -lltpipc
mremap06:	CFLAGS += -pthread
mremap06:	LDLIBS += -lrt

include $(top_srcdir)/include/mk/generic_leaf_target.mk
