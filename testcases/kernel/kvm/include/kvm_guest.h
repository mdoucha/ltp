/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 SUSE LLC <mdoucha@suse.cz>
 *
 * Minimal test library for KVM tests
 */

#ifndef KVM_GUEST_H_
#define KVM_GUEST_H_

/* The main LTP include dir is intentionally excluded during payload build */
#include "../../../../include/tst_res_flags.h"
#undef TERRNO
#undef TTERRNO
#undef TRERRNO

#define TST_TEST_TCONF(message) \
	void main(void) { tst_brk(TCONF, message); }

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Round x up to the next multiple of a.
 * a must be a power of 2.
 */
#define LTP_ALIGN(x, a)    __LTP_ALIGN_MASK((x), (typeof(x))(a) - 1)
#define __LTP_ALIGN_MASK(x, mask)  (((x) + (mask)) & ~(mask))

#define INTERRUPT_COUNT 32

typedef unsigned long size_t;
typedef long ssize_t;

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long uintptr_t;

#define NULL ((void *)0)

/**
 * DOC: KVM guest library
 *
 * The KVM guest library provides a minimal implementation of both the LTP
 * test library and the standard C library functions. Do not try to include
 * the usual LTP or C headers in guest payload code, it will not work.
 *
 * DOC: Standard C library functions
 */

/**
 * memset - Standard C library function.
 */
void *memset(void *dest, int val, size_t size);

/**
 * memzero - Standard C library function.
 */
void *memzero(void *dest, size_t size);

/**
 * memcpy - Standard C library function.
 */
void *memcpy(void *dest, const void *src, size_t size);

/**
 * strcpy - Standard C library function.
 */
char *strcpy(char *dest, const char *src);

/**
 * strcat - Standard C library function.
 */
char *strcat(char *dest, const char *src);

/**
 * strlen - Standard C library function.
 */
size_t strlen(const char *str);


/**
 * DOC: LTP library functions
 *
 * The KVM guest library currently provides the LTP functions for reporting
 * test results. All standard result flags except for `T*ERRNO` are supported
 * with the same rules as usual. However, the printf-like formatting is not
 * implemented yet.
 */

/**
 * kvm_exit - Terminate the test
 *
 * Terminate the test. Similar to calling `exit(0)` in a regular LTP test,
 * although `kvm_exit()` will terminate only one iteration of the test, not
 * the whole host process.
 */
void kvm_exit(void) __attribute__((noreturn));

/* Exit the VM using the HLT instruction but allow resume */
void kvm_yield(void);

void tst_res_(const char *file, const int lineno, int result,
	const char *message);
#define tst_res(result, msg) tst_res_(__FILE__, __LINE__, (result), (msg))

void tst_brk_(const char *file, const int lineno, int result,
	const char *message) __attribute__((noreturn));
#define tst_brk(result, msg) tst_brk_(__FILE__, __LINE__, (result), (msg))

/**
 * tst_signal_host - Send asynchronous notification to host process.
 * @data: Pointer value to be passed to host in `test_result->file_addr`.
 *   The host-side notification handler may both read and write to the buffer.
 *
 * Send asynchronous notification to host without stopping VM execution and
 * return immediately. The notification must be handled by another host thread.
 */
void tst_signal_host(void *data);

/**
 * tst_wait_host - Send notification to host and wait for response.
 * @data: Pointer to be passed to `tst_signal_host()`.
 *
 * Call `tst_signal_host(data)` and wait for host to call
 * `tst_kvm_clear_guest_signal()`.
 */
void tst_wait_host(void *data);

/**
 * tst_heap_alloc_aligned - Allocate buffer aligned to `align` bytes.
 * @size: Size of buffer.
 * @align: Buffer alignment in bytes.
 *
 * Return:
 * Pointer to allocated buffer.
 */
void *tst_heap_alloc_aligned(size_t size, size_t align);

/**
 * tst_heap_alloc - Allocate buffer.
 * @size: Size of buffer.
 *
 * Return:
 * Pointer to allocated buffer.
 */
void *tst_heap_alloc(size_t size);

/**
 * DOC: Arch dependent types and functions
 */

/**
 * struct kvm_interrupt_frame - Arch-dependent interrupt frame data.
 *
 * Opaque arch-dependent structure which holds interrupt frame information.
 * Use KVM API functions to access values stored inside.
 */
struct kvm_interrupt_frame;

/**
 * typedef tst_interrupt_callback - Interrupt handler callback prototype.
 *
 * @userdata: The pointer that was given to `tst_set_interrupt_callback()`
 * when the interrupt handler was installed.
 * @ifrm: The interrupt frame pointer.
 * @errcode: Error code defined by the interrupt vector semantics.
 * If the interrupt vector does not generate an error code, it will be
 * set to zero.
 *
 * Return:
 * Zero if the interrupt was successfully handled and test execution
 * should resume. Non-zero return value means that the interrupt could not
 * be handled and the test will terminate with error.
 */
typedef int (*tst_interrupt_callback)(void *userdata,
	struct kvm_interrupt_frame *ifrm, unsigned long errcode);

extern const char *tst_interrupt_names[INTERRUPT_COUNT];

/**
 * tst_set_interrupt_callback - Register new interrupt handler callback.
 * @vector: The interrupt vector where the handler should be installed.
 * @func: The handler function to install.
 * @userdata: An arbitrary pointer that will be passed to `func()` every time
 * it gets called.
 *
 * Register new interrupt handler callback. The previous interrupt handler
 * callback will be removed. Set `func` to `NULL` to remove any existing
 * handler. Unhandled interrupts will cause fatal error and terminate
 * the test.
 */
void tst_set_interrupt_callback(unsigned int vector,
	tst_interrupt_callback func, void *userdata);

/**
 * kvm_get_interrupt_ip - Get instruction pointer from interrupt frame.
 * @ifrm: The interrupt frame pointer.
 *
 * Get instruction pointer value from interrupt frame structure. This may be
 * the instruction which caused an interrupt or the one immediately after,
 * depending on the interrupt vector semantics.
 *
 * Return:
 * The instruction pointer value stored in the interrupt frame.
 */
uintptr_t kvm_get_interrupt_ip(const struct kvm_interrupt_frame *ifrm);

#endif /* KVM_GUEST_H_ */
