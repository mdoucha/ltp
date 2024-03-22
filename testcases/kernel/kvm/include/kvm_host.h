/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 SUSE LLC <mdoucha@suse.cz>
 *
 * KVM host library for setting up and running virtual machine tests. Tests
 * can either use the default setup/run/host functions or use the advanced
 * API to create customized VMs.
 */

/*
 * Most basic usage:
 *
 * #include "kvm_test.h"
 *
 * #ifdef COMPILE_PAYLOAD
 *
 * void main(void)
 * {
 *	[VM guest code goes here]
 * }
 *
 * #else
 *
 * [optional VM host setup/run/cleanup code goes here]
 *
 * static struct tst_test test = {
 *	.test_all = tst_kvm_run,
 *	.setup = tst_kvm_setup,
 *	.cleanup = tst_kvm_cleanup,
 * };
 *
 * #endif
 */

#ifndef KVM_HOST_H_
#define KVM_HOST_H_

#include <inttypes.h>
#include <linux/kvm.h>
#include "kvm_common.h"

#define VM_KERNEL_BASEADDR 0x1000
#define VM_RESET_BASEADDR 0xfffffff0
#define VM_RESET_CODE_SIZE 8

#define MIN_FREE_RAM (10 * 1024 * 1024)
#define DEFAULT_RAM_SIZE (16 * 1024 * 1024)
#define MAX_KVM_MEMSLOTS 8

/**
 * struct tst_kvm_instance - KVM virtual machine instance.
 * @vm_fd: Main VM file descriptor created by `ioctl(KVM_CREATE_VM)`
 * @vcpu_fd: Virtual CPU file descriptor created by `ioctl(KVM_CREATE_VCPU)`
 * @vcpu_info: VCPU state structure created by `mmap(vcpu_fd)`
 * @vcpu_info_size: Size of `vcpu_info` buffer
 * @ram: List of memory slots defined in this VM. Unused memory slots have
 * zero in the `userspace_addr` field.
 * @result: Buffer for passing test result data from the VM to the controller
 * program, mainly `tst_res()`/`tst_brk()` flags and messages.
 */
struct tst_kvm_instance {
	int vm_fd, vcpu_fd;
	struct kvm_run *vcpu_info;
	size_t vcpu_info_size;
	struct kvm_userspace_memory_region ram[MAX_KVM_MEMSLOTS];
	struct tst_kvm_result *result;
};

/* Test binary to be installed into the VM at VM_KERNEL_BASEADDR */
extern const char kvm_payload_start[], kvm_payload_end[];

/* CPU reset code to be installed into the VM at VM_RESET_BASEADDR */
extern const unsigned char tst_kvm_reset_code[VM_RESET_CODE_SIZE];

/**
 * tst_kvm_setup - Default KVM `setup()` function for `struct tst_test`.
 *
 * Must be called before `tst_kvm_run()`.
 */
void tst_kvm_setup(void);

/**
 * tst_kvm_run - Default KVM `run()` function for `struct tst_test`.
 */
void tst_kvm_run(void);

/**
 * tst_kvm_cleanup - Default KVM `cleanup()` function for `struct tst_test`.
 *
 * Must be used to clean up after `tst_kvm_run()`.
 */
void tst_kvm_cleanup(void);

/**
 * tst_kvm_validate_result - Validate result value returned by VM.
 * @value: Value to be validated.
 *
 * Validate whether the value returned in `struct tst_kvm_result.result`
 * can be safely passed to `tst_res()` or `tst_brk()`. If the value is not
 * valid, the controller program will be terminated with error.
 */
void tst_kvm_validate_result(int value);

/**
 * tst_kvm_alloc_memory - Allocate memory slot for VM.
 * @inst: KVM virtual machine instance.
 * @slot: Memory slot number where the buffer should be installed.
 * @baseaddr: Base address where the buffer should be installed.
 * @size: Minimum buffer size.
 * @flags: Memory slot flags.
 *
 * Allocate a guarded buffer of given size and install it into given memory
 * slot of the KVM virtual machine. The buffer will be automatically page
 * aligned at both ends. See the kernel documentation
 * of `KVM_SET_USER_MEMORY_REGION` ioctl for list of valid flags.
 *
 * Return:
 * Pointer to page-aligned beginning of the allocated guarded buffer.
 * Do not attempt to `free()` it. The actual requested `baseaddr` will be
 * located at `ret + baseaddr % pagesize`. Any extra space added
 * at the beginning or end for page alignment will be writable.
 */
void *tst_kvm_alloc_memory(struct tst_kvm_instance *inst, unsigned int slot,
	uint64_t baseaddr, size_t size, unsigned int flags);

/**
 * tst_kvm_get_phys_address - Convert guest pointer to physical address.
 * @inst: KVM virtual machine instance.
 * @addr: Virtual memory address from the VM to be converted.
 *
 * Convert pointer value (virtual address) from given virtual machine
 * to the corresponding physical address.
 *
 * Return:
 * Physical address corresponding to the given virtual address. If virtual
 * memory mapping is unavailable or not enabled in the VM, the input value
 * will be returned as is. Returns 0 if the virtual address is unmapped or
 * invalid.
 */
uint64_t tst_kvm_get_phys_address(const struct tst_kvm_instance *inst,
	uint64_t addr);

/**
 * tst_kvm_find_phys_memslot - Find memory slot for physical address.
 * @inst: KVM virtual machine instance.
 * @paddr: Physical memory address from the VM.
 *
 * Find the `struct tst_kvm_instance` memory slot ID for the given physical
 * address in guest memory.
 *
 * Return:
 * Memory slot ID. Returns -1 if the address is outside allocated memory slots.
 */
int tst_kvm_find_phys_memslot(const struct tst_kvm_instance *inst,
	uint64_t paddr);

/**
 * tst_kvm_find_memslot - Find memory slot for virtual address.
 * @inst: KVM virtual machine instance.
 * @addr: Virtual memory address from the VM.
 *
 * Find the `struct tst_kvm_instance` memory slot ID for the given virtual
 * address. If virtual memory mapping is unavailable or not enabled in the VM,
 * this function will treat the pointer value as physical address and return
 * the same slot ID as `tst_kvm_find_phys_memslot()`.
 *
 * Return:
 * Memory slot ID. Returns -1 if the virtual address is invalid (unmapped) or
 * the corresponding physical address is outside allocated memory slots.
 */
int tst_kvm_find_memslot(const struct tst_kvm_instance *inst, uint64_t addr);

/*
 * tst_kvm_get_memptr - Convert guest virtual memory address to host pointer.
 * @inst: KVM virtual machine instance.
 * @addr: Virtual memory address from the VM.
 *
 * Return:
 * Pointer which can be used in host code to directly access the given
 * virtual address from guest memory.
 */
void *tst_kvm_get_memptr(const struct tst_kvm_instance *inst, uint64_t addr);

/**
 * tst_kvm_get_cpuid - Find CPUID values supported by KVM.
 * @sysfd: KVM file descriptor created using `open("/dev/kvm")`.
 *
 * Find CPUID values supported by KVM. x86_64 tests must set non-default CPUID,
 * otherwise bootstrap will fail to initialize 64bit mode.
 *
 * Return:
 * CPUID data returned by `ioctl(KVM_GET_SUPPORTED_CPUID)`. NULL if the ioctl
 * is not supported.
 */
struct kvm_cpuid2 *tst_kvm_get_cpuid(int sysfd);

/**
 * tst_kvm_create_instance - Initialize KVM instance structure.
 * @inst: Uninitialized KVM virtual machine instance.
 * @ram_size: Size of RAM slot 0 memory buffer to be allocated.
 *
 * Initialize the given KVM instance structure. Creates new KVM virtual machine
 * with 1 virtual CPU, allocates VM RAM (max. 4GB minus one page) and
 * shared result structure. KVM memory slots 0 and 1 will be set by this
 * function. Call `tst_kvm_destroy_instance()` before using this function
 * to reinitialize an existing VM instance.
 */
void tst_kvm_create_instance(struct tst_kvm_instance *inst, size_t ram_size);

/**
 * tst_kvm_run_instance - Execute virtual machine.
 * @inst: KVM virtual machine instance.
 * @exp_errno: Expected error code from `ioctl(KVM_RUN)`.
 *
 * Execute the program installed in given KVM instance and print results.
 * Any result messages returned by the VM will be automatically printed
 * to controller program output. If `ioctl(KVM_RUN)` is expected to fail,
 * pass the expected error code in exp_errno, otherwise set it to zero.
 *
 * Return:
 * Last value returned by `ioctl(KVM_RUN)`.
 */
int tst_kvm_run_instance(struct tst_kvm_instance *inst, int exp_errno);

/**
 * tst_kvm_destroy_instance - Destroy virtual machine instance.
 * @inst: KVM virtual machine instance.
 *
 * Deletes the KVM virtual machine. Note that the guarded buffers assigned
 * to the VM by `tst_kvm_create_instance()` or `tst_kvm_alloc_memory()`
 * will not be freed.
 */
void tst_kvm_destroy_instance(struct tst_kvm_instance *inst);

/**
 * tst_kvm_wait_guest - Wait for asynchronous signal from VM.
 * @inst: KVM virtual machine instance.
 * @timeout_ms: Timeout value in milliseconds.
 *
 * Wait for given VM to call `tst_signal_host()` or `tst_wait_host()`. Zero
 * timeout means return immediately if no signal is pending, negative timeout
 * means wait forever. This function must be called from different host thread
 * than `tst_kvm_run_instance()`.
 *
 * Return:
 * Zero if signal was received, KVM_TEXIT if the VM exited without sending
 * a signal, or -1 if timeout was reached.
 */
int tst_kvm_wait_guest(struct tst_kvm_instance *inst, int timeout_ms);

/**
 * tst_kvm_clear_guest_signal - Clear pending guest signal.
 * @inst: KVM virtual machine instance.
 *
 * Clear VM signal sent by tst_signal_host(). If the VM is waiting
 * in `tst_wait_host()`, this function will signal the VM to resume execution.
 */
void tst_kvm_clear_guest_signal(struct tst_kvm_instance *inst);

#endif /* KVM_HOST_H_ */
