/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PVM_SWITCHER_H
#define _ASM_X86_PVM_SWITCHER_H

/*
 * The interface between the switcher in arch/x86/entry/entry_64_switcher.S
 * and the hypervisor that runs guests with it:
 *
 *  - struct tss_extra, per CPU in the TSS.  The hypervisor fills it with
 *    interrupts disabled before switcher_enter_guest() and reads back, after
 *    it returns, the fields the switcher changes (switch_flags and those
 *    documented as written by the switcher).  The switcher sets and clears
 *    host_rsp; the host entry code reads host_rsp and host_cr3.
 *  - The guest's registers, in a pt_regs at the top of the sp0 stack on the
 *    way in and on the way out, with the exit reason in orig_ax.
 *  - SWITCH_FLAGS_*, whose bits 8-63 belong to the hypervisor.
 *  - The PVCS (struct pvm_vcpu_struct), which the switcher's direct mode
 *    switches read and write through tss_extra.pvcs.
 *
 * The assembly sees these through asm-offsets_64.c.
 */

#ifdef CONFIG_X86_PVM_SWITCHER
#include <asm/processor-flags.h>

/*
 * On return from switcher_enter_guest(), pt_regs::orig_ax holds the exit
 * vector in its upper half and the error code in its lower half: ~0 for an
 * exception or interrupt without one, 0 for SWITCH_EXIT_REASONS_SYSCALL, the
 * guest SYSCALL the switcher did not handle itself.
 */
#define ORIG_RAX_VECTOR				(ORIG_RAX + 4)

#define SWITCH_EXIT_REASONS_SYSCALL		1024

/*
 * SWITCH_FLAGS control the way how the switcher code works,
 *	mostly dictate whether it should directly do the guest ring
 *	switch or just go back to hypervisor.
 *
 * SMOD and UMOD
 *	Current vcpu mode. Use two parity bits to simplify direct-switch
 *	flags checking.
 *
 * NO_DS_CR3
 *	Not to direct switch due to smod_cr3 or umod_cr3 not having been
 *	prepared.
 */
#define SWITCH_FLAGS_SMOD			_BITULL(0)
#define SWITCH_FLAGS_UMOD			_BITULL(1)
#define SWITCH_FLAGS_NO_DS_CR3			_BITULL(2)

#define SWITCH_FLAGS_MOD_TOGGLE			(SWITCH_FLAGS_SMOD | SWITCH_FLAGS_UMOD)

/* PVCS::user_cs and PVCS::user_ss, read or written as one 32-bit word. */
#define PVCS_USER_CS_SS				((__USER_DS << 16) | __USER_CS)

/*
 * Direct switching disabling bits are all the bits other than
 * SWITCH_FLAGS_SMOD or SWITCH_FLAGS_UMOD. Bits 8-63 are defined by the driver
 * using the switcher. Direct switching is enabled if all the disabling bits
 * are cleared.
 *
 * SWITCH_FLAGS_NO_DS_TO_SMOD: not to direct switch to smod due to any
 * disabling bit or smod bit being set.
 *
 * SWITCH_FLAGS_NO_DS_TO_UMOD: not to direct switch to umod due to any
 * disabling bit or umod bit being set.
 */
#define SWITCH_FLAGS_NO_DS_TO_SMOD		(~SWITCH_FLAGS_UMOD)
#define SWITCH_FLAGS_NO_DS_TO_UMOD		(~SWITCH_FLAGS_SMOD)

/* Bits allowed to be set in the underlying eflags */
#define SWITCH_ENTER_EFLAGS_ALLOWED	(X86_EFLAGS_FIXED | X86_EFLAGS_IF |\
					 X86_EFLAGS_TF | X86_EFLAGS_RF |\
					 X86_EFLAGS_AC | X86_EFLAGS_OF | \
					 X86_EFLAGS_DF | X86_EFLAGS_SF | \
					 X86_EFLAGS_ZF | X86_EFLAGS_AF | \
					 X86_EFLAGS_PF | X86_EFLAGS_CF | \
					 X86_EFLAGS_ID | X86_EFLAGS_NT)

/* Bits must be set in the underlying eflags */
#define SWITCH_ENTER_EFLAGS_FIXED	(X86_EFLAGS_FIXED | X86_EFLAGS_IF)

#ifndef __ASSEMBLER__
#include <linux/cache.h>

struct pt_regs;
struct pvm_vcpu_struct;

/*
 * Per-CPU switcher state, kept in struct tss_struct.  The page-aligned
 * tss_struct has room for it without growing, as setup_cpu_entry_area()
 * asserts.
 */
struct tss_extra {
	/* Saved host CR3 to be loaded after VM exit. */
	unsigned long host_cr3;
	/*
	 * Saved host stack to be loaded after VM exit. This also serves as a
	 * flag to indicate that it is entering the guest world in the switcher
	 * or has been in the guest world in the host entries.
	 */
	unsigned long host_rsp;
	/* Prepared guest CR3 to be loaded before VM enter. */
	unsigned long enter_cr3;

	/*
	 * Direct switching flag indicates whether direct switching
	 * is allowed.
	 */
	unsigned long switch_flags ____cacheline_aligned;
	/*
	 * Guest supervisor mode hardware CR3 for direct switching of guest
	 * user mode syscall.
	 */
	unsigned long smod_cr3;
	/*
	 * Guest user mode hardware CR3 for direct switching of guest ERETU
	 * synthetic instruction.
	 */
	unsigned long umod_cr3;
	/*
	 * The current PVCS for saving and restoring guest user mode context
	 * in direct switching.
	 */
	struct pvm_vcpu_struct *pvcs;
	unsigned long retu_rip;
	unsigned long smod_entry;
	unsigned long smod_gsbase;
	/*
	 * Protection keys.  There is one hardware PKRU and the guest is at
	 * CPL 3 in both of its modes, so a guest ring switch has to swap it
	 * the way it swaps CR3: the guest's user value lives in the register
	 * while the guest is in user mode and in PVCS::pkru while it is in
	 * supervisor mode, and smod_pkru is what supervisor mode runs on.
	 *
	 * Without that split the guest's own PKRU would govern its kernel's
	 * accesses too, because every leaf SPTE of a guest at CPL3 carries
	 * USER, where real hardware exempts supervisor pages from PKU entirely.
	 *
	 * pku_on is zero unless the guest has turned protection keys on; while
	 * it is zero the switcher leaves PKRU alone.
	 */
	u32 pku_on;
	u32 smod_pkru;
} ____cacheline_aligned;

extern struct pt_regs *switcher_enter_guest(void);
extern const char entry_SYSCALL_64_switcher[];
extern const char entry_SYSCALL_64_switcher_safe_stack[];
extern const char entry_SYSRETQ_switcher_unsafe_stack[];
#endif /* __ASSEMBLER__ */

#endif /* CONFIG_X86_PVM_SWITCHER */

#endif /* _ASM_X86_PVM_SWITCHER_H */
