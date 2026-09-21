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
 * The assembly sees these through asm-offsets_64.c.  What the switcher and
 * the hypervisor must maintain for this to be safe is listed, as S1-S12, in
 * Documentation/virt/kvm/x86/pvm-invariants.rst.
 */

#ifdef CONFIG_X86_PVM_SWITCHER
#include <asm/processor-flags.h>

/*
 * How many shadowed guest page tables the switcher can choose between without
 * exiting.  One more than KVM_MMU_NUM_PREV_ROOTS, so the current root and
 * every cached one fit; the switcher scans them linearly, so it is small on
 * purpose.
 */
#define PVM_PGTBL_CACHE_SIZE			4

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

/*
 * Direct #PF delivery (PVM_FEATURE_DIRECT_PF): the most user #PFs delivered
 * without the shadow MMU in a row, and the error code bits of the only faults
 * delivered without the walk -- user, not present, read or write.  The
 * error code bits mirror X86_PF_USER and X86_PF_WRITE, which are not usable
 * from assembly.  pvm_direct_page_fault in entry_64_switcher.S tests them in
 * assembly, and kvm-pvm through pvm_direct_pf_error_code() and
 * pvm_direct_pf_rule() below.
 */
#define PVM_DIRECT_PF_RUN			4
#define PVM_DIRECT_PF_ERR_USER			0x4
#define PVM_DIRECT_PF_ERR_WRITE			0x2

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
#include <linux/build_bug.h>
#include <linux/cache.h>
#include <asm/page_types.h>
#include <asm/trap_pf.h>

static_assert(PVM_DIRECT_PF_ERR_USER == X86_PF_USER);
static_assert(PVM_DIRECT_PF_ERR_WRITE == X86_PF_WRITE);

/*
 * The direct #PF rule in C, for the hypervisor's exit handler.  The switcher's
 * pvm_direct_page_fault is the same rule in assembly, on the same constants
 * and on the same state (tss_extra.dpf_run and dpf_page); change both
 * together.
 *
 * Only a user, not-present read or write: no P, RSVD, PK or fetch bit, and
 * no other bit either.
 */
static inline bool pvm_direct_pf_error_code(u32 error_code)
{
	return error_code == PVM_DIRECT_PF_ERR_USER ||
	       error_code == (PVM_DIRECT_PF_ERR_USER | PVM_DIRECT_PF_ERR_WRITE);
}

/*
 * Not the page of the previous delivery, and fewer than PVM_DIRECT_PF_RUN
 * deliveries in a row.  @run is the number of deliveries in a row so far and
 * @page the page of the last one.
 */
static inline bool pvm_direct_pf_rule(u32 run, unsigned long page,
				      unsigned long addr)
{
	if (run && (addr & PAGE_MASK) == page)
		return false;

	return run < PVM_DIRECT_PF_RUN;
}

struct pt_regs;
struct pvm_vcpu_struct;

/*
 * What the switcher counts under CONFIG_KVM_PVM_STATS: the events that never
 * reach the hypervisor, so it is the only one that can see them.  kvm-pvm
 * folds them into the vCPU after every run.
 */
#define PVM_SWITCHER_STATS(X)						\
	X(ds_to_smod)		/* direct switch, user -> supervisor */	\
	X(ds_to_umod)		/* direct switch, supervisor -> user */	\
	X(pgtbl_hit_paired)	/* LOAD_PGTBL served, pair loaded */	\
	X(pgtbl_hit_unpaired)	/* LOAD_PGTBL served, NO_DS_CR3 set */	\
	X(rdpkru)							\
	X(wrpkru)							\
	X(pkru_user_nonzero)	/* RDPKRU on the way in read non-zero */ \
	X(dpf_direct)		/* user #PF delivered by the switcher */

#define PVM_STAT_FIELD(name)	unsigned long name;

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
	 * Guest page tables the hypervisor has already shadowed, so that the
	 * switcher can serve PVM_HC_LOAD_PGTBL without leaving the guest.
	 *
	 * Each entry holds a guest CR3 and the hardware CR3 of both modes, so
	 * that loading one keeps the direct mode switch working.  The
	 * hypervisor refills the table from its cached roots before every VM
	 * entry (pvm_publish_pgtbl_cache()), so an entry is valid for one guest
	 * run only.  guest_cr3 == 0 marks an empty entry: a guest CR3 of 0
	 * cannot be loaded.
	 */
	struct pvm_pgtbl_entry {
		unsigned long guest_cr3;
		unsigned long smod_cr3;
		unsigned long umod_cr3;
	} pgtbl[PVM_PGTBL_CACHE_SIZE];
	/*
	 * The guest CR3 the switcher last loaded from the table, or 0 if it
	 * loaded none.  This is how the hypervisor learns, on the next exit,
	 * that the guest changed address space behind its back -- the same
	 * shape as the smod/umod toggle it already reconciles after each run.
	 */
	unsigned long pgtbl_switched;
	/*
	 * The exact PVM_HC_LOAD_PGTBL flags word the fast path may serve.  It
	 * is not enough to require the TLB bit clear: the guest also sends its
	 * paging level, and the hypervisor's handler turns a change there into
	 * a CR4 update and an MMU reset.  Serving that in the switcher would
	 * leave CR4 describing the wrong paging level, so require the whole
	 * word to equal what the hypervisor says means "nothing to do but load
	 * it", and let anything else exit.
	 */
	unsigned long pgtbl_flags;

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

	/*
	 * Direct #PF delivery: the guest's user event entry, whether the
	 * switcher may deliver at all, and the state of the rule that keeps
	 * it from sending the guest back to the same page (kvm-pvm's
	 * pvm_direct_pf_candidate(), which it shares with the switcher by
	 * copying it in and out around every run).
	 */
	unsigned long event_entry;
	unsigned long dpf_page;
	u32 dpf_on;
	u32 dpf_run;

#ifdef CONFIG_KVM_PVM_STATS
	struct pvm_switcher_stats {
		PVM_SWITCHER_STATS(PVM_STAT_FIELD)
	} stats;
#endif
} ____cacheline_aligned;

extern struct pt_regs *switcher_enter_guest(void);
extern const char entry_SYSCALL_64_switcher[];
extern const char entry_SYSCALL_64_switcher_safe_stack[];
extern const char entry_SYSRETQ_switcher_unsafe_stack[];
#endif /* __ASSEMBLER__ */

#endif /* CONFIG_X86_PVM_SWITCHER */

#endif /* _ASM_X86_PVM_SWITCHER_H */
