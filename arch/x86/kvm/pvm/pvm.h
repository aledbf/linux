/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_PVM_H
#define __KVM_X86_PVM_H

#include <linux/kvm_host.h>
#include <asm/pvm_switcher.h>
#include <uapi/asm/pvm_trace.h>

/*
 * Extra switch flags:
 *
 * IRQ_WIN:
 *	There is an irq window request, and the vcpu should not directly
 *	switch to context with IRQ enabled, e.g. user mode.
 * SINGLE_STEP:
 *	KVM_GUESTDBG_SINGLESTEP is set.
 * PVCS_INVALID:
 *	No PVCS is pinned, so the switcher has nowhere to save user state.
 */
#define SWITCH_FLAGS_IRQ_WIN				_BITULL(8)
#define SWITCH_FLAGS_SINGLE_STEP			_BITULL(9)
#define SWITCH_FLAGS_PVCS_INVALID			_BITULL(10)

/* The flags a vCPU starts with. */
#define SWITCH_FLAGS_INIT	(SWITCH_FLAGS_SMOD | SWITCH_FLAGS_PVCS_INVALID)

/*
 * Every reason not to direct switch, including the one the switcher defines
 * itself.  A new reason must take a bit here rather than an extra conditional in the
 * assembly, because a single test of SWITCH_FLAGS_NO_DS_TO_{S,U}MOD is what
 * covers all of them at once -- an inhibitor outside those masks would be
 * silently ignored by the fast path.
 */
#define SWITCH_FLAGS_INHIBITORS		(SWITCH_FLAGS_NO_DS_CR3 | \
					 SWITCH_FLAGS_IRQ_WIN | \
					 SWITCH_FLAGS_SINGLE_STEP | \
					 SWITCH_FLAGS_PVCS_INVALID)

static_assert((SWITCH_FLAGS_INHIBITORS & SWITCH_FLAGS_NO_DS_TO_SMOD) ==
	      SWITCH_FLAGS_INHIBITORS);
static_assert((SWITCH_FLAGS_INHIBITORS & SWITCH_FLAGS_NO_DS_TO_UMOD) ==
	      SWITCH_FLAGS_INHIBITORS);
/* An inhibitor must not collide with the two bits that encode the mode. */
static_assert(!(SWITCH_FLAGS_INHIBITORS & SWITCH_FLAGS_MOD_TOGGLE));
/*
 * A vCPU comes up without a PVCS, so it must come up with direct switching
 * inhibited: the bit protecting a piece of state has to be set before that
 * state can be unsafe, never after.
 */
static_assert(SWITCH_FLAGS_INIT & SWITCH_FLAGS_INHIBITORS);

#define PVM_SYSCALL_VECTOR		SWITCH_EXIT_REASONS_SYSCALL

/*
 * Not produced by the switcher: pvm_vcpu_run() stores it in exit_vector when
 * it refuses to enter the guest, so it only has to stay clear of what the
 * switcher does report.  The value is the exit reason from
 * <uapi/asm/pvm_trace.h>, which perf shares by copying that header into tools/.
 */
#define PVM_FAILED_VMENTRY_VECTOR	PVM_EXIT_REASONS_FAILED_VMENTRY
static_assert(PVM_FAILED_VMENTRY_VECTOR >= NR_VECTORS &&
	      PVM_FAILED_VMENTRY_VECTOR != PVM_SYSCALL_VECTOR);

extern u64 *host_mmu_root_pgd;

void host_mmu_destroy(void);
int host_mmu_init(void);

/*
 * A host PCID is the vCPU's ASID, the guest's PCID index in the low bits, and
 * PVM_UMOD_PCID_BIT set for the user-mode root of the pair.  The two roots of
 * a pair share everything else, so switching between them only flips that bit.
 */
#define PVM_ASID_SHIFT			3
#define NUM_PVM_GUEST_PCID_INDEX	(1U << PVM_ASID_SHIFT)
#define PVM_UMOD_PCID_BIT		11
#define PVM_UMOD_PCID_MASK		(1U << PVM_UMOD_PCID_BIT)
#define PVM_GUEST_PCID_INDEX_MASK	(NUM_PVM_GUEST_PCID_INDEX - 1)
#define PVM_GUEST_PCID_MASK		(PVM_GUEST_PCID_INDEX_MASK | PVM_UMOD_PCID_MASK)

#define PVM_ASID_MIN			1
#define PVM_ASID_MAX			(((1U << PVM_UMOD_PCID_BIT) - 1) / NUM_PVM_GUEST_PCID_INDEX)
#define PVM_ASID_GEN_RESERVED		0
#define PVM_ASID_GEN_INIT		1

/*
 * CONFIG_KVM_PVM_STATS: what the hypervisor itself can count, beside what the
 * switcher counts in tss_ex (PVM_SWITCHER_STATS).
 */
#define PVM_HYPERVISOR_STATS(X)						\
	X(entries)							\
	X(pgtbl_publish)		/* pvm_publish_pgtbl_cache() */	\
	X(pgtbl_roots_scanned)		/* is_root_usable() calls in it */ \
	X(pgtbl_published)		/* table entries it filled */	\
	X(pgtbl_published_paired)	/* ... with a user-side root */	\
	X(hc_load_pgtbl)		/* LOAD_PGTBL the switcher sent here */ \
	X(hc_load_pgtbl_flags)		/* ... because of the flags word */ \
	X(hc_invlpg)							\
	X(hc_invlpg_seq)		/* one page on from the last, no exit between */ \
	X(hc_wrmsr)			/* PVM_HC_WRMSR, by MSR below */ \
	X(hc_wrmsr_icr)			/* x2APIC ICR */		\
	X(hc_wrmsr_tsc_deadline)					\
	X(hc_wrmsr_eoi)			/* x2APIC EOI */		\
	X(hc_wrmsr_other)						\
	X(hc_flush_all)							\
	X(hc_flush_current)						\
	X(pf_exit_smod)			/* #PF exits taken in supervisor mode */ \
	X(pf_exit_umod)			/* ... and in user mode */	\
	X(syscall_umod_exit)		/* user->supervisor via the hypervisor */ \
	X(syscall_umod_exit_no_ds_cr3)					\
	X(syscall_umod_exit_other)	/* another inhibitor */		\
	X(eretu_exit)			/* supervisor->user via the hypervisor */ \
	X(eretu_exit_no_ds_cr3)						\
	X(eretu_exit_other)		/* another inhibitor */		\
	X(eretu_exit_sel)		/* no inhibitor: CS/SS not the expected pair */

/* Direct #PF delivery, on a line of its own: printk's limit. */
#define PVM_DPF_STATS(X)						\
	X(dpf_exit_delivered)		/* delivered by the exit handler */ \
	X(dpf_refused_same_page)	/* the page of the delivery before */ \
	X(dpf_refused_run)		/* PVM_DIRECT_PF_RUN in a row */

/*
 * The counters KVM itself keeps that say what the shadow MMU did, printed with
 * PVM's own so that one snapshot holds both.
 */
#define PVM_KVM_VCPU_STATS(X)						\
	X(exits) X(pf_taken) X(pf_fixed) X(pf_spurious) X(pf_emulate)	\
	X(pf_fast) X(pf_guest) X(tlb_flush) X(invlpg) X(halt_exits)	\
	X(irq_exits) X(hypercalls)

#define PVM_KVM_VM_STATS(X)						\
	X(mmu_shadow_zapped) X(mmu_pte_write) X(mmu_pde_zapped)		\
	X(mmu_flooded) X(mmu_recycled) X(mmu_cache_miss) X(mmu_unsync)

/*
 * CONFIG_KVM_PVM_STATS only, and not part of the ABI: a write prints every
 * counter of every vCPU of the VM, tagged with the value written, so that a
 * guest can bracket one benchmark with two writes and the host log holds
 * exactly that benchmark's counts.  The last PVM virtual MSR, which the ABI
 * marks reserved.
 */
#define MSR_PVM_STATS_MARK		(PVM_VIRTUAL_MSR_BASE + 0xf)

/* What PVM_CPUID_FEATURES.ebx reports and MSR_PVM_FEATURES_ENABLED accepts. */
#define PVM_FEATURES_SUPPORTED		PVM_FEATURE_DIRECT_PF

enum {
	PVM_EXIT_CLASS_OTHER,
	PVM_EXIT_CLASS_PF_FIXED,	/* #PF the shadow MMU resolved */
	PVM_EXIT_CLASS_PF_REFLECT_NP,	/* #PF reflected, guest entry not present */
	PVM_EXIT_CLASS_PF_REFLECT_OTHER, /* #PF reflected for another reason */
	PVM_EXIT_CLASS_PF_DIRECT,	/* #PF delivered without the shadow MMU */
	PVM_EXIT_CLASSES
};

#ifdef CONFIG_KVM_PVM_STATS
struct pvm_stats {
	PVM_HYPERVISOR_STATS(PVM_STAT_FIELD)
	PVM_DPF_STATS(PVM_STAT_FIELD)
	struct pvm_switcher_stats sw;
	/* For hc_invlpg_seq. */
	unsigned long last_invlpg_addr;
	unsigned long last_invlpg_entry;
	/*
	 * Host time from one exit to the next entry, by what the exit was, so
	 * that the cost of an exit class can be read off a benchmark.
	 */
	u64 exit_ns[PVM_EXIT_CLASSES], exit_count[PVM_EXIT_CLASSES];
	u64 last_exit_ns;
	int last_exit_class;
	/*
	 * A #PF exit the shadow MMU fixed, in three: from the exit to
	 * kvm_handle_page_fault(), inside it, and from its return to the next
	 * entry.
	 */
	u64 pf_mmu_start_ns, pf_mmu_end_ns;
	u64 fixed_pre_ns, fixed_mmu_ns, fixed_post_ns;
	/*
	 * fixed_post_ns again, by the vcpu_enter_guest() stamps it passes, in
	 * the order they are taken (0-8, 10, 9):
	 * [0] handler return to vcpu_enter_guest(), [1] requests, [2] events,
	 * [3] kvm_mmu_reload(), [4] prepare_switch_to_guest() and irq off,
	 * [5] mode and exit-request check, [6] FPU, [7] kvm_load_xfeatures(),
	 * [8] debug registers, [9] get_debugctlmsr(), [10] PMU load,
	 * [11] to pvm_vcpu_run().
	 */
	u64 fixed_post_part_ns[12];
};
#endif

struct vcpu_pvm {
	struct kvm_vcpu vcpu;

#ifdef CONFIG_KVM_PVM_STATS
	struct pvm_stats stats;
#endif

	/* Guest RFLAGS, turned into hardware RFLAGS by the switcher. */
	unsigned long rflags;

	unsigned long switch_flags;

	/*
	 * What supervisor mode runs on when the guest uses protection keys.
	 * Zero -- every key permitted -- until PKS is emulated, at which point
	 * it becomes the guest's MSR_IA32_PKRS.  The guest's *user* PKRU is not
	 * here: it is in the hardware register while the guest is in user mode
	 * and in PVCS::pkru while it is not.
	 */
	u32 smod_pkru;

	u16 host_ds_sel, host_es_sel;
	u64 host_debugctlmsr;

	union {
		unsigned long exit_extra;
		unsigned long exit_cr2;
		unsigned long exit_dr6;
	};
	u32 exit_vector;
	u32 exit_error_code;
	u32 hw_cs, hw_ss;

	int loaded_cpu_state;
	int int_shadow;
	bool non_pvm_mode;
	/*
	 * The direct #PF run: how many user-mode #PFs in a row were delivered
	 * without the shadow MMU, by the switcher or by
	 * pvm_direct_pf_candidate(), and the page of the last one.  A user
	 * #PF that reaches kvm-pvm and is not delivered that way ends the
	 * run; so does a vCPU reset.  Nothing else does: other exits and
	 * supervisor-mode faults leave it alone, which is safe because the
	 * rule only needs every retry on the same page and every
	 * PVM_DIRECT_PF_RUN + 1st user #PF in a run to reach the MMU.
	 */
	u8 pf_direct_run;
	unsigned long pf_direct_page;
	bool nmi_mask;

	unsigned long guest_dr7;

	/*
	 * The PVCS page is pinned for as long as MSR_PVM_VCPU_STRUCT names it.
	 * The switcher dereferences tss_ex.pvcs from assembly while the vCPU is
	 * in guest mode, without a lock and without a validity check, so the
	 * page must not be migrated or freed behind its back.
	 */
	struct page *pvcs_page;
	struct pvm_vcpu_struct *pvcs;
	gfn_t pvcs_gfn;

	bool flush_hwtlb_current;
	u32 asid;
	u64 asid_generation;

	/* Emulated x86 MSRs. */
	u64 msr_lstar;
	u64 msr_syscall_mask;
	u64 msr_star;
	u64 msr_cstar;
	u64 msr_sysenter_eip;
	u64 msr_sysenter_esp;
	u64 msr_bndcfgs;
	u64 msr_kernel_gs_base;
	u64 msr_tsc_aux;
	/*
	 * Only bits masked by msr_ia32_feature_control_valid_bits can be set in
	 * msr_ia32_feature_control. FEAT_CTL_LOCKED is always included
	 * in msr_ia32_feature_control_valid_bits.
	 */
	u64 msr_ia32_feature_control;
	u64 msr_ia32_feature_control_valid_bits;

	/* PVM paravirt MSRs. */
	unsigned long msr_vcpu_struct;
	unsigned long msr_event_entry;
	unsigned long msr_retu_rip_plus2;
	/* PVM_FEATURE_* the guest has accepted; MSR_PVM_FEATURES_ENABLED. */
	u64 msr_features_enabled;

	struct kvm_segment segments[NR_VCPU_SREG];
	struct desc_ptr idt_ptr;
	struct desc_ptr gdt_ptr;
	struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];
};

static __always_inline struct vcpu_pvm *to_pvm(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_pvm, vcpu);
}

/* pmu.c */
extern struct kvm_pmu_ops pvm_pmu_ops;

#endif /* __KVM_X86_PVM_H */
