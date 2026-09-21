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

/* What PVM_CPUID_FEATURES.ebx reports and MSR_PVM_FEATURES_ENABLED accepts. */
#define PVM_FEATURES_SUPPORTED		0

struct vcpu_pvm {
	struct kvm_vcpu vcpu;

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

#endif /* __KVM_X86_PVM_H */
