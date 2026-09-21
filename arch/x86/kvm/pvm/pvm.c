// SPDX-License-Identifier: GPL-2.0-only
/*
 * Pagetable-based Virtual Machine driver for Linux
 *
 * Copyright (C) 2020 Ant Group
 * Copyright (C) 2020 Alibaba Group
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kvm_host.h>

#include "mmu.h"
#include "x86.h"
#include "cpuid.h"
#include "lapic.h"
#include "pmu.h"
#include "trace.h"
#include "pvm.h"
#include "mmu/spte.h"

#include <linux/cc_platform.h>
#include <linux/module.h>
#include <linux/entry-virt.h>

#include <asm/desc.h>
#include <asm/gsseg.h>
#include <asm/io_bitmap.h>
#include <asm/pvm_para.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/entry-common.h>

MODULE_AUTHOR("AntGroup");
MODULE_DESCRIPTION("KVM support for Pagetable-based PV Virtual Machines");
MODULE_LICENSE("GPL");

static bool __read_mostly enable_cpuid_intercept;
module_param_named(cpuid_intercept, enable_cpuid_intercept, bool, 0444);

static bool __read_mostly is_intel;

/*
 * desc.h only defines load_ldt() for !PARAVIRT_XXL, and restoring the host's
 * LDT after a guest exit is not a paravirt operation.
 */
static __always_inline void pvm_load_ldt(u16 sel)
{
	asm volatile("lldt %0" : : "rm" (sel));
}

static void pvm_unpin_vcpu_struct(struct vcpu_pvm *pvm);
static int pvm_pin_vcpu_struct(struct vcpu_pvm *pvm, gpa_t gpa);

static inline bool is_smod(struct vcpu_pvm *pvm)
{
	unsigned long switch_flags = pvm->switch_flags;

	if ((switch_flags & SWITCH_FLAGS_MOD_TOGGLE) == SWITCH_FLAGS_SMOD)
		return true;

	WARN_ON_ONCE((switch_flags & SWITCH_FLAGS_MOD_TOGGLE) != SWITCH_FLAGS_UMOD);
	return false;
}

static inline void pvm_switch_flags_toggle_mod(struct vcpu_pvm *pvm)
{
	pvm->switch_flags ^= SWITCH_FLAGS_MOD_TOGGLE;
}

/*
 * The selectors MSR_STAR describes: kernel CS in bits 47:32 with RPL 0 and
 * kernel DS after it, 32-bit user CS in bits 63:48 with RPL 3 and 64-bit user
 * CS 16 after that.
 */
static inline u16 kernel_cs_by_msr(u64 msr_star)
{
	return ((msr_star >> 32) & ~0x3);
}

static inline u16 kernel_ds_by_msr(u64 msr_star)
{
	return ((msr_star >> 32) & ~0x3) + 8;
}

static inline u16 user_cs_by_msr(u64 msr_star)
{
	return ((msr_star >> 48) | 0x3) + 16;
}

/*
 * The switcher does a real SWAPGS on entry, so while the guest state is loaded
 * the guest's GS base is in the hardware MSR_KERNEL_GS_BASE.
 */
static inline void __save_gs_base(struct vcpu_pvm *pvm)
{
	rdmsrq(MSR_KERNEL_GS_BASE, pvm->segments[VCPU_SREG_GS].base);
}

static inline void __load_gs_base(struct vcpu_pvm *pvm)
{
	wrmsrq(MSR_KERNEL_GS_BASE, pvm->segments[VCPU_SREG_GS].base);
}

static inline void __save_fs_base(struct vcpu_pvm *pvm)
{
	rdmsrq(MSR_FS_BASE, pvm->segments[VCPU_SREG_FS].base);
}

static inline void __load_fs_base(struct vcpu_pvm *pvm)
{
	wrmsrq(MSR_FS_BASE, pvm->segments[VCPU_SREG_FS].base);
}

static u64 pvm_read_guest_gs_base(struct vcpu_pvm *pvm)
{
	preempt_disable();
	if (pvm->loaded_cpu_state)
		__save_gs_base(pvm);
	preempt_enable();

	return pvm->segments[VCPU_SREG_GS].base;
}

static u64 pvm_read_guest_fs_base(struct vcpu_pvm *pvm)
{
	preempt_disable();
	if (pvm->loaded_cpu_state)
		__save_fs_base(pvm);
	preempt_enable();

	return pvm->segments[VCPU_SREG_FS].base;
}

static u64 pvm_read_guest_kernel_gs_base(struct vcpu_pvm *pvm)
{
	return pvm->msr_kernel_gs_base;
}

/*
 * The GS base the guest runs with is written to the hardware, which faults on
 * a non-canonical value.  Some of the values come straight from the guest --
 * PVCS::user_gsbase on the ERETU hypercall -- so canonicalize them at the
 * host's address width, as the switcher does on its own ERETU path.
 */
static void pvm_write_guest_gs_base(struct vcpu_pvm *pvm, u64 data)
{
	data = __canonical_address(data, cpu_feature_enabled(X86_FEATURE_LA57) ?
				   57 : 48);

	preempt_disable();
	pvm->segments[VCPU_SREG_GS].base = data;
	if (pvm->loaded_cpu_state)
		__load_gs_base(pvm);
	preempt_enable();
}

static void pvm_write_guest_fs_base(struct vcpu_pvm *pvm, u64 data)
{
	preempt_disable();
	pvm->segments[VCPU_SREG_FS].base = data;
	if (pvm->loaded_cpu_state)
		__load_fs_base(pvm);
	preempt_enable();
}

static void pvm_write_guest_kernel_gs_base(struct vcpu_pvm *pvm, u64 data)
{
	pvm->msr_kernel_gs_base = data;
}

/*
 * Whether the guest has turned protection keys on.  The guest runs at CPL3 on
 * the host's own CR4.PKE, so the hardware applies PKRU whatever the guest was
 * told; this is about whether the guest's *architectural* keys are in play,
 * which is what decides who owns PKRU while the guest runs.
 */
static inline bool pvm_guest_uses_pku(struct kvm_vcpu *vcpu)
{
	return cpu_feature_enabled(X86_FEATURE_PKU) &&
	       ((vcpu->arch.xcr0 & XFEATURE_MASK_PKRU) ||
		kvm_is_cr4_bit_set(vcpu, X86_CR4_PKE));
}

/*
 * A PVM guest lives in the lower half and nothing else.  The
 * upper half is the host's, which is what lets the guest run at hardware CPL3
 * inside it, so the guest's confinement is the sign bit -- the same test the
 * hardware applies to a CPL3 process, and nothing the hypervisor has to grant,
 * encode or re-derive.
 */
static __always_inline bool pvm_guest_allowed_va(struct kvm_vcpu *vcpu, u64 va)
{
	return (s64)va >= 0;
}

static bool pvm_disallowed_va(struct kvm_vcpu *vcpu, u64 va)
{
	if (is_noncanonical_address(va, vcpu, 0))
		return true;

	return !pvm_guest_allowed_va(vcpu, va);
}

/*
 * A guest code address the hypervisor or the switcher acts on: the entry
 * points in MSR_LSTAR and MSR_PVM_EVENT_ENTRY, and the ERETU instruction in
 * MSR_PVM_RETU_RIP.  Canonical is not enough, the guest owns only the lower
 * half: an entry point in the upper half faults on the host's pages, and the
 * fault is delivered to that same entry point, forever.
 */
static bool pvm_invalid_entry_point(struct kvm_vcpu *vcpu, u64 addr)
{
	return is_noncanonical_msr_address(addr, vcpu) ||
	       !pvm_guest_allowed_va(vcpu, addr);
}

static void __set_cpuid_faulting(bool on)
{
	u64 msrval;

	rdmsrq_safe(MSR_MISC_FEATURES_ENABLES, &msrval);
	msrval &= ~MSR_MISC_FEATURES_ENABLES_CPUID_FAULT;
	msrval |= (on << MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT);
	wrmsrq(MSR_MISC_FEATURES_ENABLES, msrval);
}

static void reset_cpuid_intercept(struct kvm_vcpu *vcpu)
{
	if (test_thread_flag(TIF_NOCPUID))
		return;

	if (enable_cpuid_intercept || cpuid_fault_enabled(vcpu))
		__set_cpuid_faulting(false);
}

static void set_cpuid_intercept(struct kvm_vcpu *vcpu)
{
	if (test_thread_flag(TIF_NOCPUID))
		return;

	if (enable_cpuid_intercept || cpuid_fault_enabled(vcpu))
		__set_cpuid_faulting(true);
}

static void pvm_update_guest_cpuid_faulting(struct kvm_vcpu *vcpu, u64 data)
{
	bool guest_enabled = cpuid_fault_enabled(vcpu);
	bool set_enabled = data & MSR_MISC_FEATURES_ENABLES_CPUID_FAULT;
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (!(guest_enabled ^ set_enabled))
		return;
	if (enable_cpuid_intercept)
		return;
	if (test_thread_flag(TIF_NOCPUID))
		return;

	preempt_disable();
	if (pvm->loaded_cpu_state)
		__set_cpuid_faulting(set_enabled);
	preempt_enable();
}

/*
 * Non-PVM mode is everything before the guest reaches 64-bit PVM mode: the
 * firmware or boot stub of the boot vCPU and the startup code of the others.
 * It is not part of the PVM ABI and is only emulated, until the guest's
 * state allows converting it to PVM mode.
 */
#define CONVERT_TO_PVM_CR0_OFF	(X86_CR0_NW | X86_CR0_CD)
#define CONVERT_TO_PVM_CR0_ON	(X86_CR0_NE | X86_CR0_AM | X86_CR0_WP | \
				 X86_CR0_PG | X86_CR0_PE)

static inline void pvm_standard_msr_star(struct vcpu_pvm *pvm)
{
	pvm->msr_star = ((u64)pvm->segments[VCPU_SREG_CS].selector << 32) |
			((u64)__USER32_CS << 48);
}

static bool try_to_convert_to_pvm_mode(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long cr0 = vcpu->arch.cr0;

	if (!is_long_mode(vcpu))
		return false;
	if (!pvm->segments[VCPU_SREG_CS].l) {
		if (is_smod(pvm))
			return false;
		if (!pvm->segments[VCPU_SREG_CS].db)
			return false;
	}

	/* Atomically set EFER_SCE converting to PVM mode. */
	if ((vcpu->arch.efer | EFER_SCE) != vcpu->arch.efer)
		vcpu->arch.efer |= EFER_SCE;

	/* Change CR0 on converting to PVM mode. */
	cr0 &= ~CONVERT_TO_PVM_CR0_OFF;
	cr0 |= CONVERT_TO_PVM_CR0_ON;
	if (cr0 != vcpu->arch.cr0)
		kvm_set_cr0(vcpu, cr0);

	/*
	 * Atomically set MSR_STAR when switching to PVM mode if the guest is
	 * in supervisor mode. In the case of user mode, the MSR_STAR should be
	 * set using MSR setting during the VM migration.
	 */
	if (is_smod(pvm))
		pvm_standard_msr_star(pvm);

	pvm->non_pvm_mode = false;
	pvm->int_shadow = 0;
	pvm->nmi_mask = 0;

	return true;
}

/*
 * How many instructions to emulate before going back to vcpu_run() to look at
 * requests and pending work; the same batch VMX's handle_invalid_guest_state()
 * uses.
 */
#define PVM_NON_PVM_EMULATION_BATCH	130

static int handle_non_pvm_mode(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned int count = PVM_NON_PVM_EMULATION_BATCH;
	int ret = 1;

	if (try_to_convert_to_pvm_mode(vcpu))
		return 1;

	while (pvm->non_pvm_mode && count-- != 0) {
		if (kvm_test_request(KVM_REQ_EVENT, vcpu))
			return 1;

		if (try_to_convert_to_pvm_mode(vcpu))
			return 1;

		ret = kvm_emulate_instruction(vcpu, 0);

		if (!ret)
			goto out;

		/* don't do mode switch in emulation */
		if (!is_smod(pvm))
			goto emulation_error;

		if (vcpu->arch.exception.pending)
			goto emulation_error;

		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			ret = kvm_emulate_halt_noskip(vcpu);
			goto out;
		}
		/*
		 * Note, return 1 and not 0, vcpu_run() will invoke
		 * xfer_to_guest_mode() which will create a proper return
		 * code.
		 */
		if (__xfer_to_guest_mode_work_pending())
			return 1;
	}

out:
	return ret;

emulation_error:
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
	vcpu->run->internal.ndata = 0;
	return 0;
}

/*
 * switch_to_smod() and switch_to_umod() switch the mode (smod/umod) and the
 * CR3.  No vTLB flushing when switching the CR3 per PVM Spec.
 *
 * ACC_USER_MASK in the root role is the whole of the guest's kernel/user
 * split.  The two roots share a guest CR3 and are told apart by this bit
 * alone, which is why nothing may merge shadow pages whose role.access
 * differs in it.  kvm_mmu_find_shadow_page() compares the whole role.word,
 * so that holds by construction.  Sharing non-leaf shadow pages between the
 * two roots is not an optimisation to make: most of the tree below them is
 * identical, but sharing it fuses the trees this bit separates, which is
 * what emulating SMEP with NX depends on.
 */
static inline void switch_to_smod(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm_switch_flags_toggle_mod(pvm);
	kvm_mmu_role_set_user(&vcpu->arch.mmu->root_role, false);
	kvm_mmu_new_pgd(vcpu, vcpu->arch.cr3);

	pvm_write_guest_gs_base(pvm, pvm->msr_kernel_gs_base);

	pvm->hw_cs = __USER_CS;
	pvm->hw_ss = __USER_DS;
}

static inline void switch_to_umod(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm_switch_flags_toggle_mod(pvm);
	kvm_mmu_role_set_user(&vcpu->arch.mmu->root_role, true);
	kvm_mmu_new_pgd(vcpu, vcpu->arch.cr3);
}

/*
 * Test whether DS, ES, FS and GS need to be reloaded.
 *
 * Reading them only returns the selectors, but writing them (if
 * nonzero) loads the full descriptor from the GDT or LDT.
 *
 * We therefore need to write new values to the segment registers
 * on every host-guest state switch unless both the new and old
 * values are zero.
 */
static inline bool need_reload_sel(u16 sel1, u16 sel2)
{
	return unlikely(sel1 | sel2);
}

/*
 * Save host DS/ES/FS/GS selector, FS base, and inactive GS base.
 * And load guest DS/ES/FS/GS selector, FS base, and GS base.
 *
 * Note, when the guest state is loaded and it is in hypervisor, the guest
 * GS base is loaded in the hardware MSR_KERNEL_GS_BASE which is loaded
 * with host inactive GS base when the guest state is NOT loaded.
 */
static void segments_save_host_and_switch_to_guest(struct vcpu_pvm *pvm)
{
	u16 pvm_ds_sel, pvm_es_sel, pvm_fs_sel, pvm_gs_sel;

	/* Save host segments */
	savesegment(ds, pvm->host_ds_sel);
	savesegment(es, pvm->host_es_sel);
	current_save_fsgs();

	/* Load guest segments */
	pvm_ds_sel = pvm->segments[VCPU_SREG_DS].selector;
	pvm_es_sel = pvm->segments[VCPU_SREG_ES].selector;
	pvm_fs_sel = pvm->segments[VCPU_SREG_FS].selector;
	pvm_gs_sel = pvm->segments[VCPU_SREG_GS].selector;

	if (need_reload_sel(pvm_ds_sel, pvm->host_ds_sel))
		loadsegment(ds, pvm_ds_sel);
	if (need_reload_sel(pvm_es_sel, pvm->host_es_sel))
		loadsegment(es, pvm_es_sel);
	if (need_reload_sel(pvm_fs_sel, current->thread.fsindex))
		loadsegment(fs, pvm_fs_sel);
	if (need_reload_sel(pvm_gs_sel, current->thread.gsindex))
		load_gs_index(pvm_gs_sel);

	__load_gs_base(pvm);
	__load_fs_base(pvm);
}

/*
 * Save guest DS/ES/FS/GS selector, FS base, and GS base.
 * And load host DS/ES/FS/GS selector, FS base, and inactive GS base.
 */
static void segments_save_guest_and_switch_to_host(struct vcpu_pvm *pvm)
{
	u16 pvm_ds_sel, pvm_es_sel, pvm_fs_sel, pvm_gs_sel;

	/* Save guest segments */
	savesegment(ds, pvm_ds_sel);
	savesegment(es, pvm_es_sel);
	savesegment(fs, pvm_fs_sel);
	savesegment(gs, pvm_gs_sel);
	pvm->segments[VCPU_SREG_DS].selector = pvm_ds_sel;
	pvm->segments[VCPU_SREG_ES].selector = pvm_es_sel;
	pvm->segments[VCPU_SREG_FS].selector = pvm_fs_sel;
	pvm->segments[VCPU_SREG_GS].selector = pvm_gs_sel;

	__save_fs_base(pvm);
	__save_gs_base(pvm);

	/* Load host segments */
	if (need_reload_sel(pvm_ds_sel, pvm->host_ds_sel))
		loadsegment(ds, pvm->host_ds_sel);
	if (need_reload_sel(pvm_es_sel, pvm->host_es_sel))
		loadsegment(es, pvm->host_es_sel);
	if (need_reload_sel(pvm_fs_sel, current->thread.fsindex))
		loadsegment(fs, current->thread.fsindex);
	if (need_reload_sel(pvm_gs_sel, current->thread.gsindex))
		load_gs_index(current->thread.gsindex);

	wrmsrq(MSR_KERNEL_GS_BASE, current->thread.gsbase);
	wrmsrq(MSR_FS_BASE, current->thread.fsbase);
}

/*
 * Load guest TLS entries into the GDT.
 */
static inline void host_gdt_set_tls(struct vcpu_pvm *pvm)
{
	struct desc_struct *gdt = get_current_gdt_rw();
	unsigned int i;

	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++)
		gdt[GDT_ENTRY_TLS_MIN + i] = pvm->tls_array[i];
}

static void pvm_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->loaded_cpu_state)
		return;

	/* Non-PVM mode is emulated and has no hardware state to load. */
	if (unlikely(pvm->non_pvm_mode))
		return;

	pvm->loaded_cpu_state = 1;

#ifdef CONFIG_X86_IOPL_IOPERM
	/*
	 * PVM doesn't load guest I/O bitmap into hardware.  Invalidate I/O
	 * bitmap if the current task is using it.  This prevents any possible
	 * leakage of an active I/O bitmap to the guest and forces I/O
	 * instructions in guest to be trapped and emulated.
	 *
	 * The I/O bitmap will be restored when the current task exits to
	 * user mode in arch_exit_to_user_mode_prepare().
	 */
	if (test_thread_flag(TIF_IO_BITMAP))
		native_tss_invalidate_io_bitmap();
#endif

	host_gdt_set_tls(pvm);

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	/* PVM doesn't support LDT. */
	if (unlikely(current->mm->context.ldt))
		clear_LDT();
#endif

	segments_save_host_and_switch_to_guest(pvm);

	set_cpuid_intercept(vcpu);

	kvm_set_user_return_msr(0, (u64)entry_SYSCALL_64_switcher, -1ull);
	kvm_set_user_return_msr(1, pvm->msr_tsc_aux, -1ull);
	if (ia32_enabled()) {
		if (is_intel)
			kvm_set_user_return_msr(2, GDT_ENTRY_INVALID_SEG, -1ull);
		else
			kvm_set_user_return_msr(2, (u64)entry_SYSCALL32_ignore, -1ull);
	}
}

static void pvm_prepare_switch_to_host(struct vcpu_pvm *pvm)
{
	if (!pvm->loaded_cpu_state)
		return;

	++pvm->vcpu.stat.host_state_reload;

	reset_cpuid_intercept(&pvm->vcpu);

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	if (unlikely(current->mm->context.ldt)) {
		unsigned short sel = GDT_ENTRY_LDT * 8;

		pvm_load_ldt(sel);
	}
#endif

	/* Put the current task's TLS back into the GDT. */
	native_load_tls(&current->thread, smp_processor_id());

	segments_save_guest_and_switch_to_host(pvm);
	pvm->loaded_cpu_state = 0;
}

/*
 * Set all hardware states back to host.
 * Except user return MSRs.
 */
static void pvm_switch_to_host(struct vcpu_pvm *pvm)
{
	preempt_disable();
	pvm_prepare_switch_to_host(pvm);
	preempt_enable();
}

struct pvm_asid_data {
	u64 asid_generation;
	u32 max_asid;
	u32 next_asid;
	u32 min_asid;
};

static DEFINE_PER_CPU(struct pvm_asid_data, pvm_asid);

static bool is_asid_clean(struct vcpu_pvm *pvm)
{
	struct pvm_asid_data *asid_data = this_cpu_ptr(&pvm_asid);

	return pvm->asid_generation == asid_data->asid_generation;
}

static inline u32 guest_pcid_to_host_pcid(struct vcpu_pvm *pvm, u32 guest_pcid, bool is_smod)
{
	u32 pcid;

	if (guest_pcid & ~PVM_GUEST_PCID_MASK)
		guest_pcid = 0;
	pcid = (pvm->asid << PVM_ASID_SHIFT) | (guest_pcid & PVM_GUEST_PCID_MASK);
	if (!is_smod)
		pcid |= PVM_UMOD_PCID_MASK;

	return pcid;
}

static void pvm_flush_hwtlb(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm->asid_generation = PVM_ASID_GEN_RESERVED;
}

static void pvm_flush_hwtlb_current(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm->flush_hwtlb_current = true;
}

/*
 * Flush @addr from the host PCID a cached root runs on.  The mode of a root is
 * role.access, not role.word: ACC_USER_MASK is an access bit.
 */
static void pvm_flush_hwtlb_root_gva(struct vcpu_pvm *pvm,
				     struct kvm_mmu_root_info *root, gva_t addr)
{
	u32 pcid;
	bool smod;

	if (!VALID_PAGE(root->hpa))
		return;

	pcid = kvm_get_pcid(&pvm->vcpu, root->pgd);
	smod = !(root_to_sp(root->hpa)->role.access & ACC_USER_MASK);
	invpcid_flush_one(guest_pcid_to_host_pcid(pvm, pcid, smod), addr);
}

/*
 * PVM_HC_TLB_INVLPG is for every tag, so the current root and every cached
 * root, both halves of each pair: the guest may switch mode without an exit.
 */
static void pvm_flush_hwtlb_gva(struct kvm_vcpu *vcpu, gva_t addr, bool *full)
{
	struct kvm_mmu *mmu = vcpu->arch.mmu;
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int i;

	get_cpu();
	if (!is_asid_clean(pvm)) {
		put_cpu();
		return;
	}

	pvm_flush_hwtlb_root_gva(pvm, &mmu->root, addr);
	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
		pvm_flush_hwtlb_root_gva(pvm, &mmu->prev_roots[i], addr);

	put_cpu();
}

static void pvm_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa,
			     int root_level)
{
	/* Nothing to do. Guest cr3 will be prepared in pvm_set_host_cr3(). */
}

static DEFINE_PER_CPU(struct vcpu_pvm *, active_pvm_vcpu);

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void pvm_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm->host_debugctlmsr = get_debugctlmsr();

	if (__this_cpu_read(active_pvm_vcpu) == pvm && vcpu->cpu == cpu)
		return;

	__this_cpu_write(active_pvm_vcpu, pvm);

	if (vcpu->cpu != cpu)
		pvm_flush_hwtlb(vcpu);

	indirect_branch_prediction_barrier();
}

static void pvm_vcpu_put(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm_prepare_switch_to_host(pvm);
}

static void pvm_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/* KVM_X86_QUIRK_FIX_HYPERCALL_INSN should not be enabled for pvm guest */

	/* ud2; int3; */
	hypercall[0] = 0x0F;
	hypercall[1] = 0x0B;
	hypercall[2] = 0xCC;
}

static int pvm_check_emulate_instruction(struct kvm_vcpu *vcpu, int emul_type,
					 void *insn, int insn_len)
{
	return X86EMUL_CONTINUE;
}

static int pvm_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_instruction(vcpu, EMULTYPE_SKIP);
}

static int pvm_check_intercept(struct kvm_vcpu *vcpu,
			       struct x86_instruction_info *info,
			       enum x86_intercept_stage stage,
			       struct x86_exception *exception)
{
	/*
	 * HF_GUEST_MASK is not used even nested pvm is supported. L0 pvm
	 * might even be unaware the L1 pvm.
	 */
	WARN_ON_ONCE(1);
	return X86EMUL_CONTINUE;
}

static u64 pvm_get_l2_tsc_offset(struct kvm_vcpu *vcpu)
{
	return 0;
}

static u64 pvm_get_l2_tsc_multiplier(struct kvm_vcpu *vcpu)
{
	return kvm_caps.default_tsc_scaling_ratio;
}

/*
 * The guest's TSC is the host's TSC.  RDTSC and RDTSCP run natively at CPL3,
 * where the hardware applies no offset and no scaling, so whatever offset KVM
 * computes -- from a TSC write, TSC_ADJUST, vCPU creation or a restore -- is
 * dropped here, and kvmclock is computed against the host TSC the guest reads.
 * KVM keeps its own bookkeeping of the offsets, which is what keeps vCPUs
 * created together "matched" for the master clock.
 *
 * The frequency cannot differ either: pvm_vcpu_create() refuses a VM-wide
 * frequency that is not the host's and pvm_handle_exit() a vCPU one.
 */
static void pvm_write_tsc_offset(struct kvm_vcpu *vcpu)
{
	vcpu->arch.tsc_offset = 0;
	vcpu->arch.l1_tsc_offset = 0;
}

/* Never called: PVM does not set kvm_caps.has_tsc_control. */
static void pvm_write_tsc_multiplier(struct kvm_vcpu *vcpu)
{
}

static int pvm_get_feature_msr(u32 msr, u64 *data)
{
	/* PVM exposes no feature MSRs. */
	return 1;
}

static inline bool is_pvm_feature_control_msr_valid(struct vcpu_pvm *pvm,
						    struct msr_data *msr_info)
{
	/*
	 * currently only FEAT_CTL_LOCKED bit is valid, maybe
	 * vmx, sgx and mce associated bits can be valid when those features
	 * are supported for guest.
	 */
	u64 valid_bits = pvm->msr_ia32_feature_control_valid_bits;

	if (!msr_info->host_initiated &&
	    (pvm->msr_ia32_feature_control & FEAT_CTL_LOCKED))
		return false;

	return !(msr_info->data & ~valid_bits);
}

static void pvm_update_uret_msr(struct vcpu_pvm *pvm, unsigned int slot,
				u64 data, u64 mask)
{
	preempt_disable();
	if (pvm->loaded_cpu_state)
		kvm_set_user_return_msr(slot, data, mask);
	preempt_enable();
}

/*
 * Reads an msr value (of 'msr_index') into 'msr_info'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int pvm_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int ret = 0;

	switch (msr_info->index) {
	case MSR_FS_BASE:
		msr_info->data = pvm_read_guest_fs_base(pvm);
		break;
	case MSR_GS_BASE:
		msr_info->data = pvm_read_guest_gs_base(pvm);
		break;
	case MSR_KERNEL_GS_BASE:
		msr_info->data = pvm_read_guest_kernel_gs_base(pvm);
		break;
	case MSR_STAR:
		msr_info->data = pvm->msr_star;
		break;
	case MSR_LSTAR:
		msr_info->data = pvm->msr_lstar;
		break;
	case MSR_SYSCALL_MASK:
		msr_info->data = pvm->msr_syscall_mask;
		break;
	case MSR_CSTAR:
		msr_info->data = pvm->msr_cstar;
		break;
	/*
	 * Since SYSENTER is not supported for the guest, we return a bad
	 * segment to the emulator when emulating the instruction for #GP.
	 */
	case MSR_IA32_SYSENTER_CS:
		msr_info->data = GDT_ENTRY_INVALID_SEG;
		break;
	case MSR_IA32_SYSENTER_EIP:
		msr_info->data = pvm->msr_sysenter_eip;
		break;
	case MSR_IA32_SYSENTER_ESP:
		msr_info->data = pvm->msr_sysenter_esp;
		break;
	case MSR_TSC_AUX:
		msr_info->data = pvm->msr_tsc_aux;
		break;
	case MSR_IA32_DEBUGCTLMSR:
		msr_info->data = 0;
		break;
	case MSR_IA32_FEAT_CTL:
		msr_info->data = pvm->msr_ia32_feature_control;
		break;
	case MSR_IA32_BNDCFGS:
		msr_info->data = pvm->msr_bndcfgs;
		break;
	case MSR_PVM_VCPU_STRUCT:
		msr_info->data = pvm->msr_vcpu_struct;
		break;
	case MSR_PVM_EVENT_ENTRY:
		msr_info->data = pvm->msr_event_entry;
		break;
	case MSR_PVM_RETU_RIP:
		msr_info->data = pvm->msr_retu_rip_plus2 ?
				 pvm->msr_retu_rip_plus2 - 2 : 0;
		break;
	case MSR_PVM_FEATURES_ENABLED:
		msr_info->data = pvm->msr_features_enabled;
		break;
	default:
		ret = kvm_get_msr_common(vcpu, msr_info);
	}

	return ret;
}

/*
 * Writes msr value into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int pvm_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int ret = 0;
	u32 msr_index = msr_info->index;
	u64 data = msr_info->data;

	switch (msr_index) {
	case MSR_FS_BASE:
		pvm_write_guest_fs_base(pvm, data);
		break;
	case MSR_GS_BASE:
		pvm_write_guest_gs_base(pvm, data);
		break;
	case MSR_KERNEL_GS_BASE:
		pvm_write_guest_kernel_gs_base(pvm, data);
		break;
	case MSR_STAR:
		/*
		 * Guest KERNEL_CS/DS shouldn't be NULL and guest USER_CS/DS
		 * must be the same as the host USER_CS/DS.
		 */
		if (!msr_info->host_initiated) {
			if (!kernel_cs_by_msr(data))
				return 1;
			if (user_cs_by_msr(data) != __USER_CS)
				return 1;
		}
		pvm->msr_star = data;
		break;
	case MSR_LSTAR:
		if (pvm_invalid_entry_point(vcpu, data))
			return 1;
		pvm->msr_lstar = data;
		break;
	case MSR_SYSCALL_MASK:
		pvm->msr_syscall_mask = data;
		break;
	case MSR_CSTAR:
		pvm->msr_cstar = data;
		break;
	case MSR_IA32_SYSENTER_CS:
		/* Not kept: reads return GDT_ENTRY_INVALID_SEG, see pvm_get_msr(). */
		break;
	case MSR_IA32_SYSENTER_EIP:
		pvm->msr_sysenter_eip = data;
		break;
	case MSR_IA32_SYSENTER_ESP:
		pvm->msr_sysenter_esp = data;
		break;
	case MSR_TSC_AUX:
		pvm->msr_tsc_aux = data;
		pvm_update_uret_msr(pvm, 1, data, -1ull);
		break;
	case MSR_IA32_DEBUGCTLMSR:
		/*
		 * Neither LBR nor BTF can be given to a guest at CPL3, and the
		 * guest cannot be told so.  Like kvm-amd without LBR
		 * virtualization, drop the write and read back 0.
		 */
		if (data)
			kvm_pr_unimpl_wrmsr(vcpu, msr_index, data);
		break;
	case MSR_IA32_FEAT_CTL:
		if (!is_intel || !is_pvm_feature_control_msr_valid(pvm, msr_info))
			return 1;
		pvm->msr_ia32_feature_control = data;
		break;
	case MSR_MISC_FEATURES_ENABLES:
		ret = kvm_set_msr_common(vcpu, msr_info);
		if (!ret)
			pvm_update_guest_cpuid_faulting(vcpu, data);
		break;
	case MSR_PLATFORM_INFO:
		if ((data & MSR_PLATFORM_INFO_CPUID_FAULT) &&
		    !boot_cpu_has(X86_FEATURE_CPUID_FAULT))
			return 1;
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
	case MSR_IA32_BNDCFGS:
		if (!kvm_mpx_supported() ||
		    (!msr_info->host_initiated &&
		     !guest_cpu_cap_has(vcpu, X86_FEATURE_MPX)))
			return 1;
		if (is_noncanonical_msr_address(data & PAGE_MASK, vcpu) ||
		    (data & MSR_IA32_BNDCFGS_RSVD))
			return 1;
		/*
		 * As the full MPX feature function has been deprecated in the
		 * Linux kernel, it is acceptable to ignore supervisor mode MPX
		 * control for simplicity.
		 */
		pvm->msr_bndcfgs = data;
		break;
	case MSR_PVM_VCPU_STRUCT:
		if (!PAGE_ALIGNED(data))
			return 1;
		/*
		 * A VMM restoring a VM may set this before the memslot holding
		 * the page exists.  So a failed pin does not fail the write: it
		 * is retried by KVM_REQ_PINNED_PAGES_RELOAD before the next entry,
		 * which triple faults the vCPU if the page is still not there.
		 */
		pvm->msr_vcpu_struct = data;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		if (!data) {
			pvm->switch_flags |= SWITCH_FLAGS_PVCS_INVALID;
			pvm_unpin_vcpu_struct(pvm);
		} else {
			/*
			 * Even if the pin fails: the retry either pins it
			 * before the next entry or triple faults the vCPU.
			 */
			pvm->switch_flags &= ~SWITCH_FLAGS_PVCS_INVALID;
			if (pvm_pin_vcpu_struct(pvm, data))
				kvm_make_request(KVM_REQ_PINNED_PAGES_RELOAD, vcpu);
		}
		break;
	case MSR_PVM_EVENT_ENTRY:
		/* The three entry points are at +0, +256 and +PVM_EVENT_ENTRY_SUPERVISOR_OFFSET. */
		if (pvm_invalid_entry_point(vcpu, data) ||
		    pvm_invalid_entry_point(vcpu, data + 256) ||
		    pvm_invalid_entry_point(vcpu, data + PVM_EVENT_ENTRY_SUPERVISOR_OFFSET)) {
			/*
			 * A guest without an event entry cannot take the #GP
			 * that would report this.
			 */
			if (!msr_info->host_initiated)
				kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
			return 1;
		}
		pvm->msr_event_entry = data;
		break;
	case MSR_PVM_RETU_RIP:
		if (pvm_invalid_entry_point(vcpu, data))
			return 1;
		/*
		 * 0, the reset value, names no ERETU instruction and reads
		 * back as 0: a SYSCALL in the guest's half never leaves RIP 0.
		 */
		pvm->msr_retu_rip_plus2 = data ? data + 2 : 0;
		break;
	case MSR_PVM_FEATURES_ENABLED:
		/* Only what PVM_CPUID_FEATURES said is there. */
		if (data & ~PVM_FEATURES_SUPPORTED)
			return 1;
		pvm->msr_features_enabled = data;
		break;
	default:
		ret = kvm_set_msr_common(vcpu, msr_info);
	}

	return ret;
}

static void pvm_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	/* Nothing to do */
}

static int pvm_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	vcpu->arch.efer = efer;

	return 0;
}

static bool pvm_is_valid_cr0(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	return true;
}

static void pvm_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	if (vcpu->arch.efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG))
			vcpu->arch.efer |= EFER_LMA;

		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG))
			vcpu->arch.efer &= ~EFER_LMA;
	}

	vcpu->arch.cr0 = cr0;
}

static bool pvm_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	return true;
}

static void pvm_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long old_cr4 = vcpu->arch.cr4;

	vcpu->arch.cr4 = cr4;

	if ((cr4 ^ old_cr4) & (X86_CR4_OSXSAVE | X86_CR4_PKE))
		vcpu->arch.cpuid_dynamic_bits_dirty = true;
}

static void pvm_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->non_pvm_mode) {
		*var = pvm->segments[seg];
		return;
	}

	/* Update CS or SS to reflect the current mode. */
	if (seg == VCPU_SREG_CS) {
		if (is_smod(pvm)) {
			pvm->segments[seg].selector = kernel_cs_by_msr(pvm->msr_star);
			pvm->segments[seg].dpl = 0;
			pvm->segments[seg].l = 1;
			pvm->segments[seg].db = 0;
		} else {
			/*
			 * The underlying selector itself, as the spec says
			 * user mode CS is, and as every other vendor puts in
			 * kvm_segment::selector.  It already carries RPL 3.
			 */
			pvm->segments[seg].selector = pvm->hw_cs;
			pvm->segments[seg].dpl = 3;
			if (pvm->hw_cs == __USER_CS) {
				pvm->segments[seg].l = 1;
				pvm->segments[seg].db = 0;
			} else {
				/* __USER32_CS */
				pvm->segments[seg].l = 0;
				pvm->segments[seg].db = 1;
			}
		}
	} else if (seg == VCPU_SREG_SS) {
		if (is_smod(pvm)) {
			pvm->segments[seg].dpl = 0;
			pvm->segments[seg].selector = kernel_ds_by_msr(pvm->msr_star);
		} else {
			pvm->segments[seg].dpl = 3;
			pvm->segments[seg].selector = pvm->hw_ss;
		}
	}

	/* Update DS/ES/FS/GS from the hardware when the guest state is loaded. */
	pvm_switch_to_host(pvm);
	*var = pvm->segments[seg];
}

static u64 pvm_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;

	pvm_get_segment(vcpu, &var, seg);
	return var.base;
}

static int pvm_get_cpl(struct kvm_vcpu *vcpu)
{
	if (is_smod(to_pvm(vcpu)))
		return 0;
	return 3;
}

static void pvm_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int cpl = pvm_get_cpl(vcpu);

	/*
	 * Unload DS/ES/FS/GS from the hardware before changing them, which
	 * also covers leaving PVM mode.
	 */
	pvm_switch_to_host(pvm);
	pvm->segments[seg] = *var;

	switch (seg) {
	case VCPU_SREG_CS:
		if (var->dpl == 1 || var->dpl == 2)
			goto invalid_change;
		if (kvm_can_set_cpuid_and_feature_msrs(vcpu)) {
			/*
			 * The CPL may only change while the vCPU is being set up,
			 * i.e. restored by a migration.
			 */
			if (cpl != var->dpl)
				pvm_switch_flags_toggle_mod(pvm);
		} else {
			if (cpl != var->dpl)
				goto invalid_change;
			if (cpl == 0 && !var->l)
				pvm->non_pvm_mode = true;
			if (cpl == 0 && !pvm->non_pvm_mode)
				pvm_standard_msr_star(pvm);
		}
		if (pvm->non_pvm_mode)
			try_to_convert_to_pvm_mode(vcpu);
		/*
		 * In user mode the guest's CS is the underlying selector, so
		 * this is where a restore puts it back.  In supervisor mode it
		 * is emulated from MSR_STAR and the underlying CS must stay
		 * __USER_CS -- pvm_vcpu_run() triple faults a vCPU that comes
		 * back from the guest in supervisor mode with anything else --
		 * so nothing is written there.  var->dpl rather than cpl,
		 * because the mode may have just been toggled above.
		 */
		if (!pvm->non_pvm_mode && var->dpl == 3)
			pvm->hw_cs = var->selector | USER_RPL;
		break;
	case VCPU_SREG_SS:
		/* The other half of the same thing. */
		if (!pvm->non_pvm_mode && var->dpl == 3)
			pvm->hw_ss = var->selector | USER_RPL;
		break;
	case VCPU_SREG_LDTR:
		/* PVM does not support an LDT. */
		if (var->selector)
			goto invalid_change;
		break;
	default:
		break;
	}

	return;

invalid_change:
	kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
}

static void pvm_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->non_pvm_mode) {
		*db = pvm->segments[VCPU_SREG_CS].db;
		*l = pvm->segments[VCPU_SREG_CS].l;
	} else {
		if (pvm->hw_cs == __USER_CS) {
			*db = 0;
			*l = 1;
		} else {
			*db = 1;
			*l = 0;
		}
	}
}

static void pvm_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	*dt = to_pvm(vcpu)->idt_ptr;
}

static void pvm_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	to_pvm(vcpu)->idt_ptr = *dt;
}

static void pvm_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	*dt = to_pvm(vcpu)->gdt_ptr;
}

static void pvm_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	to_pvm(vcpu)->gdt_ptr = *dt;
}

static void pvm_deliver_interrupt(struct kvm_lapic *apic, int delivery_mode,
				  int trig_mode, int vector)
{
	struct kvm_vcpu *vcpu = apic->vcpu;

	kvm_lapic_set_irr(vector, apic);
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	kvm_vcpu_kick(vcpu);
}

static void pvm_refresh_apicv_exec_ctrl(struct kvm_vcpu *vcpu)
{
}

static bool pvm_apic_init_signal_blocked(struct kvm_vcpu *vcpu)
{
	return false;
}

static void pvm_update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	/* disable direct switch when single step debugging */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		to_pvm(vcpu)->switch_flags |= SWITCH_FLAGS_SINGLE_STEP;
	else
		to_pvm(vcpu)->switch_flags &= ~SWITCH_FLAGS_SINGLE_STEP;
}

static void pvm_unpin_vcpu_struct(struct vcpu_pvm *pvm)
{
	if (!pvm->pvcs_page)
		return;

	unpin_user_page(pvm->pvcs_page);
	pvm->pvcs_page = NULL;
	pvm->pvcs = NULL;
}

/*
 * Pin the guest page backing @gpa and keep a kernel mapping of the PVCS.
 *
 * A long term pin is what makes the switcher's unchecked use of tss_ex.pvcs
 * safe: it stops the page from being migrated, reclaimed or freed while the
 * vCPU is in guest mode.  One page per vCPU is pinned, and only while the
 * guest asks for it.
 *
 * The pin holds the page, not the VMM's mapping of the GFN.  A memslot change
 * re-resolves it (pvm_reload_pinned_pages()), but a change of the mapping
 * inside an unchanged memslot -- MADV_DONTNEED, hole punching, mmap over it --
 * is not seen: the shadow MMU follows the new page while pvm->pvcs stays on
 * the old one, and the guest and the hypervisor no longer share a PVCS.  The
 * old page stays valid, so this cannot hurt the host, but the guest breaks.  A
 * VMM must leave the PVCS page mapped while the guest has it registered, as it
 * must for any other guest memory that is pinned.
 */
static int pvm_pin_vcpu_struct(struct vcpu_pvm *pvm, gpa_t gpa)
{
	struct kvm_vcpu *vcpu = &pvm->vcpu;
	gfn_t gfn = gpa_to_gfn(gpa);
	struct kvm_memory_slot *slot;
	struct page *page;
	unsigned long hva;
	void *kaddr;

	pvm_unpin_vcpu_struct(pvm);

	/* The guest and the switcher write it. */
	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (!slot || (slot->flags & KVM_MEM_READONLY))
		return -EFAULT;

	hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);
	if (kvm_is_error_hva(hva))
		return -EFAULT;

	if (pin_user_pages_fast(hva, 1, FOLL_WRITE | FOLL_LONGTERM, &page) != 1)
		return -EFAULT;

	/*
	 * The switcher reads the PVCS through the direct map while the guest's
	 * root is loaded, and that root only has the top-level entries the
	 * host had when the module was loaded (see host_mmu_init()).
	 */
	kaddr = page_address(page);
	if (!host_mmu_root_pgd[pgd_index((unsigned long)kaddr)]) {
		unpin_user_page(page);
		return -EFAULT;
	}

	pvm->pvcs_page = page;
	pvm->pvcs_gfn = gfn;
	pvm->pvcs = kaddr + offset_in_page(gpa);

	return 0;
}

/*
 * The guest writes the PVCS whenever it runs and the hypervisor writes it when
 * it delivers an event, so it is marked dirty after every exit and after every
 * hypervisor write.  Not every writer holds kvm->srcu -- KVM_SET_REGS reaches
 * pvm_set_rflags() without it -- so take it here.
 */
static void pvm_mark_pvcs_dirty(struct vcpu_pvm *pvm)
{
	struct kvm *kvm = pvm->vcpu.kvm;
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	kvm_vcpu_mark_page_dirty(&pvm->vcpu, pvm->pvcs_gfn);
	srcu_read_unlock(&kvm->srcu, idx);
}

/*
 * A long term pin keeps the PVCS page alive, but not the mapping current, so a
 * memslot that moves or goes away leaves pvm->pvcs pointing at the right page
 * for the wrong GPA.  Pin it again before the next entry.
 */
static void pvm_reload_pinned_pages(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (!pvm->msr_vcpu_struct)
		return;

	if (pvm_pin_vcpu_struct(pvm, pvm->msr_vcpu_struct))
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
}

static void pvm_event_flags_update(struct kvm_vcpu *vcpu, unsigned long set,
				   unsigned long clear)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct pvm_vcpu_struct *pvcs = pvm->pvcs;
	unsigned long old_flags, new_flags;

	if (!pvcs)
		return;

	old_flags = pvcs->event_flags;
	new_flags = (old_flags | set) & ~clear;
	if (new_flags != old_flags) {
		pvcs->event_flags = new_flags;
		pvm_mark_pvcs_dirty(pvm);
	}
}

/* Deliver an event to the guest through the PVCS, as the PVM spec describes. */
static void __do_pvm_event(struct kvm_vcpu *vcpu, bool user, int vector,
			   bool has_err_code, u64 err_code)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct pvm_vcpu_struct *pvcs = pvm->pvcs;
	unsigned long entry;

	if (!pvcs) {
		vcpu_unimpl(vcpu, "no PVCS to deliver vector %d (MSR_PVM_VCPU_STRUCT=%#lx)\n",
			    vector, pvm->msr_vcpu_struct);
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}

	if (user) {
		pvcs->user_cs = pvm->hw_cs;
		pvcs->user_ss = pvm->hw_ss;
		/*
		 * The switcher's half of this is SWITCHER_PKRU_TO_SMOD.  Here
		 * the hardware PKRU is the host's again, so the guest's user
		 * value comes from where the core parked it on the way out.
		 */
		pvcs->pkru = pvm_guest_uses_pku(vcpu) ? vcpu->arch.pkru : 0;
		pvcs->user_gsbase = pvm_read_guest_gs_base(pvm);
	} else if (unlikely(pvcs->event_vector & 0xFF00)) {
		/*
		 * When the guest is busy on handling events, no nested
		 * events are allowed except for the async exceptions.
		 *
		 * Set PVM_PVCS_EVENT_VECTOR_NMI or PVM_PVCS_EVENT_VECTOR_MCE
		 * correspondingly.
		 *
		 * The guest should check async exceptions when it clears any
		 * PVM_PVCS_EVENT_VECTOR_* bits.
		 *
		 * The guest should set PVM_PVCS_EVENT_VECTOR_STD before
		 * invoking ERETU, and the hypervisor check for any unhandled
		 * async exceptions when handling ERETU.
		 */
		if (vector == NMI_VECTOR) {
			pvcs->event_vector |= PVM_PVCS_EVENT_VECTOR_NMI;
		} else if (vector == MC_VECTOR) {
			pvcs->event_vector |= PVM_PVCS_EVENT_VECTOR_MCE;
		} else {
			vcpu_unimpl(vcpu, "vector %d nested in event_vector %#x\n",
				    vector, pvcs->event_vector);
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		}

		/*
		 * Reuse SWITCH_FLAGS_IRQ_WIN to force the guest ERETU back to
		 * the hypervisor to meet the requirement stipulated above in
		 * case it is on the path to ERETU.
		 *
		 * When forced back to handle_synthetic_instruction_return_user(),
		 * SWITCH_FLAGS_IRQ_WIN will be cleared in kvm_set_rflags() or
		 * unhandled NMI/MCE will be reinjected.
		 */
		pvm->switch_flags |= SWITCH_FLAGS_IRQ_WIN;
		pvm_mark_pvcs_dirty(pvm);
		return;
	}

	pvcs->eflags = kvm_get_rflags(vcpu);
	pvcs->rip = kvm_rip_read(vcpu);
	pvcs->rcx = kvm_rcx_read(vcpu);
	pvcs->r11 = kvm_r11_read(vcpu);

	if (has_err_code)
		pvcs->event_errcode = err_code;

	if (vector == NMI_VECTOR)
		pvcs->event_vector = PVM_PVCS_EVENT_VECTOR_NMI;
	else if (vector == MC_VECTOR)
		pvcs->event_vector = PVM_PVCS_EVENT_VECTOR_MCE;
	else if (vector != PVM_SYSCALL_VECTOR)
		pvcs->event_vector = PVM_PVCS_EVENT_VECTOR_STD | vector;

	/* A #PF's CR2 reaches PVCS::cr2 on entry, see pvm_vcpu_run(). */

	pvm_mark_pvcs_dirty(pvm);

	if (user)
		switch_to_smod(vcpu);

	if (vector == PVM_SYSCALL_VECTOR)
		entry = pvm->msr_lstar;
	else if (user)
		entry = pvm->msr_event_entry;
	else
		entry = pvm->msr_event_entry + PVM_EVENT_ENTRY_SUPERVISOR_OFFSET;

	/*
	 * RCX and R11 hold the entry RIP and RFLAGS, as SYSRET needs them, so
	 * that the switcher can enter the guest with SYSRET.
	 */
	kvm_rip_write(vcpu, entry);
	kvm_rcx_write_raw(vcpu, entry);
	kvm_set_rflags(vcpu, X86_EFLAGS_FIXED);
	kvm_r11_write_raw(vcpu, X86_EFLAGS_IF | X86_EFLAGS_FIXED);
}

static void do_pvm_event(struct kvm_vcpu *vcpu, int vector,
			 bool has_error_code, u64 error_code)
{
	/*
	 * Unlike in VMX, the injected event is delivered by the guest before
	 * VM entry, so it is not allowed to inject event in non-PVM mode.
	 * The hypervisor attempts to switch to PVM mode before event
	 * injection, but the VMM may still inject an event in non-PVM mode, so
	 * say so and try to switch to PVM mode here.
	 */
	if (unlikely(to_pvm(vcpu)->non_pvm_mode)) {
		vcpu_unimpl(vcpu, "event injected in non-PVM mode\n");
		try_to_convert_to_pvm_mode(vcpu);
	}

	__do_pvm_event(vcpu, !is_smod(to_pvm(vcpu)), vector, has_error_code, error_code);
}

static unsigned long pvm_get_rflags(struct kvm_vcpu *vcpu)
{
	return to_pvm(vcpu)->rflags;
}

static void pvm_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	int need_update = !!((pvm->rflags ^ rflags) & X86_EFLAGS_IF);

	pvm->rflags = rflags;

	if (rflags & X86_EFLAGS_IF)
		pvm->switch_flags &= ~SWITCH_FLAGS_IRQ_WIN;

	/*
	 * The IF bit of 'pvcs->event_flags' should not be changed in user
	 * mode. It is recommended for this bit to be cleared when switching to
	 * user mode, so that when the guest switches back to supervisor mode,
	 * the X86_EFLAGS_IF is already cleared.
	 */
	if (unlikely(pvm->non_pvm_mode) || !need_update || !is_smod(pvm))
		return;

	if (rflags & X86_EFLAGS_IF)
		pvm_event_flags_update(vcpu, PVM_EVENT_FLAGS_IF, PVM_EVENT_FLAGS_IP);
	else
		pvm_event_flags_update(vcpu, 0, PVM_EVENT_FLAGS_IF);
}

static bool pvm_get_if_flag(struct kvm_vcpu *vcpu)
{
	return pvm_get_rflags(vcpu) & X86_EFLAGS_IF;
}

static u32 pvm_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	return to_pvm(vcpu)->int_shadow;
}

static void pvm_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	/* PVM spec: ignore interrupt shadow when in PVM mode. */
	if (pvm->non_pvm_mode)
		pvm->int_shadow = mask;
}

static void pvm_enable_irq_window(struct kvm_vcpu *vcpu)
{
	to_pvm(vcpu)->switch_flags |= SWITCH_FLAGS_IRQ_WIN;
	pvm_event_flags_update(vcpu, PVM_EVENT_FLAGS_IP, 0);
}

static int pvm_interrupt_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	/*
	 * In the non-PVM bootstrap mode the only way to deliver an interrupt
	 * is through the real-mode IVT, emulated below.  Protected mode has
	 * no PVCS yet and no IDT the hypervisor knows how to use, so say no
	 * and let the core hold the interrupt pending until the guest has
	 * reached PVM mode.
	 */
	if (unlikely(to_pvm(vcpu)->non_pvm_mode) && is_protmode(vcpu))
		return 0;

	return pvm_get_if_flag(vcpu) && !pvm_get_interrupt_shadow(vcpu);
}

static bool pvm_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	return pvm->non_pvm_mode ? pvm->nmi_mask : !pvm->msr_vcpu_struct;
}

static void pvm_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	to_pvm(vcpu)->nmi_mask = masked;
}

/*
 * Nothing to do.  In non-PVM mode the vCPU is being emulated.  With a PVCS
 * NMIs are never masked; without one they are, and writing
 * MSR_PVM_VCPU_STRUCT raises KVM_REQ_EVENT, which looks at pending NMIs.
 */
static void pvm_enable_nmi_window(struct kvm_vcpu *vcpu)
{
}

static int pvm_nmi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	return !pvm_get_nmi_mask(vcpu) && !pvm_get_interrupt_shadow(vcpu);
}

/*
 * Non-PVM mode has no PVCS, so do_pvm_event() has nowhere to deliver an event.
 * In real mode, deliver it through the IVT with the emulator, as VMX does for
 * a guest it cannot run unrestricted.
 */
static bool pvm_inject_realmode_event(struct kvm_vcpu *vcpu, int vector,
				      bool soft)
{
	int inc_eip = 0;

	if (likely(!to_pvm(vcpu)->non_pvm_mode))
		return false;

	if (WARN_ON_ONCE(is_protmode(vcpu)))
		return false;

	if (soft)
		inc_eip = vcpu->arch.event_exit_inst_len;
	kvm_inject_realmode_interrupt(vcpu, vector, inc_eip);
	return true;
}

/* Always inject the exception directly and consume the event. */
static void pvm_inject_exception(struct kvm_vcpu *vcpu)
{
	unsigned int vector = vcpu->arch.exception.vector;
	bool has_error_code = vcpu->arch.exception.has_error_code;
	u32 error_code = vcpu->arch.exception.error_code;

	kvm_deliver_exception_payload(vcpu, &vcpu->arch.exception);

	if (pvm_inject_realmode_event(vcpu, vector,
				      kvm_exception_is_soft(vector))) {
		kvm_clear_exception_queue(vcpu);
		return;
	}

	do_pvm_event(vcpu, vector, has_error_code, error_code);
	kvm_clear_exception_queue(vcpu);
}

/* Always inject the interrupt directly and consume the event. */
static void pvm_inject_irq(struct kvm_vcpu *vcpu, bool reinjected)
{
	int irq = vcpu->arch.interrupt.nr;

	trace_kvm_inj_virq(irq, vcpu->arch.interrupt.soft, reinjected);

	if (!pvm_inject_realmode_event(vcpu, irq, vcpu->arch.interrupt.soft))
		do_pvm_event(vcpu, irq, false, 0);
	kvm_clear_interrupt_queue(vcpu);

	++vcpu->stat.irq_injections;
}

/* Always inject the NMI directly and consume the event. */
static void pvm_inject_nmi(struct kvm_vcpu *vcpu)
{
	if (!pvm_inject_realmode_event(vcpu, NMI_VECTOR, false))
		do_pvm_event(vcpu, NMI_VECTOR, false, 0);
	vcpu->arch.nmi_injected = false;

	++vcpu->stat.nmi_injections;
}

static void pvm_cancel_injection(struct kvm_vcpu *vcpu)
{
	/*
	 * Nothing to do. Since exceptions/interrupts are delivered immediately
	 * during event injection, so they cannot be cancelled and reinjected.
	 */
}

static void pvm_setup_mce(struct kvm_vcpu *vcpu)
{
}

static int handle_synthetic_instruction_return_user(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct pvm_vcpu_struct *pvcs;
	unsigned long rflags;
	u32 pending_async_exceptions;

	/* switch to user mode before rsp changed. */
	switch_to_umod(vcpu);

	pvcs = pvm->pvcs;
	if (!pvcs) {
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return 1;
	}

	pending_async_exceptions = pvcs->event_vector;
	pvcs->event_vector = PVM_PVCS_EVENT_VECTOR_STD;

	kvm_rip_write(vcpu, pvcs->rip);
	kvm_rcx_write_raw(vcpu, pvcs->rcx);
	kvm_r11_write_raw(vcpu, pvcs->r11);
	rflags = pvcs->eflags;

	pvm->hw_cs = pvcs->user_cs | USER_RPL;
	pvm->hw_ss = pvcs->user_ss | USER_RPL;
	pvm_write_guest_gs_base(pvm, pvcs->user_gsbase);
	/* The switcher's half of this is SWITCHER_PKRU_TO_UMOD. */
	if (pvm_guest_uses_pku(vcpu))
		vcpu->arch.pkru = pvcs->pkru;

	pvm_mark_pvcs_dirty(pvm);

	/*
	 * Through kvm_set_rflags() rather than pvm->rflags, so that guest
	 * debugging, PVCS::event_flags and the switch flags follow.
	 */
	kvm_set_rflags(vcpu, rflags);

	if (pending_async_exceptions & PVM_PVCS_EVENT_VECTOR_MCE)
		do_pvm_event(vcpu, MC_VECTOR, false, 0);
	if (pending_async_exceptions & PVM_PVCS_EVENT_VECTOR_NMI)
		do_pvm_event(vcpu, NMI_VECTOR, false, 0);

	return 1;
}

static int handle_hc_irq_window(struct kvm_vcpu *vcpu)
{
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	to_pvm(vcpu)->switch_flags &= ~SWITCH_FLAGS_IRQ_WIN;
	pvm_event_flags_update(vcpu, 0, PVM_EVENT_FLAGS_IP);

	++vcpu->stat.irq_window_exits;
	return 1;
}

static int handle_hc_irq_halt(struct kvm_vcpu *vcpu)
{
	kvm_set_rflags(vcpu, kvm_get_rflags(vcpu) | X86_EFLAGS_IF);

	return kvm_emulate_halt_noskip(vcpu);
}

/*
 * Hypercall: PVM_HC_LOAD_PGTBL
 *	Load two PGDs into the current CR3.
 *
 * Arguments:
 *	flags:	bit0: flush the TLBs tagged with current PCID.
 *		bit1: 4 (bit1=0) or 5 (bit1=1 && cpuid_has(LA57)) level paging.
 *	pgd: to be loaded into CR3.
 */
static int handle_hc_load_pagetables(struct kvm_vcpu *vcpu, unsigned long flags,
				     unsigned long pgd)
{
	unsigned long old_cr4 = vcpu->arch.cr4;
	unsigned long cr4 = old_cr4;

	/*
	 * Unlike MOV to CR4, the paging level may change here, together with
	 * CR3.  LA57 is the only bit that changes, only where the guest's CPUID
	 * has it, and it is not one of the bits kvm_update_cpuid_runtime()
	 * follows, so there is nothing else to validate or update.
	 */
	if (!(flags & PVM_LOAD_PGTBL_FLAGS_LA57))
		cr4 &= ~X86_CR4_LA57;
	else if (guest_cpu_cap_has(vcpu, X86_FEATURE_LA57))
		cr4 |= X86_CR4_LA57;

	if (cr4 != old_cr4) {
		vcpu->arch.cr4 = cr4;
		kvm_mmu_reset_context(vcpu);
	}

	/*
	 * A CR3 KVM refuses -- reserved bits, a GPA beyond the guest's, or
	 * NOFLUSH without CR4.PCIDE -- is what MOV to CR3 answers with #GP, so
	 * do the same, with the paging level left as it was, rather than
	 * return to a guest that believes it switched address space and did
	 * not.
	 */
	if (kvm_set_cr3(vcpu, (flags & PVM_LOAD_PGTBL_FLAGS_TLB) ?
			      pgd : pgd | CR3_NOFLUSH)) {
		if (cr4 != old_cr4) {
			vcpu->arch.cr4 = old_cr4;
			kvm_mmu_reset_context(vcpu);
		}
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	if (cr4 != old_cr4)
		kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);

	return 1;
}

/*
 * Hypercall: PVM_HC_TLB_FLUSH
 *	Flush all TLBs.
 */
static int handle_hc_flush_tlb_all(struct kvm_vcpu *vcpu)
{
	kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);

	return 1;
}

/*
 * Hypercall: PVM_HC_TLB_FLUSH_CURRENT
 *	Flush all TLBs tagged with the current PCID.
 */
static int handle_hc_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	kvm_set_cr3(vcpu, vcpu->arch.cr3);

	return 1;
}

/*
 * Hypercall: PVM_HC_TLB_INVLPG
 *	Flush TLBs associated with a single address for all tags.
 */
static int handle_hc_invlpg(struct kvm_vcpu *vcpu, unsigned long addr)
{
	kvm_mmu_invlpg(vcpu, addr);

	return 1;
}

/*
 * Hypercall: PVM_HC_LOAD_GS
 *	Load %gs with the selector %rdi and load the resulted base address
 *	into RAX.
 *
 *	If %rdi is an invalid selector (including RPL != 3), NULL selector
 *	will be used instead.
 *
 *	Return the resulted GS BASE in vCPU's RAX.
 */
static int handle_hc_load_gs(struct kvm_vcpu *vcpu, unsigned short sel)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long guest_kernel_gs_base;

	/* Use NULL selector if RPL != 3. */
	if (sel != 0 && (sel & 3) != 3)
		sel = 0;

	/* Protect the guest state on the hardware. */
	preempt_disable();

	/*
	 * Switch to the guest state because the CPU is going to set the %gs to
	 * the guest value.  Save the original guest MSR_GS_BASE if it is
	 * already the guest state.
	 */
	if (!pvm->loaded_cpu_state)
		pvm_prepare_switch_to_guest(vcpu);
	else
		__save_gs_base(pvm);

	/*
	 * Load sel into %gs, which also changes the hardware MSR_KERNEL_GS_BASE.
	 *
	 * Before load_gs_index(sel):
	 *	hardware %gs:			old gs index
	 *	hardware MSR_KERNEL_GS_BASE:	guest MSR_GS_BASE
	 *
	 * After load_gs_index(sel);
	 *	hardware %gs:			resulted %gs, @sel or NULL
	 *	hardware MSR_KERNEL_GS_BASE:	resulted GS BASE
	 *
	 * The resulted %gs is the new guest %gs and will be saved into
	 * pvm->segments[VCPU_SREG_GS].selector later when the CPU is
	 * switching to host or the guest %gs is read (pvm_get_segment()).
	 *
	 * The resulted hardware MSR_KERNEL_GS_BASE will be returned via RAX
	 * to the guest and the hardware MSR_KERNEL_GS_BASE, which represents
	 * the guest MSR_GS_BASE when in VM-Exit state, is restored back to
	 * the guest MSR_GS_BASE.
	 */
	load_gs_index(sel);

	/* Get the resulted guest MSR_KERNEL_GS_BASE. */
	rdmsrq(MSR_KERNEL_GS_BASE, guest_kernel_gs_base);

	/* Restore the guest MSR_GS_BASE into the hardware MSR_KERNEL_GS_BASE. */
	__load_gs_base(pvm);

	/* Finished access to the guest state on the hardware. */
	preempt_enable();

	/* Return RAX with the resulted GS BASE. */
	kvm_rax_write_raw(vcpu, guest_kernel_gs_base);

	return 1;
}

/*
 * Hypercall: PVM_HC_RDMSR
 *	Read MSR.
 *	Return with RAX = 0 and RDX = the MSR value if succeeded.
 *	Return with RAX = -KVM_EINVAL and RDX = 0 if it failed.
 */
static int handle_hc_rdmsr(struct kvm_vcpu *vcpu, u32 index)
{
	u64 value = 0;

	/*
	 * The guest-initiated accessor, so that the guest's CPUID checks and
	 * the VMM's MSR filter apply.  kvm:kvm_msr is raised by hand because
	 * only kvm_emulate_{rd,wr}msr() raise it, and a hypercall does not go
	 * through them.
	 */
	if (kvm_emulate_msr_read(vcpu, index, &value)) {
		trace_kvm_msr_read_ex(index);
		kvm_rdx_write_raw(vcpu, 0);
		kvm_rax_write_raw(vcpu, -KVM_EINVAL);
		return 1;
	}

	trace_kvm_msr_read(index, value);
	kvm_rdx_write_raw(vcpu, value);
	kvm_rax_write_raw(vcpu, 0);

	return 1;
}

/*
 * Hypercall: PVM_HC_WRMSR
 *	Write MSR.
 *	Return with RAX = 0 if succeeded.
 *	Return with RAX = -KVM_EINVAL if it failed.
 */
static int handle_hc_wrmsr(struct kvm_vcpu *vcpu, u32 index, u64 value)
{
	/* See handle_hc_rdmsr() for the accessor and the tracepoint. */
	if (kvm_emulate_msr_write(vcpu, index, value)) {
		trace_kvm_msr_write_ex(index, value);
		kvm_rax_write_raw(vcpu, -KVM_EINVAL);
	} else {
		trace_kvm_msr_write(index, value);
		kvm_rax_write_raw(vcpu, 0);
	}

	return 1;
}

/*
 * Whether a guest TLS descriptor may go into the host GDT: a present 32-bit
 * data segment, as tls_desc_okay() in arch/x86/kernel/tls.c checks.
 */
static bool pvm_tls_desc_okay(struct desc_struct *desc)
{
	return desc->p && !(desc->type & (1 << 3)) && desc->d;
}

/*
 * Hypercall: PVM_HC_LOAD_TLS
 *	Load guest TLS desc into host GDT.
 */
static int handle_hc_load_tls(struct kvm_vcpu *vcpu, unsigned long tls_desc_0,
			      unsigned long tls_desc_1, unsigned long tls_desc_2)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long *tls_array = (unsigned long *)&pvm->tls_array[0];
	int i;

	tls_array[0] = tls_desc_0;
	tls_array[1] = tls_desc_1;
	tls_array[2] = tls_desc_2;

	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		if (!pvm_tls_desc_okay(&pvm->tls_array[i])) {
			pvm->tls_array[i] = (struct desc_struct){0};
			continue;
		}
		/* Normalize the descriptor, as fill_ldt() does. */
		pvm->tls_array[i].type |= 1;
		pvm->tls_array[i].s = 1;
		pvm->tls_array[i].dpl = 0x3;
		pvm->tls_array[i].l = 0;
	}

	preempt_disable();
	if (pvm->loaded_cpu_state)
		host_gdt_set_tls(pvm);
	preempt_enable();

	return 1;
}

/*
 * Like complete_hypercall_exit(), but RIP is already past the SYSCALL
 * instruction that made the hypercall.
 */
static int pvm_complete_hypercall(struct kvm_vcpu *vcpu)
{
	u64 ret = vcpu->run->hypercall.ret;

	if (!is_64_bit_hypercall(vcpu))
		ret = (u32)ret;
	kvm_rax_write_raw(vcpu, ret);
	return 1;
}

static int handle_kvm_hypercall(struct kvm_vcpu *vcpu)
{
	int r;

	/* PVM hypercalls pass in R10 what KVM hypercalls pass in RCX. */
	kvm_rcx_write_raw(vcpu, kvm_r10_read(vcpu));
	r = __kvm_emulate_hypercall(vcpu, kvm_x86_call(get_cpl)(vcpu),
				    pvm_complete_hypercall);
	kvm_r10_write_raw(vcpu, kvm_rcx_read(vcpu));

	return r;
}

static int handle_exit_syscall(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long rip = kvm_rip_read(vcpu);
	unsigned long a0, a1, a2;

	if (!is_smod(pvm)) {
		__do_pvm_event(vcpu, true, PVM_SYSCALL_VECTOR, false, 0);
		return 1;
	}

	if (rip == pvm->msr_retu_rip_plus2)
		return handle_synthetic_instruction_return_user(vcpu);

	a0 = kvm_rbx_read(vcpu);
	a1 = kvm_r10_read(vcpu);
	a2 = kvm_rdx_read(vcpu);

	/* A PVM hypercall, or else a KVM one. */
	switch (kvm_rax_read(vcpu)) {
	case PVM_HC_IRQ_WIN:
		return handle_hc_irq_window(vcpu);
	case PVM_HC_IRQ_HLT:
		return handle_hc_irq_halt(vcpu);
	case PVM_HC_LOAD_PGTBL:
		return handle_hc_load_pagetables(vcpu, a0, a1);
	case PVM_HC_TLB_FLUSH:
		return handle_hc_flush_tlb_all(vcpu);
	case PVM_HC_TLB_FLUSH_CURRENT:
		return handle_hc_flush_tlb_current(vcpu);
	case PVM_HC_TLB_INVLPG:
		return handle_hc_invlpg(vcpu, a0);
	case PVM_HC_LOAD_GS:
		return handle_hc_load_gs(vcpu, a0);
	case PVM_HC_RDMSR:
		return handle_hc_rdmsr(vcpu, a0);
	case PVM_HC_WRMSR:
		return handle_hc_wrmsr(vcpu, a0, a1);
	case PVM_HC_LOAD_TLS:
		return handle_hc_load_tls(vcpu, a0, a1, a2);
	default:
		return handle_kvm_hypercall(vcpu);
	}
}

static int handle_exit_debug(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct kvm_run *kvm_run = pvm->vcpu.run;

	if (pvm->vcpu.guest_debug &
	    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) {
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.dr6 = pvm->exit_dr6 | DR6_FIXED_1 | DR6_RTM;
		kvm_run->debug.arch.dr7 = vcpu->arch.guest_debug_dr7;
		kvm_run->debug.arch.pc = kvm_rip_read(vcpu);
		kvm_run->debug.arch.exception = DB_VECTOR;
		return 0;
	}

	kvm_queue_exception_p(vcpu, DB_VECTOR, pvm->exit_dr6);
	return 1;
}

/* check if the previous instruction is "int3" on receiving #BP */
static bool is_bp_trap(struct kvm_vcpu *vcpu)
{
	u8 byte = 0;
	unsigned long rip;
	struct x86_exception exception;
	int r;

	rip = kvm_rip_read(vcpu) - 1;
	r = kvm_read_guest_virt(vcpu, rip, &byte, 1, &exception);

	/* Just assume it to be int3 when failed to fetch the instruction. */
	if (r)
		return true;

	return byte == 0xcc;
}

static int handle_exit_breakpoint(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct kvm_run *kvm_run = pvm->vcpu.run;

	/*
	 * Breakpoint exception can be caused by int3 or int 3.  While "int3"
	 * participates in guest debug, but "int 3" should not.
	 */
	if ((vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP) && is_bp_trap(vcpu)) {
		kvm_rip_write(vcpu, kvm_rip_read(vcpu) - 1);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.pc = kvm_rip_read(vcpu);
		kvm_run->debug.arch.exception = BP_VECTOR;
		return 0;
	}

	kvm_queue_exception(vcpu, BP_VECTOR);
	return 1;
}

/*
 * The PVM ABI leaves, answered here rather than from the CPUID table the VMM
 * configured.  What a guest reads from them decides whether it binds itself to
 * this ABI at all, so it has to come from the code that implements the ABI --
 * a VMM that forgot to add the entries, or added the wrong ones, would
 * otherwise talk a guest into running against a contract nothing keeps.
 * Hooked into kvm_cpuid(), so the synthetic instruction and a CPUID that is
 * emulated see the same leaves.
 */
static bool pvm_get_fixed_cpuid(struct kvm_vcpu *vcpu, u32 function,
				u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	static const char sig[12] = PVM_SIGNATURE;

	switch (function) {
	case PVM_CPUID_SIGNATURE:
		*eax = PVM_CPUID_MAX;
		memcpy(ebx, &sig[0], 4);
		memcpy(ecx, &sig[4], 4);
		memcpy(edx, &sig[8], 4);
		return true;
	case PVM_CPUID_FEATURES:
		*eax = PVM_ABI_VERSION;
		*ebx = PVM_FEATURES_SUPPORTED;
		*ecx = 0;
		*edx = 0;
		return true;
	default:
		return false;
	}
}

static void pvm_handle_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	eax = kvm_rax_read(vcpu);
	ecx = kvm_rcx_read(vcpu);
	kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);
	kvm_rax_write_raw(vcpu, eax);
	kvm_rbx_write_raw(vcpu, ebx);
	kvm_rcx_write_raw(vcpu, ecx);
	kvm_rdx_write_raw(vcpu, edx);
}

static bool handle_synthetic_instruction_pvm_cpuid(struct kvm_vcpu *vcpu)
{
	/* invlpg 0xffffffffff4d5650; cpuid; */
	static const char pvm_synthetic_cpuid_insns[] = { PVM_SYNTHETIC_CPUID };
	char insns[10];
	struct x86_exception e;

	if (kvm_read_guest_virt(vcpu, kvm_get_linear_rip(vcpu),
				insns, sizeof(insns), &e) == 0 &&
	    memcmp(insns, pvm_synthetic_cpuid_insns, sizeof(insns)) == 0) {
		pvm_handle_cpuid(vcpu);
		kvm_rip_write(vcpu, kvm_rip_read(vcpu) + sizeof(insns));
		return true;
	}

	return false;
}

static int handle_exit_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	u32 vector, error_code;
	int err;

	vector = pvm->exit_vector;
	error_code = pvm->exit_error_code;

	switch (vector) {
	/*
	 * #PF, #GP, #UD, #DB and #BP may be the guest's, or the hypervisor's
	 * for emulation or debugging.
	 */
	case PF_VECTOR:
		/*
		 * The hardware sets PFERR_USER_MASK for supervisor mode too,
		 * because the guest runs at CPL3.
		 */
		if (is_smod(pvm))
			error_code &= ~PFERR_USER_MASK;

		/*
		 * A protection-key fault the guest never asked for: it reached
		 * WRPKRU anyway -- it runs at CPL 3 under the host's CR4.PKE,
		 * so it can, whatever CPUID told it -- and the fault means
		 * nothing architecturally.  Re-enter and let
		 * pvm_load_guest_xsave_state() put PKRU back to 0 on the way
		 * in; nothing here has to, and nothing here can, since PKRU is
		 * the host's again by the time this runs.
		 *
		 * One the guest did ask for goes to kvm_handle_page_fault()
		 * with every other #PF.  The walk there reaches the same
		 * verdict the hardware did -- vcpu->arch.pkru is the guest's
		 * PKRU as of this exit, and the guest PTE carries the key that
		 * the shadow MMU copied into the SPTE -- and injects it.
		 */
		if (cpu_feature_enabled(X86_FEATURE_PKU) &&
		    (error_code & PFERR_PK_MASK)) {
			if (!pvm_guest_uses_pku(vcpu))
				return 1;

			/*
			 * The MMU derives this bit itself, from the key in the
			 * guest PTE and vcpu->arch.pkru, and WARNs if it is
			 * handed one that already has it set.  The hardware's
			 * is the same verdict reached earlier, so drop it and
			 * let the walk reach it again.
			 */
			error_code &= ~PFERR_PK_MASK;
		}

		return kvm_handle_page_fault(vcpu, error_code, pvm->exit_cr2,
					     NULL, 0);
	case GP_VECTOR:
		if (is_smod(pvm) && handle_synthetic_instruction_pvm_cpuid(vcpu))
			return 1;

		err = kvm_emulate_instruction(vcpu, EMULTYPE_TRAP_GP);
		if (!err)
			return 0;

		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			return kvm_emulate_halt_noskip(vcpu);
		}
		return 1;
	case UD_VECTOR:
		if (!is_smod(pvm)) {
			kvm_queue_exception(vcpu, UD_VECTOR);
			return 1;
		}
		return handle_ud(vcpu);
	case DB_VECTOR:
		return handle_exit_debug(vcpu);
	case BP_VECTOR:
		return handle_exit_breakpoint(vcpu);

	/* Exceptions that are purely the guest's. */
	case DE_VECTOR:
	case OF_VECTOR:
	case BR_VECTOR:
	case NM_VECTOR:
	case MF_VECTOR:
	case XM_VECTOR:
		kvm_queue_exception(vcpu, vector);
		return 1;
	case AC_VECTOR:
	case TS_VECTOR:
	case NP_VECTOR:
	case SS_VECTOR:
		kvm_queue_exception_e(vcpu, vector, error_code);
		return 1;

	/*
	 * The host's own: the NMI was handled by pvm_vcpu_run_noinstr() and
	 * the #MC by pvm_handle_exit_irqoff(), both before interrupts were
	 * enabled.
	 */
	case NMI_VECTOR:
	case MC_VECTOR:
		return 1;
	default:
		/*
		 * #DF is fatal in the host's own handler and never gets here;
		 * #VE and #VC cannot occur because PVM refuses to load on a TDX
		 * or SEV-ES host.  Anything else is a host bug.
		 */
		vcpu_unimpl(vcpu, "unexpected exception exit %u, error code %#x\n",
			    vector, error_code);
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = vector;
		kvm_run->ex.error_code = error_code;
		return 0;
	}
}

static int handle_exit_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int handle_exit_failed_vmentry(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	u32 error_code = pvm->exit_error_code;

	kvm_queue_exception_e(vcpu, GP_VECTOR, error_code);
	return 1;
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int pvm_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	u32 exit_reason = pvm->exit_vector;

	/*
	 * A vCPU KVM_SET_TSC_KHZ above the host's frequency is accepted by KVM
	 * as "catch up in software", which a guest reading the host's TSC
	 * cannot do (see pvm_write_tsc_offset()).  One below it is refused
	 * outright.
	 */
	if (unlikely(vcpu->arch.tsc_always_catchup)) {
		vcpu_unimpl(vcpu, "TSC frequency %u kHz is not the host's %u kHz\n",
			    vcpu->arch.virtual_tsc_khz, tsc_khz);
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;
		return 0;
	}

	if (unlikely(pvm->non_pvm_mode))
		return handle_non_pvm_mode(vcpu);

	/*
	 * The guest may have written the PVCS while it ran.  Here rather than
	 * in pvm_vcpu_run(), which runs outside kvm->srcu.
	 */
	if (likely(pvm->pvcs))
		pvm_mark_pvcs_dirty(pvm);

	if (exit_reason == PVM_SYSCALL_VECTOR)
		return handle_exit_syscall(vcpu);
	if (exit_reason < FIRST_EXTERNAL_VECTOR)
		return handle_exit_exception(vcpu);
	if (exit_reason == IA32_SYSCALL_VECTOR) {
		do_pvm_event(vcpu, IA32_SYSCALL_VECTOR, false, 0);
		return 1;
	}
	if (exit_reason < NR_VECTORS)
		return handle_exit_external_interrupt(vcpu);
	if (exit_reason == PVM_FAILED_VMENTRY_VECTOR)
		return handle_exit_failed_vmentry(vcpu);

	vcpu_unimpl(vcpu, "unexpected exit reason 0x%x\n", exit_reason);
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror =
		KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = exit_reason;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;
	return 0;
}

/*
 * Which hypercall it was.  "HYPERCALL" on its own says almost nothing about
 * what a guest is spending its exits on -- a TLB flush and a page-table load
 * cost very different amounts -- so each known hypercall has its own reason.
 */
static u32 pvm_get_hypercall_exit_reason(struct kvm_vcpu *vcpu)
{
	switch (kvm_rax_read(vcpu)) {
	case PVM_HC_IRQ_WIN:
		return PVM_EXIT_REASONS_HC_IRQ_WIN;
	case PVM_HC_IRQ_HLT:
		return PVM_EXIT_REASONS_HC_IRQ_HALT;
	case PVM_HC_LOAD_PGTBL:
		return PVM_EXIT_REASONS_HC_LOAD_PGTBL;
	case PVM_HC_TLB_FLUSH:
		return PVM_EXIT_REASONS_HC_TLB_FLUSH;
	case PVM_HC_TLB_FLUSH_CURRENT:
		return PVM_EXIT_REASONS_HC_TLB_FLUSH_CURRENT;
	case PVM_HC_TLB_INVLPG:
		return PVM_EXIT_REASONS_HC_TLB_INVLPG;
	case PVM_HC_LOAD_GS:
		return PVM_EXIT_REASONS_HC_LOAD_GS;
	case PVM_HC_RDMSR:
		return PVM_EXIT_REASONS_HC_RDMSR;
	case PVM_HC_WRMSR:
		return PVM_EXIT_REASONS_HC_WRMSR;
	case PVM_HC_LOAD_TLS:
		return PVM_EXIT_REASONS_HC_LOAD_TLS;
	default:
		return PVM_EXIT_REASONS_HYPERCALL;
	}
}

static u32 pvm_get_syscall_exit_reason(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	unsigned long rip = kvm_rip_read(vcpu);

	if (is_smod(pvm)) {
		if (rip == pvm->msr_retu_rip_plus2)
			return PVM_EXIT_REASONS_ERETU;
		else
			return pvm_get_hypercall_exit_reason(vcpu);
	}

	return PVM_EXIT_REASONS_SYSCALL;
}

static void pvm_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason, u64 *info1, u64 *info2,
			      u32 *intr_info, u32 *error_code)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	if (pvm->exit_vector == PVM_SYSCALL_VECTOR)
		*reason = pvm_get_syscall_exit_reason(vcpu);
	else if (pvm->exit_vector == PVM_FAILED_VMENTRY_VECTOR)
		*reason = PVM_EXIT_REASONS_FAILED_VMENTRY;
	else if (pvm->exit_vector == IA32_SYSCALL_VECTOR)
		*reason = PVM_EXIT_REASONS_INT80;
	else if (pvm->exit_vector >= FIRST_EXTERNAL_VECTOR &&
		 pvm->exit_vector < NR_VECTORS)
		*reason = PVM_EXIT_REASONS_INTERRUPT;
	else
		*reason = pvm->exit_vector;
	*info1 = pvm->exit_vector;
	*info2 = pvm->exit_error_code;
	*intr_info = pvm->exit_vector;
	*error_code = pvm->exit_error_code;
}

/*
 * PVM delivers events by writing the PVCS and moving the guest's RIP, rather
 * than arming something the CPU consumes on entry, so by the time anyone asks
 * there is no pending entry event to report.
 */
static void pvm_get_entry_info(struct kvm_vcpu *vcpu, u32 *intr_info, u32 *error_code)
{
	*intr_info = 0;
	*error_code = 0;
}

static void pvm_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);
	u32 vector = pvm->exit_vector;

	if (vector >= FIRST_EXTERNAL_VECTOR && vector < NR_VECTORS &&
	    vector != IA32_SYSCALL_VECTOR)
		x86_entry_from_kvm(EVENT_TYPE_EXTINT, vector);
	else if (vector == MC_VECTOR)
		kvm_machine_check();
}

static bool pvm_has_emulated_msr(struct kvm *kvm, u32 index)
{
	switch (index) {
	case MSR_IA32_MCG_EXT_CTL:
	case KVM_FIRST_EMULATED_VMX_MSR ... KVM_LAST_EMULATED_VMX_MSR:
		return false;
	case MSR_AMD64_VIRT_SPEC_CTRL:
	case MSR_AMD64_TSC_RATIO:
		/* This is AMD SVM only. */
		return false;
	case MSR_IA32_SMBASE:
		/* No SMM. */
		return false;
	case MSR_PVM_VCPU_STRUCT ... MSR_PVM_FEATURES_ENABLED:
		/* The guest's PVM state, saved and restored like any other. */
		return true;
	default:
		break;
	}

	return true;
}

static bool cpu_has_pvm_wbinvd_exit(void)
{
	return true;
}

static void pvm_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	WARN_ONCE(1, "pvm never sets KVM_DEBUGREG_WONT_EXIT\n");
}

static void pvm_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	to_pvm(vcpu)->guest_dr7 = val;
}

static __always_inline unsigned long __dr7_enable_mask(int drnum)
{
	unsigned long bp_mask = 0;

	bp_mask |= (DR_LOCAL_ENABLE << (drnum * DR_ENABLE_SIZE));
	bp_mask |= (DR_GLOBAL_ENABLE << (drnum * DR_ENABLE_SIZE));

	return bp_mask;
}

static __always_inline unsigned long __dr7_mask(int drnum)
{
	unsigned long bp_mask = 0xf;

	bp_mask <<= (DR_CONTROL_SHIFT + drnum * DR_CONTROL_SIZE);
	bp_mask |= __dr7_enable_mask(drnum);

	return bp_mask;
}

/*
 * Calculate the correct dr7 for the hardware to avoid the host
 * being watched.
 *
 * It only needs to be calculated each time when vcpu->arch.eff_db or
 * pvm->guest_dr7 is changed.  But now it is calculated each time on
 * VM-enter since there is no proper callback for vcpu->arch.eff_db and
 * it is slow path.
 */
static __always_inline unsigned long pvm_eff_dr7(struct kvm_vcpu *vcpu)
{
	unsigned long eff_dr7 = to_pvm(vcpu)->guest_dr7;
	int i;

	/*
	 * DR7_GD should not be set to hardware. And it doesn't need to be
	 * set to hardware since PVM guest is running on hardware ring3.
	 * All access to debug registers will be trapped and the emulation
	 * code can handle DR7_GD correctly for PVM.
	 */
	eff_dr7 &= ~DR7_GD;

	/*
	 * Disallow addresses that are not for the guest, especially addresses
	 * on the host entry code.
	 */
	for (i = 0; i < KVM_NR_DB_REGS; i++) {
		if (!pvm_guest_allowed_va(vcpu, vcpu->arch.eff_db[i]))
			eff_dr7 &= ~__dr7_mask(i);
		if (!pvm_guest_allowed_va(vcpu, vcpu->arch.eff_db[i] + 7))
			eff_dr7 &= ~__dr7_mask(i);
	}

	return eff_dr7;
}

static int pvm_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	BUILD_BUG_ON(offsetof(struct vcpu_pvm, vcpu) != 0);

	/*
	 * The guest's TSC is the host's, see pvm_write_tsc_offset().  A
	 * different frequency set with the VM-wide KVM_SET_TSC_KHZ cannot be
	 * refused there, so refuse the vCPU.
	 */
	if (vcpu->kvm->arch.default_tsc_khz != tsc_khz)
		return -EINVAL;

	pvm->switch_flags = SWITCH_FLAGS_INIT;

	return 0;
}

static void pvm_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_pvm *pvm = to_pvm(vcpu);

	pvm_unpin_vcpu_struct(pvm);
}

static void pvm_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
}

/*
 * Every VM runs on the one root template: the host has no KPTI, so the
 * template's kernel half already maps the PVCS the switcher reads through the
 * direct map.
 */
static int pvm_vm_init(struct kvm *kvm)
{
	return 0;
}

static void pvm_asid_data_init(void)
{
	struct pvm_asid_data *asid_data = this_cpu_ptr(&pvm_asid);

	asid_data->asid_generation = PVM_ASID_GEN_INIT;
	asid_data->max_asid = PVM_ASID_MAX;
	asid_data->next_asid = PVM_ASID_MIN;
	asid_data->min_asid = PVM_ASID_MIN;
	__flush_tlb_all();
}

static int pvm_enable_virtualization_cpu(void)
{
	pvm_asid_data_init();
	return 0;
}

static void pvm_disable_virtualization_cpu(void)
{
	/* Nothing to do */
}

/*
 * hardware_cap_check() and pvm_host_init() look at the boot CPU.  Check the
 * features they require on every CPU that KVM enables, including one brought
 * online later.
 */
static int pvm_check_processor_compat(void)
{
	int cpu = smp_processor_id();
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	const char *missing = NULL;

	if (!cpu_has(c, X86_FEATURE_FSGSBASE))
		missing = "FSGSBASE";
	else if (!cpu_has(c, X86_FEATURE_PCID))
		missing = "PCID";
	else if (!cpu_has(c, X86_FEATURE_INVPCID))
		missing = "INVPCID";
	else if (!cpu_has(c, X86_FEATURE_NX))
		missing = "NX";
	else if (!cpu_has(c, X86_FEATURE_RDTSCP))
		missing = "RDTSCP";
	else if (!cpu_has(c, X86_FEATURE_CX16))
		missing = "CMPXCHG16B";
	else if (enable_cpuid_intercept && !cpu_has(c, X86_FEATURE_CPUID_FAULT))
		missing = "CPUID faulting";

	if (missing) {
		pr_err("CPU %d does not support %s\n", cpu, missing);
		return -EIO;
	}

	return 0;
}

#ifdef CONFIG_KVM_SMM
static int pvm_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	return 0;
}

static int pvm_enter_smm(struct kvm_vcpu *vcpu, union kvm_smram *smram)
{
	return 0;
}

static int pvm_leave_smm(struct kvm_vcpu *vcpu, const union kvm_smram *smram)
{
	return 0;
}

static void pvm_enable_smi_window(struct kvm_vcpu *vcpu)
{
}
#endif

/*
 * When in PVM mode, the hardware MSR_LSTAR is set to the entry point
 * provided by the host entry code (switcher), and the
 * hypervisor can also change the hardware MSR_TSC_AUX to emulate
 * the guest MSR_TSC_AUX.
 */
static __init void pvm_setup_user_return_msrs(void)
{
	kvm_add_user_return_msr(MSR_LSTAR);
	kvm_add_user_return_msr(MSR_TSC_AUX);
	if (ia32_enabled()) {
		if (is_intel)
			kvm_add_user_return_msr(MSR_IA32_SYSENTER_CS);
		else
			kvm_add_user_return_msr(MSR_CSTAR);
	}
}

static __init void pvm_set_cpu_caps(void)
{
	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_caps.supported_efer_bits |= EFER_NX;
	if (boot_cpu_has(X86_FEATURE_FXSR_OPT))
		kvm_caps.supported_efer_bits |= EFER_FFXSR;

	kvm_initialize_cpu_caps();

	/* Unloading kvm-intel.ko doesn't clean up kvm_caps.supported_mce_cap. */
	kvm_caps.supported_mce_cap = MCG_CTL_P | MCG_SER_P;

	kvm_caps.supported_xss = 0;

	/*
	 * ARCH_CAP_IBRS_ALL says "enhanced IBRS is in effect", and a Linux
	 * guest that sees it selects the eIBRS mitigation and then writes
	 * MSR_IA32_SPEC_CTRL to arm it.  PVM does not emulate that MSR, and
	 * a guest that ignores the failed write would report a mitigation it
	 * does not have.  Clearing the
	 * CPUID bits alone does not prevent this: eIBRS is selected from
	 * ARCH_CAPABILITIES, not from CPUID.
	 *
	 * ARCH_CAP_TSX_CTRL_MSR has the same shape: it promises
	 * MSR_IA32_TSX_CTRL, which PVM does not implement either.
	 */
	kvm_caps.supported_arch_cap &= ~(ARCH_CAP_IBRS_ALL | ARCH_CAP_TSX_CTRL_MSR);

	if (kvm_mpx_supported())
		kvm_cpu_cap_check_and_set(X86_FEATURE_MPX);

	/* PVM supervisor mode runs on hardware ring3, so no xsaves. */
	kvm_cpu_cap_clear(X86_FEATURE_XSAVES);

	/*
	 * PVM supervisor mode runs on hardware ring3, so neither SMEP nor SMAP
	 * comes from the hardware.  SMAP is not emulated.
	 */
	kvm_cpu_cap_clear(X86_FEATURE_SMAP);

	/*
	 * SMEP is emulated by setting NX on the guest's user mappings while
	 * the guest is in supervisor mode, see kvm_mmu_set_guest_cpl3_paging().
	 */
	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_cpu_cap_set(X86_FEATURE_SMEP);

	/*
	 * PVM implements guest LA57 with host LA57 shadow paging, so the guest
	 * may only have it where the host does.
	 */
	if (!pgtable_l5_enabled())
		kvm_cpu_cap_clear(X86_FEATURE_LA57);

	/*
	 * Even host pcid is not enabled, guest pcid can be enabled to reduce
	 * the heavy guest tlb flushing.  Guest CR4.PCIDE is not directly
	 * mapped to the hardware and is virtualized by PVM so that it can be
	 * enabled unconditionally.
	 */
	kvm_cpu_cap_set(X86_FEATURE_PCID);

	/*
	 * MSR_IA32_SPEC_CTRL is not emulated: it appears in neither
	 * pvm_set_msr() nor kvm_set_msr_common(), and it cannot simply be
	 * passed through -- the guest runs at hardware CPL3 on the host's own
	 * SPEC_CTRL, so letting it write there would change the host's
	 * protection, and doing it properly means saving and restoring the
	 * MSR across every world switch.
	 *
	 * So every CPUID bit whose meaning is "MSR_IA32_SPEC_CTRL exists and
	 * accepts this bit" has to go.  Clearing only some of them is worse
	 * than clearing none: a guest that sees STIBP or SSBD sets
	 * X86_FEATURE_MSR_SPEC_CTRL, reads and writes the MSR through
	 * PVM_HC_{RD,WR}MSR -- which have no way to report the failure back --
	 * and then reports a mitigation it does not have.
	 */
	kvm_cpu_cap_clear(X86_FEATURE_SPEC_CTRL);
	kvm_cpu_cap_clear(X86_FEATURE_INTEL_STIBP);
	kvm_cpu_cap_clear(X86_FEATURE_SPEC_CTRL_SSBD);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_STIBP);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_IBRS);
	kvm_cpu_cap_clear(X86_FEATURE_AMD_SSBD);
	kvm_cpu_cap_clear(X86_FEATURE_VIRT_SSBD);

	/* PVM hypervisor hasn't implemented LAM so far */
	kvm_cpu_cap_clear(X86_FEATURE_LAM);

	/* Don't expose MSR_IA32_DEBUGCTLMSR related features. */
	kvm_cpu_cap_clear(X86_FEATURE_BUS_LOCK_DETECT);

	/*
	 * PKU, which kvm_initialize_cpu_caps() has just cleared because
	 * !tdp_enabled: with ordinary shadow paging the hardware never
	 * consults the guest's PKRU, so the check would have to be emulated on
	 * a walk that only happens on a fault.
	 *
	 * A PVM guest runs on the shadow tables itself, at CPL3, on the real
	 * PKRU: the shadow MMU puts the guest's key into every leaf SPTE and
	 * the hardware applies the live register to it, so a guest WRPKRU
	 * takes effect with no hypervisor involvement.
	 *
	 * Every leaf SPTE carries USER, as CPL3 needs, so the hardware would
	 * apply PKRU to the guest kernel's pages too, where real hardware
	 * exempts supervisor pages from PKU.  Supervisor mode therefore runs on
	 * smod_pkru rather than the guest's PKRU; see
	 * pvm_load_guest_xsave_state().
	 */
	if (boot_cpu_has(X86_FEATURE_OSPKE))
		kvm_cpu_cap_set(X86_FEATURE_PKU);
}

static __init int pvm_hardware_setup(void)
{
	pvm_setup_user_return_msrs();

	pvm_set_cpu_caps();

	/*
	 * The guest runs at hardware CPL3 in both of its modes, so every
	 * mapping it can reach has to be a user mapping and SMEP has to be
	 * emulated with NX.  hardware_cap_check() has already refused to load
	 * without NX, which is what that emulation needs.
	 */
	kvm_mmu_set_guest_cpl3_paging(host_mmu_root_pgd);

	kvm_configure_mmu(false, 0, 0, 0);

	/*
	 * Shadow paging already handles a guest MAXPHYADDR smaller than the
	 * host's.  Set before kvm_init() makes VM creation possible.
	 */
	allow_smaller_maxphyaddr = true;

	enable_apicv = 0;

	return 0;
}

static void pvm_hardware_unsetup(void)
{
}

/*
 * PVM has no nested virtualization: a PVM guest is never in guest mode, and
 * pvm_nested_ops.enabled stays false.  KVM still requires the mandatory nested
 * operations -- kvm_nested_ops_update() WARNs at load for each one missing --
 * and calls some of them without asking about guest mode, leave_nested() on
 * every vCPU reset among them.  These are what a vendor without nesting
 * answers.  The ones reachable only from guest mode say so if they are ever
 * reached.
 */
static void pvm_leave_nested(struct kvm_vcpu *vcpu)
{
}

static bool pvm_is_exception_vmexit(struct kvm_vcpu *vcpu, u8 vector,
				    u32 error_code)
{
	return false;
}

static int pvm_check_nested_events(struct kvm_vcpu *vcpu)
{
	return 0;
}

static void pvm_nested_triple_fault(struct kvm_vcpu *vcpu)
{
	WARN_ON_ONCE(1);
}

static int pvm_get_nested_state(struct kvm_vcpu *vcpu,
				struct kvm_nested_state __user *user_kvm_nested_state,
				unsigned int user_data_size)
{
	return 0;
}

static int pvm_set_nested_state(struct kvm_vcpu *vcpu,
				struct kvm_nested_state __user *user_kvm_nested_state,
				struct kvm_nested_state *kvm_state)
{
	return -EINVAL;
}

static bool pvm_get_nested_state_pages(struct kvm_vcpu *vcpu)
{
	WARN_ON_ONCE(1);
	return false;
}

static gpa_t pvm_translate_nested_gpa(struct kvm_vcpu *vcpu, gpa_t gpa,
				      u64 access, struct x86_exception *exception,
				      u64 pte_access)
{
	WARN_ON_ONCE(1);
	return INVALID_GPA;
}

#ifdef CONFIG_KVM_HYPERV
static void pvm_hv_inject_synthetic_vmexit_post_tlb_flush(struct kvm_vcpu *vcpu)
{
	WARN_ON_ONCE(1);
}
#endif

/*
 * Every guest MSR access already arrives here -- WRMSR and RDMSR fault at
 * CPL3, and PVM_HC_RDMSR/WRMSR are hypercalls -- and goes through
 * kvm_emulate_msr_{read,write}(), where the VMM's filter is applied.  There is
 * no bitmap to recompute when the filter or the guest's CPUID changes.
 */
static void pvm_recalc_intercepts(struct kvm_vcpu *vcpu)
{
}

/*
 * No posted interrupts: kvm_arch_has_irq_bypass() is false without APICv,
 * which PVM never enables, so nothing asks to post one.  Refuse if something
 * does, rather than let KVM believe an interrupt is being delivered.
 */
static int pvm_pi_update_irte(struct kvm_kernel_irqfd *irqfd, struct kvm *kvm,
			      unsigned int host_irq, uint32_t guest_irq,
			      struct kvm_vcpu *vcpu, u32 vector)
{
	return vcpu ? -EINVAL : 0;
}

struct kvm_x86_nested_ops pvm_nested_ops = {
	.leave_nested = pvm_leave_nested,
	.is_exception_vmexit = pvm_is_exception_vmexit,
	.check_events = pvm_check_nested_events,
	.triple_fault = pvm_nested_triple_fault,
	.get_state = pvm_get_nested_state,
	.set_state = pvm_set_nested_state,
	.get_nested_state_pages = pvm_get_nested_state_pages,
	.translate_nested_gpa = pvm_translate_nested_gpa,
#ifdef CONFIG_KVM_HYPERV
	.hv_inject_synthetic_vmexit_post_tlb_flush =
		pvm_hv_inject_synthetic_vmexit_post_tlb_flush,
#endif
};

static struct kvm_x86_ops pvm_x86_ops __initdata = {
	.name = KBUILD_MODNAME,

	.check_processor_compatibility = pvm_check_processor_compat,

	.hardware_unsetup = pvm_hardware_unsetup,
	.enable_virtualization_cpu = pvm_enable_virtualization_cpu,
	.disable_virtualization_cpu = pvm_disable_virtualization_cpu,
	.has_emulated_msr = pvm_has_emulated_msr,

	.has_wbinvd_exit = cpu_has_pvm_wbinvd_exit,

	.vm_size = sizeof(struct kvm),
	.vm_init = pvm_vm_init,

	.vcpu_create = pvm_vcpu_create,
	.vcpu_free = pvm_vcpu_free,

	.prepare_switch_to_guest = pvm_prepare_switch_to_guest,
	.vcpu_load = pvm_vcpu_load,
	.vcpu_put = pvm_vcpu_put,

	.update_exception_bitmap = pvm_update_exception_bitmap,
	.get_feature_msr = pvm_get_feature_msr,
	.get_msr = pvm_get_msr,
	.set_msr = pvm_set_msr,
	.get_segment_base = pvm_get_segment_base,
	.get_segment = pvm_get_segment,
	.set_segment = pvm_set_segment,
	.get_cpl = pvm_get_cpl,
	/* Nothing cached: the mode is switch_flags, which is always current. */
	.get_cpl_no_cache = pvm_get_cpl,
	.get_cs_db_l_bits = pvm_get_cs_db_l_bits,
	.is_valid_cr0 = pvm_is_valid_cr0,
	.set_cr0 = pvm_set_cr0,
	.load_mmu_pgd = pvm_load_mmu_pgd,
	.is_valid_cr4 = pvm_is_valid_cr4,
	.set_cr4 = pvm_set_cr4,
	.set_efer = pvm_set_efer,
	.get_gdt = pvm_get_gdt,
	.set_gdt = pvm_set_gdt,
	.get_idt = pvm_get_idt,
	.set_idt = pvm_set_idt,
	.set_dr7 = pvm_set_dr7,
	.sync_dirty_debug_regs = pvm_sync_dirty_debug_regs,
	.cache_reg = pvm_cache_reg,
	.get_rflags = pvm_get_rflags,
	.set_rflags = pvm_set_rflags,
	.get_if_flag = pvm_get_if_flag,

	.flush_tlb_all = pvm_flush_hwtlb,
	.flush_tlb_current = pvm_flush_hwtlb_current,
	.flush_tlb_gva = pvm_flush_hwtlb_gva,
	.flush_tlb_guest = pvm_flush_hwtlb,

	.handle_exit = pvm_handle_exit,
	.skip_emulated_instruction = pvm_skip_emulated_instruction,
	.set_interrupt_shadow = pvm_set_interrupt_shadow,
	.get_interrupt_shadow = pvm_get_interrupt_shadow,
	.patch_hypercall = pvm_patch_hypercall,
	.inject_irq = pvm_inject_irq,
	.inject_nmi = pvm_inject_nmi,
	.inject_exception = pvm_inject_exception,
	.cancel_injection = pvm_cancel_injection,
	.interrupt_allowed = pvm_interrupt_allowed,
	.nmi_allowed = pvm_nmi_allowed,
	.get_nmi_mask = pvm_get_nmi_mask,
	.set_nmi_mask = pvm_set_nmi_mask,
	.enable_nmi_window = pvm_enable_nmi_window,
	.enable_irq_window = pvm_enable_irq_window,
	.refresh_apicv_exec_ctrl = pvm_refresh_apicv_exec_ctrl,
	.deliver_interrupt = pvm_deliver_interrupt,

	.get_exit_info = pvm_get_exit_info,
	.get_entry_info = pvm_get_entry_info,

	.vcpu_after_set_cpuid = pvm_vcpu_after_set_cpuid,
	.get_fixed_cpuid = pvm_get_fixed_cpuid,

	.recalc_intercepts = pvm_recalc_intercepts,

	.pi_update_irte = pvm_pi_update_irte,

	.check_intercept = pvm_check_intercept,
	.handle_exit_irqoff = pvm_handle_exit_irqoff,

	.setup_mce = pvm_setup_mce,

#ifdef CONFIG_KVM_SMM
	.smi_allowed = pvm_smi_allowed,
	.enter_smm = pvm_enter_smm,
	.leave_smm = pvm_leave_smm,
	.enable_smi_window = pvm_enable_smi_window,
#endif

	.apic_init_signal_blocked = pvm_apic_init_signal_blocked,
	.complete_emulated_msr = kvm_complete_insn_gp,
	.vcpu_deliver_sipi_vector = kvm_vcpu_deliver_sipi_vector,

	.get_l2_tsc_offset = pvm_get_l2_tsc_offset,
	.get_l2_tsc_multiplier = pvm_get_l2_tsc_multiplier,
	.write_tsc_offset = pvm_write_tsc_offset,
	.write_tsc_multiplier = pvm_write_tsc_multiplier,
	.check_emulate_instruction = pvm_check_emulate_instruction,
	.disallowed_va = pvm_disallowed_va,
	.reload_pinned_pages = pvm_reload_pinned_pages,
};

static struct kvm_x86_init_ops pvm_init_ops __initdata = {
	.hardware_setup = pvm_hardware_setup,

	.runtime_ops = &pvm_x86_ops,
	.pmu_ops = &pvm_pmu_ops,
	.nested_ops = &pvm_nested_ops,
};

static void pvm_exit(void)
{
	kvm_exit();
	kvm_x86_vendor_exit();
	host_mmu_destroy();
	allow_smaller_maxphyaddr = false;
}
module_exit(pvm_exit);

static int __init hardware_cap_check(void)
{
	/*
	 * The PVM and the host PCID spaces must be disjoint.  The lowest PCID
	 * PVM can emit is PVM_ASID_MIN << PVM_ASID_SHIFT and the host's dynamic
	 * ASIDs run up to TLB_NR_DYN_ASIDS, so that is the whole requirement.
	 * TLB_NR_DYN_ASIDS is taken from <asm/tlbflush.h> rather than restated
	 * here, so that raising it on the host side breaks this build instead
	 * of silently colliding with a guest PCID.
	 */
	BUILD_BUG_ON((PVM_ASID_MIN << PVM_ASID_SHIFT) <= TLB_NR_DYN_ASIDS);
	BUILD_BUG_ON(PVM_ASID_MAX < PVM_ASID_MIN);

	/* The signature is read out of ebx/ecx/edx, so it is exactly 12 bytes. */
	BUILD_BUG_ON(sizeof(PVM_SIGNATURE) - 1 != 12);
	/* One 0x100 hypervisor sub-class, and nothing outside it. */
	BUILD_BUG_ON((PVM_CPUID_MAX & ~0xffU) != PVM_CPUID_SIGNATURE);

	/*
	 * The hardware floor, and the switcher's hooks in the host entry code.
	 * X86_FEATURE_PVM_HOST is set at boot only for a kernel booted with
	 * pvm_host on a host without KPTI or FRED, with FSGSBASE, PCID and
	 * INVPCID, and not a Xen PV guest; the boot log says which one failed.
	 * PVM targets processors that do not need page table isolation --
	 * Intel from Cascade Lake/Ice Lake on, every AMD Zen -- and supports
	 * nothing older: no KPTI-aware switcher paths, no flush-everything
	 * fallbacks.
	 */
	if (!boot_cpu_has(X86_FEATURE_PVM_HOST)) {
		pr_warn("the host entry code was not set up for PVM: boot with pvm_host on a host without KPTI or FRED, with FSGSBASE, PCID and INVPCID.\n");
		return -EOPNOTSUPP;
	}

	/*
	 * A guest kernel page and a guest user page are both USER to the
	 * hardware, so the guest-kernel-executes-guest-user case is blocked by
	 * setting NX on the user mapping.  Without host NX there is nothing to
	 * set, and the guest would silently lose the protection SMEP gives it.
	 */
	if (!boot_cpu_has(X86_FEATURE_NX)) {
		pr_warn("NX is required: SMEP is emulated with it.\n");
		return -EOPNOTSUPP;
	}
	if (!boot_cpu_has(X86_FEATURE_RDTSCP)) {
		pr_warn("RDTSCP is required to support for getcpu in guest vdso.\n");
		return -EOPNOTSUPP;
	}
	if (!boot_cpu_has(X86_FEATURE_CX16)) {
		pr_warn("CMPXCHG16B is required for guest.\n");
		return -EOPNOTSUPP;
	}
	if (!boot_cpu_has(X86_FEATURE_CPUID_FAULT) && enable_cpuid_intercept) {
		pr_warn("Host doesn't support cpuid faulting.\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

/*
 * A confidential-computing host takes #VE (TDX) or #VC (SEV-ES) for
 * instructions the guest runs at CPL3, and the switcher has no path to hand
 * those to the host's handlers with the host's state loaded.
 */
static int __init pvm_check_confidential_host(void)
{
	if (boot_cpu_has(X86_FEATURE_TDX_GUEST) ||
	    cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT)) {
		pr_warn("PVM cannot run on a TDX or SEV-ES host.\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int __init pvm_init(void)
{
	int r;

	/*
	 * Not every operation a vendor module has to provide is in place yet,
	 * so refuse to load.
	 */
	return -EOPNOTSUPP;

	r = pvm_check_confidential_host();
	if (r)
		return r;

	r = hardware_cap_check();
	if (r)
		return r;

	r = host_mmu_init();
	if (r)
		return r;

	is_intel = boot_cpu_data.x86_vendor == X86_VENDOR_INTEL;

	r = kvm_x86_vendor_init(&pvm_init_ops);
	if (r)
		goto exit_host_mmu;

	r = kvm_init(sizeof(struct vcpu_pvm), __alignof__(struct vcpu_pvm), THIS_MODULE);
	if (r)
		goto exit_vendor;

	return 0;

exit_vendor:
	kvm_x86_vendor_exit();
exit_host_mmu:
	host_mmu_destroy();
	allow_smaller_maxphyaddr = false;
	return r;
}
module_init(pvm_init);
