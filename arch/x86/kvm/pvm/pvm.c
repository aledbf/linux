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

struct pvm_asid_data {
	u64 asid_generation;
	u32 max_asid;
	u32 next_asid;
	u32 min_asid;
};

static DEFINE_PER_CPU(struct pvm_asid_data, pvm_asid);

static bool cpu_has_pvm_wbinvd_exit(void)
{
	return true;
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

	.has_wbinvd_exit = cpu_has_pvm_wbinvd_exit,

	.vm_size = sizeof(struct kvm),
	.vm_init = pvm_vm_init,

	.vcpu_create = pvm_vcpu_create,

#ifdef CONFIG_KVM_SMM
	.smi_allowed = pvm_smi_allowed,
	.enter_smm = pvm_enter_smm,
	.leave_smm = pvm_leave_smm,
	.enable_smi_window = pvm_enable_smi_window,
#endif
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
