// SPDX-License-Identifier: GPL-2.0-only
/*
 * A PMU that answers nothing, for PVM.
 *
 * KVM requires every vendor module to supply kvm_pmu_ops, but the PMU
 * implementations live inside kvm-intel.ko and kvm-amd.ko rather than in
 * modules of their own, so kvm-pvm.ko cannot reuse either.  A PVM guest sees
 * no PMU at all: every counter MSR is invalid and RDPMC faults.
 */

#include <linux/kvm_host.h>

#include "pmu.h"
#include "pvm.h"

static struct kvm_pmc *pvm_pmu_rdpmc_ecx_to_pmc(struct kvm_vcpu *vcpu,
						unsigned int idx, u64 *mask)
{
	return NULL;
}

static int pvm_pmu_check_rdpmc_early(struct kvm_vcpu *vcpu, unsigned int idx)
{
	return -EINVAL;
}

static struct kvm_pmc *pvm_pmu_msr_idx_to_pmc(struct kvm_vcpu *vcpu, u32 msr)
{
	return NULL;
}

static bool pvm_pmu_is_valid_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	return false;
}

static int pvm_pmu_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	return 1;
}

static int pvm_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	return 1;
}

static void pvm_pmu_refresh(struct kvm_vcpu *vcpu)
{
}

static void pvm_pmu_init(struct kvm_vcpu *vcpu)
{
}

static void pvm_pmu_reset(struct kvm_vcpu *vcpu)
{
}

/*
 * Mandatory in kvm_pmu_ops, called only for a vCPU with a mediated PMU, which
 * needs is_mediated_pmu_supported() -- not provided -- so never here.
 */
static void pvm_pmu_mediated_load(struct kvm_vcpu *vcpu)
{
}

static void pvm_pmu_mediated_put(struct kvm_vcpu *vcpu)
{
}

struct kvm_pmu_ops pvm_pmu_ops = {
	.rdpmc_ecx_to_pmc = pvm_pmu_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = pvm_pmu_msr_idx_to_pmc,
	.check_rdpmc_early = pvm_pmu_check_rdpmc_early,
	.is_valid_msr = pvm_pmu_is_valid_msr,
	.get_msr = pvm_pmu_get_msr,
	.set_msr = pvm_pmu_set_msr,
	.refresh = pvm_pmu_refresh,
	.init = pvm_pmu_init,
	.reset = pvm_pmu_reset,
	.mediated_load = pvm_pmu_mediated_load,
	.mediated_put = pvm_pmu_mediated_put,
};
