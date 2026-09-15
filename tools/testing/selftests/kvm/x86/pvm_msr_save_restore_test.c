// SPDX-License-Identifier: GPL-2.0-only
/*
 * Save and restore of the PVM MSRs.
 *
 * MSR_PVM_VCPU_STRUCT, MSR_PVM_EVENT_ENTRY, MSR_PVM_RETU_RIP and
 * MSR_PVM_FEATURES_ENABLED are per-vCPU state of a PVM guest.  A VMM finds
 * them through KVM_GET_MSR_INDEX_LIST, which must report them with kvm-pvm
 * and only with kvm-pvm.  They must read back exactly what the host wrote,
 * and restore in the order a VMM uses: MSRs before the memslot that holds
 * the PVCS.
 */
#include <unistd.h>

#include <asm/pvm_para.h>
#include <linux/stringify.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define PVCS_SLOT	10
#define PVCS_GPA	0xc0000000ull

/* Canonical lower-half addresses, never reached by the guest below. */
#define EVENT_ENTRY	0x00007f0012340000ull
#define RETU_RIP	0x00007f0012346000ull

static const u32 pvm_msrs[] = {
	MSR_PVM_VCPU_STRUCT,
	MSR_PVM_EVENT_ENTRY,
	MSR_PVM_RETU_RIP,
	MSR_PVM_FEATURES_ENABLED,
};

static void guest_code(void)
{
	u32 eax = PVM_CPUID_FEATURES, ebx, ecx = 0, edx;

	asm volatile(".byte " __stringify(PVM_SYNTHETIC_CPUID)
	    : "=a" (eax),
	      "=b" (ebx),
	      "=c" (ecx),
	      "=d" (edx)
	    : "0" (eax), "2" (ecx)
	    : "memory");

	GUEST_SYNC(ebx);
	GUEST_SYNC(0);
	GUEST_DONE();
}

static u64 run_to_ucall(struct kvm_vcpu *vcpu, u64 expected)
{
	struct ucall uc;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		TEST_ASSERT_EQ(expected, UCALL_SYNC);
		return uc.args[1];
	case UCALL_DONE:
		TEST_ASSERT_EQ(expected, UCALL_DONE);
		return 0;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	default:
		TEST_FAIL("Unexpected ucall %lu", uc.cmd);
	}
	return 0;
}

static void check_msrs(struct kvm_vcpu *vcpu, const u64 *values, const char *when)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pvm_msrs); i++) {
		u64 val = vcpu_get_msr(vcpu, pvm_msrs[i]);

		TEST_ASSERT(val == values[i],
			    "MSR 0x%x %s: got 0x%lx, expected 0x%lx",
			    pvm_msrs[i], when, val, values[i]);
	}
}

static void check_index_list(bool pvm)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pvm_msrs); i++)
		TEST_ASSERT(kvm_msr_is_in_save_restore_list(pvm_msrs[i]) == pvm,
			    "MSR 0x%x is %sin KVM_GET_MSR_INDEX_LIST with%s kvm-pvm",
			    pvm_msrs[i], pvm ? "not " : "", pvm ? "" : "out");
}

int main(void)
{
	const u64 zero[ARRAY_SIZE(pvm_msrs)] = {};
	u64 values[ARRAY_SIZE(pvm_msrs)];
	struct kvm_x86_state *state;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	char pvcs[PAGE_SIZE];
	bool pvm;
	int i, j;

	pvm = !access("/sys/module/kvm_pvm", F_OK);
	check_index_list(pvm);
	TEST_REQUIRE(pvm);

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	/* 0 at reset, all four. */
	check_msrs(vcpu, zero, "at reset");

	/* The guest reads what MSR_PVM_FEATURES_ENABLED accepts. */
	values[0] = PVCS_GPA;
	values[1] = EVENT_ENTRY;
	values[2] = RETU_RIP;
	values[3] = run_to_ucall(vcpu, UCALL_SYNC);

	TEST_ASSERT(_vcpu_set_msr(vcpu, MSR_PVM_FEATURES_ENABLED, BIT_ULL(63)) == 0,
		    "MSR_PVM_FEATURES_ENABLED accepted an unknown feature");

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, PVCS_GPA,
				    PVCS_SLOT, 1, 0);
	for (i = 0; i < ARRAY_SIZE(pvm_msrs); i++)
		vcpu_set_msr(vcpu, pvm_msrs[i], values[i]);
	check_msrs(vcpu, values, "after set");

	run_to_ucall(vcpu, UCALL_SYNC);
	check_msrs(vcpu, values, "after running");

	/* What a VMM saves: every MSR in KVM_GET_MSR_INDEX_LIST. */
	state = vcpu_save_state(vcpu);
	for (i = 0; i < ARRAY_SIZE(pvm_msrs); i++) {
		for (j = 0; j < state->msrs.nmsrs; j++)
			if (state->msrs.entries[j].index == pvm_msrs[i])
				break;
		TEST_ASSERT(j < state->msrs.nmsrs, "MSR 0x%x not saved", pvm_msrs[i]);
		TEST_ASSERT_EQ(state->msrs.entries[j].data, values[i]);
	}
	memcpy(pvcs, addr_gpa2hva(vm, PVCS_GPA), PAGE_SIZE);

	/*
	 * The second VM gets the PVCS memslot only after its MSRs are restored,
	 * so MSR_PVM_VCPU_STRUCT names a page that is not there yet.
	 */
	vm_mem_region_delete(vm, PVCS_SLOT);
	kvm_vm_release(vm);
	vcpu = vm_recreate_with_one_vcpu(vm);
	check_msrs(vcpu, zero, "in the new vCPU");

	vcpu_load_state(vcpu, state);
	kvm_x86_state_cleanup(state);
	check_msrs(vcpu, values, "restored without the memslot");

	/* The order does not matter either. */
	for (i = ARRAY_SIZE(pvm_msrs) - 1; i >= 0; i--)
		vcpu_set_msr(vcpu, pvm_msrs[i], values[i]);
	check_msrs(vcpu, values, "restored in reverse order");

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, PVCS_GPA,
				    PVCS_SLOT, 1, 0);
	memcpy(addr_gpa2hva(vm, PVCS_GPA), pvcs, PAGE_SIZE);
	check_msrs(vcpu, values, "after adding the memslot");

	/* The PVCS is pinned again on entry and the guest carries on. */
	run_to_ucall(vcpu, UCALL_DONE);
	check_msrs(vcpu, values, "after running the restored guest");

	kvm_vm_free(vm);
	return 0;
}
