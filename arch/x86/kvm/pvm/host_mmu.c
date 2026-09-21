// SPDX-License-Identifier: GPL-2.0-only
/*
 * PVM host mmu implementation
 *
 * Copyright (C) 2020 Ant Group
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kvm_host.h>

#include <asm/cpufeature.h>
#include <asm/vsyscall.h>
#include <asm/pgtable.h>

#include "mmu.h"
#include "mmu/spte.h"
#include "pvm.h"

/*
 * The root template every PVM guest runs on: the host's upper half with
 * _PAGE_USER stripped, and an empty lower half for the guest's shadow tree.
 *
 * The top-level entries are copied once, at module load.  The host's kernel
 * half gains a top-level entry later only when the direct map grows into a
 * range it did not cover (memory hotplug, with 4-level or 5-level paging), and
 * such an entry is missing here.  The switcher runs on this root only through
 * entry text, per-CPU data and stacks, all mapped at boot, and through the
 * PVCS it reads from the direct map, so pvm_pin_vcpu_struct() refuses a PVCS
 * page the template does not map.
 */
static __init void clone_host_mmu(u64 *spt, u64 *host)
{
	int i;

	/* Clearing the user bit also hides the vsyscall page from the guest. */
	for (i = PTRS_PER_PGD / 2; i < PTRS_PER_PGD; i++)
		spt[i] = host[i] & ~(_PAGE_USER | SPTE_MMU_PRESENT_MASK);
}

u64 *host_mmu_root_pgd;

/*
 * S6 and M2 in Documentation/virt/kvm/x86/pvm-invariants.rst: the root a
 * guest runs on must map nothing of host user space, and every host mapping
 * cloned into it must have lost _PAGE_USER, since that bit is the only thing
 * standing between a CPL3 guest and host kernel memory through the shared
 * root.  SPTE_MMU_PRESENT_MASK goes with it: a cloned host entry is not
 * a shadow page and must not be walked as one.
 *
 * Both hold by construction -- the page is zeroed and clone_host_mmu() starts
 * at PTRS_PER_PGD/2 -- and are checked anyway, so that a mistake fails the
 * module load rather than handing the guest the host.
 */
static __init int verify_host_mmu_root(void)
{
	int i;

	for (i = 0; i < PTRS_PER_PGD / 2; i++) {
		if (host_mmu_root_pgd[i]) {
			pr_err("host root maps host user space at index %d\n", i);
			return -EINVAL;
		}
	}

	for (i = PTRS_PER_PGD / 2; i < PTRS_PER_PGD; i++) {
		if (host_mmu_root_pgd[i] & (_PAGE_USER | SPTE_MMU_PRESENT_MASK)) {
			pr_err("host root entry %d is reachable from the guest: %llx\n",
			       i, host_mmu_root_pgd[i]);
			return -EINVAL;
		}
	}

	return 0;
}

int __init host_mmu_init(void)
{
	u64 *host_pgd = (void *)current->active_mm->pgd;

	host_mmu_root_pgd = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!host_mmu_root_pgd)
		return -ENOMEM;

	clone_host_mmu(host_mmu_root_pgd, host_pgd);

	if (verify_host_mmu_root()) {
		host_mmu_destroy();
		return -EINVAL;
	}

	return 0;
}

void host_mmu_destroy(void)
{
	if (host_mmu_root_pgd)
		free_page((unsigned long)(void *)host_mmu_root_pgd);
	host_mmu_root_pgd = NULL;
}
