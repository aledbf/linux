/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PVM_PARA_H
#define _ASM_X86_PVM_PARA_H

#include <uapi/asm/pvm_para.h>

#ifndef __ASSEMBLER__
#include <linux/init.h>

#ifdef CONFIG_PVM_GUEST
#include <asm/irqflags.h>
#include <uapi/asm/kvm_para.h>

/*
 * A PVM guest owns the lower half of the address space.  Its user space is
 * the lower half of that, and its kernel the upper half, starting here.
 */
#define PVM_KERNEL_HALF_L4	(1UL << 46)
#define PVM_KERNEL_HALF_L5	(1UL << 55)

extern bool pvm_detected;

void __init pvm_relocate_kernel(unsigned long physbase);
bool __init pvm_kernel_layout_relocate(void);

/* The page tables the PVH entry point runs on, from platform/pvh/head.S. */
extern char pvh_init_top_pgt[], pvh_level3_ident_pgt[];
extern char pvh_level3_kernel_pgt[], pvh_level2_kernel_pgt[];

static inline void pvm_cpuid(unsigned int *eax, unsigned int *ebx,
			     unsigned int *ecx, unsigned int *edx)
{
	asm(__ASM_FORM(.byte PVM_SYNTHETIC_CPUID ;)
		: "=a" (*eax),
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));
}

/*
 * Compare the signature a CPUID leaf returns in EBX:ECX:EDX.  Open-coded
 * because pvm_detect() runs from the identity mapping, before memcmp() can
 * be called.
 */
static __always_inline bool pvm_cpuid_has_signature(unsigned int *eax,
						    const char *sig)
{
	unsigned int reg[3] = { 0 };
	const unsigned char *p = (const unsigned char *)reg;
	unsigned int i;

	pvm_cpuid(eax, &reg[0], &reg[1], &reg[2]);
	for (i = 0; i < sizeof(reg); i++) {
		if (p[i] != (unsigned char)sig[i])
			return false;
	}
	return true;
}

/*
 * Detect PVM, from the identity mapping on the boot CPU.  Only a hypervisor
 * that runs the kernel at CPL3 with interrupts enabled gets past the first two
 * checks; under anything else this returns before PVM_SYNTHETIC_CPUID runs.
 */
static inline bool pvm_detect(void)
{
	unsigned int eax, ebx, ecx = 0, edx;
	unsigned long cs;

	/* check the underlying interrupt flag */
	if (arch_irqs_disabled_flags(native_save_fl()))
		return false;

	/* check the underlying CS */
	asm volatile("mov %%cs,%0\n\t" : "=r" (cs) : );
	if ((cs & 3) != 3)
		return false;

	eax = KVM_CPUID_SIGNATURE;
	if (!pvm_cpuid_has_signature(&eax, KVM_SIGNATURE))
		return false;

	/*
	 * Only PVM runs a KVM guest kernel with IF=1 and CPL3, so this is a
	 * PVM hypervisor.  The MSR and hypercall numbers, the PVCS layout and
	 * the address space split are fixed at build time and a mismatch
	 * cannot be detected later, so insist on the ABI revision this kernel
	 * was built for.
	 */
	eax = PVM_CPUID_SIGNATURE;
	if (!pvm_cpuid_has_signature(&eax, PVM_SIGNATURE))
		return false;
	if (eax < PVM_CPUID_FEATURES)
		return false;

	eax = PVM_CPUID_FEATURES;
	pvm_cpuid(&eax, &ebx, &ecx, &edx);
	return eax == PVM_ABI_VERSION;
}
#else
static inline bool pvm_kernel_layout_relocate(void)
{
	return false;
}
#endif /* CONFIG_PVM_GUEST */
#endif /* !__ASSEMBLER__ */

#endif /* _ASM_X86_PVM_PARA_H */
