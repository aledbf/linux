// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KVM PVM paravirt_ops implementation
 *
 * Copyright (C) 2020 Ant Group
 */
#define pr_fmt(fmt) "pvm-guest: " fmt

#include <linux/mm_types.h>

#include <asm/cpufeature.h>
#include <asm/cpu_entry_area.h>
#include <asm/desc.h>
#include <asm/pvm_para.h>
#include <asm/setup.h>
#include <asm/traps.h>

DEFINE_PER_CPU_PAGE_ALIGNED(struct pvm_vcpu_struct, pvm_vcpu_struct);
static DEFINE_PER_CPU(unsigned long, pvm_guest_cr3);

/* PVM_CPUID_FEATURES.ebx: the PVM_FEATURE_* the hypervisor offers. */
static u32 pvm_features __ro_after_init;

/*
 * PVM_FEATURE_DIRECT_PF: take user not-present faults that the hypervisor
 * delivers without walking our page tables.  The price is the occasional
 * fault on a PTE that is already present, which do_user_addr_fault() handles
 * like any fault that finds the mapping in place -- it returns, and counts a
 * minor fault.  Such a fault carries no X86_PF_PK even when a protection key
 * denies the access; access_error() and bad_area_access_from_pkeys() check
 * the VMA's key against read_pkru() and deliver SEGV_PKUERR all the same.
 *
 * "pvm_direct_pf=off" declines the feature, to tell whether a fault handling
 * problem, such as a task that keeps faulting on the same address, comes from
 * the direct delivery or the hypervisor's regular path.
 */
static bool pvm_direct_pf __ro_after_init = true;

static int __init parse_pvm_direct_pf(char *arg)
{
	return kstrtobool(arg, &pvm_direct_pf);
}
early_param("pvm_direct_pf", parse_pvm_direct_pf);

/*
 * Until idt.c installs the real handlers, early events go to
 * do_early_exception(), as they would through the early IDT.
 */
static enum {
	PVM_EARLY_EXCEPTIONS,
	PVM_EARLY_TRAPS,	/* #DB and #BP have their real handlers */
	PVM_EARLY_PF,		/* ... and so has #PF */
} pvm_early_stage __initdata;

static __always_inline long pvm_hypercall0(unsigned int nr)
{
	long ret;

	asm volatile("call pvm_hypercall"
		     : ASM_CALL_CONSTRAINT, "=a"(ret)
		     : "a"(nr)
		     : "memory");
	return ret;
}

static __always_inline long pvm_hypercall1(unsigned int nr, unsigned long p1)
{
	long ret;

	asm volatile("call pvm_hypercall"
		     : ASM_CALL_CONSTRAINT, "=a"(ret)
		     : "a"(nr), "b"(p1)
		     : "memory");
	return ret;
}

static __always_inline long pvm_hypercall2(unsigned int nr, unsigned long p1,
					   unsigned long p2)
{
	long ret;

	asm volatile("call pvm_hypercall"
		     : ASM_CALL_CONSTRAINT, "=a"(ret)
		     : "a"(nr), "b"(p1), "c"(p2)
		     : "memory");
	return ret;
}

static __always_inline long pvm_hypercall3(unsigned int nr, unsigned long p1,
					   unsigned long p2, unsigned long p3)
{
	long ret;

	asm volatile("call pvm_hypercall"
		     : ASM_CALL_CONSTRAINT, "=a"(ret)
		     : "a"(nr), "b"(p1), "c"(p2), "d"(p3)
		     : "memory");
	return ret;
}

static void pvm_load_gs_index(unsigned int sel)
{
	if (sel & SEGMENT_TI_MASK) {
		pr_warn_once("pvm guest doesn't support LDT\n");
		this_cpu_write(pvm_vcpu_struct.user_gsbase, 0);
	} else {
		unsigned long base;

		preempt_disable();
		base = pvm_hypercall1(PVM_HC_LOAD_GS, sel);
		__this_cpu_write(pvm_vcpu_struct.user_gsbase, base);
		preempt_enable();
	}
}

/* PVM_HC_RDMSR returns a status in RAX and the value in RDX. */
static __always_inline long pvm_hypercall_rdmsr(u32 msr, u64 *val)
{
	unsigned long value;
	long ret;

	asm volatile("call pvm_hypercall"
		     : ASM_CALL_CONSTRAINT, "=a"(ret), "=d"(value)
		     : "a"((unsigned long)PVM_HC_RDMSR), "b"((unsigned long)msr)
		     : "memory");
	*val = value;
	return ret;
}

static int notrace pvm_read_msr_safe(u32 msr, u64 *val)
{
	switch (msr) {
	case MSR_FS_BASE:
		*val = rdfsbase();
		return 0;
	case MSR_KERNEL_GS_BASE:
		*val = this_cpu_read(pvm_vcpu_struct.user_gsbase);
		return 0;
	default:
		return pvm_hypercall_rdmsr(msr, val) ? -EIO : 0;
	}
}

static u64 notrace pvm_read_msr(u32 msr)
{
	u64 val;

	if (pvm_read_msr_safe(msr, &val)) {
		pr_warn_once("unchecked MSR access error: RDMSR from 0x%x\n", msr);
		val = 0;
	}
	return val;
}

static int notrace pvm_write_msr_safe(u32 msr, u64 val)
{
	unsigned long base = val;

	switch (msr) {
	case MSR_FS_BASE:
		wrfsbase(base);
		return 0;
	case MSR_KERNEL_GS_BASE:
		this_cpu_write(pvm_vcpu_struct.user_gsbase, base);
		return 0;
	default:
		return pvm_hypercall2(PVM_HC_WRMSR, msr, base) ? -EIO : 0;
	}
}

static void notrace pvm_write_msr(u32 msr, u64 val)
{
	if (pvm_write_msr_safe(msr, val))
		pr_warn_once("unchecked MSR access error: WRMSR to 0x%x (tried to write 0x%016llx)\n",
			     msr, val);
}

static void pvm_load_tls(struct thread_struct *t, unsigned int cpu)
{
	struct desc_struct *gdt = get_cpu_gdt_rw(cpu);
	unsigned long *tls_array = (unsigned long *)gdt;

	if (memcmp(&gdt[GDT_ENTRY_TLS_MIN], &t->tls_array[0], sizeof(t->tls_array))) {
		native_load_tls(t, cpu);
		pvm_hypercall3(PVM_HC_LOAD_TLS, tls_array[GDT_ENTRY_TLS_MIN],
			       tls_array[GDT_ENTRY_TLS_MIN + 1],
			       tls_array[GDT_ENTRY_TLS_MIN + 2]);
	}
}

static noinstr void pvm_safe_halt(void)
{
	pvm_hypercall0(PVM_HC_IRQ_HLT);
}

/*
 * The PVCS holds the guest's CR2: the hypervisor fills it in when it delivers
 * a #PF and reads it back on every exit.
 */
static noinstr void pvm_write_cr2(unsigned long cr2)
{
	this_cpu_write(pvm_vcpu_struct.cr2, cr2);
}

static unsigned long pvm_read_cr3(void)
{
	return this_cpu_read(pvm_guest_cr3);
}

static void pvm_write_cr3(unsigned long val)
{
	unsigned long flags = (val & X86_CR3_PCID_NOFLUSH) ? 0 : PVM_LOAD_PGTBL_FLAGS_TLB;
	unsigned long pgd = val & ~X86_CR3_PCID_NOFLUSH;

	if (pgtable_l5_enabled())
		flags |= PVM_LOAD_PGTBL_FLAGS_LA57;
	this_cpu_write(pvm_guest_cr3, pgd);
	pvm_hypercall2(PVM_HC_LOAD_PGTBL, flags, pgd);
}

static void pvm_flush_tlb_user(void)
{
	pvm_hypercall0(PVM_HC_TLB_FLUSH_CURRENT);
}

static void pvm_flush_tlb_kernel(void)
{
	pvm_hypercall0(PVM_HC_TLB_FLUSH);
}

static void pvm_flush_tlb_one_user(unsigned long addr)
{
	pvm_hypercall1(PVM_HC_TLB_INVLPG, addr);
}

void __init pvm_early_event(struct pt_regs *regs, u32 vector, u32 errcode)
{
	if (unlikely(!(vector & PVM_PVCS_EVENT_VECTOR_STD)))
		return;
	vector &= 0xFF;

	switch (vector) {
	case X86_TRAP_DB:
		if (pvm_early_stage < PVM_EARLY_TRAPS)
			break;
		exc_debug(regs);
		return;
	case X86_TRAP_BP:
		if (pvm_early_stage < PVM_EARLY_TRAPS)
			break;
		exc_int3(regs);
		return;
	case X86_TRAP_PF:
		if (pvm_early_stage < PVM_EARLY_PF)
			break;
		exc_page_fault(regs, errcode);
		return;
	}

	do_early_exception(regs, vector);
}

/* Called after idt_setup_early_traps(). */
void __init pvm_setup_early_traps(void)
{
	pvm_early_stage = PVM_EARLY_TRAPS;
}

/*
 * Called after idt_setup_early_pf(), which says why a #PF keeps going to
 * early_make_pgtable() until then.
 */
void __init pvm_setup_early_pf(void)
{
	pvm_early_stage = PVM_EARLY_PF;
}

static noinstr void pvm_bad_event(struct pt_regs *regs, unsigned long vector,
				  unsigned long error_code)
{
	irqentry_state_t irq_state = irqentry_nmi_enter(regs);

	instrumentation_begin();

	/* In NMI context die() panics. */
	if (!user_mode(regs)) {
		pr_emerg("invalid or fatal PVM event: vector %lu\n", vector);
		die("invalid or fatal PVM event", regs, error_code);
	} else {
		unsigned long flags = oops_begin();
		int sig = SIGKILL;

		pr_alert("BUG: invalid or fatal PVM event; vector %lu error 0x%lx at %04lx:%016lx\n",
			 vector, error_code, (unsigned long)regs->cs, regs->ip);

		if (__die("Invalid or fatal PVM event", regs, error_code))
			sig = 0;

		oops_end(flags, regs, sig);
	}
	instrumentation_end();
	irqentry_nmi_exit(regs, irq_state);
}

/* There is no IST on PVM; pick the handler by the mode the event came from. */
static noinstr void pvm_exc_debug(struct pt_regs *regs)
{
	if (user_mode(regs))
		noist_exc_debug(regs);
	else
		exc_debug(regs);
}

#ifdef CONFIG_X86_MCE
static noinstr void pvm_exc_machine_check(struct pt_regs *regs)
{
	if (user_mode(regs))
		noist_exc_machine_check(regs);
	else
		exc_machine_check(regs);
}
#endif

static noinstr void pvm_exception(struct pt_regs *regs, unsigned long vector,
				  unsigned long error_code)
{
	switch (vector) {
	case X86_TRAP_DE: return exc_divide_error(regs);
	case X86_TRAP_DB: return pvm_exc_debug(regs);
	case X86_TRAP_BP: return exc_int3(regs);
	case X86_TRAP_OF: return exc_overflow(regs);
	case X86_TRAP_BR: return exc_bounds(regs);
	case X86_TRAP_UD: return exc_invalid_op(regs);
	case X86_TRAP_NM: return exc_device_not_available(regs);
	case X86_TRAP_TS: return exc_invalid_tss(regs, error_code);
	case X86_TRAP_NP: return exc_segment_not_present(regs, error_code);
	case X86_TRAP_SS: return exc_stack_segment(regs, error_code);
	case X86_TRAP_GP: return exc_general_protection(regs, error_code);
	case X86_TRAP_PF: return exc_page_fault(regs, error_code);
	case X86_TRAP_MF: return exc_coprocessor_error(regs);
	case X86_TRAP_AC: return exc_alignment_check(regs, error_code);
	case X86_TRAP_XF: return exc_simd_coprocessor_error(regs);
#ifdef CONFIG_X86_MCE
	case X86_TRAP_MC: return pvm_exc_machine_check(regs);
#endif
#ifdef CONFIG_X86_CET
	case X86_TRAP_CP: return exc_control_protection(regs, error_code);
#endif
	default: return pvm_bad_event(regs, vector, error_code);
	}
}

static noinstr void pvm_handle_INT80_compat(struct pt_regs *regs)
{
#ifdef CONFIG_IA32_EMULATION
	if (ia32_enabled()) {
		int80_emulation(regs);
		return;
	}
#endif
	exc_general_protection(regs, 0);
}

__visible noinstr void pvm_event(struct pt_regs *regs, u32 vector, u32 errcode)
{
	/* Optimize for #PF. */
	if (likely(vector == (PVM_PVCS_EVENT_VECTOR_STD | X86_TRAP_PF)))
		return exc_page_fault(regs, errcode);

	if (unlikely(vector & (PVM_PVCS_EVENT_VECTOR_NMI | PVM_PVCS_EVENT_VECTOR_MCE))) {
		if (vector & PVM_PVCS_EVENT_VECTOR_MCE)
			pvm_exception(regs, X86_TRAP_MC, 0);
		if (vector & PVM_PVCS_EVENT_VECTOR_NMI)
			exc_nmi(regs);
	}
	if (unlikely(!(vector & PVM_PVCS_EVENT_VECTOR_STD)))
		return;

	vector &= 0xFF;
	if (vector < NUM_EXCEPTION_VECTORS)
		pvm_exception(regs, vector, errcode);
	else if (unlikely(vector == IA32_SYSCALL_VECTOR))
		pvm_handle_INT80_compat(regs);
	else
		external_interrupt(regs, vector);
}

void __init pvm_early_setup(void)
{
	unsigned int eax, ebx, ecx = 0, edx;

	if (!pvm_detected)
		return;

	/*
	 * this_cpu_cmpxchg16b_emu(), the fallback for CPUs without
	 * CMPXCHG16B, relies on POPF restoring IF, which it never does at
	 * CPL3.
	 */
	eax = 1;
	pvm_cpuid(&eax, &ebx, &ecx, &edx);
	if (!(ecx & BIT(13)))		/* CPUID.1:ECX.CX16 */
		panic("PVM guest requires CMPXCHG16B");

	eax = PVM_CPUID_FEATURES;
	ecx = 0;
	pvm_cpuid(&eax, &ebx, &ecx, &edx);
	pvm_features = ebx;

	setup_force_cpu_cap(X86_FEATURE_KVM_PVM_GUEST);
	setup_force_cpu_cap(X86_FEATURE_PV_GUEST);

	/* Don't use SYSENTER (Intel) and SYSCALL32 (AMD) in vdso. */
	setup_clear_cpu_cap(X86_FEATURE_SYSFAST32);
	setup_clear_cpu_cap(X86_FEATURE_SYSCALL32);

	/*
	 * The user GSBASE is PVCS::user_gsbase, which the hypervisor loads on
	 * the return to user mode.
	 */
	pv_ops.cpu.load_gs_index = pvm_load_gs_index;
	pv_ops.cpu.cpuid = pvm_cpuid;

	pv_ops.cpu.read_msr = pvm_read_msr;
	pv_ops.cpu.write_msr = pvm_write_msr;
	pv_ops.cpu.read_msr_safe = pvm_read_msr_safe;
	pv_ops.cpu.write_msr_safe = pvm_write_msr_safe;
	pv_ops.cpu.load_tls = pvm_load_tls;

	pv_ops.irq.save_fl = __PV_IS_CALLEE_SAVE(pvm_save_fl);
	pv_ops.irq.irq_disable = __PV_IS_CALLEE_SAVE(pvm_irq_disable);
	pv_ops.irq.irq_enable = __PV_IS_CALLEE_SAVE(pvm_irq_enable);
	pv_ops.irq.safe_halt = pvm_safe_halt;

	this_cpu_write(pvm_guest_cr3, __native_read_cr3());
	pv_ops.mmu.read_cr2 = __PV_IS_CALLEE_SAVE(pvm_read_cr2);
	pv_ops.mmu.write_cr2 = pvm_write_cr2;
	pv_ops.mmu.read_cr3 = pvm_read_cr3;
	pv_ops.mmu.write_cr3 = pvm_write_cr3;
	pv_ops.mmu.flush_tlb_user = pvm_flush_tlb_user;
	pv_ops.mmu.flush_tlb_kernel = pvm_flush_tlb_kernel;
	pv_ops.mmu.flush_tlb_one_user = pvm_flush_tlb_one_user;

	/*
	 * The boot CPU still runs on the per-CPU area in the kernel image,
	 * where __pa() is valid; pvm_register_pvcs() moves the PVCS to the
	 * runtime per-CPU area once GSBASE points there.
	 */
	wrmsrq(MSR_PVM_VCPU_STRUCT, __pa(this_cpu_ptr(&pvm_vcpu_struct)));
	/*
	 * Supervisor events enter at pvm_early_kernel_event_entry.  The user
	 * entry this implies is unrelated init text, but nothing runs in user
	 * mode before pvm_setup_event_handling() replaces both.
	 */
	wrmsrq(MSR_PVM_EVENT_ENTRY, (unsigned long)pvm_early_kernel_event_entry -
				    PVM_EVENT_ENTRY_SUPERVISOR_OFFSET);
}

/*
 * Register this CPU's PVCS, the pvm_vcpu_struct of its per-CPU area, with the
 * hypervisor.  Called whenever GSBASE moves to a different per-CPU area.  The
 * runtime per-CPU areas may be vmalloc()ed, so the physical address is looked
 * up in the page tables.
 */
void pvm_register_pvcs(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_KVM_PVM_GUEST))
		return;

	wrmsrq(MSR_PVM_VCPU_STRUCT, slow_virt_to_phys(this_cpu_ptr(&pvm_vcpu_struct)));
}

void pvm_setup_event_handling(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_KVM_PVM_GUEST))
		return;

	pvm_register_pvcs();
	wrmsrq(MSR_PVM_EVENT_ENTRY, (unsigned long)pvm_user_event_entry);
	wrmsrq(MSR_PVM_RETU_RIP, (unsigned long)pvm_retu_rip);

	/*
	 * Only now: a direct fault arrives at pvm_user_event_entry.  The MSR
	 * is per vCPU, so every CPU enables it for itself.
	 */
	if (pvm_direct_pf && (pvm_features & PVM_FEATURE_DIRECT_PF))
		wrmsrq(MSR_PVM_FEATURES_ENABLED, PVM_FEATURE_DIRECT_PF);

	/*
	 * The PVM spec requires the hypervisor-maintained MSR_KERNEL_GS_BASE
	 * to be the kernel GSBASE for event delivery from user mode.
	 * wrmsrq(MSR_KERNEL_GS_BASE) only updates the user GSBASE in the PVCS
	 * (see pvm_write_msr_safe()), so use the hypercall directly.
	 */
	pvm_hypercall2(PVM_HC_WRMSR, MSR_KERNEL_GS_BASE,
		       cpu_kernelmode_gs_base(smp_processor_id()));
}

#ifndef CONFIG_RANDOMIZE_MEMORY
/* DIRECT_MAP_PHYSMEM_END in a PVM_GUEST kernel; kaslr.c defines it otherwise. */
unsigned long direct_map_physmem_end __ro_after_init;
#endif

#define TB_SHIFT	40
#define PB_SHIFT	50

#define HOLE_L4_SIZE	(1UL << 39)
#define HOLE_L5_SIZE	(1UL << 48)

#define PVM_DIRECT_MAPPING_L4_SIZE	(8UL << TB_SHIFT)
#define PVM_DIRECT_MAPPING_L5_SIZE	(4UL << PB_SHIFT)
#define PVM_VMALLOC_L4_SIZE		(5UL << TB_SHIFT)
#define PVM_VMALLOC_L5_SIZE		(3UL << PB_SHIFT)
#define PVM_VMEM_MAPPING_L4_SIZE	HOLE_L4_SIZE
#define PVM_VMEM_MAPPING_L5_SIZE	HOLE_L5_SIZE

#define PVM_CPU_ENTRY_AREA_MAP_SIZE	(1UL << 39)
#define PVM_IDENTICAL_AREA_SIZE		(1UL << 40)

/*
 * A PVM guest owns the lower half of the address space and nothing else, so
 * its kernel and its user space share that half: user space below 2^46 (2^55
 * with 5-level paging), the kernel above, up to twice that.  The guest lays
 * its direct mapping, vmalloc area, vmemmap and CPU entry area out inside the
 * kernel half.
 *
 * With 4-level page tables that is 64TB, and the layout is:
 *
 * 0000000000000000 - 00003fffffffffff (=64 TB) guest user space
 * ... guest kernel range start
 * 0000400000000000 - 000047ffffffffff (=8 TB) direct mapping of all physical memory
 * 0000480000000000 - 0000487fffffffff (=0.5 TB) hole
 * 0000488000000000 - 00004d7fffffffff (=5 TB) vmalloc/ioremap space
 * 00004d8000000000 - 00004dffffffffff (=0.5 TB) hole
 * 00004e0000000000 - 00004e7fffffffff (=0.5 TB) virtual memory map
 * ... unused: 53 TB of room the layout does not ask for ...
 * 00007f0000000000 - 00007f7fffffffff (=0.5 TB) cpu_entry_area mapping
 * 00007f8000000000 - 00007fff7fffffff (=510 GB) hole
 * 00007fff80000000 - 00007fffffffffff (=2 GB) kernel image
 * ... guest kernel range end, and the host's half above it
 *
 * With 5-level page tables it is 32PB, in the same order and with the L5
 * sizes below.
 *
 * Two things follow from the halves being where they are.  User space stops
 * one page below the kernel half, which is what TASK_SIZE_MAX says and what
 * access_ok() enforces; and every address the guest can form has bit 63
 * clear, which is the whole of what the host has to check.
 *
 * Modules and the fixmap follow the kernel image, as natively.  The ESPfix
 * and EFI runtime areas keep their native addresses in the host's half, where
 * nothing of the guest can reach them, and nothing needs them: the return to
 * user mode is EVENT_RETURN_USER, which never uses the ESPfix stack, and a
 * PVM guest does not run EFI firmware.
 *
 * The layout replaces memory KASLR: the regions are not randomized.
 */
bool __init pvm_kernel_layout_relocate(void)
{
	unsigned long area_size, kernel_half;
	unsigned long direct_mapping_size, vmalloc_size;
	unsigned long vmem_mapping_size, hole_size;

	/*
	 * A PVM_GUEST kernel always takes DIRECT_MAP_PHYSMEM_END from the
	 * variable; without RANDOMIZE_MEMORY nothing else gives it the native
	 * value.
	 */
	if (!IS_ENABLED(CONFIG_RANDOMIZE_MEMORY))
		direct_map_physmem_end = (1ULL << MAX_PHYSMEM_BITS) - 1;

	if (!cpu_feature_enabled(X86_FEATURE_KVM_PVM_GUEST))
		return false;

	if (pgtable_l5_enabled()) {
		kernel_half = PVM_KERNEL_HALF_L5;
		direct_mapping_size = PVM_DIRECT_MAPPING_L5_SIZE;
		vmalloc_size = PVM_VMALLOC_L5_SIZE;
		vmem_mapping_size = PVM_VMEM_MAPPING_L5_SIZE;
		hole_size = HOLE_L5_SIZE;
	} else {
		kernel_half = PVM_KERNEL_HALF_L4;
		direct_mapping_size = PVM_DIRECT_MAPPING_L4_SIZE;
		vmalloc_size = PVM_VMALLOC_L4_SIZE;
		vmem_mapping_size = PVM_VMEM_MAPPING_L4_SIZE;
		hole_size = HOLE_L4_SIZE;
	}

	area_size = max_pfn << PAGE_SHIFT;
	if (area_size > direct_mapping_size)
		panic("The memory size is too large for the direct mapping area");

	/*
	 * page_offset_base was set to kernel_half by pvm_relocate_kernel().
	 * Memory hotplug must not add memory beyond the direct mapping area,
	 * whose end the vmalloc area follows.
	 */
	direct_map_physmem_end = direct_mapping_size - 1;

	vmalloc_base = page_offset_base + direct_mapping_size + hole_size;
	vmalloc_size_tb = vmalloc_size >> TB_SHIFT;

	vmemmap_base = VMEMORY_END + 1 + hole_size;
	area_size = max_pfn * sizeof(struct page);
	if (area_size > vmem_mapping_size)
		panic("The memory size is too large for virtual memory mapping area");

	/* The CPU entry area starts the last 1TB, below the kernel image. */
	cpu_entry_area_base = 2 * kernel_half - PVM_IDENTICAL_AREA_SIZE;
	BUILD_BUG_ON(CPU_ENTRY_AREA_MAP_SIZE > PVM_CPU_ENTRY_AREA_MAP_SIZE);
	if (cpu_entry_area_base < vmemmap_base + vmem_mapping_size)
		panic("The kernel half is too small for the layout");

	return true;
}
