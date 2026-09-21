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
#include <asm/pvm_para.h>
#include <asm/setup.h>

DEFINE_PER_CPU_PAGE_ALIGNED(struct pvm_vcpu_struct, pvm_vcpu_struct);

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
