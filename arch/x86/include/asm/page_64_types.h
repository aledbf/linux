/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGE_64_DEFS_H
#define _ASM_X86_PAGE_64_DEFS_H

#ifndef __ASSEMBLER__
#include <asm/kaslr.h>

extern unsigned long kernel_map_base;

#ifdef CONFIG_PVM_GUEST
/* The top of a PVM guest's user space, see arch/x86/boot/startup/pvm_startup.c. */
extern unsigned long pvm_task_size_max;
#endif
#endif

#ifdef CONFIG_KASAN
#define KASAN_STACK_ORDER 1
#else
#define KASAN_STACK_ORDER 0
#endif

#define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)

#define EXCEPTION_STACK_ORDER (1 + KASAN_STACK_ORDER)
#define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)

#define IRQ_STACK_ORDER (2 + KASAN_STACK_ORDER)
#define IRQ_STACK_SIZE (PAGE_SIZE << IRQ_STACK_ORDER)

/*
 * The index for the tss.ist[] array. The hardware limit is 7 entries.
 */
#define	IST_INDEX_DF		0
#define	IST_INDEX_NMI		1
#define	IST_INDEX_DB		2
#define	IST_INDEX_MCE		3
#define	IST_INDEX_VC		4

/*
 * Set __PAGE_OFFSET to the most negative possible address +
 * PGDIR_SIZE*17 (pgd slot 273).
 *
 * The gap is to allow a space for LDT remap for PTI (1 pgd slot) and space for
 * a hypervisor (16 slots). Choosing 16 slots for a hypervisor is arbitrary,
 * but it's what Xen requires.
 */
#define __PAGE_OFFSET_BASE_L5	_AC(0xff11000000000000, UL)
#define __PAGE_OFFSET_BASE_L4	_AC(0xffff888000000000, UL)

#define __PAGE_OFFSET           page_offset_base

#define __START_KERNEL_map	_AC(0xffffffff80000000, UL)

/*
 * KERNEL_MAP_BASE is where the kernel image mapping starts: the image, the
 * modules area and the fixmap, 2GB in all.  It is __START_KERNEL_map unless
 * a CONFIG_X86_PIE kernel is moved at boot, and then the new base has to:
 *
 *  - be the start of the second to last PUD entry of its PGD entry (with
 *    5-level paging, of the last P4D entry of its PGD entry), so that only
 *    the PGD entry of the mapping moves and the tables below it stay;
 *  - use a PGD entry that the early identity mapping does not;
 *  - be above PAGE_OFFSET, as pgd_alloc() and the trampoline page table
 *    only share the PGD entries from pgd_index(PAGE_OFFSET) up;
 *  - be above the direct mapping, the vmalloc area and the vmemmap, as
 *    __phys_addr() and __virt_addr_valid() take any address below it for a
 *    direct mapping address.
 *
 * __startup_64() checks the first two, cleanup_highmap() the others once the
 * layout of the kernel half is final.
 */
#ifdef CONFIG_X86_PIE
#define KERNEL_MAP_BASE		kernel_map_base
#else
#define KERNEL_MAP_BASE		__START_KERNEL_map
#endif

/* See Documentation/arch/x86/x86_64/mm.rst for a description of the memory map. */

#define __PHYSICAL_MASK_SHIFT	52
#define __VIRTUAL_MASK_SHIFT	(pgtable_l5_enabled() ? 56 : 47)

#define TASK_SIZE_MAX		task_size_max()
#define DEFAULT_MAP_WINDOW	((1UL << 47) - PAGE_SIZE)

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define IA32_PAGE_OFFSET	((current->personality & ADDR_LIMIT_3GB) ? \
					0xc0000000 : 0xFFFFe000)

#define TASK_SIZE_LOW		(test_thread_flag(TIF_ADDR32) ? \
					IA32_PAGE_OFFSET : DEFAULT_MAP_WINDOW)
#define TASK_SIZE		(test_thread_flag(TIF_ADDR32) ? \
					IA32_PAGE_OFFSET : TASK_SIZE_MAX)
#define TASK_SIZE_OF(child)	((test_tsk_thread_flag(child, TIF_ADDR32)) ? \
					IA32_PAGE_OFFSET : TASK_SIZE_MAX)

#define STACK_TOP		TASK_SIZE_LOW
#define STACK_TOP_MAX		TASK_SIZE_MAX

/*
 * In spite of the name, KERNEL_IMAGE_SIZE is a limit on the maximum virtual
 * address for the kernel image, rather than the limit on the size itself.
 * This can be at most 1 GiB, due to the fixmap living in the next 1 GiB (see
 * level2_kernel_pgt in arch/x86/kernel/head_64.S).
 *
 * On KASLR use 1 GiB by default, leaving 1 GiB for modules once the
 * page tables are fully set up.
 *
 * If KASLR is disabled we can shrink it to 0.5 GiB and increase the size
 * of the modules area to 1.5 GiB.
 */
#ifdef CONFIG_RANDOMIZE_BASE
#define KERNEL_IMAGE_SIZE	(1024 * 1024 * 1024)
#else
#define KERNEL_IMAGE_SIZE	(512 * 1024 * 1024)
#endif

#endif /* _ASM_X86_PAGE_64_DEFS_H */
