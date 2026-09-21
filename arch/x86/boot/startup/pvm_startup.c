// SPDX-License-Identifier: GPL-2.0
/*
 * Early relocation of a PVM guest.
 *
 * A PVM guest may only use the lower half of the address space: the upper half
 * is the host's, which is what lets the guest run at hardware CPL3 inside it.
 * That excludes the top 2GB the kernel is normally linked at, so the image has
 * to relocate itself before anything uses a kernel virtual address.
 *
 * This runs from the identity mapping, before the relocation table has been
 * applied.  It relies on being built as PIE with hidden visibility, which is
 * what CONFIG_X86_PIE gives the whole kernel: every reference to a global is
 * a plain %rip-relative lea with no GOT, so it resolves to the identity
 * address the code is currently executing from.  objtool --noabs rejects any
 * absolute reference in this object (see the Makefile), and nothing here may
 * call into instrumented code.
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pgtable.h>
#include <linux/sizes.h>

#include <asm/init.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/pvm_para.h>
#include <asm/sections.h>
#include <asm/setup.h>

/*
 * The current virtual address of _text, from head_64.S: data that holds an
 * absolute reference, so it has been relocated along with the rest of the
 * image by the decompressor's KASLR or by an earlier pvm_relocate_kernel().
 */
extern unsigned long pvm_text_va;

static bool __init check_la57(void)
{
	return !!(native_read_cr4() & X86_CR4_LA57);
}

#ifdef CONFIG_PVH
/*
 * The PVH entry point runs on its own page tables.  Their entries are built as
 * "sym - __START_KERNEL_map", which is a physical address but carries a
 * relocation, and pvh_start_xen() has already fixed them up for the load
 * address.  Unlike early_top_pgt, nothing fixes them up again after
 * relocation, and this code is still running on them, so skip them.
 *
 * pvh_level2_ident_pgt is not listed: it maps large pages and refers to no
 * symbol, so it has no relocations.
 */
static bool __init in_page(unsigned long ptr, const char *base)
{
	return ptr >= (unsigned long)base &&
	       ptr < (unsigned long)base + PAGE_SIZE;
}

/*
 * Deliberately four separate comparisons rather than a table: a static array
 * of pointers lives in .data.rel.ro with its own relocations, so before the
 * relocation table has been applied it would hold link-time virtual addresses
 * rather than the identity addresses this code runs on.  Taken one at a time,
 * each symbol reference is a plain %rip-relative lea.
 */
static bool __init is_in_pvh_pgtable(unsigned long ptr)
{
	return in_page(ptr, pvh_init_top_pgt) ||
	       in_page(ptr, pvh_level3_ident_pgt) ||
	       in_page(ptr, pvh_level3_kernel_pgt) ||
	       in_page(ptr, pvh_level2_kernel_pgt);
}

/*
 * Alias the range the kernel just moved to onto the identity mapping.
 *
 * Relocation rewrites every absolute reference to the new virtual address,
 * but the code doing it, and everything up to __startup_64() building its
 * own page tables, still executes from the identity mapping.  In between,
 * xen_prepare_pvh() calls through relocated pv_ops pointers.
 *
 * pvh_init_top_pgt maps the low 1GB at both 0 and PAGE_OFFSET through
 * pvh_level3_ident_pgt.  Point the new base's slots at the same tables and
 * both addresses resolve to the same physical memory, which is all that is
 * needed until __startup_64() takes over.  This relies on the image being
 * loaded at its link-time physical address, as the PVH boot protocol does.
 */
static void __init pvm_update_pgtable(unsigned long virtbase)
{
	pgdval_t *pgd = (pgdval_t *)pvh_init_top_pgt;
	pudval_t *pud = (pudval_t *)pvh_level3_ident_pgt;

	/*
	 * Only if these are the tables in use.  pvm_relocate_kernel() is also
	 * called from startup_64(), where CR3 is whatever the boot loader
	 * built and pvh_init_top_pgt is not live.  Running at the identity
	 * mapping, a %rip-relative reference to it is its physical address,
	 * so this comparison is exact.
	 */
	if (__native_read_cr3() != (unsigned long)pvh_init_top_pgt)
		return;

	pgd[pgd_index(virtbase)] = pgd[0];
	pgd[pgd_index(page_offset_base)] = pgd[0];
	pud[pud_index(virtbase)] = pud[0];
}
#else
static bool __init is_in_pvh_pgtable(unsigned long ptr)
{
	return false;
}

static void __init pvm_update_pgtable(unsigned long virtbase)
{
}
#endif

/*
 * Apply the relocation table that "relocs --keep" wrote to the end of
 * .data.reloc.  Read backwards from __relocation_end, it holds:
 *
 *	32-bit relocations, terminated by a zero
 *	64-bit relocations, terminated by a zero
 *
 * Each entry is the link-time address of a place to fix up.  The 32-bit list
 * is always empty for a PIE kernel, which "relocs --keep" enforces: a 32-bit
 * field cannot hold an address in the lower half.
 *
 * The image may already have been moved by the decompressor's KASLR, so the
 * delta is taken from where it currently is rather than from where it was
 * linked.
 */
static void __init __relocate_kernel(unsigned long physbase,
				     unsigned long virtbase)
{
	s32 *reloc = (s32 *)__relocation_end;
	unsigned long base = pvm_text_va - (__START_KERNEL - __START_KERNEL_map);
	unsigned long delta = virtbase - base;
	unsigned long map = physbase - __START_KERNEL;
	unsigned long ptr;

	if (!delta)
		return;

	/* The 32-bit list must be empty; stop here rather than ignore it. */
	if (*--reloc)
		for (;;);

	while (*--reloc) {
		ptr = (unsigned long)((long)*reloc + map);
		if (is_in_pvh_pgtable(ptr))
			continue;
		*(u64 *)ptr += delta;
	}
}

bool pvm_detected __initdata;
unsigned long pvm_task_size_max __ro_after_init;

void __init pvm_relocate_kernel(unsigned long physbase)
{
	unsigned long kernel_half, virtbase;

	if (!pvm_detect())
		return;

	pvm_detected = true;
	kernel_half = check_la57() ? PVM_KERNEL_HALF_L5 : PVM_KERNEL_HALF_L4;

	/*
	 * User space stops one page below the kernel half.  TASK_SIZE_MAX is
	 * what USER_PTR_MAX, and so access_ok() and the get_user()/put_user()
	 * masking, are derived from, which keeps a guest user process out of
	 * the guest kernel.
	 */
	pvm_task_size_max = kernel_half - PAGE_SIZE;

	/*
	 * An early page fault maps pages into the direct mapping area, so
	 * page_offset_base has to be correct before that can happen.
	 */
	page_offset_base = kernel_half;

	/*
	 * The image goes in the last 2GB of the kernel half.  kernel_map_base
	 * is set from the moved image in __startup_64(), which also moves the
	 * page tables to match.
	 */
	virtbase = 2 * kernel_half - SZ_2G;
	__relocate_kernel(physbase, virtbase);

	/* The moved addresses have to resolve before __startup_64() runs. */
	pvm_update_pgtable(virtbase);
}
