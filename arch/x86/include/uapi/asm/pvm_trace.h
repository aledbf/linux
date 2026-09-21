/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_PVM_TRACE_H
#define _UAPI_ASM_X86_PVM_TRACE_H

/*
 * Exit reasons reported by the PVM host in the kvm_exit tracepoint, and the
 * names perf uses to print them.
 *
 * This header is copied verbatim into tools/ and compiled as part of perf, so
 * it has to stand on its own: no kernel headers, and nothing that is not
 * available to user space.  That is why the exception vector numbers are
 * spelled out here rather than pulled in from <asm/irq_vectors.h>, and why
 * the shifts are written out rather than using BIT().
 */

/* Architectural exception vectors, as in <asm/irq_vectors.h>. */
#define PVM_DE_VECTOR				0
#define PVM_DB_VECTOR				1
#define PVM_NMI_VECTOR				2
#define PVM_BP_VECTOR				3
#define PVM_OF_VECTOR				4
#define PVM_BR_VECTOR				5
#define PVM_UD_VECTOR				6
#define PVM_NM_VECTOR				7
#define PVM_DF_VECTOR				8
#define PVM_TS_VECTOR				10
#define PVM_SS_VECTOR				12
#define PVM_GP_VECTOR				13
#define PVM_PF_VECTOR				14
#define PVM_MF_VECTOR				16
#define PVM_AC_VECTOR				17
#define PVM_MC_VECTOR				18
#define PVM_XM_VECTOR				19
#define PVM_VE_VECTOR				20

/* KVM refused to enter the guest; no guest code ran. */
#define PVM_EXIT_REASONS_FAILED_VMENTRY		1025

/*
 * Synthetic reasons, kept clear of the vector numbers above.  A guest exit
 * that is not an exception carries one of these.
 */
#define PVM_EXIT_REASONS_SHIFT			16
#define PVM_EXIT_REASONS_SYSCALL		(1UL << PVM_EXIT_REASONS_SHIFT)
#define PVM_EXIT_REASONS_HYPERCALL		(2UL << PVM_EXIT_REASONS_SHIFT)
#define PVM_EXIT_REASONS_ERETU			(3UL << PVM_EXIT_REASONS_SHIFT)
#define PVM_EXIT_REASONS_INTERRUPT		(4UL << PVM_EXIT_REASONS_SHIFT)
#define PVM_EXIT_REASONS_INT80			(5UL << PVM_EXIT_REASONS_SHIFT)

/*
 * The reason of a known hypercall.  "HYPERCALL" on its own says almost
 * nothing -- a TLB flush and a page-table load cost very different amounts --
 * so it is only reported for a hypercall number not listed here.
 */
#define PVM_EXIT_REASONS_HC_IRQ_WIN		(PVM_EXIT_REASONS_HYPERCALL + 1)
#define PVM_EXIT_REASONS_HC_IRQ_HALT		(PVM_EXIT_REASONS_HYPERCALL + 2)
#define PVM_EXIT_REASONS_HC_LOAD_PGTBL		(PVM_EXIT_REASONS_HYPERCALL + 3)
#define PVM_EXIT_REASONS_HC_TLB_FLUSH		(PVM_EXIT_REASONS_HYPERCALL + 4)
#define PVM_EXIT_REASONS_HC_TLB_FLUSH_CURRENT	(PVM_EXIT_REASONS_HYPERCALL + 5)
#define PVM_EXIT_REASONS_HC_TLB_INVLPG		(PVM_EXIT_REASONS_HYPERCALL + 6)
#define PVM_EXIT_REASONS_HC_LOAD_GS		(PVM_EXIT_REASONS_HYPERCALL + 7)
#define PVM_EXIT_REASONS_HC_RDMSR		(PVM_EXIT_REASONS_HYPERCALL + 8)
#define PVM_EXIT_REASONS_HC_WRMSR		(PVM_EXIT_REASONS_HYPERCALL + 9)
#define PVM_EXIT_REASONS_HC_LOAD_TLS		(PVM_EXIT_REASONS_HYPERCALL + 10)

#define PVM_EXIT_REASONS						\
	{ PVM_DE_VECTOR, "DE excp" },					\
	{ PVM_DB_VECTOR, "DB excp" },					\
	{ PVM_NMI_VECTOR, "NMI excp" },					\
	{ PVM_BP_VECTOR, "BP excp" },					\
	{ PVM_OF_VECTOR, "OF excp" },					\
	{ PVM_BR_VECTOR, "BR excp" },					\
	{ PVM_UD_VECTOR, "UD excp" },					\
	{ PVM_NM_VECTOR, "NM excp" },					\
	{ PVM_DF_VECTOR, "DF excp" },					\
	{ PVM_TS_VECTOR, "TS excp" },					\
	{ PVM_SS_VECTOR, "SS excp" },					\
	{ PVM_GP_VECTOR, "GP excp" },					\
	{ PVM_PF_VECTOR, "PF excp" },					\
	{ PVM_MF_VECTOR, "MF excp" },					\
	{ PVM_AC_VECTOR, "AC excp" },					\
	{ PVM_MC_VECTOR, "MC excp" },					\
	{ PVM_XM_VECTOR, "XM excp" },					\
	{ PVM_VE_VECTOR, "VE excp" },					\
	{ PVM_EXIT_REASONS_SYSCALL, "SYSCALL" },			\
	{ PVM_EXIT_REASONS_HYPERCALL, "HYPERCALL" },			\
	{ PVM_EXIT_REASONS_ERETU, "ERETU" },				\
	{ PVM_EXIT_REASONS_INTERRUPT, "INTERRUPT" },			\
	{ PVM_EXIT_REASONS_INT80, "INT80" },				\
	{ PVM_EXIT_REASONS_HC_IRQ_WIN, "HC_IRQ_WIN" },			\
	{ PVM_EXIT_REASONS_HC_IRQ_HALT, "HC_IRQ_HALT" },		\
	{ PVM_EXIT_REASONS_HC_LOAD_PGTBL, "HC_LOAD_PGTBL" },		\
	{ PVM_EXIT_REASONS_HC_TLB_FLUSH, "HC_TLB_FLUSH" },		\
	{ PVM_EXIT_REASONS_HC_TLB_FLUSH_CURRENT, "HC_TLB_FLUSH_CURRENT" },\
	{ PVM_EXIT_REASONS_HC_TLB_INVLPG, "HC_TLB_INVLPG" },		\
	{ PVM_EXIT_REASONS_HC_LOAD_GS, "HC_LOAD_GS" },			\
	{ PVM_EXIT_REASONS_HC_RDMSR, "HC_RDMSR" },			\
	{ PVM_EXIT_REASONS_HC_WRMSR, "HC_WRMSR" },			\
	{ PVM_EXIT_REASONS_HC_LOAD_TLS, "HC_LOAD_TLS" },		\
	{ PVM_EXIT_REASONS_FAILED_VMENTRY, "FAILED_VMENTRY" }

#endif /* _UAPI_ASM_X86_PVM_TRACE_H */
