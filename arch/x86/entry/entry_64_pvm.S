/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/percpu.h>
#include <asm/pvm_para.h>

#include "calling.h"

/*
 * Room left below the interrupted %rsp for an event from supervisor mode:
 * int3_emulate_call() pushes one word onto the interrupted stack, and the
 * pt_regs built below must not overlap it.
 */
#define REDZONE_SIZE	16

/*
 * The stack of .L_pvm_supervisor_restore_regs_and_return at its IRETQ,
 * relative to %rsp: the IRETQ frame, the guest %r11, %rcx and %rax that are
 * restored last, and the frame of the event being returned from.
 */
#define PVM_IRET_R11		(5*8)
#define PVM_IRET_RCX		(6*8)
#define PVM_IRET_RAX		(7*8)
#define PVM_IRET_EVENT_FRAME	(8*8)

/* Construct struct pt_regs on stack */
.macro PUSH_IRET_FRAME_FROM_PVCS user:req
	movq	%rsp,	%r11
	.if \user == 1
		movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

		movzwl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_ss), %ecx
		pushq	%rcx				/* pt_regs->ss */
	.else
		andq	$-16, %rsp

		subq	$REDZONE_SIZE, %rsp

		pushq	$__KERNEL_DS
	.endif

	pushq	%r11					/* pt_regs->sp */
	movl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_eflags), %ecx
	pushq	%rcx					/* pt_regs->flags */

	.if \user == 1
		movzwl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_cs), %ecx
		pushq	%rcx				/* pt_regs->cs */
	.else
		pushq	$__KERNEL_CS
	.endif

	pushq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rip) /* pt_regs->ip */

	/* set %rcx, %r11 per PVM event handling specification */
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx), %rcx
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_r11), %r11
.endm

.macro PUSH_REGS_AND_HANDLE_EVENT handler:req
	/* Invalidate orig_ax so that syscall_get_nr() works correctly */
	pushq	$-1
	PUSH_AND_CLEAR_REGS

	/*
	 * Take the event out of the PVCS and unlock it first: until then any
	 * event other than NMI or #MC is fatal.  The hypervisor only writes
	 * the PVCS between two guest instructions, so a single XCHG takes the
	 * vector together with every NMI or #MC recorded so far, and one
	 * recorded after it arrives as an event of its own.  The error code is
	 * kept in %r12, which the mitigations below preserve.
	 */
	movzwl	PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_errcode), %r12d
	xorl	%esi, %esi
	xchgw	%si, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_vector)

	/* Mitigations as on native entry; they clobber AX, CX and DX. */
	IBRS_ENTER
	UNTRAIN_RET
	CLEAR_BRANCH_HISTORY

	movq	%rsp, %rdi	/* %rdi -> pt_regs */
	movl	%r12d, %edx
	call	\handler
.endm

.macro POP_REGS_AND_LOAD_IRET_FRAME_INTO_PVCS
	POP_REGS

	/* Mark the PVCS busy before accessing it */
	btsw	$PVM_PVCS_EVENT_VECTOR_STD_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_vector)

	/* Copy %rcx, %r11 to the PVCS */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx)
	movq	%r11, PER_CPU_VAR(pvm_vcpu_struct + PVCS_r11)

	/* Copy the IRET frame to the PVCS */
	movq	1*8(%rsp), %rcx		/* RIP */
	movq	%rcx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rip)
	movq	2*8(%rsp), %rcx		/* CS */
	movw	%cx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_cs)
	movq	3*8(%rsp), %rcx		/* RFLAGS */
	movl	%ecx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_eflags)
	movq	5*8(%rsp), %rcx		/* SS */
	movw	%cx, PER_CPU_VAR(pvm_vcpu_struct + PVCS_user_ss)

	movq	4*8(%rsp), %rsp		/* RSP */
.endm

.code64
.section .entry.text, "ax"

SYM_CODE_START(entry_SYSCALL_64_pvm)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS user=1

	btrw	$PVM_PVCS_EVENT_VECTOR_STD_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_vector)
	cmpw	$0, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_vector)
	jz	.L_pvm_syscall_to_native

	PUSH_REGS_AND_HANDLE_EVENT handler=pvm_event
	POP_REGS
	addq	$8, %rsp

/*
 * Both paths arrive with exactly the IRET frame on the stack, as
 * entry_SYSCALL_64_after_hwframe expects.  This is the bottom of the task
 * stack, as on the native path to that label.
 */
.L_pvm_syscall_to_native:
	UNWIND_HINT_END_OF_STACK
	jmp	entry_SYSCALL_64_after_hwframe
SYM_CODE_END(entry_SYSCALL_64_pvm)

.pushsection .noinstr.text, "ax"
SYM_FUNC_START(pvm_hypercall)
	ENDBR
	push	%r11
	push	%r10
	movq	%rcx, %r10
	UNWIND_HINT_SAVE
	syscall
	UNWIND_HINT_RESTORE
	movq	%r10, %rcx
	popq	%r10
	popq	%r11
	RET
SYM_FUNC_END(pvm_hypercall)
/* kvm_hypercall*() are inline and used by modules, e.g. ptp_kvm. */
EXPORT_SYMBOL_GPL(pvm_hypercall)

/*
 * Callee-save paravirt ops: they clobber nothing but %rax.
 */
SYM_FUNC_START(pvm_save_fl)
	ENDBR
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags), %rax
	RET
SYM_FUNC_END(pvm_save_fl)

SYM_FUNC_START(pvm_irq_disable)
	ENDBR
	btrq	$PVM_EVENT_FLAGS_IF_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	RET
SYM_FUNC_END(pvm_irq_disable)

SYM_FUNC_START(pvm_irq_enable)
	ENDBR
	orq	$PVM_EVENT_FLAGS_IF, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	btq	$PVM_EVENT_FLAGS_IP_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	jc	.L_maybe_interrupt_pending
	RET
.L_maybe_interrupt_pending:
	/* handle pending IRQ */
	movq	$PVM_HC_IRQ_WIN, %rax
	jmp	pvm_hypercall
SYM_FUNC_END(pvm_irq_enable)

SYM_FUNC_START(pvm_read_cr2)
	ENDBR
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_cr2), %rax
	RET
SYM_FUNC_END(pvm_read_cr2)
.popsection

/*
 * The new RIP value that PVM event delivery establishes is
 * MSR_PVM_EVENT_ENTRY for vector events that occur in user mode.
 */
	.align 64
SYM_CODE_START(pvm_user_event_entry)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS user=1
	PUSH_REGS_AND_HANDLE_EVENT handler=pvm_event

SYM_INNER_LABEL(pvm_restore_regs_and_return_to_usermode, SYM_L_GLOBAL)
	STACKLEAK_ERASE
	POP_REGS_AND_LOAD_IRET_FRAME_INTO_PVCS
SYM_INNER_LABEL(pvm_retu_rip, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	syscall
SYM_CODE_END(pvm_user_event_entry)

/*
 * The new RIP value that PVM event delivery establishes is
 * MSR_PVM_EVENT_ENTRY + PVM_EVENT_ENTRY_SUPERVISOR_OFFSET for supervisor mode
 * events.
 */
	.org pvm_user_event_entry + PVM_EVENT_ENTRY_SUPERVISOR_OFFSET, 0xcc
SYM_CODE_START(pvm_kernel_event_entry)
	UNWIND_HINT_ENTRY
	ENDBR

	PUSH_IRET_FRAME_FROM_PVCS user=0

	/* if RIP < .L_pvm_supervisor_iret_irq_enabled_start ==> skip fixup */
	leaq	.L_pvm_supervisor_iret_irq_enabled_start(%rip), %rcx
	cmpq	(%rsp), %rcx
	ja	.L_pvm_supervisor_iret_irq_fixed

	/* if RIP >= .L_pvm_supervisor_iret_irq_enabled_end ==> skip fixup */
	leaq	.L_pvm_supervisor_iret_irq_enabled_end(%rip), %rcx
	cmpq	(%rsp), %rcx
	jbe	.L_pvm_supervisor_iret_irq_fixed

	/*
	 * The event arrived in the return sequence below after it had set
	 * PVM_EVENT_FLAGS_IF.  Its %rsp is the IRETQ stack, see PVM_IRET_*:
	 *
	 *	frame of the event being returned from
	 *	RAX
	 *	RCX
	 *	R11
	 *	IRETQ frame		<-- interrupted %rsp
	 *	alignment and REDZONE_SIZE
	 *	frame of this event	<-- %rsp
	 *
	 * Finish that return here instead: restore %rax, %rcx and %r11 and
	 * handle this event on the frame of the one being returned from, as if
	 * it had arrived before the IRETQ.
	 */
	movq	RSP-RIP(%rsp), %rcx
	movq	PVM_IRET_RAX(%rcx), %rax
	movq	PVM_IRET_RCX(%rcx), %r11
	movq	%r11, PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx)
	movq	PVM_IRET_R11(%rcx), %r11
	leaq	PVM_IRET_EVENT_FRAME(%rcx), %rsp
.L_pvm_supervisor_iret_irq_fixed:
	movq	PER_CPU_VAR(pvm_vcpu_struct + PVCS_rcx), %rcx

	PUSH_REGS_AND_HANDLE_EVENT handler=pvm_event

.L_pvm_supervisor_restore_regs_and_return:
	POP_REGS
	/* Build the stack described at PVM_IRET_*. */
	movq	%rax, (%rsp)
	pushq	%rcx
	pushq	%r11
	mov	%ss, %rax
	pushq	%rax		/* current hw SS for supervisor_iret */
	pushq	8*7(%rsp)	/* RSP */
	pushq	8*7(%rsp)	/* RFLAGS */
	mov	%cs, %rax
	pushq	%rax		/* current hw CS for supervisor_iret */
	pushq	8*7(%rsp)	/* RIP */
	testl	$X86_EFLAGS_IF, EFLAGS-RIP(%rsp)
	jz	.L_pvm_supervisor_iret
	orq	$PVM_EVENT_FLAGS_IF, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
.L_pvm_supervisor_iret_irq_enabled_start:
	/* Not an indirect branch target: its address is only compared against. */
	ANNOTATE_NOENDBR
	btq	$PVM_EVENT_FLAGS_IP_BIT, PER_CPU_VAR(pvm_vcpu_struct + PVCS_event_flags)
	jc	.L_pvm_supervisor_iret_irq_pending
.L_pvm_supervisor_iret:
	movq	PVM_IRET_RAX(%rsp), %rax
	iretq
.L_pvm_supervisor_iret_irq_pending:
	/*
	 * Let the hypervisor deliver the pending interrupt.  The hypercall
	 * clobbers only %rax, %rcx and %r11, and all three are reloaded.
	 */
	movq	$PVM_HC_IRQ_WIN, %rax
	syscall
	/* Only reached when no interrupt was delivered after all. */
	movq	PVM_IRET_R11(%rsp), %r11
	movq	PVM_IRET_RCX(%rsp), %rcx
	jmp	.L_pvm_supervisor_iret
.L_pvm_supervisor_iret_irq_enabled_end:
SYM_CODE_END(pvm_kernel_event_entry)
