/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <linux/export.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/percpu.h>
#include <asm/nospec-branch.h>
#include <asm/pvm_switcher.h>
#include <uapi/asm/pvm_para.h>

#include "calling.h"

/*
 * Protection keys across a guest mode switch.
 *
 * One hardware PKRU and a guest at CPL 3 in both modes: the register has to be
 * swapped the way CR3 is.  The guest's user value is loaded while it is in
 * user mode, TSS_extra(smod_pkru) while it is in supervisor mode, and
 * PVCS::pkru holds the user value while it is not loaded.
 *
 * RDPKRU and WRPKRU use EAX/ECX/EDX, and on both paths RAX and RDX are live
 * guest registers, so they are saved on the sp0 stack across the sequence.
 * %rdi points at the PVCS through its host mapping, so none of this is subject
 * to the key the guest may have put on that page.
 */
.macro SWITCHER_PKRU_TO_SMOD
	cmpl	$0, TSS_extra(pku_on)
	je	.Lend_\@
	pushq	%rax
	pushq	%rdx
	xorl	%ecx, %ecx
	rdpkru
	movl	%eax, PVCS_pkru(%rdi)
	movl	TSS_extra(smod_pkru), %eax
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	wrpkru
	popq	%rdx
	popq	%rax
.Lend_\@:
.endm

.macro SWITCHER_PKRU_TO_UMOD
	cmpl	$0, TSS_extra(pku_on)
	je	.Lend_\@
	pushq	%rax
	pushq	%rdx
	movl	PVCS_pkru(%rdi), %eax
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	wrpkru
	popq	%rdx
	popq	%rax
.Lend_\@:
.endm

/*
 * Clear CPU buffers before running the guest after host code ran, as VMX and
 * SVM do before VM-Enter: on the way in from kvm-pvm, and in
 * SWITCHER_RESTORE_CR3 after a host handler interrupted the switcher.  The
 * direct switches between the guest's modes run no host code and do not clear
 * them; the guest kernel clears them itself on its way back to user mode.
 * Clobbers ZF only.
 */
#define SWITCHER_CLEAR_CPU_BUFFERS \
	ALTERNATIVE "", __CLEAR_CPU_BUFFERS, X86_FEATURE_CLEAR_CPU_BUF_VM

/* The same canonical address check as the SYSCALL64 entry in entry_64.S. */
.macro canonical_rcx
	/*
	 * If width of "canonical tail" ever becomes variable, this will need
	 * to be updated to remain correct on both old and new CPUs.
	 *
	 * Change top bits to match most significant bit (47th or 56th bit
	 * depending on paging mode) in the address.
	 */
	ALTERNATIVE "shl $(64 - 48), %rcx; sar $(64 - 48), %rcx", \
		    "shl $(64 - 57), %rcx; sar $(64 - 57), %rcx", X86_FEATURE_LA57
.endm

.code64
.section .entry.text, "ax"

/*
 * switcher_enter_guest - Run the PVM guest until it exits
 *
 * Called with the guest registers in a pt_regs at the top of the sp0 stack and
 * the switcher state in cpu_tss_rw.tss_ex.  Returns a pointer to that pt_regs,
 * holding the guest registers and, in orig_ax, the exit reason (see
 * ORIG_RAX_VECTOR).
 *
 * A code symbol rather than a function: the way into the guest leaves through
 * SYSRET or through native_irq_return_iret, and the way back arrives from the
 * host entry code.
 */
SYM_CODE_START(switcher_enter_guest)
	UNWIND_HINT_FUNC
	ENDBR
	pushq	%rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx

	/* Save host RSP and mark the switcher active */
	movq	%rsp, TSS_extra(host_rsp)

	/* Switch to the guest registers on the sp0 stack */
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rdi
	subq	$FRAME_SIZE, %rdi
	movq	%rdi, %rsp
	UNWIND_HINT_REGS

	IBRS_EXIT

	movq	TSS_extra(enter_cr3), %rax
	movq	%rax, %cr3

	POP_REGS
	addq	$8, %rsp

	swapgs
	SWITCHER_CLEAR_CPU_BUFFERS
	jmp	.L_switcher_return_to_guest

/*
 * Every exit from the guest arrives here: on the host GSBASE, the guest CR3,
 * the guest registers in a pt_regs at %rsp, and IBRS_ENTER already done.
 */
SYM_INNER_LABEL(switcher_return_from_guest, SYM_L_GLOBAL)
	UNWIND_HINT_REGS
	ANNOTATE_NOENDBR

	movq	TSS_extra(host_cr3), %rax
	movq	%rax, %cr3

	/*
	 * RSB filling must be done before the first unbalanced RET, as after
	 * VM-Exit.  eIBRS protects against a poisoned RSB and does not need it.
	 */
	FILL_RETURN_BUFFER %rcx, RSB_CLEAR_LOOPS, X86_FEATURE_RSB_VMEXIT, \
			   X86_FEATURE_RSB_VMEXIT_LITE

	/* RET must be untrained before the first RET, as for VM-Exit. */
	UNTRAIN_RET_VM

	CLEAR_BRANCH_HISTORY_VMEXIT

	/* Restore the host RSP and mark the switcher inactive */
	movq	%rsp, %rax
	movq	TSS_extra(host_rsp), %rsp
	UNWIND_HINT sp_reg=ORC_REG_SP sp_offset=7*8 type=UNWIND_HINT_TYPE_CALL
	movq	$0, TSS_extra(host_rsp)

	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	CALL_DEPTH_ACCOUNT
	RET
SYM_CODE_END(switcher_enter_guest)
EXPORT_SYMBOL_GPL(switcher_enter_guest)

/*
 * The hardware MSR_LSTAR while a PVM guest runs: every SYSCALL of the guest,
 * in either mode, lands here.
 */
SYM_CODE_START(entry_SYSCALL_64_switcher)
	UNWIND_HINT_ENTRY
	ENDBR

	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp

SYM_INNER_LABEL(entry_SYSCALL_64_switcher_safe_stack, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS				/* pt_regs->ss */
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)	/* pt_regs->sp */
	pushq	%r11					/* pt_regs->flags */
	pushq	$__USER_CS				/* pt_regs->cs */
	pushq	%rcx					/* pt_regs->ip */
	pushq	%rdi					/* put rdi on ORIG_RAX */

	/* check if it can do direct switch from umod to smod */
	testq	$SWITCH_FLAGS_NO_DS_TO_SMOD, TSS_extra(switch_flags)
	jnz	.L_switcher_check_return_umod_instruction

	/* Now it must be umod, start to do direct switch from umod to smod */
	movq	TSS_extra(pvcs), %rdi
	movl	$PVCS_USER_CS_SS, PVCS_user_cs(%rdi)
	movl	%r11d, PVCS_eflags(%rdi)
	movq	%rcx, PVCS_rip(%rdi)
	movq	%rcx, PVCS_rcx(%rdi)
	movq	%r11, PVCS_r11(%rdi)

	SWITCHER_PKRU_TO_SMOD

	/* switch umod to smod (switch_flags & cr3) */
	xorb	$SWITCH_FLAGS_MOD_TOGGLE, TSS_extra(switch_flags)
	movq	TSS_extra(smod_cr3), %rcx
	movq	%rcx, %cr3

	/* load smod registers from TSS_extra to sp0 stack or %r11 */
	movq	TSS_extra(smod_entry), %rcx
	movq	%rcx, RIP-ORIG_RAX(%rsp)
	movq	TSS_extra(smod_gsbase), %r11

	/* switch host gsbase to guest gsbase, TSS_extra can't be used afterwards */
	swapgs

	/* save guest gsbase as user_gsbase and switch to smod_gsbase */
	rdgsbase %rcx
	movq	%rcx, PVCS_user_gsbase(%rdi)
	wrgsbase %r11

	/*
	 * Restore umod rdi and load smod rflags/r11 and rip/rcx for SYSRET.
	 * The entry, MSR_LSTAR of the guest, is canonical: kvm-pvm refuses a
	 * non-canonical value on the MSR write.
	 */
	popq	%rdi
	movq	$SWITCH_ENTER_EFLAGS_FIXED, %r11
	movq	RIP-RIP(%rsp), %rcx

.L_switcher_sysretq:
	UNWIND_HINT_IRET_REGS
	/* now everything is ready for sysretq except for %rsp */
	movq	RSP-RIP(%rsp), %rsp
	/* No instruction can be added between setting the guest %rsp and doing sysretq */
SYM_INNER_LABEL(entry_SYSRETQ_switcher_unsafe_stack, SYM_L_GLOBAL)
	sysretq

.L_switcher_check_return_umod_instruction:
	UNWIND_HINT_IRET_REGS offset=8

	/* check if it can do direct switch from smod to umod */
	testq	$SWITCH_FLAGS_NO_DS_TO_UMOD, TSS_extra(switch_flags)
	jnz	.L_switcher_return_to_hypervisor

	/*
	 * Now it must be smod, check if it is the return-umod instruction.
	 * Switcher and the PVM specification defines a SYSCALL instruction
	 * at TSS_extra(retu_rip) - 2 in smod as the return-umod instruction.
	 */
	cmpq	%rcx, TSS_extra(retu_rip)
	jne	.L_switcher_return_to_hypervisor

	/* only handle for the most common cs/ss */
	movq	TSS_extra(pvcs), %rdi
	cmpl	$PVCS_USER_CS_SS, PVCS_user_cs(%rdi)
	jne	.L_switcher_return_to_hypervisor

	/* switch smod to umod (switch_flags & cr3) */
	xorb	$SWITCH_FLAGS_MOD_TOGGLE, TSS_extra(switch_flags)
	movq	TSS_extra(umod_cr3), %rcx
	movq	%rcx, %cr3

	SWITCHER_PKRU_TO_UMOD

	/* switch host gsbase to guest gsbase, TSS_extra can't be used afterwards */
	swapgs

	/* write umod gsbase */
	movq	PVCS_user_gsbase(%rdi), %rcx
	canonical_rcx
	wrgsbase %rcx

	/* load flags, ip to sp0 stack and cx, r11, rdi to registers */
	movl	PVCS_eflags(%rdi), %r11d
	movq	%r11, EFLAGS-ORIG_RAX(%rsp)
	movq	PVCS_rip(%rdi), %rcx
	movq	%rcx, RIP-ORIG_RAX(%rsp)
	movq	PVCS_rcx(%rdi), %rcx
	movq	PVCS_r11(%rdi), %r11
	popq	%rdi		/* saved rdi (on ORIG_RAX) */

.L_switcher_return_to_guest:
	/*
	 * Now the RSP points to an IRET frame with guest state on the
	 * top of the sp0 stack.  Check if it can do sysretq.
	 */
	UNWIND_HINT_IRET_REGS

	andq	$SWITCH_ENTER_EFLAGS_ALLOWED, EFLAGS-RIP(%rsp)
	orq	$SWITCH_ENTER_EFLAGS_FIXED, EFLAGS-RIP(%rsp)
	testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), EFLAGS-RIP(%rsp)
	jnz	.L_switcher_iretq
	cmpq	%r11, EFLAGS-RIP(%rsp)
	jne	.L_switcher_iretq

	cmpq	%rcx, RIP-RIP(%rsp)
	jne	.L_switcher_iretq
	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the guest take over
	 * the host, since guest controls RSP.
	 */
	canonical_rcx
	cmpq	%rcx, RIP-RIP(%rsp)
	je	.L_switcher_sysretq

	/* RCX matches for RIP only before RCX is canonicalized, restore RCX and do IRET. */
	movq	RIP-RIP(%rsp), %rcx

.L_switcher_iretq:
	jmp	native_irq_return_iret

.L_switcher_return_to_hypervisor:
	popq	%rdi					/* saved rdi */
	pushq	$0					/* pt_regs->orig_ax */
	movl	$SWITCH_EXIT_REASONS_SYSCALL, ORIG_RAX_VECTOR-ORIG_RAX(%rsp)

	PUSH_AND_CLEAR_REGS
	IBRS_ENTER
	jmp	switcher_return_from_guest
SYM_CODE_END(entry_SYSCALL_64_switcher)
EXPORT_SYMBOL_GPL(entry_SYSCALL_64_switcher)
