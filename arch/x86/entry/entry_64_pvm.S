/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/percpu.h>
#include <asm/pvm_para.h>

#include "calling.h"

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
.popsection
