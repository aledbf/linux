// SPDX-License-Identifier: GPL-2.0
#ifndef __LINUX_KBUILD_H
# error "Please do not build this file directly, build asm-offsets.c instead"
#endif

#include <asm/ia32.h>

#if defined(CONFIG_X86_PVM_SWITCHER) || defined(CONFIG_PVM_GUEST)
#include <asm/pvm_para.h>
#endif

#if defined(CONFIG_KVM_GUEST)
#include <asm/kvm_para.h>
#endif

int main(void)
{
#ifdef CONFIG_PARAVIRT
#ifdef CONFIG_PARAVIRT_XXL
#ifdef CONFIG_DEBUG_ENTRY
	OFFSET(PV_IRQ_save_fl, paravirt_patch_template, irq.save_fl);
#endif
#endif
	BLANK();
#endif

#if defined(CONFIG_KVM_GUEST)
	OFFSET(KVM_STEAL_TIME_preempted, kvm_steal_time, preempted);
	BLANK();
#endif

#define ENTRY(entry) OFFSET(pt_regs_ ## entry, pt_regs, entry)
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(sp);
	ENTRY(bp);
	ENTRY(si);
	ENTRY(di);
	ENTRY(r8);
	ENTRY(r9);
	ENTRY(r10);
	ENTRY(r11);
	ENTRY(r12);
	ENTRY(r13);
	ENTRY(r14);
	ENTRY(r15);
	ENTRY(flags);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(saved_context_ ## entry, saved_context, entry)
	ENTRY(cr0);
	ENTRY(cr2);
	ENTRY(cr3);
	ENTRY(cr4);
	ENTRY(gdt_desc);
	BLANK();
#undef ENTRY

#ifdef CONFIG_X86_PVM_SWITCHER
#define ENTRY(entry) OFFSET(TSS_EX_ ## entry, tss_struct, tss_ex.entry)
	ENTRY(host_cr3);
	ENTRY(host_rsp);
	ENTRY(enter_cr3);
	ENTRY(switch_flags);
	ENTRY(smod_cr3);
	ENTRY(umod_cr3);
	ENTRY(pvcs);
	ENTRY(retu_rip);
	ENTRY(smod_entry);
	ENTRY(smod_gsbase);
	ENTRY(pku_on);
	ENTRY(smod_pkru);
	ENTRY(pgtbl);
	ENTRY(pgtbl_switched);
	ENTRY(pgtbl_flags);
	ENTRY(event_entry);
	ENTRY(dpf_page);
	ENTRY(dpf_on);
	ENTRY(dpf_run);
	BLANK();
#undef ENTRY
	DEFINE(PVM_PGTBL_ENTRY_SIZE, sizeof(struct pvm_pgtbl_entry));
	OFFSET(PVM_PGTBL_guest_cr3, pvm_pgtbl_entry, guest_cr3);
	OFFSET(PVM_PGTBL_smod_cr3, pvm_pgtbl_entry, smod_cr3);
	OFFSET(PVM_PGTBL_umod_cr3, pvm_pgtbl_entry, umod_cr3);
	BLANK();
#endif

#if defined(CONFIG_X86_PVM_SWITCHER) || defined(CONFIG_PVM_GUEST)
#define ENTRY(entry) OFFSET(PVCS_ ## entry, pvm_vcpu_struct, entry)
	ENTRY(event_flags);
	ENTRY(cr2);
	ENTRY(event_errcode);
	ENTRY(event_vector);
	ENTRY(user_cs);
	ENTRY(user_ss);
	ENTRY(user_gsbase);
	ENTRY(eflags);
	ENTRY(rip);
	ENTRY(rcx);
	ENTRY(r11);
	ENTRY(pkru);
	BLANK();
#undef ENTRY

	/* The PVCS layout is ABI, see Documentation/virt/kvm/x86/pvm-spec.rst. */
	BUILD_BUG_ON(sizeof(struct pvm_vcpu_struct) != 128);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, event_flags) != 0x00);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, cr2) != 0x08);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, user_cs) != 0x40);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, user_ss) != 0x42);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, event_errcode) != 0x44);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, event_vector) != 0x46);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, user_gsbase) != 0x48);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, eflags) != 0x50);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, pkru) != 0x54);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, rip) != 0x58);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, rcx) != 0x60);
	BUILD_BUG_ON(offsetof(struct pvm_vcpu_struct, r11) != 0x68);
#endif

	return 0;
}
