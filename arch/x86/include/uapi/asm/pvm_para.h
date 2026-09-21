/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_X86_PVM_PARA_H
#define _UAPI_ASM_X86_PVM_PARA_H

#include <linux/const.h>
#include <linux/types.h>

/*
 * PVM_SYNTHETIC_CPUID: "invlpg 0xffffffffff4d5650; cpuid", as a byte list for
 * .byte or an array initializer.
 *
 * A PVM guest kernel runs at hardware CPL3, where CPUID does not necessarily
 * trap but INVLPG, a privileged instruction, always does.  The hypervisor
 * recognizes the INVLPG of this address and emulates the pair as a CPUID that
 * returns the PVM guest's values.  At CPL0, on bare metal or under another
 * hypervisor, the INVLPG only drops a TLB entry and the CPUID that follows is
 * an ordinary CPUID.
 * See Documentation/virt/kvm/x86/pvm-spec.rst.
 */
#define PVM_SYNTHETIC_CPUID		0x0f, 0x01, 0x3c, 0x25, 0x50, \
					0x56, 0x4d, 0xff, 0x0f, 0xa2
#define PVM_SYNTHETIC_CPUID_ADDRESS	0xffffffffff4d5650

/*
 * The PVM ABI leaves, in the 0x40000200-0x400002ff sub-range of the
 * hypervisor CPUID class.
 *
 * A PVM guest reads these through PVM_SYNTHETIC_CPUID after it has detected
 * PVM at all, and binds itself to the ABI they describe.  They are answered by
 * the hypervisor itself rather than out of the VMM's CPUID table: the ABI a
 * guest is about to commit to is a property of the implementation, not of the
 * VM's configuration.
 *
 * PVM_CPUID_SIGNATURE:
 *	eax = the highest PVM leaf supported
 *	ebx, ecx, edx = PVM_SIGNATURE
 *
 * PVM_CPUID_FEATURES:
 *	eax = PVM_ABI_VERSION, the revision of this specification implemented
 *	ebx = feature bitmap, PVM_FEATURE_*
 *	ecx, edx = reserved, zero
 */
#define PVM_CPUID_SIGNATURE		0x40000200
#define PVM_SIGNATURE			"PVMPVMPVM\0\0\0"
#define PVM_CPUID_FEATURES		0x40000201
#define PVM_CPUID_MAX			PVM_CPUID_FEATURES

/*
 * The ABI revision.  It covers everything a guest cannot discover any other
 * way: the MSR numbers, the hypercall numbers, the PVCS layout, the event
 * rules, the address space split.  A guest must refuse to run on a hypervisor
 * reporting a version it was not built for; a mismatch is not detectable
 * any other way and shows up as a guest that boots and then misbehaves.
 *
 * Bumping this breaks every existing guest, so it is the last resort.  An
 * addition that old guests can ignore -- a new hypercall, a field taken out of
 * the PVCS reserved space, an optional behaviour -- takes a PVM_FEATURE_ bit
 * in PVM_CPUID_FEATURES.ebx instead and leaves the version alone.
 */
#define PVM_ABI_VERSION			1

/*
 * PVM_FEATURE_*: bits of PVM_CPUID_FEATURES.ebx, which say what the
 * hypervisor supports, and of MSR_PVM_FEATURES_ENABLED, which says what the
 * guest has accepted.  A supported bit changes nothing until the guest sets
 * it in the MSR.
 *
 * PVM_FEATURE_DIRECT_PF
 *	The hypervisor may deliver a user-mode, not-present page fault without
 *	walking the guest page tables.  An enabled guest may therefore receive
 *	a #PF with P=0 for an address whose guest PTE is already present, and
 *	must return from it like any other fault that finds the mapping in
 *	place.  The retry reaches the hypervisor's normal handling.
 */
#define PVM_FEATURE_DIRECT_PF_BIT	0
#define PVM_FEATURE_DIRECT_PF		_BITUL(PVM_FEATURE_DIRECT_PF_BIT)

/*
 * PVM virtual MSRs, 0x4b564d20-0x4b564d2f.
 *
 * KVM's own paravirtual MSRs start at 0x4b564d00 and grow upwards, and KVM
 * allocates its internal synthetic MSR indices downwards from 0x4b564dff.
 * The middle of the range keeps PVM clear of both.  Indices not defined
 * below, 0x4b564d24-0x4b564d2f, are reserved.
 */
#define PVM_VIRTUAL_MSR_BASE		0x4b564d20

#define MSR_PVM_VCPU_STRUCT		(PVM_VIRTUAL_MSR_BASE + 0)
#define MSR_PVM_EVENT_ENTRY		(PVM_VIRTUAL_MSR_BASE + 1)
#define MSR_PVM_RETU_RIP		(PVM_VIRTUAL_MSR_BASE + 2)
#define MSR_PVM_FEATURES_ENABLED	(PVM_VIRTUAL_MSR_BASE + 3)

/*
 * Supervisor-mode events are delivered at MSR_PVM_EVENT_ENTRY plus this
 * offset; user-mode events at MSR_PVM_EVENT_ENTRY itself.
 */
#define PVM_EVENT_ENTRY_SUPERVISOR_OFFSET	512

/*
 * PVM hypercall numbers, 0x17088200-0x170882ff, made with SYSCALL from
 * supervisor mode.  A number outside this range is a KVM hypercall; the base
 * only has to stay clear of KVM's hypercall numbers, which count up from 1.
 * Numbers in the range not defined below are reserved.
 */
#define PVM_HC_SPECIAL_BASE		0x17088200

#define PVM_HC_LOAD_PGTBL		(PVM_HC_SPECIAL_BASE + 0)
#define PVM_HC_IRQ_WIN			(PVM_HC_SPECIAL_BASE + 1)
#define PVM_HC_IRQ_HLT			(PVM_HC_SPECIAL_BASE + 2)
#define PVM_HC_TLB_FLUSH		(PVM_HC_SPECIAL_BASE + 3)
#define PVM_HC_TLB_FLUSH_CURRENT	(PVM_HC_SPECIAL_BASE + 4)
#define PVM_HC_TLB_INVLPG		(PVM_HC_SPECIAL_BASE + 5)
#define PVM_HC_LOAD_GS			(PVM_HC_SPECIAL_BASE + 6)
#define PVM_HC_RDMSR			(PVM_HC_SPECIAL_BASE + 7)
#define PVM_HC_WRMSR			(PVM_HC_SPECIAL_BASE + 8)
#define PVM_HC_LOAD_TLS			(PVM_HC_SPECIAL_BASE + 9)

/*
 * Bits of pvm_vcpu_struct::event_flags; all others are reserved.
 *
 * PVM_EVENT_FLAGS_IF is the virtual interrupt enable flag in supervisor mode.
 * It has the value of X86_EFLAGS_IF, and every other bit is defined above bit
 * 31, where RFLAGS has no flags, so a guest may hand the word to code that
 * tests RFLAGS.IF without masking it.
 *
 * PVM_EVENT_FLAGS_IP is set by the hypervisor when it holds back a maskable
 * interrupt because PVM_EVENT_FLAGS_IF is clear.
 */
#define PVM_EVENT_FLAGS_IF_BIT		9
#define PVM_EVENT_FLAGS_IF		_BITUL(PVM_EVENT_FLAGS_IF_BIT)
#define PVM_EVENT_FLAGS_IP_BIT		32
#define PVM_EVENT_FLAGS_IP		_BITUL(PVM_EVENT_FLAGS_IP_BIT)

/*
 * Bits of pvm_vcpu_struct::event_vector.  The low 8 bits are the vector of an
 * event other than NMI and #MC.  The high 8 bits lock the event fields of the
 * PVCS, see "Events do not nest" in pvm-spec.rst:
 *
 * PVM_PVCS_EVENT_VECTOR_STD	an event other than NMI or #MC was delivered,
 *				or the guest is on its way to user mode
 * PVM_PVCS_EVENT_VECTOR_NMI	an NMI was delivered or is pending
 * PVM_PVCS_EVENT_VECTOR_MCE	a #MC was delivered or is pending
 */
#define PVM_PVCS_EVENT_VECTOR_STD_BIT		8
#define PVM_PVCS_EVENT_VECTOR_STD		_BITUL(PVM_PVCS_EVENT_VECTOR_STD_BIT)
#define PVM_PVCS_EVENT_VECTOR_NMI_BIT		9
#define PVM_PVCS_EVENT_VECTOR_NMI		_BITUL(PVM_PVCS_EVENT_VECTOR_NMI_BIT)
#define PVM_PVCS_EVENT_VECTOR_MCE_BIT		10
#define PVM_PVCS_EVENT_VECTOR_MCE		_BITUL(PVM_PVCS_EVENT_VECTOR_MCE_BIT)

#define PVM_LOAD_PGTBL_FLAGS_TLB	_BITUL(0)
#define PVM_LOAD_PGTBL_FLAGS_LA57	_BITUL(1)

#ifndef __ASSEMBLER__

/*
 * The PVM vCPU struct (PVCS), shared between the guest and the hypervisor and
 * registered with MSR_PVM_VCPU_STRUCT.  128 bytes at the start of a page of
 * guest memory; the hypervisor does not touch the rest of the page.
 *
 * Event delivery saves the interrupted context here, and EVENT_RETURN_USER
 * loads the user mode context from here.  See pvm-spec.rst for each field.
 *
 * Reserved fields and reserved bits must be written as zero by the guest and
 * are ignored by the hypervisor, unless a PVM_FEATURE_ bit the guest has
 * enabled gives them a meaning.
 */
struct pvm_vcpu_struct {
	__u64 event_flags;		/* PVM_EVENT_FLAGS_* */
	__u64 cr2;
	__u64 reserved0[6];

	__u16 user_cs;			/* written for events from user mode */
	__u16 user_ss;			/* written for events from user mode */
	__u16 event_errcode;		/* the low 16 bits of the error code */
	__u16 event_vector;		/* PVM_PVCS_EVENT_VECTOR_* | vector */
	__u64 user_gsbase;		/* written for events from user mode */
	__u32 eflags;
	__u32 pkru;			/* written for events from user mode */
	__u64 rip;
	__u64 rcx;
	__u64 r11;
	__u64 reserved1[2];
};

#endif /* !__ASSEMBLER__ */

#endif /* _UAPI_ASM_X86_PVM_PARA_H */
