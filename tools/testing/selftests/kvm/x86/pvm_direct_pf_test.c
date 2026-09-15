// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test PVM's direct delivery of user page faults, PVM_FEATURE_DIRECT_PF.
 *
 * With the feature enabled, a user-mode not-present #PF may be delivered to
 * the guest's event entry by the host's #PF handler, without an exit and
 * without the shadow MMU's walk.  Whether a fault took that path is visible
 * in two vCPU stats: pf_guest counts the #PFs KVM injects, which a delivery
 * without an exit never is, and pf_taken counts the faults that reach the
 * shadow MMU.
 *
 * The guest cannot be built with the selftest guest library: a PVM guest runs
 * at hardware CPL3 and takes its events through MSR_PVM_EVENT_ENTRY and the
 * PVCS, not through an IDT.  It is a few instructions of assembly, copied
 * into guest memory.  Supervisor mode reports each event and system call on
 * an MMIO page, then returns to user mode with the state the host left in a
 * control page; the host inspects the PVCS, the stats and CR2 at each report.
 */
#include <asm/pvm_para.h>
#include <linux/kvm_para.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

/* Guest physical layout: GUEST_PAGES pages of RAM, and two MMIO pages. */
#define GUEST_GPA		0x100000
#define GUEST_PAGES		16
#define KMMIO_GPA		0xd0000000	/* supervisor reports */
#define UMMIO_GPA		0xd0001000	/* accessed from user mode */

#define PG_PML4			0
#define PG_PDPT_K		1
#define PG_PD_K			2
#define PG_PT_K			3
#define PG_PDPT_U		4
#define PG_PD_U			5
#define PG_PT_U			6
#define PG_PVCS			7
#define PG_CTRL			8
#define PG_KCODE		9
#define PG_UCODE		10
#define PG_UDATA		11
#define PG_UDATA2		12
#define PG_URO			13
#define PG_USUPER		14
#define PG_UPKEY		15

#define KVA			0x400000000000	/* guest page N is at KVA + N pages */
#define K_PVCS			(KVA + PG_PVCS * 0x1000)
#define K_CTRL			(KVA + PG_CTRL * 0x1000)
#define K_CODE			(KVA + PG_KCODE * 0x1000)
#define K_MMIO			(KVA + 0x100000)	/* KMMIO_GPA */
#define K_MMIO_VALUE		(K_MMIO + 8)

/* User mappings.  Everything from UVA_ABSENT on has no guest PTE. */
#define UVA			0x40000000
#define UVA_CODE		(UVA + 0x0000)
#define UVA_DATA		(UVA + 0x1000)	/* present, not yet shadowed */
#define UVA_DATA2		(UVA + 0x2000)	/* present, not yet shadowed */
#define UVA_RO			(UVA + 0x3000)	/* present, read-only */
#define UVA_SUPER		(UVA + 0x4000)	/* present, supervisor-only */
#define UVA_PKEY		(UVA + 0x5000)	/* present, protection key 1 */
#define UVA_MMIO		(UVA + 0x6000)	/* UMMIO_GPA */
#define UVA_ABSENT(n)		(UVA + 0x10000 + (n) * 0x1000 + 0x123)
#define UVA_RSVD		(0x8000000000 + 0x123)	/* PML4E with a reserved bit */
#define UVA_UPPER		0xffffffc000000123	/* upper half, host's */

#define PTE_P			BIT_ULL(0)
#define PTE_RW			BIT_ULL(1)
#define PTE_US			BIT_ULL(2)
#define PTE_PS			BIT_ULL(7)
#define PTE_PKEY1		BIT_ULL(59)
#define PTE_NX			BIT_ULL(63)

/* The control page: what supervisor mode puts into the PVCS for ERETU. */
#define CTRL_RIP		0x00	/* if non-zero, the user RIP, then zeroed */
#define CTRL_RCX		0x08	/* if non-zero, the user RCX, then zeroed */
#define CTRL_PKRU		0x10	/* the user PKRU */

/* The PVCS fields the guest code touches, checked against the uapi below. */
#define PVCS_CR2		0x08
#define PVCS_USER_CS		0x40
#define PVCS_USER_SS		0x42
#define PVCS_EVENT_VECTOR	0x46
#define PVCS_EFLAGS		0x50
#define PVCS_PKRU		0x54
#define PVCS_RIP		0x58
#define PVCS_RCX		0x60
#define PVCS_R11		0x68

/* The host's 64-bit user selectors, the only pair the switcher delivers from. */
#define USER_CS			0x33
#define USER_SS			0x2b

#define USER_EFLAGS		0x202
#define USER_R11		0x5a5a5a5a
#define USER_GSBASE		0x7f0000001000
#define EVENT_VECTOR_STD	0x100

/* What supervisor mode writes to K_MMIO. */
#define REPORT_SYSCALL		1
#define REPORT_USER_EVENT	2
#define REPORT_SUPER_EVENT	3

/* User RAX on SYSCALL: what supervisor mode does before it reports. */
#define SYS_NOP			0
#define SYS_KREAD		1	/* read a byte at user RBX */
#define SYS_PROBE		2	/* PVM CPUID and the feature MSR */

#define FEATURE_UNKNOWN		0x2

/*
 * Not ABI: the most user #PFs KVM delivers in a row without the shadow MMU,
 * PVM_DIRECT_PF_RUN in arch/x86/include/asm/pvm_switcher.h.
 */
#define PVM_DIRECT_PF_RUN	4

kvm_static_assert(offsetof(struct pvm_vcpu_struct, cr2) == PVCS_CR2);
kvm_static_assert(offsetof(struct pvm_vcpu_struct, user_cs) == PVCS_USER_CS);
kvm_static_assert(offsetof(struct pvm_vcpu_struct, user_ss) == PVCS_USER_SS);
kvm_static_assert(offsetof(struct pvm_vcpu_struct, event_vector) == PVCS_EVENT_VECTOR);
kvm_static_assert(offsetof(struct pvm_vcpu_struct, eflags) == PVCS_EFLAGS);
kvm_static_assert(offsetof(struct pvm_vcpu_struct, pkru) == PVCS_PKRU);
kvm_static_assert(offsetof(struct pvm_vcpu_struct, rip) == PVCS_RIP);
kvm_static_assert(offsetof(struct pvm_vcpu_struct, rcx) == PVCS_RCX);
kvm_static_assert(offsetof(struct pvm_vcpu_struct, r11) == PVCS_R11);
kvm_static_assert(EVENT_VECTOR_STD == PVM_PVCS_EVENT_VECTOR_STD);
kvm_static_assert(FEATURE_UNKNOWN == PVM_FEATURE_DIRECT_PF << 1);

/*
 * Supervisor mode, copied to K_CODE.  The user event entry is at the start
 * and the supervisor event entry PVM_EVENT_ENTRY_SUPERVISOR_OFFSET after it.
 */
extern char pvm_kernel_start[], pvm_kernel_end[];
extern char pvm_syscall[], pvm_return_user[], pvm_retu[];
asm(
"pvm_kernel_start:\n"
"pvm_user_event:\n"
"	mov $" __stringify(REPORT_USER_EVENT) ", %eax\n"
"	jmp pvm_report\n"
"	.org pvm_kernel_start + " __stringify(PVM_EVENT_ENTRY_SUPERVISOR_OFFSET) "\n"
"pvm_super_event:\n"
"	mov $" __stringify(REPORT_SUPER_EVENT) ", %eax\n"
"	jmp pvm_report\n"

"pvm_syscall:\n"
"	cmp $" __stringify(SYS_KREAD) ", %rax\n"
"	je pvm_kread\n"
"	cmp $" __stringify(SYS_PROBE) ", %rax\n"
"	je pvm_probe\n"
"	mov $" __stringify(REPORT_SYSCALL) ", %eax\n"

/* Report %rax, then return to user mode. */
"pvm_report:\n"
"	movabs $" __stringify(K_MMIO) ", %rdx\n"
"	mov %rax, (%rdx)\n"
"pvm_return_user:\n"
"	movabs $" __stringify(K_CTRL) ", %rsi\n"
"	movabs $" __stringify(K_PVCS) ", %rdi\n"
"	mov " __stringify(CTRL_RIP) "(%rsi), %rax\n"
"	test %rax, %rax\n"
"	jz 1f\n"
"	mov %rax, " __stringify(PVCS_RIP) "(%rdi)\n"
"	movq $0, " __stringify(CTRL_RIP) "(%rsi)\n"
"1:	mov " __stringify(CTRL_RCX) "(%rsi), %rax\n"
"	test %rax, %rax\n"
"	jz 2f\n"
"	mov %rax, " __stringify(PVCS_RCX) "(%rdi)\n"
"	movq $0, " __stringify(CTRL_RCX) "(%rsi)\n"
"2:	mov " __stringify(CTRL_PKRU) "(%rsi), %eax\n"
"	mov %eax, " __stringify(PVCS_PKRU) "(%rdi)\n"
"	movl $" __stringify(USER_EFLAGS) ", " __stringify(PVCS_EFLAGS) "(%rdi)\n"
"	movw $" __stringify(USER_CS) ", " __stringify(PVCS_USER_CS) "(%rdi)\n"
"	movw $" __stringify(USER_SS) ", " __stringify(PVCS_USER_SS) "(%rdi)\n"
"	movq $" __stringify(USER_R11) ", " __stringify(PVCS_R11) "(%rdi)\n"
"	movw $" __stringify(EVENT_VECTOR_STD) ", " __stringify(PVCS_EVENT_VECTOR) "(%rdi)\n"
"pvm_retu:\n"
"	syscall\n"
"	ud2\n"

/*
 * A supervisor-mode read of the user address in %rbx.  The event interlock
 * is released first, as a guest does once it has handled the system call, so
 * that the fault can be delivered.
 */
"pvm_kread:\n"
"	movabs $" __stringify(K_PVCS) ", %rdi\n"
"	movw $0, " __stringify(PVCS_EVENT_VECTOR) "(%rdi)\n"
"	movb (%rbx), %al\n"
"	mov $" __stringify(REPORT_SYSCALL) ", %eax\n"
"	jmp pvm_report\n"

/*
 * PVM_CPUID_FEATURES, then MSR_PVM_FEATURES_ENABLED through the hypercalls:
 * write an unknown bit, write PVM_FEATURE_DIRECT_PF, read it back.  Each
 * result goes to K_MMIO_VALUE: eax, ebx, three RAX and the RDMSR value.
 */
"pvm_probe:\n"
"	mov $" __stringify(PVM_CPUID_FEATURES) ", %eax\n"
"	xor %ecx, %ecx\n"
"	.byte " __stringify(PVM_SYNTHETIC_CPUID) "\n"
"	movabs $" __stringify(K_MMIO_VALUE) ", %rdx\n"
"	mov %rax, (%rdx)\n"
"	mov %rbx, (%rdx)\n"
"	mov $" __stringify(PVM_HC_WRMSR) ", %eax\n"
"	mov $" __stringify(MSR_PVM_FEATURES_ENABLED) ", %ebx\n"
"	mov $" __stringify(FEATURE_UNKNOWN) ", %r10d\n"
"	syscall\n"
"	mov %rax, (%rdx)\n"
"	mov $" __stringify(PVM_HC_WRMSR) ", %eax\n"
"	mov $1, %r10d\n"
"	syscall\n"
"	mov %rax, (%rdx)\n"
"	mov $" __stringify(PVM_HC_RDMSR) ", %eax\n"
"	syscall\n"
"	mov %rdx, %r8\n"
"	movabs $" __stringify(K_MMIO_VALUE) ", %rdx\n"
"	mov %rax, (%rdx)\n"
"	mov %r8, (%rdx)\n"
"	mov $" __stringify(REPORT_SYSCALL) ", %eax\n"
"	jmp pvm_report\n"
"pvm_kernel_end:\n"
);

/*
 * User mode, copied to UVA_CODE.  The address to access is in %rcx.  A
 * routine that faults is retried at the faulting instruction when supervisor
 * mode returns without a new CTRL_RIP.
 */
extern char pvm_user_start[], pvm_user_end[];
extern char u_nop[], u_read[], u_write[], u_exec[], u_kread[], u_probe[];
asm(
"pvm_user_start:\n"
"u_nop:\n"
"	xor %eax, %eax\n"
"	syscall\n"
"	ud2\n"
"u_read:\n"
"	movb (%rcx), %al\n"
"	xor %eax, %eax\n"
"	syscall\n"
"	ud2\n"
"u_write:\n"
"	movb $0x5a, (%rcx)\n"
"	xor %eax, %eax\n"
"	syscall\n"
"	ud2\n"
"u_exec:\n"
"	jmp *%rcx\n"
"u_kread:\n"
"	mov %rcx, %rbx\n"
"	mov $" __stringify(SYS_KREAD) ", %eax\n"
"	syscall\n"
"	ud2\n"
"u_probe:\n"
"	mov $" __stringify(SYS_PROBE) ", %eax\n"
"	syscall\n"
"	ud2\n"
"pvm_user_end:\n"
);

#define KADDR(sym)		(K_CODE + ((sym) - pvm_kernel_start))
#define UADDR(sym)		(UVA_CODE + ((sym) - pvm_user_start))

#define GUEST_PKE		BIT(0)	/* CR4.PKE */
#define GUEST_IRQCHIP		BIT(1)	/* an in-kernel local APIC */

struct pvm_guest {
	unsigned long flags;
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	u8 *mem;
	struct pvm_vcpu_struct *pvcs;
	u64 *ctrl;
	u64 values[8];
	int nr_values;
	int user_mmio;
};

struct pf_stats {
	u64 guest;
	u64 taken;
};

static bool is_kvm_pvm(void)
{
	return !access("/sys/module/kvm_pvm", F_OK);
}

static void set_pte(struct pvm_guest *g, int table, u64 va, int level, u64 val)
{
	u64 *pt = (u64 *)(g->mem + table * PAGE_SIZE);

	pt[(va >> (12 + 9 * (level - 1))) & 0x1ff] = val;
}

static u64 gpa(int page)
{
	return GUEST_GPA + page * PAGE_SIZE;
}

static void build_page_tables(struct pvm_guest *g)
{
	int i;

	set_pte(g, PG_PML4, KVA, 4, gpa(PG_PDPT_K) | PTE_P | PTE_RW);
	set_pte(g, PG_PDPT_K, KVA, 3, gpa(PG_PD_K) | PTE_P | PTE_RW);
	set_pte(g, PG_PD_K, KVA, 2, gpa(PG_PT_K) | PTE_P | PTE_RW);
	for (i = 0; i <= PG_KCODE; i++)
		set_pte(g, PG_PT_K, KVA + i * PAGE_SIZE, 1,
			gpa(i) | PTE_P | PTE_RW);
	set_pte(g, PG_PT_K, K_MMIO, 1, KMMIO_GPA | PTE_P | PTE_RW | PTE_NX);

	/* The user half: the kernel half above, with _PAGE_USER. */
	set_pte(g, PG_PML4, UVA, 4, gpa(PG_PDPT_U) | PTE_P | PTE_RW | PTE_US);
	set_pte(g, PG_PDPT_U, UVA, 3, gpa(PG_PD_U) | PTE_P | PTE_RW | PTE_US);
	set_pte(g, PG_PD_U, UVA, 2, gpa(PG_PT_U) | PTE_P | PTE_RW | PTE_US);
	set_pte(g, PG_PT_U, UVA_CODE, 1, gpa(PG_UCODE) | PTE_P | PTE_US);
	set_pte(g, PG_PT_U, UVA_DATA, 1,
		gpa(PG_UDATA) | PTE_P | PTE_RW | PTE_US | PTE_NX);
	set_pte(g, PG_PT_U, UVA_DATA2, 1,
		gpa(PG_UDATA2) | PTE_P | PTE_RW | PTE_US | PTE_NX);
	set_pte(g, PG_PT_U, UVA_RO, 1, gpa(PG_URO) | PTE_P | PTE_US | PTE_NX);
	set_pte(g, PG_PT_U, UVA_SUPER, 1,
		gpa(PG_USUPER) | PTE_P | PTE_RW | PTE_NX);
	set_pte(g, PG_PT_U, UVA_PKEY, 1,
		gpa(PG_UPKEY) | PTE_P | PTE_RW | PTE_US | PTE_NX | PTE_PKEY1);
	set_pte(g, PG_PT_U, UVA_MMIO, 1,
		UMMIO_GPA | PTE_P | PTE_RW | PTE_US | PTE_NX);

	/* Bit 7 is reserved in a PML4E. */
	set_pte(g, PG_PML4, UVA_RSVD, 4,
		gpa(PG_PDPT_U) | PTE_P | PTE_RW | PTE_US | PTE_PS);
}

static void set_segment(struct kvm_segment *seg, u16 selector, u8 type, bool l)
{
	*seg = (struct kvm_segment) {
		.selector = selector,
		.limit = 0xfffff,
		.type = type,
		.present = 1,
		.s = 1,
		.l = l,
		.db = !l,
		.g = 1,
	};
}

/*
 * A vCPU comes out of reset in non-PVM mode.  Long mode with a DPL0 64-bit
 * CS is what switches it to PVM supervisor mode, at pvm_return_user, which
 * enters user mode at CTRL_RIP.
 */
static void guest_setup_vcpu(struct pvm_guest *g)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	vcpu_set_msr(g->vcpu, MSR_PVM_VCPU_STRUCT, gpa(PG_PVCS));
	vcpu_set_msr(g->vcpu, MSR_PVM_EVENT_ENTRY, KADDR(pvm_kernel_start));
	vcpu_set_msr(g->vcpu, MSR_PVM_RETU_RIP, KADDR(pvm_retu));
	vcpu_set_msr(g->vcpu, MSR_LSTAR, KADDR(pvm_syscall));
	vcpu_set_msr(g->vcpu, MSR_SYSCALL_MASK, 0);

	vcpu_sregs_get(g->vcpu, &sregs);
	sregs.cr0 = X86_CR0_PG | X86_CR0_AM | X86_CR0_WP | X86_CR0_NE |
		    X86_CR0_ET | X86_CR0_MP | X86_CR0_PE;
	sregs.cr3 = gpa(PG_PML4);
	sregs.cr4 = X86_CR4_PAE | X86_CR4_PCIDE;
	if (g->flags & GUEST_PKE)
		sregs.cr4 |= X86_CR4_PKE;
	sregs.efer = EFER_NX | EFER_LMA | EFER_LME | EFER_SCE;
	set_segment(&sregs.cs, 0x10, 0xb, true);
	set_segment(&sregs.ds, 0x18, 0x3, false);
	sregs.es = sregs.fs = sregs.gs = sregs.ss = sregs.ds;
	memset(&sregs.ldt, 0, sizeof(sregs.ldt));
	sregs.tr.present = 1;
	sregs.tr.type = 11;
	vcpu_sregs_set(g->vcpu, &sregs);

	memset(&regs, 0, sizeof(regs));
	regs.rip = KADDR(pvm_return_user);
	regs.rflags = 0x2;
	vcpu_regs_set(g->vcpu, &regs);
}

static void guest_create(struct pvm_guest *g, unsigned long flags)
{
	memset(g, 0, sizeof(*g));
	g->flags = flags;
	g->vm = vm_create_barebones();
	if (flags & GUEST_IRQCHIP)
		vm_create_irqchip(g->vm);
	vm_userspace_mem_region_add(g->vm, VM_MEM_SRC_ANONYMOUS, GUEST_GPA, 0,
				    GUEST_PAGES, 0);
	g->mem = addr_gpa2hva(g->vm, GUEST_GPA);
	g->pvcs = (void *)(g->mem + PG_PVCS * PAGE_SIZE);
	g->ctrl = (void *)(g->mem + PG_CTRL * PAGE_SIZE);

	TEST_ASSERT(pvm_kernel_end - pvm_kernel_start <= PAGE_SIZE &&
		    pvm_user_end - pvm_user_start <= PAGE_SIZE,
		    "Guest code does not fit its page");
	memcpy(g->mem + PG_KCODE * PAGE_SIZE, pvm_kernel_start,
	       pvm_kernel_end - pvm_kernel_start);
	memcpy(g->mem + PG_UCODE * PAGE_SIZE, pvm_user_start,
	       pvm_user_end - pvm_user_start);
	build_page_tables(g);
	g->pvcs->user_gsbase = USER_GSBASE;

	g->vcpu = __vm_vcpu_add(g->vm, 0);
	vcpu_init_cpuid(g->vcpu, kvm_get_supported_cpuid());
	guest_setup_vcpu(g);
}

static void pf_stats_get(struct pvm_guest *g, struct pf_stats *s)
{
	s->guest = vcpu_get_stat(g->vcpu, pf_guest);
	s->taken = vcpu_get_stat(g->vcpu, pf_taken);
}

/* Run the guest until supervisor mode reports; return the report. */
static u64 guest_run(struct pvm_guest *g)
{
	struct kvm_run *run = g->vcpu->run;
	u64 data;

	g->nr_values = 0;
	for (;;) {
		vcpu_run(g->vcpu);
		TEST_ASSERT_KVM_EXIT_REASON(g->vcpu, KVM_EXIT_MMIO);
		TEST_ASSERT(run->mmio.is_write, "MMIO read at 0x%llx",
			    run->mmio.phys_addr);

		if (run->mmio.phys_addr == UMMIO_GPA) {
			g->user_mmio++;
			continue;
		}

		TEST_ASSERT_EQ(run->mmio.len, 8);
		memcpy(&data, run->mmio.data, sizeof(data));
		if (run->mmio.phys_addr == KMMIO_GPA)
			return data;

		TEST_ASSERT(run->mmio.phys_addr == KMMIO_GPA + 8,
			    "MMIO write at 0x%llx", run->mmio.phys_addr);
		TEST_ASSERT(g->nr_values < ARRAY_SIZE(g->values),
			    "Too many values reported");
		g->values[g->nr_values++] = data;
	}
}

/* Enter @rip in user mode with @rcx, and expect a system call back. */
static void user_call(struct pvm_guest *g, char *rip, u64 rcx)
{
	u64 report;

	g->ctrl[CTRL_RIP / 8] = UADDR(rip);
	g->ctrl[CTRL_RCX / 8] = rcx;
	report = guest_run(g);
	TEST_ASSERT(report == REPORT_SYSCALL,
		    "Wanted a system call from user mode, got report %lu, event vector 0x%x",
		    report, g->pvcs->event_vector);
}

/*
 * Two round trips between the modes, so that both shadow roots exist and
 * the host may switch between them, and deliver faults, by itself.
 */
static void guest_warm_up(struct pvm_guest *g)
{
	user_call(g, u_nop, 0);
	user_call(g, u_nop, 0);
}

static void set_features(struct pvm_guest *g, u64 features)
{
	vcpu_set_msr(g->vcpu, MSR_PVM_FEATURES_ENABLED, features);
}

enum pf_path {
	PF_DIRECT,	/* delivered without an exit */
	PF_SLOW,	/* through the shadow MMU, which injected it */
};

/*
 * Run until the next report, which must be a user #PF for @addr with
 * @error_code, taken by @path.  The state saved in the PVCS must be that of
 * the faulting user instruction whichever path delivered the fault.
 */
static void __expect_user_pf(struct pvm_guest *g, u64 rip, u64 addr,
			     u16 error_code, enum pf_path path)
{
	struct pvm_vcpu_struct *pvcs = g->pvcs;
	struct pf_stats before, after;
	struct kvm_sregs sregs;
	u64 report;

	pf_stats_get(g, &before);
	report = guest_run(g);
	pf_stats_get(g, &after);

	TEST_ASSERT(report == REPORT_USER_EVENT,
		    "Wanted a user #PF at 0x%lx, got report %lu", addr, report);
	TEST_ASSERT(pvcs->event_vector == (PVM_PVCS_EVENT_VECTOR_STD | PF_VECTOR),
		    "Wanted #PF at 0x%lx, got event vector 0x%x",
		    addr, pvcs->event_vector);
	TEST_ASSERT(pvcs->event_errcode == error_code,
		    "#PF at 0x%lx: error code 0x%x, wanted 0x%x",
		    addr, pvcs->event_errcode, error_code);
	TEST_ASSERT(pvcs->cr2 == addr, "#PF at 0x%lx: PVCS::cr2 0x%llx",
		    addr, pvcs->cr2);
	vcpu_sregs_get(g->vcpu, &sregs);
	TEST_ASSERT(sregs.cr2 == addr, "#PF at 0x%lx: KVM reports CR2 0x%llx",
		    addr, sregs.cr2);

	TEST_ASSERT(pvcs->rip == rip && pvcs->rcx == addr &&
		    pvcs->r11 == USER_R11 &&
		    (pvcs->eflags & ~X86_EFLAGS_RF) == USER_EFLAGS &&
		    pvcs->user_cs == USER_CS && pvcs->user_ss == USER_SS &&
		    pvcs->user_gsbase == USER_GSBASE &&
		    pvcs->pkru == g->ctrl[CTRL_PKRU / 8],
		    "#PF at 0x%lx: saved rip 0x%llx rcx 0x%llx r11 0x%llx eflags 0x%x cs 0x%x ss 0x%x gsbase 0x%llx pkru 0x%x",
		    addr, pvcs->rip, pvcs->rcx, pvcs->r11, pvcs->eflags,
		    pvcs->user_cs, pvcs->user_ss, pvcs->user_gsbase, pvcs->pkru);

	if (path == PF_DIRECT)
		TEST_ASSERT(after.guest == before.guest && after.taken == before.taken,
			    "#PF at 0x%lx (error code 0x%x) was not delivered directly: pf_guest +%lu, pf_taken +%lu",
			    addr, error_code, after.guest - before.guest,
			    after.taken - before.taken);
	else
		TEST_ASSERT(after.guest == before.guest + 1 &&
			    after.taken == before.taken + 1,
			    "#PF at 0x%lx (error code 0x%x) did not go through the shadow MMU: pf_guest +%lu, pf_taken +%lu",
			    addr, error_code, after.guest - before.guest,
			    after.taken - before.taken);
}

/* Start @rip with @addr in RCX, and expect a #PF for @addr. */
static void expect_user_pf(struct pvm_guest *g, char *rip, u64 addr,
			   u16 error_code, enum pf_path path)
{
	g->ctrl[CTRL_RIP / 8] = UADDR(rip);
	g->ctrl[CTRL_RCX / 8] = addr;
	__expect_user_pf(g, rip == u_exec ? addr : UADDR(rip), addr,
			 error_code, path);
}

/* Return from a #PF that @rip took, and expect it again. */
static void expect_user_pf_again(struct pvm_guest *g, char *rip, u64 addr,
				 u16 error_code, enum pf_path path)
{
	__expect_user_pf(g, UADDR(rip), addr, error_code, path);
}

/*
 * Return from a spurious #PF: the retry must be handled by the shadow MMU,
 * which maps the page without injecting anything, and the routine completes.
 */
static void expect_retry_fixed(struct pvm_guest *g)
{
	struct pf_stats before, after;
	u64 report;

	pf_stats_get(g, &before);
	report = guest_run(g);
	pf_stats_get(g, &after);

	TEST_ASSERT(report == REPORT_SYSCALL,
		    "Wanted the retry to complete, got report %lu, event vector 0x%x error code 0x%x cr2 0x%llx",
		    report, g->pvcs->event_vector, g->pvcs->event_errcode,
		    g->pvcs->cr2);
	TEST_ASSERT(after.guest == before.guest && after.taken == before.taken + 1,
		    "Retry: pf_guest +%lu, pf_taken +%lu, wanted +0, +1",
		    after.guest - before.guest, after.taken - before.taken);
}

#define PFERR_U		PFERR_USER_MASK
#define PFERR_UW	(PFERR_USER_MASK | PFERR_WRITE_MASK)

static void test_features_msr(void)
{
	struct pvm_guest g;

	guest_create(&g, 0);

	TEST_ASSERT_EQ(vcpu_get_msr(g.vcpu, MSR_PVM_FEATURES_ENABLED), 0);
	set_features(&g, PVM_FEATURE_DIRECT_PF);

	TEST_ASSERT(!_vcpu_set_msr(g.vcpu, MSR_PVM_FEATURES_ENABLED, FEATURE_UNKNOWN),
		    "An unknown feature bit was accepted");
	TEST_ASSERT(!_vcpu_set_msr(g.vcpu, MSR_PVM_FEATURES_ENABLED, BIT_ULL(63)),
		    "Feature bit 63 was accepted");
	TEST_ASSERT_EQ(vcpu_get_msr(g.vcpu, MSR_PVM_FEATURES_ENABLED),
		       PVM_FEATURE_DIRECT_PF);

	set_features(&g, 0);
	kvm_vm_free(g.vm);
}

/* The guest's view: PVM_CPUID_FEATURES, and the MSR through hypercalls. */
static void test_guest_enable(void)
{
	struct pvm_guest g;

	guest_create(&g, 0);
	guest_warm_up(&g);

	user_call(&g, u_probe, 0);
	TEST_ASSERT_EQ(g.nr_values, 6);
	TEST_ASSERT_EQ((u32)g.values[0], PVM_ABI_VERSION);
	TEST_ASSERT((u32)g.values[1] & PVM_FEATURE_DIRECT_PF,
		    "PVM_CPUID_FEATURES.ebx 0x%lx without PVM_FEATURE_DIRECT_PF",
		    g.values[1]);
	TEST_ASSERT(g.values[2] == (u64)-KVM_EINVAL,
		    "PVM_HC_WRMSR of an unknown feature returned 0x%lx", g.values[2]);
	TEST_ASSERT(g.values[3] == 0,
		    "PVM_HC_WRMSR of PVM_FEATURE_DIRECT_PF returned 0x%lx", g.values[3]);
	TEST_ASSERT(g.values[4] == 0 && g.values[5] == PVM_FEATURE_DIRECT_PF,
		    "PVM_HC_RDMSR returned 0x%lx, value 0x%lx",
		    g.values[4], g.values[5]);
	TEST_ASSERT_EQ(vcpu_get_msr(g.vcpu, MSR_PVM_FEATURES_ENABLED),
		       PVM_FEATURE_DIRECT_PF);

	expect_user_pf(&g, u_read, UVA_ABSENT(0), PFERR_U, PF_DIRECT);
	kvm_vm_free(g.vm);
}

/*
 * INIT resets every PVM MSR, the feature included, and the run of direct
 * deliveries: set up again, the guest's first fault on the page of its last
 * delivery before the INIT is delivered directly.  The INIT is the latched
 * one KVM_SET_VCPU_EVENTS restores, which KVM_GET_MP_STATE accepts.
 */
static void test_reset(void)
{
	struct kvm_vcpu_events events;
	struct kvm_mp_state mp_state;
	struct pvm_guest g;

	guest_create(&g, GUEST_IRQCHIP);
	guest_warm_up(&g);
	set_features(&g, PVM_FEATURE_DIRECT_PF);
	expect_user_pf(&g, u_read, UVA_ABSENT(0), PFERR_U, PF_DIRECT);

	vcpu_events_get(g.vcpu, &events);
	events.flags = KVM_VCPUEVENT_VALID_SMM;
	events.smi.latched_init = 1;
	vcpu_events_set(g.vcpu, &events);
	vcpu_mp_state_get(g.vcpu, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_RUNNABLE);

	TEST_ASSERT_EQ(vcpu_get_msr(g.vcpu, MSR_PVM_FEATURES_ENABLED), 0);
	TEST_ASSERT_EQ(vcpu_get_msr(g.vcpu, MSR_PVM_VCPU_STRUCT), 0);
	TEST_ASSERT_EQ(vcpu_get_msr(g.vcpu, MSR_PVM_EVENT_ENTRY), 0);
	TEST_ASSERT_EQ(vcpu_get_msr(g.vcpu, MSR_PVM_RETU_RIP), 0);

	guest_setup_vcpu(&g);
	guest_warm_up(&g);
	set_features(&g, PVM_FEATURE_DIRECT_PF);
	expect_user_pf(&g, u_read, UVA_ABSENT(0), PFERR_U, PF_DIRECT);
	kvm_vm_free(g.vm);
}

/* Not enabled, enabled, and disabled again, for a read and a write. */
static void test_enable_disable(void)
{
	struct pvm_guest g;

	guest_create(&g, 0);
	guest_warm_up(&g);

	expect_user_pf(&g, u_read, UVA_ABSENT(0), PFERR_U, PF_SLOW);
	expect_user_pf(&g, u_write, UVA_ABSENT(1), PFERR_UW, PF_SLOW);

	set_features(&g, PVM_FEATURE_DIRECT_PF);
	expect_user_pf(&g, u_read, UVA_ABSENT(2), PFERR_U, PF_DIRECT);
	expect_user_pf(&g, u_write, UVA_ABSENT(3), PFERR_UW, PF_DIRECT);

	set_features(&g, 0);
	expect_user_pf(&g, u_read, UVA_ABSENT(4), PFERR_U, PF_SLOW);
	expect_user_pf(&g, u_write, UVA_ABSENT(5), PFERR_UW, PF_SLOW);
	kvm_vm_free(g.vm);
}

/*
 * A present guest PTE without a shadow PTE faults as not present, and may be
 * delivered as such; the guest returns from it and the retry, on the same
 * page, is the shadow MMU's.
 */
static void test_present_pte(void)
{
	struct pvm_guest g;

	guest_create(&g, 0);
	guest_warm_up(&g);
	set_features(&g, PVM_FEATURE_DIRECT_PF);

	expect_user_pf(&g, u_read, UVA_DATA, PFERR_U, PF_DIRECT);
	expect_retry_fixed(&g);
	expect_user_pf(&g, u_write, UVA_DATA2, PFERR_UW, PF_DIRECT);
	expect_retry_fixed(&g);
	kvm_vm_free(g.vm);
}

/* Faults that are not "user, not present" are never delivered directly. */
static void test_protection(void)
{
	struct pvm_guest g;

	guest_create(&g, 0);
	guest_warm_up(&g);

	/* A write to a read-only page the shadow MMU has already mapped. */
	user_call(&g, u_read, UVA_RO);
	set_features(&g, PVM_FEATURE_DIRECT_PF);
	expect_user_pf(&g, u_write, UVA_RO,
		       PFERR_PRESENT_MASK | PFERR_UW, PF_SLOW);

	/*
	 * A supervisor-only page is not in the user shadow table, so the
	 * first fault is not present; the exact one follows on the retry.
	 */
	expect_user_pf(&g, u_read, UVA_SUPER, PFERR_U, PF_DIRECT);
	expect_user_pf_again(&g, u_read, UVA_SUPER,
			     PFERR_PRESENT_MASK | PFERR_U, PF_SLOW);

	/* Instruction fetch. */
	expect_user_pf(&g, u_exec, UVA_ABSENT(0),
		       PFERR_FETCH_MASK | PFERR_U, PF_SLOW);

	/* A reserved bit in the guest's page table, and a reserved SPTE. */
	expect_user_pf(&g, u_read, UVA_RSVD, PFERR_U, PF_DIRECT);
	expect_user_pf_again(&g, u_read, UVA_RSVD,
			     PFERR_RSVD_MASK | PFERR_PRESENT_MASK | PFERR_U,
			     PF_SLOW);
	kvm_vm_free(g.vm);
}

/*
 * A user access to emulated MMIO faults with RSVD once the shadow MMU has
 * installed its MMIO SPTE, and must exit to be emulated, not be delivered.
 */
static void test_mmio(void)
{
	struct pf_stats before, after;
	struct pvm_guest g;

	guest_create(&g, 0);
	guest_warm_up(&g);

	user_call(&g, u_write, UVA_MMIO);
	TEST_ASSERT_EQ(g.user_mmio, 1);

	set_features(&g, PVM_FEATURE_DIRECT_PF);
	pf_stats_get(&g, &before);
	user_call(&g, u_write, UVA_MMIO);
	pf_stats_get(&g, &after);
	TEST_ASSERT_EQ(g.user_mmio, 2);
	TEST_ASSERT_EQ(after.guest, before.guest);
	kvm_vm_free(g.vm);
}

/* A fault a protection key denies, on a page with a shadow PTE. */
static void test_pkey(void)
{
	struct pvm_guest g;

	guest_create(&g, GUEST_PKE);
	guest_warm_up(&g);

	user_call(&g, u_read, UVA_PKEY);
	set_features(&g, PVM_FEATURE_DIRECT_PF);
	g.ctrl[CTRL_PKRU / 8] = 0x4;	/* access disabled for key 1 */
	expect_user_pf(&g, u_read, UVA_PKEY,
		       PFERR_PK_MASK | PFERR_PRESENT_MASK | PFERR_U, PF_SLOW);
	kvm_vm_free(g.vm);
}

/* A fault on the host's half is never the guest's to have delivered directly. */
static void test_upper_half(void)
{
	struct pvm_guest g;

	guest_create(&g, 0);
	guest_warm_up(&g);
	set_features(&g, PVM_FEATURE_DIRECT_PF);

	expect_user_pf(&g, u_read, UVA_UPPER, PFERR_U, PF_SLOW);
	kvm_vm_free(g.vm);
}

/* A supervisor-mode fault is delivered at the supervisor entry, by KVM. */
static void test_supervisor(void)
{
	struct pvm_vcpu_struct *pvcs;
	struct pf_stats before, after;
	struct pvm_guest g;
	u64 report;

	guest_create(&g, 0);
	guest_warm_up(&g);
	set_features(&g, PVM_FEATURE_DIRECT_PF);
	pvcs = g.pvcs;

	g.ctrl[CTRL_RIP / 8] = UADDR(u_kread);
	g.ctrl[CTRL_RCX / 8] = UVA_ABSENT(0);
	pf_stats_get(&g, &before);
	report = guest_run(&g);
	pf_stats_get(&g, &after);

	TEST_ASSERT(report == REPORT_SUPER_EVENT,
		    "Wanted a supervisor #PF, got report %lu", report);
	TEST_ASSERT(pvcs->event_vector == (PVM_PVCS_EVENT_VECTOR_STD | PF_VECTOR) &&
		    pvcs->event_errcode == 0 && pvcs->cr2 == UVA_ABSENT(0),
		    "Supervisor #PF: event vector 0x%x error code 0x%x cr2 0x%llx",
		    pvcs->event_vector, pvcs->event_errcode, pvcs->cr2);
	TEST_ASSERT(after.guest == before.guest + 1 &&
		    after.taken == before.taken + 1,
		    "Supervisor #PF: pf_guest +%lu, pf_taken +%lu",
		    after.guest - before.guest, after.taken - before.taken);
	kvm_vm_free(g.vm);
}

/*
 * The repeat rule, one fault at a time on pages without a guest PTE, in the
 * order of @pattern (a letter per page).  A fault on the page of the
 * delivery just before it, or after PVM_DIRECT_PF_RUN deliveries in a row,
 * goes to the shadow MMU, and a fault that does starts the run again.
 */
static void test_repeat_pattern(const char *pattern)
{
	u8 page, last_page = 0;
	struct pvm_guest g;
	int i, run = 0;
	enum pf_path path;

	guest_create(&g, 0);
	guest_warm_up(&g);
	set_features(&g, PVM_FEATURE_DIRECT_PF);

	for (i = 0; pattern[i]; i++) {
		page = pattern[i] - 'A';
		if (run && page == last_page)
			path = PF_SLOW;
		else if (run >= PVM_DIRECT_PF_RUN)
			path = PF_SLOW;
		else
			path = PF_DIRECT;

		if (path == PF_DIRECT) {
			run++;
			last_page = page;
		} else {
			run = 0;
		}

		/* Every fault returns to the same instruction, with a new RCX. */
		if (!i)
			expect_user_pf(&g, u_read, UVA_ABSENT(page), PFERR_U, path);
		else {
			g.ctrl[CTRL_RCX / 8] = UVA_ABSENT(page);
			expect_user_pf_again(&g, u_read, UVA_ABSENT(page),
					     PFERR_U, path);
		}
	}
	kvm_vm_free(g.vm);
}

static void test_repeat_same_page(void)
{
	test_repeat_pattern("AAAAAA");
}

static void test_repeat_run_limit(void)
{
	test_repeat_pattern("AABCDEFGH");
}

static void test_repeat_interleaved(void)
{
	test_repeat_pattern("AABCBCBCB");
}

static const struct {
	const char *name;
	void (*fn)(void);
	bool pkey;
} tests[] = {
	{ "features_msr", test_features_msr },
	{ "guest_enable", test_guest_enable },
	{ "reset", test_reset },
	{ "enable_disable", test_enable_disable },
	{ "present_pte", test_present_pte },
	{ "protection", test_protection },
	{ "mmio", test_mmio },
	{ "pkey", test_pkey, true },
	{ "upper_half", test_upper_half },
	{ "supervisor", test_supervisor },
	{ "repeat_same_page", test_repeat_same_page },
	{ "repeat_run_limit", test_repeat_run_limit },
	{ "repeat_interleaved", test_repeat_interleaved },
};

int main(void)
{
	bool have_pkey;
	int i;

	TEST_REQUIRE(is_kvm_pvm());

	/* The guest's PKRU is the hardware's; only a host with OSPKE has one. */
	have_pkey = kvm_cpu_has(X86_FEATURE_PKU) && this_cpu_has(X86_FEATURE_OSPKE);

	ksft_print_header();
	ksft_set_plan(ARRAY_SIZE(tests));

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (tests[i].pkey && !have_pkey) {
			ksft_test_result_skip("%s: no protection keys\n", tests[i].name);
			continue;
		}
		tests[i].fn();
		ksft_test_result_pass("%s\n", tests[i].name);
	}

	ksft_finished();
}
