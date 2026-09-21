// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test KVM's emulation of RDPKRU and WRPKRU via the forced emulation prefix.
 */
#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define PKRU_VAL1	0xaaaaaaa8u
#define PKRU_VAL2	0x0000000cu
#define PKRU_HIGH_BITS	0x100000000ull

/*
 * Run a PKRU instruction, optionally forced through the emulator, with EAX,
 * RCX and RDX as inputs; EAX and RDX are updated.  Returns the exception
 * vector, or 0 if the instruction did not fault.
 */
#define pkru_insn_safe(fep, insn, eax, ecx, edx)			\
({									\
	u64 __error_code;						\
	u8 __vector;							\
									\
	asm volatile(__KVM_ASM_SAFE(insn, fep)				\
		     : "+a"(eax), "+d"(edx),				\
		       KVM_ASM_SAFE_OUTPUTS(__vector, __error_code)	\
		     : "c"(ecx)						\
		     : KVM_ASM_SAFE_CLOBBERS);				\
	__vector;							\
})

static u32 rdpkru_native(void)
{
	u32 eax = 0, ecx = 0, edx = 0;
	u8 vector;

	vector = pkru_insn_safe("", "rdpkru", eax, ecx, edx);
	__GUEST_ASSERT(!vector, "Native RDPKRU faulted, vector %u", vector);
	return eax;
}

static void wrpkru_native(u32 pkru)
{
	u32 eax = pkru, ecx = 0, edx = 0;
	u8 vector;

	vector = pkru_insn_safe("", "wrpkru", eax, ecx, edx);
	__GUEST_ASSERT(!vector, "Native WRPKRU faulted, vector %u", vector);
}

static void guest_test_rdpkru(void)
{
	u64 ecx, edx;
	u32 eax;
	u8 vector;

	wrpkru_native(PKRU_VAL1);

	eax = 0;
	ecx = 0;
	edx = 0xdead0000deadull;
	vector = pkru_insn_safe(KVM_FEP, "rdpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, 0);
	GUEST_ASSERT_EQ(eax, PKRU_VAL1);
	GUEST_ASSERT_EQ(edx, 0);

	ecx = 1;
	vector = pkru_insn_safe(KVM_FEP, "rdpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, GP_VECTOR);

	/* Only ECX must be zero, the upper half of RCX is ignored. */
	eax = 0;
	ecx = PKRU_HIGH_BITS;
	vector = pkru_insn_safe("", "rdpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, 0);
	GUEST_ASSERT_EQ(eax, PKRU_VAL1);

	eax = 0;
	ecx = PKRU_HIGH_BITS;
	vector = pkru_insn_safe(KVM_FEP, "rdpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, 0);
	GUEST_ASSERT_EQ(eax, PKRU_VAL1);
}

static void guest_test_wrpkru(void)
{
	u64 ecx, edx;
	u32 eax;
	u8 vector;

	eax = PKRU_VAL2;
	ecx = 0;
	edx = 0;
	vector = pkru_insn_safe(KVM_FEP, "wrpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, 0);
	GUEST_ASSERT_EQ(rdpkru_native(), PKRU_VAL2);

	eax = PKRU_VAL1;
	ecx = 1;
	vector = pkru_insn_safe(KVM_FEP, "wrpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, GP_VECTOR);

	ecx = 0;
	edx = 1;
	vector = pkru_insn_safe(KVM_FEP, "wrpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, GP_VECTOR);

	GUEST_ASSERT_EQ(rdpkru_native(), PKRU_VAL2);

	/* Only ECX and EDX must be zero, the upper halves are ignored. */
	eax = PKRU_VAL1;
	ecx = PKRU_HIGH_BITS;
	edx = PKRU_HIGH_BITS;
	vector = pkru_insn_safe("", "wrpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, 0);
	GUEST_ASSERT_EQ(rdpkru_native(), PKRU_VAL1);

	eax = PKRU_VAL2;
	ecx = PKRU_HIGH_BITS;
	edx = PKRU_HIGH_BITS;
	vector = pkru_insn_safe(KVM_FEP, "wrpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, 0);
	GUEST_ASSERT_EQ(rdpkru_native(), PKRU_VAL2);
}

/*
 * Both instructions are NP: a 66, F2 or F3 prefix makes them #UD.  This is a
 * macro rather than a function because the prefix is pasted into the
 * assembly string.
 */
#define guest_test_prefix_ud(prefix)					\
do {									\
	u32 eax = 0, ecx = 0, edx = 0;					\
	u8 vector;							\
									\
	vector = pkru_insn_safe(KVM_FEP, ".byte " prefix "; rdpkru",	\
				eax, ecx, edx);				\
	__GUEST_ASSERT(vector == UD_VECTOR,				\
		       "Wanted #UD for %s RDPKRU, got vector %u",	\
		       prefix, vector);					\
									\
	eax = rdpkru_native();						\
	vector = pkru_insn_safe(KVM_FEP, ".byte " prefix "; wrpkru",	\
				eax, ecx, edx);				\
	__GUEST_ASSERT(vector == UD_VECTOR,				\
		       "Wanted #UD for %s WRPKRU, got vector %u",	\
		       prefix, vector);					\
} while (0)

static void guest_test_no_pke(void)
{
	u32 eax = 0, ecx = 0, edx = 0;
	u8 vector;

	set_cr4(get_cr4() & ~X86_CR4_PKE);

	vector = pkru_insn_safe(KVM_FEP, "rdpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, UD_VECTOR);

	vector = pkru_insn_safe(KVM_FEP, "wrpkru", eax, ecx, edx);
	GUEST_ASSERT_EQ(vector, UD_VECTOR);
}

static void guest_code(void)
{
	set_cr4(get_cr4() | X86_CR4_PKE);

	guest_test_rdpkru();
	guest_test_wrpkru();

	guest_test_prefix_ud("0x66");
	guest_test_prefix_ud("0xf2");
	guest_test_prefix_ud("0xf3");

	guest_test_no_pke();

	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;

	TEST_REQUIRE(is_forced_emulation_enabled);
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_PKU));

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	case UCALL_DONE:
		break;
	default:
		TEST_FAIL("Unknown ucall %lu", uc.cmd);
	}

	kvm_vm_free(vm);
	return 0;
}
