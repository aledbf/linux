.. SPDX-License-Identifier: GPL-2.0

=======================================
PVM host-side implementation invariants
=======================================

``pvm-spec.rst`` describes the guest-visible ABI.  This document describes the
properties the host side must hold for that ABI to be safe to implement.  A PVM
guest kernel runs at hardware CPL 3 on a hardware CR3 that also maps the host
kernel, which makes several ordinary-looking lines load-bearing.

Each invariant has a stable number, ``S1`` to ``S12`` for the switcher and
entry code and ``M1`` to ``M8`` for the shadow MMU, cited from code comments.
Numbers are not reused.

Threat model
============

The PVM guest kernel is untrusted and runs at hardware CPL 3, in the same
address space as the host kernel's upper half.  It controls:

- all general purpose registers at the moment of a mode transition, RSP
  included;
- the contents of its own page tables;
- the contents of the PVCS page;
- when and how often it issues synthetic instructions and hypercalls.

A guest that violates the ABI must only be able to damage itself.  Any path
where guest-controlled state reaches host execution flow or host page tables is
a host escape.

Switcher invariants (S)
=======================

These are properties of ``arch/x86/entry/entry_64_switcher.S``, of the host
entry paths it hooks in ``arch/x86/entry/entry_64.S``, and of the kvm-pvm code
that prepares its state.

S1 -- SYSRET is only reached with a canonical RIP
-------------------------------------------------

**Rule.**  The generic return path takes SYSRET only when RCX equals the return
RIP and is canonical at the running host's address width, and IRET otherwise::

	cmpq	%rcx, RIP-RIP(%rsp)
	jne	.L_switcher_iretq
	canonical_rcx
	cmpq	%rcx, RIP-RIP(%rsp)
	je	.L_switcher_sysretq
	movq	RIP-RIP(%rsp), %rcx
	/* fall through to IRET */

The direct paths that jump to SYSRET without this check (user to supervisor
SYSCALL, ``PVM_HC_LOAD_PGTBL``, direct #PF) return to the guest's own SYSCALL
RIP or to ``MSR_LSTAR`` or ``MSR_PVM_EVENT_ENTRY``, which are checked on write.

**Why.**  On Intel CPUs SYSRET with a non-canonical RCX raises #GP in kernel
mode, on a stack the guest controls.  The RIP comes from ``PVCS::rip``, which
the guest writes.

**Where enforced.**  ``.L_switcher_return_to_guest`` and ``canonical_rcx``
(``X86_FEATURE_LA57`` alternative) in ``entry_64_switcher.S``;
``pvm_invalid_entry_point()`` for ``MSR_LSTAR``, ``MSR_PVM_EVENT_ENTRY`` and
``MSR_PVM_RETU_RIP`` in ``pvm_set_msr()``.

S2 -- RFLAGS entering the guest is sanitized
--------------------------------------------

**Rule.**  Before returning to the guest, RFLAGS is masked with
``SWITCH_ENTER_EFLAGS_ALLOWED`` and ``SWITCH_ENTER_EFLAGS_FIXED`` (``FIXED |
IF``) is forced.  ``RF`` or ``TF`` set, or R11 not equal to the resulting
RFLAGS, forces IRET, since SYSRET does not restore them correctly.

**Why.**  The value comes from ``PVCS::eflags``.  IOPL, VM, VIF and VIP must
never be settable by the guest, and IF must stay set on the hardware.

**Where enforced.**  ``.L_switcher_return_to_guest``; ``load_regs()``; the
direct user to supervisor switches load ``SWITCH_ENTER_EFLAGS_FIXED``.

S3 -- Direct switching is gated on all inhibitor bits at once
-------------------------------------------------------------

**Rule.**  ``SWITCH_FLAGS_NO_DS_TO_SMOD`` is ``~SWITCH_FLAGS_UMOD`` so that one
``test`` answers both "is in user mode" and "no inhibitor is set".  The
inhibitors are:

===== ======================= ==================================================
Bit   Name                    Set when
===== ======================= ==================================================
2     ``NO_DS_CR3``           no root for the other mode in ``prev_roots[]``
8     ``IRQ_WIN``             an IRQ window is requested, or an NMI/#MC was
                              recorded in a busy PVCS
9     ``SINGLE_STEP``         ``KVM_GUESTDBG_SINGLESTEP``
10    ``PVCS_INVALID``        no PVCS is registered
===== ======================= ==================================================

A new reason not to direct switch takes a bit in ``SWITCH_FLAGS_INHIBITORS``,
set before the state it protects becomes unsafe.

**Why.**  The fast paths are single tests by construction.  An inhibitor outside
the masks would be silently ignored by them.

**Where enforced.**  The ``static_assert()``\ s beside
``SWITCH_FLAGS_INHIBITORS`` in ``arch/x86/kvm/pvm/pvm.h``: every inhibitor lies
inside both ``SWITCH_FLAGS_NO_DS_TO_{SMOD,UMOD}``, none collides with the mode
bits, and ``SWITCH_FLAGS_INIT`` starts a vCPU inhibited.  Setters:
``pvm_set_host_cr3_for_guest()`` and ``PGTBL_TRY`` (``NO_DS_CR3``),
``pvm_enable_irq_window()`` and ``__do_pvm_event()`` (``IRQ_WIN``),
``pvm_update_exception_bitmap()`` (``SINGLE_STEP``), ``pvm_set_msr()`` for
``MSR_PVM_VCPU_STRUCT`` (``PVCS_INVALID``).

S4 -- ERETU takes the fast path only for the expected selectors
---------------------------------------------------------------

**Rule.**  The supervisor to user direct switch is taken only when
``PVCS::user_cs``/``user_ss`` read as the 32-bit word ``PVCS_USER_CS_SS``,
``(__USER_DS << 16) | __USER_CS``.  Anything else exits to
``handle_synthetic_instruction_return_user()``.

**Why.**  The fast path does not validate selectors; it assumes them.

**Where enforced.**  ``entry_SYSCALL_64_switcher``.

S5 -- ``TSS_extra(host_rsp)`` is the "guest running" flag
---------------------------------------------------------

**Rule.**  It is non-zero exactly between ``switcher_enter_guest()`` setting it
and ``switcher_return_from_guest`` clearing it.  Host entry paths reachable
while a guest runs test it to decide whether the event came from the guest or
interrupted the host with the guest's CR3 loaded.

**Why.**  A guest's exceptions arrive at the host's IDT looking like faults of
the VMM process.  Without the test a guest page fault becomes a SIGSEGV for the
VMM, and the ``preempt_disable()`` taken around the guest run is never paired.

**Where enforced.**  One setter and one clearer in ``switcher_enter_guest``.
Readers, all behind the ``X86_FEATURE_PVM_HOST`` alternative (S9):
``error_entry`` (``.Lerror_entry_from_pvm_guest`` and
``.Lerror_entry_switcher_active``, consumed by ``idtentry_body``),
``asm_exc_nmi``, ``SWITCHER_SAVE_AND_SWITCH_TO_HOST_CR3`` in
``paranoid_entry``, and the #PF entry, which asks it of every #PF from CPL 3
before jumping to ``pvm_direct_page_fault``, since that is a host process's
fault as often as a guest's.  The #PF entry runs before SWAPGS and reads it
through ``SP0_TSS_EXTRA()``, the read-only TSS mapping right above the entry
stack, so a host fault pays no SWAPGS.

S6 -- The guest never runs on a CR3 that maps host user space
-------------------------------------------------------------

**Rule.**  ``enter_cr3``, ``smod_cr3``, ``umod_cr3`` and every root in
``tss_extra.pgtbl[]`` are shadow roots, whose lower half is the guest's own
shadow tree and nothing else.  ``host_cr3`` is only loaded on exit paths.

**Why.**  The guest is at CPL 3.  An error in CR3 composition would hand it
host user memory.

**Where enforced.**  Roots come only from the shadow MMU through
``pvm_set_host_cr3_for_guest()`` and ``pvm_publish_pgtbl_cache()``.  Every root
starts as a copy of ``host_mmu_root_pgd`` (see M2), whose lower half
``verify_host_mmu_root()`` checks to be empty at module load.

S7 -- The PVM and host PCID spaces are disjoint
-----------------------------------------------

**Rule.**  A host PCID for a guest is ``asid << PVM_ASID_SHIFT``, the guest's
PCID index in the low 3 bits and ``PVM_UMOD_PCID_BIT`` (bit 11) for the user
mode root.  With ``PVM_ASID_MIN`` = 1 and ``PVM_ASID_SHIFT`` = 3 PVM never uses
a PCID below 8, while the host's own PCIDs are 1 to ``TLB_NR_DYN_ASIDS``
(6)::

	BUILD_BUG_ON((PVM_ASID_MIN << PVM_ASID_SHIFT) <= TLB_NR_DYN_ASIDS);

A guest PCID that does not fit the index falls back to index 0, which is never
loaded with ``CR3_NOFLUSH``.  ASID exhaustion bumps the per-CPU generation and
flushes everything.

**Why.**  A PCID shared by host and guest is a stale TLB entry that shows up as
memory corruption in either of them.

**Where enforced.**  ``hardware_cap_check()``; ``guest_pcid_to_host_pcid()``,
``update_asid()``, ``pvm_set_host_cr3_for_guest()`` and
``pvm_publish_pgtbl_cache()``.  ``TLB_NR_DYN_ASIDS`` is visible to modules so
that raising it on the host side breaks the build rather than colliding.

S8 -- The PVCS page is pinned while the guest can run
-----------------------------------------------------

**Rule.**  The page ``MSR_PVM_VCPU_STRUCT`` names is pinned with
``FOLL_WRITE | FOLL_LONGTERM`` for as long as it is registered, and the vCPU is
never entered with the MSR set but no pinned page.  The pin is refused for a
missing or read-only memslot and for a page the root template does not map
(direct map grown after module load).  It is dropped on reset, on writing 0 and
on vCPU teardown.  A memslot move or deletion re-resolves the GPA before the
next entry; a failure there is a triple fault.

A pin keeps the page, not the VMM's mapping: a VMM that replaces the mapping
inside an unchanged memslot breaks its guest, which the host does not detect
and which cannot harm the host.

**Why.**  The switcher dereferences ``tss_extra.pvcs`` from assembly while the
guest runs, with no lock and no validity check.

**Where enforced.**  ``pvm_pin_vcpu_struct()``, ``pvm_unpin_vcpu_struct()``;
``pvm_reload_pinned_pages()``, reached through ``KVM_REQ_PINNED_PAGES_RELOAD``
raised by ``kvm_arch_flush_shadow_memslot()`` and by a failed pin on the MSR
write; the ``!pvm->pvcs && pvm->msr_vcpu_struct`` check in ``pvm_vcpu_run()``.
``pvm_mark_pvcs_dirty()`` keeps dirty logging correct for a page the guest
writes without faulting.

S9 -- The host meets the hardware floor
---------------------------------------

**Rule.**  PVM runs only on a host without KPTI, with PCID and INVPCID, FSGSBASE
and NX, without FRED, not as a Xen PV guest, and not as a TDX or SEV-ES guest.
The entry code hooks are patched in at boot by ``X86_FEATURE_PVM_HOST``,
which is set only for a kernel booted with ``pvm_host`` whose host meets the
entry code's conditions; kvm-pvm refuses to load without it rather than
repeating those checks, and additionally requires NX, RDTSCP, CMPXCHG16B, and
CPUID faulting when ``cpuid_intercept`` is set.  The hooks cannot be patched
in when kvm-pvm loads instead: live text patching places an int3 at the
patched instruction, and ``error_entry`` is on the int3 handler's own path.

**Why.**  The root a guest runs on carries the host's kernel half (M2), so every
host instruction that runs on a guest CR3 -- the switcher, the direct switches,
``pvm_direct_page_fault``, the first instructions of an exception entry --
finds per-CPU data, ``tss_extra`` and the PVCS mapped.  Such a path must still
reach the host CR3 before a handler runs, because the root's lower half is the
guest's (S6).  With KPTI none of that is mapped; FRED replaces the IDT paths
the switcher hooks; a confidential guest takes #VE or #VC for guest
instructions, which the switcher cannot route.  NX is needed by M4.

**Where enforced.**  ``pvm_host_init()`` in ``arch/x86/kernel/cpu/common.c``;
``pvm_check_confidential_host()`` and ``hardware_cap_check()``;
``SWITCHER_SAVE_AND_SWITCH_TO_HOST_CR3``/``SWITCHER_RESTORE_CR3`` in the
paranoid paths and ``.Lerror_entry_switcher_active`` in ``error_entry``.

S10 -- World switches apply the VM entry and exit mitigations
-------------------------------------------------------------

**Rule.**  Every return to the guest after host code ran clears CPU buffers
(VERW under ``X86_FEATURE_CLEAR_CPU_BUF_VM``): ``switcher_enter_guest`` on the
way in from kvm-pvm, and ``SWITCHER_RESTORE_CR3`` when a host handler that
interrupted the switcher window returns to it.  The direct switches between
the guest's modes (syscall, ERETU, ``PVM_HC_LOAD_PGTBL``, direct #PF) run only
switcher code on guest state and do not clear them; the guest kernel does on
its own return to user mode.  ``IBRS_EXIT`` is done before entering the
guest.  Every exit does ``IBRS_ENTER`` before any host code with indirect
branches, and ``switcher_return_from_guest`` fills the RSB, untrains the return
predictor and clears branch history (``FILL_RETURN_BUFFER``,
``UNTRAIN_RET_VM``, ``CLEAR_BRANCH_HISTORY_VMEXIT``) before the first return.

**Why.**  The guest is a VM for the purpose of transient execution attacks,
and the mitigations VMX and SVM apply around VM entry and exit apply here.

**Where enforced.**  ``entry_64_switcher.S``; ``IBRS_ENTER`` in the host entry
code and ``.L_switcher_return_to_hypervisor``.

S11 -- ``PKRU`` is swapped with the guest's mode
------------------------------------------------

**Rule.**  For a guest using protection keys, the hardware ``PKRU`` is the
guest's user value while it is in user mode and ``smod_pkru`` (0) while it is
in supervisor mode; the user value is in ``PVCS::pkru`` meanwhile, and in
``vcpu->arch.pkru`` whenever the host runs.  For a guest not using protection
keys, ``PKRU`` is 0 while it runs and the host's value is restored after.

**Why.**  Every leaf SPTE carries ``USER`` (M1), so without the swap the
guest's ``PKRU`` would govern its kernel's accesses, where hardware exempts
supervisor pages.  A host process's restrictive ``PKRU`` must not deny a guest
its own pages, and a guest's ``PKRU`` must not reach the host.

**Where enforced.**  ``SWITCHER_PKRU_TO_SMOD``/``SWITCHER_PKRU_TO_UMOD`` on the
direct paths; ``pvm_load_guest_xsave_state()``,
``pvm_load_host_xsave_state()``, ``__do_pvm_event()`` and
``handle_synthetic_instruction_return_user()`` on the others.

S12 -- Direct #PF delivery applies one rule in two places
---------------------------------------------------------

**Rule.**  A user #PF is delivered without the shadow MMU only if the guest
enabled ``PVM_FEATURE_DIRECT_PF``, the error code is exactly a user not-present
read or write (no ``P``, ``RSVD``, ``PK``, fetch or other bit), ``CR2`` is in
the lower half, it is not on the page of the
previous direct delivery, and fewer than ``PVM_DIRECT_PF_RUN`` (4) direct
deliveries precede it.  The switcher additionally requires the 64-bit user
selectors and no direct switch inhibitor; kvm-pvm requires no pending exception
and no host async #PF.  Both share the run state through ``tss_extra.dpf_run``
and ``dpf_page``, copied in and out around every run.

**Why.**  A wrong delivery costs the guest a spurious fault it must tolerate
(see the spec).  The repeat rule is what guarantees such a fault reaches the
shadow MMU next time, so the guest cannot loop; two diverging copies of it would
lose that guarantee.

**Where enforced.**  ``pvm_direct_page_fault`` in ``entry_64_switcher.S`` and
``pvm_direct_pf_candidate()``; ``pvm_vcpu_run_noinstr()`` copies the state.
The assembly tests the constants in ``<asm/pvm_switcher.h>``
(``PVM_DIRECT_PF_ERR_*``, ``PVM_DIRECT_PF_RUN``), and the C side uses
``pvm_direct_pf_error_code()`` and ``pvm_direct_pf_rule()``, defined next to
them.

Shadow MMU invariants (M)
=========================

These are properties of the shadow MMU in ``arch/x86/kvm/mmu/`` when
``kvm_mmu_set_guest_cpl3_paging()`` has been called, which sets
``shadow_guest_cpl3`` and ``shadow_host_root``.

M1 -- Every leaf SPTE carries ``USER``
--------------------------------------

**Rule.**  Every mapping the guest may reach is a user mapping, regardless of
the guest's own U/S bit.

**Why.**  The guest runs at hardware CPL 3 in both of its modes, so a mapping
without ``USER`` is unreachable to it.  Hardware SMEP and SMAP therefore cannot
enforce the guest's kernel/user split; M3 and M4 replace them.

**Where enforced.**  ``make_spte()`` sets ``PT_USER_MASK``;
``kvm_mmu_check_leaf_spte()`` checks it under ``CONFIG_KVM_PROVE_MMU`` in
``mmu_set_spte()``, ``FNAME(sync_spte)()`` and
``shadow_mmu_split_huge_page()``.  The direct symptom of a missing ``USER`` bit
is a fault loop that points nowhere near the cause.

M2 -- Host entries in a root lose ``_PAGE_USER`` and ``SPTE_MMU_PRESENT_MASK``
------------------------------------------------------------------------------

**Rule.**  The host's upper-half top-level entries are copied into a template
once, with both bits stripped::

	spt[i] = host[i] & ~(_PAGE_USER | SPTE_MMU_PRESENT_MASK);

and every shadow root starts as a copy of that template.

**Why.**  The guest's root maps the host kernel.  Dropping ``_PAGE_USER`` is
what stops the CPL 3 guest from reading host memory through it; dropping
``SPTE_MMU_PRESENT_MASK`` stops the MMU from walking or zapping a host entry as
a shadow page.  The vsyscall page is hidden as a side effect.

**Where enforced.**  ``clone_host_mmu()`` and ``verify_host_mmu_root()`` at
module load; the ``shadow_host_root`` copy in ``kvm_mmu_alloc_shadow_page()``.

M3 -- ``role.access & ACC_USER_MASK`` separates the guest's two roots
---------------------------------------------------------------------

**Rule.**  The guest's supervisor and user roots for one guest CR3 differ
exactly in this bit, which follows the guest's mode.  Non-leaf shadow pages are
never shared between the two trees.

**Why.**  Sharing them is an attractive memory saving that fuses the trees this
bit separates, and with them the guest's kernel/user isolation (M4).

**Where enforced.**  ``init_kvm_shadow_mmu()`` sets the bit from the CPL;
``switch_to_smod()``, ``switch_to_umod()`` and the mode reconciliation after a
run in ``pvm_vcpu_run()`` flip it.  ``kvm_mmu_find_shadow_page()`` compares the
whole ``role.word``, so pages differing in the bit are never merged.

M4 -- SMEP is emulated with NX
------------------------------

**Rule.**  A user shadow page linked beneath a kernel shadow page gets NX on the
link, and a user leaf mapped directly by a kernel shadow page carries NX itself.
A kernel-side walk strips ``ACC_USER_MASK``, and a user walk through an entry
that already holds a kernel child keeps that child.  SMAP is never advertised.

**Why.**  Because of M1 a guest kernel page and a guest user page are both
``USER`` to the hardware, so hardware SMEP cannot block the guest kernel
executing guest user pages.  NX can.  A host without NX has no substitute and is
refused (S9).  SMAP has no substitute at all.  Without keeping the kernel child,
a 5-level host, where a guest's whole lower half is one top-level entry, would
have the kernel and user walks replace each other's child forever.

**Where enforced.**  ``__link_shadow_page()``, ``make_spte()``,
``mmu_adjust_kernel_only_access()`` called from ``FNAME(fetch)()``;
``pvm_set_cpu_caps()``.

M5 -- The shadow root level equals the host root level
------------------------------------------------------

**Rule.**  Every root has the host's paging level; where the guest's paging
level is lower, the extra level is ``passthrough``.  LA57 is advertised to a
guest only on a 5-level host.

**Why.**  The root carries the host's top-level entries (M2) and is loaded into
the hardware CR3, so it must have the host's shape.

**Where enforced.**  ``init_kvm_shadow_mmu()`` (``HOST_ROOT_LEVEL``);
``pvm_set_cpu_caps()``.

M6 -- Any guest PTE may have changed at any time
------------------------------------------------

**Rule.**  The shadow MMU must not assume that a present non-leaf SPTE points
at a shadow page whose ``gfn`` and ``role`` still match what the walk expects.

**Why.**  A guest that rewrites its page tables from another vCPU can otherwise
make the MMU reuse the wrong shadow page, which ends in use-after-free.  PVM
guests are exactly as able to do that as any shadow paging guest.

**Where enforced.**  ``kvm_mmu_get_child_sp()`` compares both and
``__link_shadow_page()`` zaps rather than reuses (upstream commits
0cb2af2ea66a and 81ccda30b4e8).  PVM must not shortcut either.

M7 -- Guest linear addresses are confined to the lower half
-----------------------------------------------------------

**Rule.**  ``pvm_guest_allowed_va()`` is the single source of truth, and is a
sign test::

	return (s64)va >= 0;

**Why.**  The upper half is the host's.  An upper-half guest mapping, breakpoint
or entry point would reach host memory or fault forever on host pages.

**Where enforced.**  ``pvm_disallowed_va()`` as ``kvm_x86_ops.disallowed_va``,
which fails ``FNAME(walk_addr_generic)()`` for such addresses;
``pvm_invalid_entry_point()`` for the entry MSRs; ``pvm_eff_dr7()`` for
breakpoints; ``pvm_direct_pf_candidate()`` and the sign test in
``pvm_direct_page_fault``.

M8 -- A leaf SPTE's protection key is the guest PTE's
-----------------------------------------------------

**Rule.**  For a guest with ``CR4.PKE`` set, ``role.cr4_pke`` is set and every
leaf SPTE carries the protection key of the guest PTE it shadows, in bits 59-62.
Such SPTEs always use A/D bits, since bits 60-61 are part of the key.  An
unsync SPTE whose guest key changed is rewritten when it is synced.

**Why.**  The hardware checks the key against the live ``PKRU`` (S11), so a
stale or missing key silently changes the guest's protection.  ``CR4.PKE`` is
in the page role because it changes SPTE contents.

**Where enforced.**  ``init_kvm_shadow_mmu()`` sets ``root_role.cr4_pke``;
``spte_set_guest_pkey()`` in ``mmu_set_spte()`` and ``FNAME(sync_spte)()``, the
key threaded through ``kvm_mmu_prefetch_sptes()``; the key comparison in
``FNAME(sync_spte)()``; ``spte_ad_enabled()`` and
``spte_ad_need_write_protect()``; ``pvm_set_cpu_caps()`` advertises PKU only
with host ``OSPKE``.  Static asserts next to ``SPTE_GUEST_PKEY_MASK`` in
``spte.h`` pin the key to bits 59-62, covering the A/D type and no other bit a
present shadow SPTE uses.
