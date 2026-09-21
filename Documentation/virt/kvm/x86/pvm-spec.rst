.. SPDX-License-Identifier: GPL-2.0

=====================
X86 PVM Specification
=====================

PVM (Pagetable-based Virtual Machine) runs a paravirtualized 64-bit x86 guest
kernel at hardware CPL 3, inside the host's address space, directly on shadow
page tables maintained by the hypervisor.  It needs no VMX or SVM.  This
document is the guest-visible ABI: what a guest may rely on, and what it has to
tolerate.  How a hypervisor implements it is not part of the ABI.

The ABI constants are defined in ``arch/x86/include/uapi/asm/pvm_para.h``.

Underlying states
-----------------

**The PVM guest only runs on the underlying CPU with underlying CPL=3.**

The term "underlying" refers to the actual hardware state.  For example,
``underlying CR3`` is the hardware ``CR3``, while ``CR3`` or ``PVM CR3`` is the
virtualized register.  Registers in this document are PVM registers unless
described as "underlying".

While the guest runs on the CPU, the underlying state is:

+-------------------+--------------------------------------------------+
| Registers         | Values                                           |
+===================+==================================================+
| Underlying RFLAGS | IOPL=VM=VIF=VIP=0, IF=1, fixed-bit1=1.  Other    |
|                   | flags are guest-controlled and passed through    |
|                   | to the hardware.                                 |
+-------------------+--------------------------------------------------+
| Underlying CR3    | implementation-defined, a shadow of the          |
|                   | ``PVM CR3`` with the host kernel mapped in the   |
|                   | upper half.                                      |
+-------------------+--------------------------------------------------+
| Underlying CR0    | PE=PG=WP=ET=NE=AM=MP=1, CD=NW=EM=TS=0.           |
+-------------------+--------------------------------------------------+
| Underlying CR4    | VME=PVI=0, PAE=FSGSBASE=PCIDE=1.  Others are     |
|                   | implementation-defined.                          |
+-------------------+--------------------------------------------------+
| Underlying EFER   | SCE=LMA=LME=NXE=1.                               |
+-------------------+--------------------------------------------------+
| Underlying GDTR   | All entries with DPL < 3 are hypervisor-defined. |
|                   | The table has DPL=3 entries for the selectors    |
|                   | ``__USER32_CS``, ``__USER_CS`` and               |
|                   | ``__USER_DS`` (``__USER32_CS`` is                |
|                   | implementation-defined, ``__USER_CS`` =          |
|                   | ``__USER32_CS`` + 8, ``__USER_DS`` =             |
|                   | ``__USER32_CS`` + 16).  The table may have other |
|                   | hypervisor-defined DPL=3 data entries, see       |
|                   | :ref:`pvm_host_information`.                     |
+-------------------+--------------------------------------------------+
| Underlying TR     | implementation-defined, no I/O port access.      |
+-------------------+--------------------------------------------------+
| Underlying LDTR   | NULL.                                            |
+-------------------+--------------------------------------------------+
| Underlying IDT    | implementation-defined, see ``INT n`` in         |
|                   | :ref:`pvm_changed_instructions`.                 |
+-------------------+--------------------------------------------------+
| Underlying CS     | ``__USER_CS`` or ``__USER32_CS``.                |
+-------------------+--------------------------------------------------+
| Underlying SS     | ``__USER_DS``.                                   |
+-------------------+--------------------------------------------------+
| Underlying        | NULL, ``__USER_DS`` or another DPL=3 data entry  |
| DS/ES/FS/GS       | of the underlying ``GDT``.                       |
+-------------------+--------------------------------------------------+

PVM modes and states
--------------------

PVM has three modes, all variants of IA-32e mode:

- PVM 64-bit supervisor mode: x86 64-bit supervisor mode modified by this ABI.
- PVM 64-bit user mode: x86 64-bit user mode.
- PVM 32-bit compatibility user mode: x86 compatibility mode.

A hypervisor may also run the guest in a non-PVM mode (non-IA-32e mode, or
IA-32e compatibility mode at CPL 0) to bootstrap it.  Non-PVM mode is not part
of this ABI; it follows the plain x86 architecture and is emulated.  Once the
guest is in 64-bit supervisor mode, the hypervisor sets ``CR0``, ``EFER.SCE``
and ``MSR_STAR`` to the PVM values and switches it to PVM 64-bit supervisor
mode.

States or registers in PVM modes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+-----------------------+----------------------------------------------+
| Register              | Values                                       |
+=======================+==============================================+
| ``CR0``               | PE=PG=WP=ET=NE=AM=MP=1, CD=NW=EM=TS=0.       |
+-----------------------+----------------------------------------------+
| ``CR4``               | VME=PVI=SMAP=0; PAE=FSGSBASE=1;              |
|                       | UMIP/PKE/OSXSAVE/OSXMMEXCPT/OSFXSR as the    |
|                       | host; PCIDE and SMEP may be set (both are    |
|                       | virtualized); LA57 only on a 5-level host.   |
+-----------------------+----------------------------------------------+
| ``EFER``              | SCE=LMA=LME=NXE=1.                           |
+-----------------------+----------------------------------------------+
| ``RFLAGS``            | Mapped to the underlying RFLAGS except for   |
|                       | IF (the underlying RFLAGS.IF is always 1).   |
|                       | IOPL=VM=VIF=VIP=0, fixed-bit1=1.  AC should  |
|                       | not be set in supervisor mode.               |
|                       |                                              |
|                       | The PVM interrupt flag is:                   |
|                       |                                              |
|                       | - bit 9 of ``PVCS::event_flags`` in          |
|                       |   supervisor mode when a PVCS is registered; |
|                       | - 0 in supervisor mode when                  |
|                       |   ``MSR_PVM_VCPU_STRUCT`` is 0;              |
|                       | - 1 in user mode.                            |
+-----------------------+----------------------------------------------+
| ``GDTR``              | Ignored (can be written and read but has no  |
|                       | effect).  The effective ``GDT`` is read-only |
|                       | and consists of the emulated supervisor mode |
|                       | ``CS/SS`` and the DPL=3 entries of the       |
|                       | underlying ``GDT``, whose TLS entries are    |
|                       | set with ``PVM_HC_LOAD_TLS``.                |
+-----------------------+----------------------------------------------+
| ``TR``, ``IDT``       | Ignored, replaced by PVM event delivery.     |
+-----------------------+----------------------------------------------+
| ``LDTR``              | Not supported; only a NULL ``LDTR``.         |
|                       |                                              |
+-----------------------+----------------------------------------------+
| ``CS`` in             | Emulated, taken from ``MSR_STAR``; the       |
| supervisor mode       | underlying ``CS`` is ``__USER_CS``.          |
+-----------------------+----------------------------------------------+
| ``CS`` in user mode   | The underlying ``CS``, ``__USER_CS`` or      |
|                       | ``__USER32_CS``.                             |
+-----------------------+----------------------------------------------+
| ``SS`` in             | Emulated, taken from ``MSR_STAR``; the       |
| supervisor mode       | underlying ``SS`` is ``__USER_DS``.          |
+-----------------------+----------------------------------------------+
| ``SS`` in user mode   | The underlying ``SS``, ``__USER_DS``.        |
+-----------------------+----------------------------------------------+
| DS/ES/FS/GS           | The underlying DS/ES/FS/GS: NULL,            |
|                       | ``__USER_DS`` or another DPL=3 data entry of |
|                       | the underlying ``GDT``.                      |
+-----------------------+----------------------------------------------+
| Interrupt shadow      | None.                                        |
+-----------------------+----------------------------------------------+
| NMI mask              | NMIs are never masked while a PVCS is        |
|                       | registered, and always masked while          |
|                       | ``MSR_PVM_VCPU_STRUCT`` is 0.                |
+-----------------------+----------------------------------------------+

.. _pvm_guest_address_space:

Guest address space
-------------------

A PVM guest may use the lower half of the address space, and nothing else::

  [ 0, 1UL << 47 )    with 4-level paging
  [ 0, 1UL << 56 )    with 5-level paging

Every PVM virtual address is canonical with bit 63 clear.  The upper half
belongs to the host kernel, which is what allows the guest to run at hardware
CPL 3 inside the same address space.

- Page table walks of upper-half addresses fail as if nothing were mapped.
- The guest kernel shares the lower half with the guest's user space and has to
  place itself inside it, so it must be position independent: the top 2GB,
  where a 64-bit kernel is normally linked, is in the host's half.
- Breakpoints (``DR0-DR3``) outside the lower half are not activated.
- Entry points and the ``EVENT_RETURN_USER`` address (``MSR_LSTAR``,
  ``MSR_PVM_EVENT_ENTRY``, ``MSR_PVM_RETU_RIP``) must be canonical lower-half
  addresses; the MSR write checks it.
- ``PVM_SYNTHETIC_CPUID``'s INVLPG operand, 0xffffffffff4d5650, is an upper-half
  address and therefore never a legitimate guest address.

Detection, ABI version and features
-----------------------------------

A PVM guest kernel can be booted through the Linux 64-bit boot entry points,
so it must detect PVM as early as possible:

- check that the underlying ``RFLAGS.IF`` is 1;
- check that the underlying ``CS`` has CPL 3;
- use ``PVM_SYNTHETIC_CPUID`` to read ``KVM_CPUID_SIGNATURE`` (0x40000000) and
  check for the KVM signature;
- use ``PVM_SYNTHETIC_CPUID`` to read the PVM leaves below.

A PVM hypervisor places its KVM leaves at 0x40000000 and nowhere else.

The probe is harmless elsewhere.  A kernel entered at CPL 0 or with interrupts
disabled, which is how the other x86 boot protocols and hypervisors enter it,
stops at one of the first two checks.  Should the synthetic instruction run at
CPL 0 anyway, its INVLPG only drops a TLB entry and its CPUID is a plain CPUID.

Almost nothing in this ABI can be discovered by probing: an MSR that does not
exist reads as zero, a hypercall that does not exist returns something, a PVCS
field that has been redefined still holds a value.  A guest must therefore read
the PVM leaves before it commits to anything else.  They are in PVM's
sub-range of the hypervisor CPUID class, 0x40000200-0x400002ff, and are answered
by the hypervisor itself rather than from the CPUID table the VMM configured::

  PVM_CPUID_SIGNATURE   (0x40000200)
    eax           the highest PVM leaf supported
    ebx, ecx, edx PVM_SIGNATURE, "PVMPVMPVM\0\0\0"

  PVM_CPUID_FEATURES    (0x40000201)
    eax           PVM_ABI_VERSION, the revision implemented (currently 1)
    ebx           feature bitmap, PVM_FEATURE_*
    ecx, edx      reserved, zero

A guest must refuse to run as a PVM guest if the signature does not match, if
``eax`` of ``PVM_CPUID_SIGNATURE`` is below ``PVM_CPUID_FEATURES``, or if
``eax`` of ``PVM_CPUID_FEATURES`` is not the ``PVM_ABI_VERSION`` it was built
for.

``PVM_ABI_VERSION`` covers everything a guest cannot discover otherwise: the
MSR numbers, the hypercall numbers, the PVCS layout, the event rules and the
address space split.  An addition that an older guest can ignore (a new
hypercall, a field taken from the PVCS reserved space, an optional behaviour)
takes a ``PVM_FEATURE_`` bit instead.  A feature that changes what the guest
can observe stays off until the guest sets the same bit in
``MSR_PVM_FEATURES_ENABLED``.

The only feature defined is ``PVM_FEATURE_DIRECT_PF`` (bit 0), see
:ref:`pvm_direct_pf`.

CPUID
~~~~~

The standard CPUID leaves describe the host, restricted to what PVM supports:

- Features the host lacks are not advertised.
- SMEP is advertised: it is emulated (see :ref:`pvm_paging`).
- PCID is advertised; guest PCIDs are virtualized.
- PKU is advertised if the host has ``OSPKE``.
- LA57 is advertised only on a host running 5-level paging.
- SMAP, PKS, LASS, LAM, XSAVES and ``MSR_IA32_XSS`` are not supported.
- CET is not supported: neither indirect branch tracking nor shadow stacks are
  advertised, for either mode.
- FRED is not supported.
- ``MSR_IA32_SPEC_CTRL`` and ``MSR_IA32_TSX_CTRL`` are not available: SPEC_CTRL,
  STIBP, SSBD and the AMD IBRS/STIBP/SSBD bits are clear, and so are
  ``ARCH_CAP_IBRS_ALL`` and ``ARCH_CAP_TSX_CTRL_MSR`` in
  ``MSR_IA32_ARCH_CAPABILITIES``.

MSRs
----

PVM MSRs
~~~~~~~~

PVM's MSRs are in 0x4b564d20-0x4b564d2f.  Indices not listed are reserved.

============================== ========== ======================================
MSR                            Index      Purpose
============================== ========== ======================================
``MSR_PVM_VCPU_STRUCT``        0x4b564d20 Physical address of the PVCS
``MSR_PVM_EVENT_ENTRY``        0x4b564d21 Event entry point
``MSR_PVM_RETU_RIP``           0x4b564d22 Address of ``EVENT_RETURN_USER``
``MSR_PVM_FEATURES_ENABLED``   0x4b564d23 ``PVM_FEATURE_*`` enabled by the guest
============================== ========== ======================================

All of them are per vCPU and 0 at reset.

MSR_PVM_VCPU_STRUCT
^^^^^^^^^^^^^^^^^^^

The guest physical address of the vCPU's PVCS (``struct pvm_vcpu_struct``),
see :ref:`pvm_pvcs`.  The value must be page aligned, otherwise the write raises
#GP.  0 unregisters the PVCS.

The page must be writable guest memory: if the hypervisor cannot map it (no
memslot, a read-only memslot, memory that cannot be pinned), the vCPU takes a
triple fault before it next runs.  The VMM must keep the page mapped at the same
host address for as long as it is registered; replacing the mapping inside a
memslot is not detected and breaks the guest.

MSR_PVM_EVENT_ENTRY
^^^^^^^^^^^^^^^^^^^

The entry point for events from user mode.  Events from supervisor mode enter at
``MSR_PVM_EVENT_ENTRY + PVM_EVENT_ENTRY_SUPERVISOR_OFFSET`` (512).  Both must be
canonical lower-half addresses.  A value that is not is refused; since a guest
without a valid event entry cannot take the #GP, a guest write of such a value
is a triple fault.

MSR_PVM_RETU_RIP
^^^^^^^^^^^^^^^^

The address of the SYSCALL instruction that is ``EVENT_RETURN_USER``, see
:ref:`pvm_synthetic_instructions`.  It must be a canonical lower-half address,
otherwise the write raises #GP.

MSR_PVM_FEATURES_ENABLED
^^^^^^^^^^^^^^^^^^^^^^^^

The ``PVM_FEATURE_*`` behaviours the guest has accepted, per vCPU.  Zero at
reset.  Writing a bit that ``PVM_CPUID_FEATURES.ebx`` does not report raises
#GP.  A change takes effect from the next entry into the guest; writing zero
turns every optional behaviour off again.

x86 MSRs
~~~~~~~~

MSR_GS_BASE, MSR_KERNEL_GS_BASE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``MSR_GS_BASE`` is mapped to the underlying ``GSBASE``.

On a switch from supervisor mode to user mode, ``MSR_GS_BASE`` is loaded from
``PVCS::user_gsbase``.  On a switch from user mode to supervisor mode,
``PVCS::user_gsbase`` is set to ``MSR_GS_BASE`` and ``MSR_GS_BASE`` is loaded
from ``MSR_KERNEL_GS_BASE``, atomically.

``MSR_KERNEL_GS_BASE`` is kept by the hypervisor and must hold the supervisor
``GSBASE`` before the next ``EVENT_RETURN_USER``.

MSR_STAR
^^^^^^^^

The supervisor mode ``CS`` is bits 47:32 with RPL 0 and ``SS`` is that plus 8.
A guest write raises #GP if that ``CS`` is 0, or if the 64-bit user ``CS``
derived from bits 63:48 (with RPL 3, plus 16) is not the host's ``__USER_CS``.

MSR_SYSCALL_MASK, MSR_CSTAR, MSR_IA32_SYSENTER_EIP/ESP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Stored but ignored.  On a system call ``RFLAGS`` is loaded with
``X86_EFLAGS_FIXED`` (0x2), as on every event delivery.  Compatibility system
calls use ``INT 0x80``.

MSR_IA32_SYSENTER_CS
^^^^^^^^^^^^^^^^^^^^

Writes are ignored; reads return 0.

TSC
~~~

The guest TSC is the host TSC: RDTSC and RDTSCP run natively at CPL 3 with no
offset and no scaling.  Writes to the TSC or ``MSR_IA32_TSC_ADJUST`` do not
change what the guest reads.

.. _pvm_pvcs:

PVCS
----

The PVM vCPU struct (PVCS) is shared between the guest and the hypervisor and
registered with ``MSR_PVM_VCPU_STRUCT``.  It occupies the first 128 bytes of a
page of guest memory; the hypervisor does not read or write the rest of the
page::

   struct pvm_vcpu_struct {
       u64 event_flags;
       u64 cr2;
       u64 reserved0[6];

       u16 user_cs, user_ss;
       u16 event_errcode;
       u16 event_vector;
       u64 user_gsbase;
       u32 eflags;
       u32 pkru;
       u64 rip;
       u64 rcx;
       u64 r11;
       u64 reserved1[2];
   };

====================== ====== ====
Field                  Offset Size
====================== ====== ====
``event_flags``        0x00   8
``cr2``                0x08   8
``reserved0``          0x10   48
``user_cs``            0x40   2
``user_ss``            0x42   2
``event_errcode``      0x44   2
``event_vector``       0x46   2
``user_gsbase``        0x48   8
``eflags``             0x50   4
``pkru``               0x54   4
``rip``                0x58   8
``rcx``                0x60   8
``r11``                0x68   8
``reserved1``          0x70   16
====================== ====== ====

Reserved fields, and reserved bits of defined fields, must be written as zero by
the guest and are ignored by the hypervisor, unless a ``PVM_FEATURE_`` bit that
the guest has enabled gives them a meaning.

PVCS::event_flags
~~~~~~~~~~~~~~~~~

``PVM_EVENT_FLAGS_IF`` (bit 9): interrupt enable flag, set to respond to
maskable external interrupts and cleared to inhibit them.  It is the PVM
``RFLAGS.IF`` in supervisor mode and has no effect in user mode, where the vCPU
always responds to maskable interrupts.  Delivery of an event from supervisor
mode clears it.  Delivery of an event from user mode leaves it as it is, so the
guest must clear it before ``EVENT_RETURN_USER``: then every event handler
starts with interrupts disabled.

``PVM_EVENT_FLAGS_IP`` (bit 32): interrupt pending flag.  The hypervisor sets it
when it cannot inject a maskable interrupt because ``PVM_EVENT_FLAGS_IF`` is
clear in supervisor mode.  A guest that sets ``PVM_EVENT_FLAGS_IF`` and finds
this bit set must issue ``PVM_HC_IRQ_WIN``.  The bit may be left set without an
interrupt actually pending, which is harmless.  The hypervisor clears it when it
handles ``PVM_HC_IRQ_WIN`` and when interrupts are enabled.

``PVM_EVENT_FLAGS_IF`` has the value of ``X86_EFLAGS_IF``, and every other bit
that is or will be defined lies above bit 31, where ``RFLAGS`` has no flags.
The word is not ``RFLAGS``, but a guest may pass it to code that only tests
``RFLAGS.IF``.

Other bits are reserved.

PVCS::event_vector, PVCS::event_errcode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a vector event is delivered, the low 8 bits of ``PVCS::event_vector`` hold
the vector and ``PVCS::event_errcode`` the error code, if the event has one.
``PVCS::event_errcode`` holds the low 16 bits of the error code.  That is the
whole error code of every exception PVM delivers: the #PF error code bits above
15 (SGX, RMP) do not occur, and #CP does not occur without CET.  A feature that
needs more bits takes a ``PVM_FEATURE_`` bit.

The high 8 bits are:

``PVM_PVCS_EVENT_VECTOR_STD`` (bit 8)
  Set by the hypervisor when it delivers an event other than NMI or #MC.  The
  guest sets it before it writes the PVCS fields for ``EVENT_RETURN_USER``; it
  stays set while in user mode and when a SYSCALL from user mode is delivered.

``PVM_PVCS_EVENT_VECTOR_NMI`` (bit 9), ``PVM_PVCS_EVENT_VECTOR_MCE`` (bit 10)
  An NMI or #MC is being delivered, or is pending while the guest is on its
  way to ``EVENT_RETURN_USER``.

See :ref:`pvm_events_do_not_nest` for how the guest must handle these bits.

PVCS::cr2
~~~~~~~~~

``PVCS::cr2`` is the guest's ``CR2`` while a PVCS is registered.  The hypervisor
writes its value of ``CR2`` there on every entry into the guest and reads it
back on every exit, so a page fault delivered without an exit and a value the
guest writes there are both what ``CR2`` reads afterwards.  A delivered #PF sets
it to the faulting linear address.

PVCS::user_cs, user_ss, user_gsbase, pkru, eflags, rip, rcx, r11
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These are written with the corresponding registers when an event is delivered
and loaded into them by ``EVENT_RETURN_USER``.

- ``user_cs``, ``user_ss``, ``user_gsbase`` and ``pkru`` are only written for an
  event from user mode and only used by ``EVENT_RETURN_USER``.
- ``pkru`` holds the guest's user ``PKRU`` while the guest is in supervisor
  mode (0 if the guest has not enabled protection keys).  See
  :ref:`pvm_protection_keys`.
- ``user_gsbase`` is canonicalized before being loaded: bits 63:N are set to
  bit N-1, where N is the host's linear address width (48 or 57).
- ``eflags`` holds the PVM ``RFLAGS`` of the interrupted context, whose IF is
  the virtual one: ``PVM_EVENT_FLAGS_IF`` for an event from supervisor mode, 1
  for an event from user mode.
- ``eflags`` is sanitized before being loaded: IOPL, VM, VIF and VIP are
  cleared, IF and the fixed bit 1 are set.

.. _pvm_synthetic_instructions:

Synthetic instructions
----------------------

PVM_SYNTHETIC_CPUID: ``invlpg 0xffffffffff4d5650; cpuid``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The byte sequence ``0f 01 3c 25 50 56 4d ff 0f a2``.  It behaves like CPUID but
is guaranteed to be handled by the PVM hypervisor, which returns the CPUID
values for the PVM guest.  At hardware CPL 3 its INVLPG, a privileged
instruction, always traps, which is what lets the hypervisor emulate the pair.
At CPL 0 the INVLPG only drops a TLB entry and the CPUID is a plain CPUID.

EVENT_RETURN_USER: SYSCALL at ``MSR_PVM_RETU_RIP``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns from supervisor mode to user mode with the state in the PVCS.  It is the
only way for the guest to switch to user mode.

It loads ``CS``, ``SS``, ``GSBASE``, ``PKRU``, ``RFLAGS``, ``RIP``, ``RCX``
and ``R11`` from the PVCS, with the conversions of ``GSBASE`` and ``RFLAGS``
described above, and sets ``PVCS::event_vector`` to
``PVM_PVCS_EVENT_VECTOR_STD``.  ``PVCS::event_flags.IF`` is not changed.  An NMI
or #MC recorded in ``PVCS::event_vector`` is then delivered.

.. _pvm_changed_instructions:

x86 instructions with changed behaviour
---------------------------------------

CPUID
  Without CPUID faulting the bare instruction returns the host's CPUID.  The
  guest kernel should use ``PVM_SYNTHETIC_CPUID``.

SGDT, SIDT, SLDT, STR, SMSW
  Return the host's values, see :ref:`pvm_host_information`.

LAR, LSL, VERR, VERW
  Operate on the host ``GDT``.

STAC, CLAC, SWAPGS, SYSEXIT, SYSRET
  Must not be used by the guest kernel; the result is undefined.

SYSENTER
  Raises #GP.

INT n
  Only ``INT 3``, ``INT 4`` and ``INT 0x80`` are allowed; other vectors raise
  #GP.

XSAVE, XRSTOR and their variants
  Operate on the underlying ``PKRU`` like RDPKRU and WRPKRU.  In supervisor mode
  a ``PKRU`` loaded by XRSTOR does not reach user mode and, while it is loaded,
  restricts the guest kernel's own accesses.  The guest kernel should leave the
  ``PKRU`` state component out of XRSTOR and write ``PVCS::pkru`` instead.

RDPKRU, WRPKRU
  The guest runs at CPL 3 under the host's ``CR4.PKE``, so these always access
  the underlying ``PKRU``.  In supervisor mode that is the supervisor value (see
  :ref:`pvm_protection_keys`), so the guest kernel must access the user
  ``PKRU`` through ``PVCS::pkru`` instead.  A guest that has not enabled
  protection keys and writes a restrictive ``PKRU`` anyway has ``PKRU`` reset
  to 0 on the next entry.

.. _pvm_host_information:

Host information visible to the guest
-------------------------------------

The guest runs at CPL 3 on the host's descriptor tables, so some host
information is visible to it.  A guest must not rely on any of it:

- SGDT, SIDT, SLDT, STR and SMSW return the host's values unless the host
  enables ``CR4.UMIP``.
- LAR, LSL, VERR and VERW operate on the host's ``GDT``.  Its DPL=3 data entries
  may include host per-CPU data; on a Linux host the segment limit of the
  CPUNODE entry holds the host CPU and node number.

.. _pvm_paging:

Paging
------

The hypervisor keeps two shadow page tables for each guest page table, one for
supervisor mode and one for user mode, and switches between them on every mode
switch without flushing the guest's TLB.  The user mode table maps nothing that
the guest marks supervisor-only.

Both tables map guest pages as user pages at the hardware level, so the
features that depend on the hardware U/S bit are changed:

- SMEP is emulated: the supervisor mode table maps user pages non-executable.
- SMAP is not supported and ``CR4.SMAP`` cannot be set.
- PKS is not supported.

.. _pvm_protection_keys:

Protection keys
~~~~~~~~~~~~~~~

Protection keys for user pages are enforced by the hardware: the key in the
guest page table entry is copied into the shadow page table entry.

Because the guest is at CPL 3 in both of its modes and every shadow mapping is a
user mapping, the hardware would apply the guest's ``PKRU`` to the guest
kernel's accesses too.  ``PKRU`` is therefore swapped on every mode switch:
in user mode it holds the guest's user value, in supervisor mode it holds 0
(every key permitted), and the user value is kept in ``PVCS::pkru``.  The guest
kernel reads and writes its user ``PKRU`` there.

.. _pvm_direct_pf:

Direct page fault delivery
~~~~~~~~~~~~~~~~~~~~~~~~~~

With ``PVM_FEATURE_DIRECT_PF`` set in ``MSR_PVM_FEATURES_ENABLED``, the
hypervisor may deliver a page fault from user mode to the guest without first
walking the guest page tables.  The hardware reports "not present" both when the
guest PTE is absent and when it is present but not yet shadowed, so a guest that
enables the feature accepts that:

- it may receive a not-present #PF (``P`` = 0 in the error code) for an address
  whose guest PTE is already present when its handler looks, and must return
  from that fault the way it returns from any fault that finds the mapping in
  place;
- the error code of such a fault is ``U``, or ``U|W`` for a write, which is what
  a walk would have produced for an absent PTE, and ``CR2`` is the faulting
  address.

Only a fault with no ``P``, ``RSVD``, ``PK`` or ``I/D`` bit, from user mode, on
a lower-half address is delivered this way.  The hypervisor guarantees progress:
a guest that returns from such a fault and retries the access does not keep
receiving spurious faults for it, but eventually finds the mapping resolved or
receives the exact fault.  How often a spurious fault can occur is not part of
the ABI.

Because such a fault carries no ``PK`` bit, an access that a protection key
denies, on a page the hypervisor has not shadowed yet, may arrive as a
not-present fault.  The guest has to check the access against its ``PKRU``
itself rather than rely on the error code.

Events
------

Special events
~~~~~~~~~~~~~~

No double fault
  The hypervisor does not generate #DF.  An event that cannot be delivered
  because it would nest is a triple fault, see :ref:`pvm_events_do_not_nest`.

Discarded #DB
  When MOV SS or POP SS loads from a watched address and the next instruction
  enters supervisor mode by a trap, the data breakpoint is discarded.

Event delivery
~~~~~~~~~~~~~~

The hypervisor delivers an event by saving context into the PVCS; it does not
touch the stack or ``RSP``.  A vector event is delivered in these steps, all
without the guest running in between:

- For an NMI or #MC in supervisor mode while the high 8 bits of
  ``PVCS::event_vector`` are non-zero, set its bit there and stop.  Any other
  event in that state is a triple fault.
- Save ``RFLAGS``, ``RIP``, ``RCX`` and ``R11`` into the PVCS.
- For an event from user mode, save ``CS``, ``SS``, ``PKRU`` and ``GSBASE`` into
  the PVCS.
- Save the vector and error code into ``PVCS::event_vector`` (with
  ``PVM_PVCS_EVENT_VECTOR_STD``, or the NMI or MCE bit) and
  ``PVCS::event_errcode``.  A SYSCALL from user mode leaves
  ``PVCS::event_vector`` unchanged.
- For a #PF, ``CR2`` (and so ``PVCS::cr2``) is the faulting address.
- For an event from user mode, switch to supervisor mode: ``CS/SS`` are taken
  from ``MSR_STAR`` (the underlying ``CS/SS`` stay ``__USER_CS`` and
  ``__USER_DS``), ``GSBASE`` is loaded from ``MSR_KERNEL_GS_BASE`` and ``PKRU``
  from the supervisor value.
- Load ``RFLAGS`` with ``X86_EFLAGS_FIXED``.  For an event from supervisor
  mode that clears ``PVM_EVENT_FLAGS_IF``; for an event from user mode
  ``PVM_EVENT_FLAGS_IF`` is left as the guest wrote it, which is clear (see
  :ref:`pvm_pvcs`).  ``R11`` is loaded with ``X86_EFLAGS_IF |
  X86_EFLAGS_FIXED``.
- Load ``RIP`` and ``RCX`` with the entry point: ``MSR_LSTAR`` for a SYSCALL
  from user mode, ``MSR_PVM_EVENT_ENTRY`` for another event from user mode, and
  ``MSR_PVM_EVENT_ENTRY + PVM_EVENT_ENTRY_SUPERVISOR_OFFSET`` for an event from
  supervisor mode.

Every other register, ``RSP`` included, keeps its value.

.. _pvm_events_do_not_nest:

Events do not nest
~~~~~~~~~~~~~~~~~~

There is one set of event fields in the PVCS, and event delivery does not use
the stack, so an event delivered while the previous one's state is still in the
PVCS would overwrite it.  The high 8 bits of ``PVCS::event_vector`` are the
interlock:

- The hypervisor sets ``PVM_PVCS_EVENT_VECTOR_STD`` when it delivers an event
  other than NMI or #MC, and the guest clears the high bits once it has taken
  the state out of the PVCS.  The guest must then check for an NMI or #MC that
  was recorded meanwhile.
- While those bits are non-zero, an NMI or #MC is recorded by setting its bit,
  without jumping to the entry point.
- Any other event that arrives in supervisor mode while those bits are non-zero
  is a triple fault.

Between entering a supervisor mode event handler and clearing the high bits,
the guest must not fault: no demand-paged stack and no access to anything that
is not already present.

Hypercalls
----------

Except for ``EVENT_RETURN_USER``, a SYSCALL instruction in supervisor mode is a
hypercall.  ``RAX`` is the hypercall number.  The range from
``PVM_HC_SPECIAL_BASE`` to ``PVM_HC_SPECIAL_BASE + 255`` (0x17088200-0x170882ff)
is reserved for PVM hypercalls, of which the ones listed below are defined.  Any
other number is handled as a KVM hypercall
(Documentation/virt/kvm/x86/hypercalls.rst).

The register contract is the same for PVM and KVM hypercalls:

- The arguments are in ``RBX``, ``R10``, ``RDX`` and ``RSI``, in that order.  A
  KVM hypercall is handled as if ``R10`` were ``RCX``, which is where KVM
  hypercalls take their second argument.
- On return ``RAX`` holds the result.  A hypercall that has no result leaves
  ``RAX`` unspecified.  ``PVM_HC_RDMSR`` also returns a value in ``RDX``.
- ``RCX`` and ``R11`` are clobbered by the SYSCALL instruction.
- Every other register, ``R10`` and ``RSP`` included, is preserved, and so is
  ``RDX`` except by ``PVM_HC_RDMSR``.

A guest that needs ``RCX`` across a hypercall can therefore keep it in ``R10``.
Hypercalls return errors as negative ``KVM_E*`` values from
``include/uapi/linux/kvm_para.h``.

============================== ========== ===============================
Hypercall                      Number     Arguments
============================== ========== ===============================
``PVM_HC_LOAD_PGTBL``          0x17088200 *flags*, *cr3*
``PVM_HC_IRQ_WIN``             0x17088201
``PVM_HC_IRQ_HLT``             0x17088202
``PVM_HC_TLB_FLUSH``           0x17088203
``PVM_HC_TLB_FLUSH_CURRENT``   0x17088204
``PVM_HC_TLB_INVLPG``          0x17088205 *addr*
``PVM_HC_LOAD_GS``             0x17088206 *gs_sel*
``PVM_HC_RDMSR``               0x17088207 *msr_index*
``PVM_HC_WRMSR``               0x17088208 *msr_index*, *msr_value*
``PVM_HC_LOAD_TLS``            0x17088209 *tls0*, *tls1*, *tls2*
============================== ========== ===============================

PVM_HC_LOAD_PGTBL
~~~~~~~~~~~~~~~~~

Loads *cr3* into ``CR3``.

- *flags* bit 0 (``PVM_LOAD_PGTBL_FLAGS_TLB``): flush the TLB of the PCID in
  *cr3*.  When clear the load does not flush, which requires ``CR4.PCIDE``.
- *flags* bit 1 (``PVM_LOAD_PGTBL_FLAGS_LA57``): 5-level (1) or 4-level (0)
  paging; ``CR4.LA57`` is updated to match.  Setting it has no effect unless
  LA57 is advertised.

A *cr3* that MOV to CR3 would refuse raises #GP, as MOV to CR3 does, and leaves
the paging level unchanged.  No result.

PVM_HC_IRQ_WIN
~~~~~~~~~~~~~~

Informs the hypervisor that interrupts have been enabled, so it can deliver a
pending one.  Clears ``PVM_EVENT_FLAGS_IP``.

PVM_HC_IRQ_HLT
~~~~~~~~~~~~~~

Equivalent to ``STI; HLT``.

PVM_HC_TLB_FLUSH
~~~~~~~~~~~~~~~~

Flushes the guest's TLB for all PCIDs.

PVM_HC_TLB_FLUSH_CURRENT
~~~~~~~~~~~~~~~~~~~~~~~~

Flushes the guest's TLB for the current PCID.

PVM_HC_TLB_INVLPG
~~~~~~~~~~~~~~~~~

Flushes the TLB entries for *addr* in all PCIDs.

PVM_HC_LOAD_GS
~~~~~~~~~~~~~~

Loads ``GS`` with the selector *gs_sel*.  A selector with RPL other than 3, or
one that fails to load, is replaced by the NULL selector.  Returns the resulting
``GSBASE``.

PVM_HC_RDMSR
~~~~~~~~~~~~

Reads MSR *msr_index*, checked as a guest RDMSR would be.  Returns 0 in ``RAX``
and the value in ``RDX``, or ``-KVM_EINVAL`` in ``RAX`` and 0 in ``RDX`` if the
RDMSR would raise #GP or cannot be completed.

PVM_HC_WRMSR
~~~~~~~~~~~~

Writes *msr_value* to MSR *msr_index*, checked as a guest WRMSR would be.
Returns 0, or ``-KVM_EINVAL`` if the WRMSR would raise #GP or cannot be
completed.

PVM_HC_LOAD_TLS
~~~~~~~~~~~~~~~

Sets the three TLS entries of the underlying ``GDT``
(``GDT_ENTRY_TLS_MIN`` to ``GDT_ENTRY_TLS_MAX``) from the 8-byte descriptors
*tls0*, *tls1* and *tls2*.  A descriptor that is not a present 32-bit data
segment is replaced by a null descriptor; the others are forced to DPL 3,
non-system, not 64-bit and accessed.  No return value.
