// SPDX-License-Identifier: GPL-2.0
/*
 * External interrupt dispatch for event delivery mechanisms that hand the
 * kernel a vector number instead of vectoring through the IDT, such as FRED.
 */
#include <linux/kernel.h>
#include <linux/nospec.h>

#include <asm/desc.h>
#include <asm/fred.h>
#include <asm/idtentry.h>

#define SYSVEC(_vector, _function) [_vector - FIRST_SYSTEM_VECTOR] = fred_sysvec_##_function

/* A NULL entry is a vector nobody installed a handler for. */
static idtentry_t sysvec_table[NR_SYSTEM_VECTORS] __ro_after_init = {
	SYSVEC(ERROR_APIC_VECTOR,		error_interrupt),
	SYSVEC(SPURIOUS_APIC_VECTOR,		spurious_apic_interrupt),
	SYSVEC(LOCAL_TIMER_VECTOR,		apic_timer_interrupt),
	SYSVEC(X86_PLATFORM_IPI_VECTOR,		x86_platform_ipi),

	SYSVEC(RESCHEDULE_VECTOR,		reschedule_ipi),
	SYSVEC(CALL_FUNCTION_SINGLE_VECTOR,	call_function_single),
	SYSVEC(CALL_FUNCTION_VECTOR,		call_function),
	SYSVEC(REBOOT_VECTOR,			reboot),

	SYSVEC(THRESHOLD_APIC_VECTOR,		threshold),
	SYSVEC(DEFERRED_ERROR_VECTOR,		deferred_error),
	SYSVEC(THERMAL_APIC_VECTOR,		thermal),

	SYSVEC(IRQ_WORK_VECTOR,			irq_work),

	SYSVEC(PERF_GUEST_MEDIATED_PMI_VECTOR,	perf_guest_mediated_pmi_handler),
	SYSVEC(POSTED_INTR_VECTOR,		kvm_posted_intr_ipi),
	SYSVEC(POSTED_INTR_WAKEUP_VECTOR,	kvm_posted_intr_wakeup_ipi),
	SYSVEC(POSTED_INTR_NESTED_VECTOR,	kvm_posted_intr_nested_ipi),

	SYSVEC(POSTED_MSI_NOTIFICATION_VECTOR,	posted_msi_notification),
};

static bool sysvec_setup_done __initdata;

void __init fred_install_sysvec(unsigned int sysvec, idtentry_t handler)
{
	if (WARN_ON_ONCE(sysvec < FIRST_SYSTEM_VECTOR))
		return;

	if (WARN_ON_ONCE(sysvec_setup_done))
		return;

	if (!WARN_ON_ONCE(sysvec_table[sysvec - FIRST_SYSTEM_VECTOR]))
		sysvec_table[sysvec - FIRST_SYSTEM_VECTOR] = handler;
}

/*
 * Only called for CONFIG_X86_FRED.  Other users of external_interrupt() get
 * their system_vectors bits from the IDT setup, and find unused vectors as
 * NULL entries, which the dispatch handles without this.
 */
void __init fred_complete_exception_setup(void)
{
	unsigned int vector;

	for (vector = 0; vector < FIRST_EXTERNAL_VECTOR; vector++)
		set_bit(vector, system_vectors);

	for (vector = 0; vector < NR_SYSTEM_VECTORS; vector++) {
		if (sysvec_table[vector])
			set_bit(vector + FIRST_SYSTEM_VECTOR, system_vectors);
	}
	sysvec_setup_done = true;
}

noinstr void external_interrupt(struct pt_regs *regs, unsigned int vector)
{
	irqentry_state_t state;
	idtentry_t handler;

	if (WARN_ON_ONCE(vector < FIRST_EXTERNAL_VECTOR))
		return;

	if (unlikely(vector < FIRST_SYSTEM_VECTOR)) {
		common_interrupt(regs, vector);
		return;
	}

	handler = sysvec_table[array_index_nospec(vector - FIRST_SYSTEM_VECTOR,
						  NR_SYSTEM_VECTORS)];
	/* spurious_interrupt() does its own irqentry_enter(). */
	if (unlikely(!handler)) {
		spurious_interrupt(regs, vector);
		return;
	}

	state = irqentry_enter(regs);
	instrumentation_begin();
	handler(regs);
	instrumentation_end();
	irqentry_exit(regs, state);
}
