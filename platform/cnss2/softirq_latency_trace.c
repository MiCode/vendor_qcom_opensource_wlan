#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <trace/events/irq.h>
#include "softirq_latency_trace.h"

#ifdef CONFIG_CNSS2_SOFTIRQ_LATENCY_TRACE
struct softirqlat_state {
	bool in_softirq;
	bool in_irq;
	unsigned int vec_nr;
	u64 soft_start_ns;
	u64 irq_block_ns;
	u64 irq_start_ns;
};
static DEFINE_PER_CPU(struct softirqlat_state, si_stat);

static unsigned long cnss2_softirq_mask =
	BIT(NET_RX_SOFTIRQ) |
	BIT(TASKLET_SOFTIRQ);

static unsigned int softirqlat_thresh_us = 8000;
static void notrace cnss2_irq_entry(void *ignore, int irq,
				   struct irqaction *action)
{
	struct softirqlat_state *st = this_cpu_ptr(&si_stat);

	if (!st->in_softirq)
		return;

	st->in_irq = true;
	st->irq_start_ns = ktime_get_ns();
}

static void notrace cnss2_irq_exit(void *ignore, int irq,
				  struct irqaction *action, int ret)
{
	struct softirqlat_state *st = this_cpu_ptr(&si_stat);
	u64 now;

	if (!st->in_softirq || !st->in_irq)
		return;

	now = ktime_get_ns();
	if (now > st->irq_start_ns)
		st->irq_block_ns += now - st->irq_start_ns;

	st->in_irq = false;
}

static void notrace cnss2_softirq_entry(void *ignore, unsigned int vec_nr)
{
	struct softirqlat_state *st;

	if (!(cnss2_softirq_mask & BIT(vec_nr)))
		return;

	st = this_cpu_ptr(&si_stat);

	st->in_softirq    = true;
	st->vec_nr        = vec_nr;
	st->soft_start_ns = ktime_get_ns();

	st->irq_block_ns  = 0;
	st->in_irq        = false;
	st->irq_start_ns  = 0;
}

static void notrace cnss2_softirq_exit(void *ignore, unsigned int vec_nr)
{
	struct softirqlat_state *st = this_cpu_ptr(&si_stat);
	u64 now, total_ns, softirq_ns;
	u64 thresh_ns = (u64)softirqlat_thresh_us * 1000ULL;

	if (!st->in_softirq || st->vec_nr != vec_nr)
		return;

	now = ktime_get_ns();
	if (now <= st->soft_start_ns)
		goto out;

	total_ns = now - st->soft_start_ns;

	if (total_ns > st->irq_block_ns)
		softirq_ns = total_ns - st->irq_block_ns;
	else
		softirq_ns = 0;

	if (softirq_ns >= thresh_ns) {
		printk_deferred(KERN_ERR
			"[CNSS2_SOFTIRQ_LAT] cpu=%d vec=%u "
			"total=%llu us softirq=%llu us irq=%llu us "
			"current=%s:%d:%d\n",
			smp_processor_id(), vec_nr,
			total_ns / 1000ULL,
			softirq_ns / 1000ULL,
			st->irq_block_ns / 1000ULL,
			current->comm, current->pid, current->tgid);
	}

out:
	st->in_softirq    = false;
	st->soft_start_ns = 0;
	st->irq_block_ns  = 0;
	st->vec_nr        = 0;
	st->in_irq        = false;
	st->irq_start_ns  = 0;
}


void cnss2_softirqlat_init(void)
{
	register_trace_irq_handler_entry(cnss2_irq_entry, NULL);
	register_trace_irq_handler_exit(cnss2_irq_exit, NULL);
	register_trace_softirq_entry(cnss2_softirq_entry, NULL);
	register_trace_softirq_exit(cnss2_softirq_exit, NULL);

	pr_info("cnss2 softirqlat: initialized (thresh=%u us, mask=0x%lx)\n",
		softirqlat_thresh_us, cnss2_softirq_mask);
}

void cnss2_softirqlat_exit(void)
{
	unregister_trace_softirq_exit(cnss2_softirq_exit, NULL);
	unregister_trace_softirq_entry(cnss2_softirq_entry, NULL);

	unregister_trace_irq_handler_exit(cnss2_irq_exit, NULL);
	unregister_trace_irq_handler_entry(cnss2_irq_entry, NULL);

	pr_info("cnss2 softirqlat: exited\n");
}
#endif /* CONFIG_CNSS2_SOFTIRQ_LATENCY_TRACE */
