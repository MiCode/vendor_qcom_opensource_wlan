#ifndef __SOFTIRQ_LATENCY_H__
#define __SOFTIRQ_LATENCY_H__

#ifdef CONFIG_CNSS2_SOFTIRQ_LATENCY_TRACE
void cnss2_softirqlat_init(void);
void cnss2_softirqlat_exit(void);
#else
static inline void cnss2_softirqlat_init(void) {}
static inline void cnss2_softirqlat_exit(void) {}
#endif /* CONFIG_CNSS2_SOFTIRQ_LATENCY_TRACE */

#endif /* __SOFTIRQ_LATENCY_H__ */
