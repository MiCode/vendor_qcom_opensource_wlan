// MIUI ADD: WIFI_P2PHC
#ifndef _P2PHC_H_
#define _P2PHC_H_

#include <net/ip.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/netfilter.h>

#include "dlhc.h"
#include "p2phc_debug.h"
#include "p2phc_switch.h"

//#define PER_CPU
#define TX_HOOK_NETDEV
//#define TX_HOOK_IPV4

int p2phc_init(void);
int p2phc_cleanup(void);

typedef struct _p2phc {
	spinlock_t tcp_rx_lock;
	spinlock_t tcp_tx_lock;
	spinlock_t udp_rx_lock;
	spinlock_t udp_tx_lock;
#ifdef PER_CPU
	struct dlhc *dlc[CONFIG_NR_CPUS];
#else
	struct dlhc *dlc;
#endif
	bool hooks_is_reg;
#ifdef STAT_DUMP
	struct task_struct *task;
#endif
	struct ctl_table_header *ctl;
} p2phc_t;

extern p2phc_t g_p2phc;
extern struct notifier_block p2phc_nb __read_mostly;

#ifdef TX_HOOK_NETDEV
extern unsigned int p2phc_tx_netdev_hook(struct sk_buff *skb,
	struct net_device *dev);
#else
static inline unsigned int p2phc_tx_netdev_hook(struct sk_buff *skb,
	struct net_device *dev)
{
	return 0;
}
#endif

#endif	/* _MINET_P2PHC_H_ */

// END WIFI_P2PHC
