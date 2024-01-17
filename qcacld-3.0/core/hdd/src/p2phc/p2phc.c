// MIUI ADD: WIFI_P2PHC

#include "p2phc.h"

p2phc_t g_p2phc = {.hooks_is_reg = false};

#define ETH_HLEN	14		/* Total octets in header.	 */

#define IP_HDR_LEN_MAX (60)
#define TCP_HDR_LEN_MAX (60)
#define HDR_LEN_MAX (IP_HDR_LEN_MAX + TCP_HDR_LEN_MAX)

static inline int p2phc_enable(const struct net *net)
{
	return sysctl_p2phc_enable;
}

/*
* netfilter hooks handler
*/
static inline int __disable_tcp_timestamps(struct sk_buff *skb)
{
	struct sock *sk;
	struct tcp_sock *tp;

	sk = skb_to_full_sk(skb);
	if (sk == NULL)
		return -1;

	if (sk->sk_state == TCP_ESTABLISHED) {
		tp = tcp_sk(sk);
		if (unlikely(tp->rx_opt.tstamp_ok)) {
			tp->rx_opt.tstamp_ok = 0;
			p2phc_dbg("%s", __func__);
		}
	}

	return 0;
}

#ifdef TX_HOOK_NETDEV
static inline unsigned int __p2phc_tx_netdev_hook(struct sk_buff *skb,
	struct net_device *dev)
{
	p2phc_t *p2phc = &g_p2phc;
	spinlock_t *plock = NULL;
	struct dlhc *dlc = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	unsigned char hc[HDR_LEN_MAX] = {0,}, dl_type;
	unsigned char *phc = hc, *h;
	int hlen, hclen, clen;
	unsigned int verdict = NF_ACCEPT;
	static atomic_t pkg_cmp = {0}, pkg_mark = {0};
	(void)pkg_cmp;
	(void)pkg_mark;

	if (strncmp(skb->dev->name, "p2p", 3))
		return NF_ACCEPT;

	//p2phc_dbg("%s dev:%s", __func__, skb->dev->name);

	iph = ip_hdr(skb);
	if (iph == NULL)
		return NF_ACCEPT;

	if (iph->version != 4 || ipv4_is_multicast(iph->daddr))
		return NF_ACCEPT;

	if (iph->protocol == IPPROTO_TCP) {
		__disable_tcp_timestamps(skb);
		tcph = tcp_hdr(skb);
		if (tcph == NULL)
			return NF_ACCEPT;
		hlen = (iph->ihl * 4) + (tcph->doff * 4);
		plock = &p2phc->tcp_tx_lock;
	} else if (iph->protocol == IPPROTO_UDP) {
		hlen = (iph->ihl * 4) + 8;
		plock = &p2phc->udp_tx_lock;
	} else {
		return NF_ACCEPT;
	}

#ifdef SKB_DUMP
	p2phc_info("%s before hc", __func__);
	skb_dump(KERN_INFO, skb, true);
#endif

#ifdef PER_CPU
	unsigned int cpu;
	/* get per-CPU data */
	cpu = get_cpu();
	if (cpu < 0 || cpu >= CONFIG_NR_CPUS)
		goto err;
	dlc = p2phc->dlc[cpu];
#else
	dlc = p2phc->dlc;
#endif

	/* tx handler */
	h = (unsigned char *)iph;
	spin_lock(plock);
	hclen = dlhc_compress(dlc, h, hlen, hc, &phc, 0);
	spin_unlock(plock);
	clen = hlen - hclen;
	dl_type = hc[0] & DL_TYPE_MASK;

	if (clen) {
		p2phc_dbg("%s hc compress clen:%d cnt:%d", __func__, clen, atomic_inc_return(&pkg_cmp));
		/*p2phc_dbg("%s ack:%u win:%hu", __func__,
			ntohl(tcph->ack_seq), ntohs(tcph->window));*/
		/* mac header */
		memmove(skb->data + clen, skb->data, ETH_HLEN);
		skb_pull(skb, clen);
		skb_reset_mac_header(skb);
		/* ip header */
		memcpy(h + clen, hc, hclen);
		skb->network_header += clen;
	} else if (dl_type == DL_TYPE_UNCOMPRESSED_TCP || dl_type == DL_TYPE_UNCOMPRESSED_UDP) {
		p2phc_dbg("%s hc mark cid:%d cnt:%d", __func__, hc[9], atomic_inc_return(&pkg_mark));
		h[0] &= ~DL_TYPE_MASK;
		h[0] |= dl_type;
		h[9] = hc[9];
		ip_send_check(iph);
	} else {
		goto err;
	}

err:
#ifdef PER_CPU
	put_cpu();
#endif

#ifdef SKB_DUMP
	p2phc_info("%s after hc", __func__);
	skb_dump(KERN_INFO, skb, true);
#endif
	return verdict;
}

unsigned int p2phc_tx_netdev_hook(struct sk_buff *skb,
	struct net_device *dev)
{
	unsigned int ret = -1;
#ifdef TIME_DUMP
	ktime_t start, diff;
	start = ktime_get();
#endif
	if (p2phc_enable(&init_net)) {
		ret = __p2phc_tx_netdev_hook(skb, dev);
	}
#ifdef TIME_DUMP
	diff = ktime_sub(ktime_get(), start);
	p2phc_info("%s used %lld ns", __func__, ktime_to_ns(diff));
#endif
	return ret;
}


#elif defined(TX_HOOK_IPV4)

static unsigned int tx_ipv4_hook(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	p2phc_t *p2phc = (p2phc_t *)priv;
	struct dlhc *dlc = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	unsigned char hc[HDR_LEN_MAX] = {0,};
	unsigned char *phc = hc, *h;
	int hlen, hclen, clen;
	unsigned int verdict = NF_ACCEPT;

	if (strncmp(skb->dev->name, "p2p", 3))
		return NF_ACCEPT;

	//p2phc_dbg("%s dev:%s", __func__, skb->dev->name);

	iph = ip_hdr(skb);
	if (iph == NULL)
		return NF_ACCEPT;

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);
	if (tcph == NULL)
		return NF_ACCEPT;

#ifdef SKB_DUMP
	p2phc_info("%s before hc", __func__);
	skb_dump(KERN_INFO, skb, true);
#endif

#ifdef PER_CPU
	unsigned int cpu;
	/* get per-CPU data */
	cpu = get_cpu();
	if (cpu < 0 || cpu >= CONFIG_NR_CPUS)
		goto err;
	dlc = p2phc->dlc[cpu];
#else
	dlc = p2phc->dlc;
#endif

	/* tx handler */
	h = (unsigned char *)iph;
	hlen = (iph->ihl * 4) + (tcph->doff * 4);
	spin_lock_bh(&p2phc->tcp_tx_lock);
	hclen = dlhc_compress(dlc, h, hlen, hc, &phc, 0);
	spin_unlock_bh(&p2phc->tcp_tx_lock);
	clen = hlen - hclen;

	if (clen) {
		//p2phc_dbg("%s hc compress clen:%d", __func__, clen);
		memcpy(h + clen, hc, hclen);
		skb_pull(skb, clen);
		skb_reset_mac_header(skb);
		skb->network_header += clen;
	} else if (hc[0] & DL_TYPE_UNCOMPRESSED_TCP) {
		//p2phc_dbg("%s hc mark cid:%d", __func__, hc[9]);
		h[0] |= DL_TYPE_UNCOMPRESSED_TCP;
		h[9] = hc[9];
		//ip_send_check(iph);
	} else {
		goto err;
	}

err:
#ifdef PER_CPU
	put_cpu();
#endif

#ifdef SKB_DUMP
	p2phc_info("%s after hc", __func__);
	skb_dump(KERN_INFO, skb, true);
#endif
	return verdict;
}
#else
#error "tx hook not set"
#endif

static inline unsigned int __rx_inet_hook(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	p2phc_t *p2phc = (p2phc_t *)priv;
	spinlock_t *plock = NULL;
	struct dlhc *dlc = NULL;
	struct iphdr *iph = NULL;
	unsigned char *h, dl_type;
	int len, hclen;
	unsigned int verdict = NF_ACCEPT;
	static atomic_t pkg_cmp = {0}, pkg_mark = {0};
	(void)pkg_cmp;
	(void)pkg_mark;

	if (strncmp(skb->dev->name, "p2p", 3))
		return NF_ACCEPT;

	//p2phc_dbg("%s dev:%s", __func__, skb->dev->name);

	iph = ip_hdr(skb);
	if (iph == NULL)
		return NF_ACCEPT;
	h = (unsigned char *)iph;

	dl_type = h[0] & DL_TYPE_MASK;
	if (dl_type == DL_TYPE_UNCOMPRESSED_TCP || dl_type == DL_TYPE_COMPRESSED_TCP) {
		plock = &p2phc->tcp_rx_lock;
	} else if (dl_type == DL_TYPE_UNCOMPRESSED_UDP || dl_type == DL_TYPE_COMPRESSED_UDP) {
		plock = &p2phc->udp_rx_lock;
	} else {
		return NF_ACCEPT;
	}

#ifdef SKB_DUMP
	p2phc_info("%s before hc", __func__);
	skb_dump(KERN_INFO, skb, true);
#endif

#ifdef PER_CPU
	unsigned int cpu;
	/* get per-CPU data */
	cpu = get_cpu();
	if (cpu < 0 || cpu >= CONFIG_NR_CPUS)
		goto err;
	dlc = p2phc->dlc[cpu];
#else
	dlc = p2phc->dlc;
#endif

	/* rx handler */
	len = skb->len;
	if (dl_type == DL_TYPE_COMPRESSED_TCP || dl_type == DL_TYPE_COMPRESSED_UDP) {
		p2phc_dbg("%s hc uncompress cnt:%d", __func__, atomic_inc_return(&pkg_cmp));
		skb_put(skb, HDR_LEN_MAX);
		spin_lock(plock);
		hclen = dlhc_uncompress(dlc, h, len);
		spin_unlock(plock);
		if (hclen <= 0) {
			p2phc_err("%s hc uncompress err [%02x %02x]", __func__, h[0], h[1]);
			verdict = NF_DROP;
			goto err;
		}
		skb->transport_header = skb->network_header + (iph->ihl * 4);
		/*p2phc_dbg("%s ack:%u win:%hu", __func__,
			ntohl(tcp_hdr(skb)->ack_seq), ntohs(tcp_hdr(skb)->window));*/
		// TODO revert skb_put length:(HDR_LEN_MAX - (hclen - len))
	} else if (dl_type == DL_TYPE_UNCOMPRESSED_TCP || dl_type == DL_TYPE_UNCOMPRESSED_UDP) {
		p2phc_dbg("%s hc remember, cid:%d cnt:%d", __func__, h[9], atomic_inc_return(&pkg_mark));
		spin_lock(plock);
		hclen = dlhc_remember(dlc, h, len);
		spin_unlock(plock);
		if (hclen <= 0) {
			p2phc_err("%s hc remember err", __func__);
			verdict = NF_DROP;
			goto err;
		}
	}

err:
#ifdef PER_CPU
	put_cpu();
#endif

#ifdef SKB_DUMP
	p2phc_info("%s after hc", __func__);
	skb_dump(KERN_INFO, skb, true);
#endif
	return verdict;
}

static unsigned int rx_inet_hook(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	unsigned int ret;
#ifdef TIME_DUMP
	ktime_t start, diff;
	start = ktime_get();
#endif
	ret = __rx_inet_hook(priv, skb, state);
#ifdef TIME_DUMP
	diff = ktime_sub(ktime_get(), start);
	p2phc_info("%s used %lld ns", __func__, ktime_to_ns(diff));
#endif
	return ret;
}

static struct nf_hook_ops p2phc_hooks[] = {
	{
		.hook = rx_inet_hook,
		.priv = &g_p2phc,
		.pf = NFPROTO_INET,
		.hooknum = NF_INET_INGRESS,
		.priority = NF_IP_PRI_FIRST,
	},
#ifdef TX_HOOK_IPV4
	{
		.hook = tx_ipv4_hook,
		.priv = &g_p2phc,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
#endif
};

/**
 * device notifier event handler
 */
#if 1
static inline int p2phc_p2px_event(struct net_device *dev, enum netdev_cmd cmd)
{
	int ret = 0;
	if (cmd == NETDEV_REGISTER && !g_p2phc.hooks_is_reg) {
		p2phc_hooks[0].dev = dev;
		ret = nf_register_net_hooks(&init_net, p2phc_hooks,
						ARRAY_SIZE(p2phc_hooks));
		if (ret) {
			p2phc_err("%s nf_register_net_hooks err:%d", __func__, ret);
			return 0;
		}
		g_p2phc.hooks_is_reg = true;
		p2phc_info("%s nf_register_net_hooks", __func__);
	} else if (cmd == NETDEV_UNREGISTER && g_p2phc.hooks_is_reg) {
		nf_unregister_net_hooks(&init_net, p2phc_hooks,
				    ARRAY_SIZE(p2phc_hooks));
		g_p2phc.hooks_is_reg = false;
		p2phc_info("%s nf_unregister_net_hooks", __func__);
	}

	return 0;
}

/*
static const char *__netdev_cmd_to_name(enum netdev_cmd cmd)
{
#define N(val) 						\
	case NETDEV_##val:				\
		return "NETDEV_" __stringify(val);
	switch (cmd) {
	N(UP) N(DOWN) N(REBOOT) N(CHANGE) N(REGISTER) N(UNREGISTER)
	N(CHANGEMTU) N(CHANGEADDR) N(GOING_DOWN) N(CHANGENAME) N(FEAT_CHANGE)
	N(BONDING_FAILOVER) N(PRE_UP) N(PRE_TYPE_CHANGE) N(POST_TYPE_CHANGE)
	N(POST_INIT) N(RELEASE) N(NOTIFY_PEERS) N(JOIN) N(CHANGEUPPER)
	N(RESEND_IGMP) N(PRECHANGEMTU) N(CHANGEINFODATA) N(BONDING_INFO)
	N(PRECHANGEUPPER) N(CHANGELOWERSTATE) N(UDP_TUNNEL_PUSH_INFO)
	N(UDP_TUNNEL_DROP_INFO) N(CHANGE_TX_QUEUE_LEN)
	N(CVLAN_FILTER_PUSH_INFO) N(CVLAN_FILTER_DROP_INFO)
	N(SVLAN_FILTER_PUSH_INFO) N(SVLAN_FILTER_DROP_INFO)
	N(PRE_CHANGEADDR)
	}
#undef N
	return "UNKNOWN_NETDEV_EVENT";
}
*/

static int p2phc_device_event(struct notifier_block *nb,
			       unsigned long event, void *data)
{
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	p2phc_t *p2phc = &g_p2phc;
	struct dlhc *dlc = NULL;

	if(strncmp(dev->name, "p2p", 3)) {
		return NOTIFY_DONE;
	}

#ifdef PER_CPU
	unsigned int cpu;
	/* get per-CPU data */
	cpu = get_cpu();
	if (cpu < 0 || cpu >= CONFIG_NR_CPUS)
		return NOTIFY_DONE;
	dlc = p2phc->dlc[cpu];
#else
	dlc = p2phc->dlc;
#endif

	/*
	p2phc_dbg("%s %s %s", __func__, dev->name, __netdev_cmd_to_name(event));
	p2phc_dbg("%s dev->operstate:%d", __func__, dev->operstate);
	*/

	switch (event) {
	case NETDEV_REGISTER:
	case NETDEV_UNREGISTER:
		p2phc_p2px_event(dev, event);
		break;
	case NETDEV_UP:
	case NETDEV_CHANGE:
		if (netif_oper_up(dev)){
			p2phc_dbg("%s dlhc_reset", __func__);
			dlhc_reset(dlc);
		}
		break;
	default :
		break;
	}

	return NOTIFY_DONE;
}

struct notifier_block p2phc_nb __read_mostly = {
	.notifier_call = p2phc_device_event,
};
#endif

/**
 * init & cleanup
 */
int p2phc_init(void)
{
	int ret = -1;

#ifdef PER_CPU
	int cpu;
	for (cpu = 0; cpu < CONFIG_NR_CPUS; cpu ++) {
		g_p2phc.dlc[cpu] = dlhc_init(16, 16);
		if (IS_ERR(g_p2phc.dlc[cpu]))
			goto err_init;
		p2phc_info("%s dlhc_init cpu:%d, dlc:%p", __func__, cpu, g_p2phc.dlc[cpu]);
	}
#else
	g_p2phc.dlc = dlhc_init(16, 16);
	if (IS_ERR(g_p2phc.dlc)) {
		p2phc_err("%s dlhc_init err", __func__);
		goto err_init;
	}
#endif
	spin_lock_init(&g_p2phc.tcp_rx_lock);
	spin_lock_init(&g_p2phc.tcp_tx_lock);
	spin_lock_init(&g_p2phc.udp_rx_lock);
	spin_lock_init(&g_p2phc.udp_tx_lock);

	ret = register_netdevice_notifier(&p2phc_nb);
	if (ret) {
		p2phc_err("%s register_netdevice_notifier err:%d", __func__, ret);
		goto err_reg_notifier;
	}

	p2phc_info("%s ok", __func__);
	return 0;

err_reg_notifier:
	unregister_netdevice_notifier(&p2phc_nb);
err_init:
#ifdef PER_CPU
	for (cpu = 0; cpu < CONFIG_NR_CPUS; cpu ++) {
		if (g_p2phc.dlc[cpu]) {
			dlhc_free(g_p2phc.dlc[cpu]);
			g_p2phc.dlc[cpu] = NULL;
		}
		p2phc_info("%s dlhc_free cpu:%d, dlc:%p", __func__, cpu, g_p2phc.dlc[cpu]);
	}
#else
	if (g_p2phc.dlc) {
		dlhc_free(g_p2phc.dlc);
		g_p2phc.dlc = NULL;
	}
#endif
	return ret;
}

int p2phc_cleanup(void)
{
#ifdef STAT_DUMP
	if (g_p2phc.task) {
		kthread_stop(g_p2phc.task);
		sysctl_p2phc_debug = 0;
		g_p2phc.task = NULL;
	}
#endif

#ifdef PER_CPU
	int cpu;
	for (cpu = 0; cpu < CONFIG_NR_CPUS; cpu ++) {
		if (g_p2phc.dlc[cpu]) {
			dlhc_free(g_p2phc.dlc[cpu]);
			g_p2phc.dlc[cpu] = NULL;
		}
		p2phc_dbg("%s dlhc_free cpu:%d, dlc:%p", __func__, cpu, g_p2phc.dlc[cpu]);
	}
#else
	if (g_p2phc.dlc) {
		dlhc_free(g_p2phc.dlc);
		g_p2phc.dlc = NULL;
	}
#endif
	unregister_netdevice_notifier(&p2phc_nb);

	if (g_p2phc.hooks_is_reg) {
		nf_unregister_net_hooks(&init_net, p2phc_hooks,
				    ARRAY_SIZE(p2phc_hooks));
		g_p2phc.hooks_is_reg = false;
		p2phc_info("%s nf_unregister_net_hooks", __func__);
	}

	p2phc_info("%s ok", __func__);
	return 0;
}
// END WIFI_P2PHC
