// MIUI ADD: WIFI_P2PHC
#ifndef __P2PHC_DEBUG_H_
#define __P2PHC_DEBUG_H_

//#define SKB_DUMP
#define STAT_DUMP
//#define TIME_DUMP
//#define DEBUG_LOG

#ifdef DEBUG_LOG
#define p2phc_dbg(fmt, ...)                                              	\
	printk(KERN_DEBUG "p2phc-d: " fmt, ##__VA_ARGS__)
#else
#define p2phc_dbg(fmt, ...)
#endif

#define p2phc_info(fmt, ...)                                              	\
	printk(KERN_INFO "p2phc-i: " fmt, ##__VA_ARGS__)

#define p2phc_err(fmt, ...)                                               	\
	printk(KERN_ERR "p2phc-e: " fmt, ##__VA_ARGS__)

#define IPv4_FMT "%d.%d.%d.%d"
#define IPv4_ARG(x)                                                       	\
	((u8 *)(x))[0], ((u8 *)(x))[1], ((u8 *)(x))[2], ((u8 *)(x))[3]

#define IPv6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define IPv6_ARG(x)                                                        	\
	ntohs((x.s6_addr16)[0]), ntohs((x.s6_addr16)[1]), 						\
	ntohs((x.s6_addr16)[2]), ntohs((x.s6_addr16)[3]),						\
	ntohs((x.s6_addr16)[4]), ntohs((x.s6_addr16)[5]), 						\
	ntohs((x.s6_addr16)[6]), ntohs((x.s6_addr16)[7])

#endif /* __P2PHC_DEBUG_H_*/
// END WIFI_P2PHC
