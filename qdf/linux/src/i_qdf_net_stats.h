/*
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: qdf_net_dev_stats
 * QCA driver framework (QDF) network interface stats management APIs
 */

#if !defined(__I_QDF_NET_STATS_H)
#define __I_QDF_NET_STATS_H

/* Include Files */
#include <qdf_types.h>
#include <qdf_util.h>
#include <linux/netdevice.h>

#define QDF_NET_DEV_STATS_INC_RX_PKTS(stats) \
	(((struct net_device_stats *)stats)->rx_packets++)

#define QDF_NET_DEV_STATS_INC_TX_PKTS(stats) \
	(((struct net_device_stats *)stats)->tx_packets++)

#define QDF_NET_DEV_STATS_INC_RX_BYTES(stats) \
	(((struct net_device_stats *)stats)->rx_bytes++)

#define QDF_NET_DEV_STATS_INC_TX_BYTES(stats) \
	(((struct net_device_stats *)stats)->tx_bytes++)

#define QDF_NET_DEV_STATS_INC_RX_ERRORS(stats) \
	(((struct net_device_stats *)stats)->rx_errors++)

#define QDF_NET_DEV_STATS_INC_TX_ERRORS(stats) \
	(((struct net_device_stats *)stats)->tx_errors++)

#define QDF_NET_DEV_STATS_INC_RX_DROPPED(stats) \
	(((struct net_device_stats *)stats)->rx_dropped++)

#define QDF_NET_DEV_STATS_INC_TX_DROPEED(stats) \
	(((struct net_device_stats *)stats)->tx_dropped++)

#define QDF_NET_DEV_STATS_RX_PKTS(stats) \
	(((struct net_device_stats *)stats)->rx_packets)

#define QDF_NET_DEV_STATS_TX_PKTS(stats) \
	(((struct net_device_stats *)stats)->tx_packets)

#define QDF_NET_DEV_STATS_RX_BYTES(stats) \
	(((struct net_device_stats *)stats)->rx_bytes)

#define QDF_NET_DEV_STATS_TX_BYTES(stats) \
	(((struct net_device_stats *)stats)->tx_bytes)

#define QDF_NET_DEV_STATS_RX_ERRORS(stats) \
	(((struct net_device_stats *)stats)->rx_errors)

#define QDF_NET_DEV_STATS_TX_ERRORS(stats) \
	(((struct net_device_stats *)stats)->tx_errors)

#define QDF_NET_DEV_STATS_RX_DROPPED(stats) \
	(((struct net_device_stats *)stats)->rx_dropped)

#define QDF_NET_DEV_STATS_TX_DROPEED(stats) \
	(((struct net_device_stats *)stats)->tx_dropped)

#endif /*__I_QDF_NET_STATS_H*/
