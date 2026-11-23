/*
 * Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: ISC
 */

#ifdef FEATURE_MGMT_RX_OVER_SRNG

#include "wlan_cmn.h"
#include "wlan_objmgr_cmn.h"
#include "wlan_objmgr_vdev_obj.h"
#include "wlan_objmgr_global_obj.h"
#include <wlan_mgmt_rx_srng_public_structs.h>
#include <hal_internal.h>

#define MGMT_RX_SRNG_ENTRIES 128
#define MGMT_RX_BUF_SIZE 3520

#if defined(IPA_OFFLOAD) && defined(FEATURE_DIRECT_LINK)
#ifdef IPA_WDI3_VLAN_SUPPORT
#define MGMT_RX_BUF_REFILL_RING_IDX 5
#else
#define MGMT_RX_BUF_REFILL_RING_IDX 4
#endif
#elif defined(IPA_OFFLOAD)
#ifdef IPA_WDI3_VLAN_SUPPORT
#define MGMT_RX_BUF_REFILL_RING_IDX 4
#else
#define MGMT_RX_BUF_REFILL_RING_IDX 3
#endif
#elif defined(FEATURE_DIRECT_LINK)
#define MGMT_RX_BUF_REFILL_RING_IDX 3
#else
#define MGMT_RX_BUF_REFILL_RING_IDX 2
#endif

/** struct mgmt_rx_srng_hdr - header info for mgmt frame
 * @buff_len: buffer len
 * @reserved: Reserved
 */
struct mgmt_rx_srng_hdr {
	A_UINT16 buff_len;
	A_UINT16 reserved;
};

/**
 * struct mgmt_rx_srng_psoc_priv - mgmt rx srng component psoc priv obj
 * @psoc: pointer to psoc object
 * @mgmt_rx_srng_is_enable: is feature enabled by both host and target
 * @tx_ops: TX ops registered with target_if for southbound WMI cmds
 * @rx_ops: RX ops registered with target_if for northbound WMI events
 */
struct mgmt_rx_srng_psoc_priv {
	struct wlan_objmgr_psoc *psoc;
	bool mgmt_rx_srng_is_enable;
	struct wlan_mgmt_rx_srng_tx_ops tx_ops;
	struct wlan_mgmt_rx_srng_rx_ops rx_ops;
};

/**
 * struct mgmt_rx_srng_desc - srng descriptor table entry
 * @nbuf: skb
 * @pa: physical address of skb
 * @cookie: cookie value
 * @in_use: indicate whether entry is in use or not
 */
struct mgmt_rx_srng_desc {
	qdf_nbuf_t nbuf;
	qdf_dma_addr_t pa;
	uint8_t cookie;
	bool in_use;
};

/**
 * struct mgmt_srng_cfg - ring configuration
 * @base_paddr_unaligned: unaligned phy addr of ring
 * @base_vaddr_unaligned: unaligned virt addr of ring
 * @base_paddr_aligned: aligned phy addr of ring
 * @base_vaddr_aligned: aligned virt addr of ring
 * @ring_alloc_size: allocated ring size
 * @srng: hal ring pointer
 */
struct mgmt_srng_cfg {
	qdf_dma_addr_t base_paddr_unaligned;
	void *base_vaddr_unaligned;
	qdf_dma_addr_t base_paddr_aligned;
	void *base_vaddr_aligned;
	uint32_t ring_alloc_size;
	hal_ring_handle_t *srng;
};

/**
 * struct mgmt_rx_srng_pdev_priv - mgmt_rx_srng component pdev priv
 * @pdev: pdev obj
 * @new_skb_alloc_fail_cnt: Counter increments on each failure to allocate
 * new skb to replenish the SRNG with new buffer.
 * @osdev: os dev
 * @hal_soc: opaque hal object
 * @mgmt_rx_srng_cfg: srng config
 * @rx_desc: rx descriptors array
 * @read_idx: read index
 * @write_idx: write index
 */
struct mgmt_rx_srng_pdev_priv {
	struct wlan_objmgr_pdev *pdev;
	uint32_t new_skb_alloc_fail_cnt;
	qdf_device_t osdev;
	void *hal_soc;
	struct mgmt_srng_cfg mgmt_rx_srng_cfg;
	struct mgmt_rx_srng_desc *rx_desc;
	int read_idx;
	int write_idx;
};

#endif
