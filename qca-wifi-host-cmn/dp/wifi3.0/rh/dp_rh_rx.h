/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
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

#ifndef _DP_RH_RX_H_
#define _DP_RH_RX_H_

#include <dp_types.h>
#include <dp_rx.h>
#include "dp_rh.h"

/**
 * dp_rx_desc_pool_init_rh() - Initialize Rx Descriptor pool(s)
 * @soc: Handle to DP Soc structure
 * @rx_desc_pool: Rx descriptor pool handler
 * @pool_id: Rx descriptor pool ID
 *
 * Return: None
 */
QDF_STATUS dp_rx_desc_pool_init_rh(struct dp_soc *soc,
				   struct rx_desc_pool *rx_desc_pool,
				   uint32_t pool_id);

/**
 * dp_rx_desc_pool_deinit_rh() - De-initialize Rx Descriptor pool(s)
 * @soc: Handle to DP Soc structure
 * @rx_desc_pool: Rx descriptor pool handler
 * @pool_id: Rx descriptor pool ID
 *
 * Return: None
 */
void dp_rx_desc_pool_deinit_rh(struct dp_soc *soc,
			       struct rx_desc_pool *rx_desc_pool,
			       uint32_t pool_id);

/**
 * dp_rx_desc_cookie_2_va_rh() - Convert RX Desc cookie ID to VA
 * @soc:Handle to DP Soc structure
 * @cookie: cookie used to lookup virtual address
 *
 * Return: Rx descriptor virtual address
 */
static inline
struct dp_rx_desc *dp_rx_desc_cookie_2_va_rh(struct dp_soc *soc,
					     uint32_t cookie)
{
	return dp_rx_cookie_2_va_rxdma_buf(soc, cookie);
}

#define DP_PEER_METADATA_VDEV_ID_MASK	0x003f0000
#define DP_PEER_METADATA_VDEV_ID_SHIFT	16
#define DP_PEER_METADATA_OFFLOAD_MASK	0x01000000
#define DP_PEER_METADATA_OFFLOAD_SHIFT	24

#define DP_PEER_METADATA_VDEV_ID_GET_RH(_peer_metadata)		\
	(((_peer_metadata) & DP_PEER_METADATA_VDEV_ID_MASK)	\
			>> DP_PEER_METADATA_VDEV_ID_SHIFT)

#define DP_PEER_METADATA_OFFLOAD_GET_RH(_peer_metadata)		\
	(((_peer_metadata) & DP_PEER_METADATA_OFFLOAD_MASK)	\
			>> DP_PEER_METADATA_OFFLOAD_SHIFT)

static inline uint16_t
dp_rx_peer_metadata_peer_id_get_rh(struct dp_soc *soc, uint32_t peer_metadata)
{
	struct htt_rx_peer_metadata_v0 *metadata =
			(struct htt_rx_peer_metadata_v0 *)&peer_metadata;

	return metadata->peer_id;
}

/**
 * dp_rx_data_flush() - Flush RX data after reaping from RX rings
 *
 * @data: reference to flush RX data
 *
 * Return: None
 */
void
dp_rx_data_flush(void *data);

/**
 * dp_rx_data_indication_handler() - Indicate when RX data is available in rings
 *
 * @soc:DP soc reference
 * @data_ind: Data indication message info
 * @vdev_id: Vdev id
 * @peer_id: Peer id
 * @msdu_count: Number of MSDUs available in message
 *
 * Return: None
 */
void
dp_rx_data_indication_handler(struct dp_soc *soc, qdf_nbuf_t data_ind,
			      uint16_t vdev_id, uint16_t peer_id,
			      uint16_t msdu_count);

/**
 * dp_rx_frag_indication_handler() - Indicate when RX frag data is available in ring
 *
 * @soc:DP soc reference
 * @data_ind: Data indication message info
 * @vdev_id: Vdev id
 * @peer_id: Peer id
 *
 * Return: None
 */
void
dp_rx_frag_indication_handler(struct dp_soc *soc, qdf_nbuf_t data_ind,
			      uint16_t vdev_id, uint16_t peer_id);

static inline bool
dp_rx_intrabss_handle_nawds_rh(struct dp_soc *soc, struct dp_txrx_peer *ta_peer,
			       qdf_nbuf_t nbuf_copy,
			       struct cdp_tid_rx_stats *tid_stats,
			       uint8_t link_id)
{
	return false;
}

/**
 * dp_wbm_get_rx_desc_from_hal_desc_rh() - NOP in RH arch implementation
 *
 * @soc: Handle to DP Soc structure
 * @ring_desc: ring descriptor structure pointer
 * @r_rx_desc: pointer to a pointer of Rx Desc
 *
 * Return: QDF_STATUS_SUCCESS - succeeded, others - failed
 */
static inline
QDF_STATUS dp_wbm_get_rx_desc_from_hal_desc_rh(
					struct dp_soc *soc,
					void *ring_desc,
					struct dp_rx_desc **r_rx_desc)
{
	return QDF_STATUS_SUCCESS;
}

static inline
void dp_rx_word_mask_subscribe_rh(struct dp_soc *soc,
				  uint32_t *msg_word,
				  void *rx_filter)
{
}

static inline
void dp_peer_get_reo_hash_rh(struct dp_vdev *vdev,
			     struct cdp_peer_setup_info *setup_info,
			     enum cdp_host_reo_dest_ring *reo_dest,
			     bool *hash_based,
			     uint8_t *lmac_peer_id_msb)
{
}

static inline
bool dp_reo_remap_config_rh(struct dp_soc *soc,
			    uint32_t *remap0,
			    uint32_t *remap1,
			    uint32_t *remap2)
{
	return false;
}

/**
 * dp_rx_prefetch_hw_sw_nbuf_desc() - function to prefetch HW and SW desc
 * @soc: DP soc structure
 * @hal_soc: Handle to HAL Soc structure
 * @quota: quota to process
 * @hal_ring_hdl: Destination ring pointer
 * @last_prefetched_hw_desc: pointer to the last prefetched HW descriptor
 * @last_prefetched_sw_desc: input & output param of last prefetch SW desc
 *
 * Return: None
 */
static inline
void dp_rx_prefetch_hw_sw_nbuf_desc(struct dp_soc *soc,
				    hal_soc_handle_t hal_soc,
				    uint32_t quota,
				    hal_ring_handle_t hal_ring_hdl,
				    hal_ring_desc_t *last_prefetched_hw_desc,
				    struct dp_rx_desc **last_prefetched_sw_desc)
{
}

/**
 * dp_peer_rx_reorder_queue_setup_rh() - NOP for RH arch implementation
 * @soc: Handle to HAL Soc structure
 * @peer: DP peer structure
 * @tid: tid id
 * @ba_window_size: BA window size
 *
 * Return: None
 */
static inline
QDF_STATUS dp_peer_rx_reorder_queue_setup_rh(struct dp_soc *soc,
					     struct dp_peer *peer,
					     int tid,
					     uint32_t ba_window_size)
{
	return QDF_STATUS_SUCCESS;
}
#endif
