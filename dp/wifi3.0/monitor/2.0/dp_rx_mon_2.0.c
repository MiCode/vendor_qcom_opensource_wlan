/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "hal_be_hw_headers.h"
#include "dp_types.h"
#include "hal_be_rx.h"
#include "hal_api.h"
#include "qdf_trace.h"
#include "hal_be_api_mon.h"
#include "dp_internal.h"
#include "qdf_mem.h"   /* qdf_mem_malloc,free */
#include "dp_mon.h"
#include <dp_rx_mon.h>
#include <dp_mon_2.0.h>
#include <dp_rx_mon_2.0.h>
#include <dp_rx.h>
#include <dp_be.h>
#include <hal_be_api_mon.h>

void dp_rx_mon_process_ppdu(void *context)
{
}

void dp_rx_mon_add_ppdu_info_to_wq(struct dp_mon_pdev_be *mon_pdev_be,
				   struct hal_rx_ppdu_info *ppdu_info)
{
	if (ppdu_info) {
		qdf_spin_lock_bh(&mon_pdev_be->rx_mon_wq_lock);
		TAILQ_INSERT_TAIL(&mon_pdev_be->rx_mon_queue,
				  ppdu_info, ppdu_list_elem);
		mon_pdev_be->rx_mon_queue_depth++;
		qdf_spin_unlock_bh(&mon_pdev_be->rx_mon_wq_lock);

		if (mon_pdev_be->rx_mon_queue_depth > DP_MON_QUEUE_DEPTH_MAX) {
			qdf_queue_work(0, mon_pdev_be->rx_mon_workqueue,
				       &mon_pdev_be->rx_mon_work);
		}
	}
}

/**
 * dp_rx_mon_handle_flush_n_trucated_ppdu () - Handle flush and truncated ppdu
 *
 * @soc: DP soc handle
 * @pdev: pdev handle
 * @mon_desc: mon sw desc
 */
static inline void
dp_rx_mon_handle_flush_n_trucated_ppdu(struct dp_soc *soc,
				       struct dp_pdev *pdev,
				       struct dp_mon_desc *mon_desc)
{
	union dp_mon_desc_list_elem_t *desc_list = NULL;
	union dp_mon_desc_list_elem_t *tail = NULL;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be =
			dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);
	struct dp_mon_desc_pool *rx_mon_desc_pool = &mon_soc_be->rx_desc_mon;
	uint16_t work_done;

	qdf_frag_free(mon_desc->buf_addr);
	dp_mon_add_to_free_desc_list(&desc_list, &tail, mon_desc);
	work_done = 1;
	dp_mon_buffers_replenish(soc, &soc->rxdma_mon_buf_ring[0],
				 rx_mon_desc_pool,
				 work_done,
				 &desc_list, &tail);
}

void dp_rx_mon_process_tlv_status(struct dp_pdev *pdev,
				  struct hal_rx_ppdu_info *ppdu_info,
				  void *status_frag,
				  uint16_t tlv_status)
{
	struct dp_soc *soc  = pdev->soc;
	qdf_nbuf_t nbuf;
	qdf_frag_t addr;
	uint8_t user_id = ppdu_info->user_id;
	uint8_t mpdu_idx = ppdu_info->mpdu_count[user_id];
	uint16_t num_frags;
	uint16_t frag_len = RX_MONITOR_BUFFER_SIZE;

	switch (tlv_status) {
	case HAL_TLV_STATUS_HEADER: {
		/* If this is first RX_HEADER for MPDU, allocate skb
		 * else add frag to already allocated skb
		 */
		if (!ppdu_info->mpdu_info[user_id].mpdu_start_received) {
			nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
					      DP_MON_DATA_BUFFER_SIZE,
					      MAX_MONITOR_HEADER,
					      0, FALSE);

			if (!nbuf) {
				dp_mon_err("malloc failed pdev: %pK ", pdev);
				return;
			}
			ppdu_info->mpdu_q[user_id][mpdu_idx] = nbuf;
			dp_rx_mon_add_frag_to_skb(ppdu_info, nbuf, status_frag);
		} else {
			nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];
			dp_rx_mon_add_frag_to_skb(ppdu_info, nbuf, status_frag);
		}
	}
	break;
	case HAL_TLV_STATUS_MON_BUF_ADDR:
	{
		struct hal_mon_packet_info *packet_info = &ppdu_info->packet_info;
		struct dp_mon_desc *mon_desc = dp_mon_desc_get(&packet_info->sw_cookie);
		struct hal_rx_mon_msdu_info *buf_info;

		qdf_assert_always(mon_desc);

		addr = mon_desc->buf_addr;
		qdf_assert_always(addr);

		if (!mon_desc->unmapped) {
			qdf_mem_unmap_page(soc->osdev,
					   (qdf_dma_addr_t)mon_desc->paddr,
					   QDF_DMA_FROM_DEVICE,
					   DP_MON_DATA_BUFFER_SIZE);
			mon_desc->unmapped = 1;
		}

		nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];
		num_frags = qdf_nbuf_get_nr_frags(nbuf);
		if (num_frags < QDF_NBUF_MAX_FRAGS) {
			qdf_nbuf_add_rx_frag(addr, nbuf,
					     packet_info->dma_length,
					     frag_len,
					     RX_MONITOR_BUFFER_SIZE,
					     false);
		}

		buf_info = addr;

		if (ppdu_info->msdu[user_id].first_buffer) {
			buf_info->first_buffer = true;
			ppdu_info->msdu[user_id].first_buffer = false;
		} else {
			buf_info->first_buffer = false;
		}

		if (packet_info->msdu_continuation)
			buf_info->last_buffer = false;
		else
			buf_info->last_buffer = true;

		buf_info->frag_len = packet_info->dma_length;
	}
	break;
	case HAL_TLV_STATUS_MSDU_END:
	{
		struct hal_rx_mon_msdu_info *msdu_info = &ppdu_info->msdu[user_id];
		struct hal_rx_mon_msdu_info *last_buf_info;
		/* update msdu metadata at last buffer of msdu in MPDU */
		nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];
		num_frags = qdf_nbuf_get_nr_frags(nbuf);

		/* This points to last buffer of MSDU . update metadata here */
		addr = qdf_nbuf_get_frag_addr(nbuf, num_frags - 1);
		last_buf_info = addr;

		last_buf_info->first_msdu = msdu_info->first_msdu;
		last_buf_info->last_msdu = msdu_info->last_msdu;
		last_buf_info->decap_type = msdu_info->decap_type;
		last_buf_info->msdu_index = msdu_info->msdu_index;
		last_buf_info->user_rssi = msdu_info->user_rssi;
		last_buf_info->l3_header_padding = msdu_info->l3_header_padding;
		last_buf_info->stbc = msdu_info->stbc;
		last_buf_info->sgi = msdu_info->sgi;
		last_buf_info->reception_type = msdu_info->reception_type;

		/* reset msdu info for next msdu for same user */
		qdf_mem_zero(msdu_info, sizeof(msdu_info));

		/* If flow classification is enabled,
		 * update cce_metadata and fse_metadata
		 */
	}
	break;
	case HAL_TLV_STATUS_MPDU_START:
	{
		struct hal_rx_mon_mpdu_info *mpdu_info, *mpdu_meta;

		nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];
		mpdu_meta = (struct hal_rx_mon_mpdu_info *)qdf_nbuf_data(nbuf);
		mpdu_info = &ppdu_info->mpdu_info[user_id];
		mpdu_meta->decap_type = mpdu_info->decap_type;
	}
	break;
	case HAL_TLV_STATUS_MPDU_END:
	{
		struct hal_rx_mon_mpdu_info *mpdu_info, *mpdu_meta;

		mpdu_info = &ppdu_info->mpdu_info[user_id];
		nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];
		mpdu_meta = (struct hal_rx_mon_mpdu_info *)qdf_nbuf_data(nbuf);
		mpdu_meta->mpdu_length_err = mpdu_info->mpdu_length_err;
		mpdu_meta->fcs_err = mpdu_info->fcs_err;
		mpdu_meta->overflow_err = mpdu_info->overflow_err;
		mpdu_meta->decrypt_err = mpdu_info->decrypt_err;

		/* reset msdu info for next msdu for same user */
		qdf_mem_zero(mpdu_info, sizeof(mpdu_info));
	}
	break;
	}
}

/**
 * dp_rx_mon_process_status_tlv () - Handle mon status process TLV
 *
 * @pdev: DP pdev handle
 *
 * Return
 */
static inline struct hal_rx_ppdu_info *
dp_rx_mon_process_status_tlv(struct dp_pdev *pdev)
{
	struct dp_soc *soc = pdev->soc;
	struct dp_mon_pdev *mon_pdev = pdev->monitor_pdev;
	struct dp_mon_pdev_be *mon_pdev_be =
			dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	union dp_mon_desc_list_elem_t *desc_list = NULL;
	union dp_mon_desc_list_elem_t *tail = NULL;
	struct dp_mon_desc *mon_desc;
	uint8_t idx;
	void *buf;
	struct hal_rx_ppdu_info *ppdu_info;
	uint8_t *rx_tlv;
	uint8_t *rx_tlv_start;
	uint16_t end_offset = 0;
	uint16_t tlv_status = HAL_TLV_STATUS_BUF_DONE;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);
	struct dp_mon_desc_pool *rx_mon_desc_pool = &mon_soc_be->rx_desc_mon;
	uint8_t work_done = 0;
	uint16_t status_buf_count;

	if (!mon_pdev_be->desc_count) {
		dp_mon_err("no of status buffer count is zero: %pK", pdev);
		return NULL;
	}

	ppdu_info = qdf_mem_malloc(sizeof(*ppdu_info));

	if (!ppdu_info) {
		dp_mon_err("ppdu_info malloc failed pdev: %pK", pdev);
		return NULL;
	}

	status_buf_count = mon_pdev_be->desc_count;
	for (idx = 0; idx < status_buf_count; idx++) {
		mon_desc = mon_pdev_be->status[idx];
		if (!mon_desc) {
			qdf_assert_always(0);
			return NULL;
		}

		buf = mon_desc->buf_addr;
		end_offset = mon_desc->end_offset;

		dp_mon_add_to_free_desc_list(&desc_list, &tail, mon_desc);
		work_done++;

		rx_tlv = buf;
		rx_tlv_start = buf;

		do {
			tlv_status = hal_rx_status_get_tlv_info(rx_tlv,
								ppdu_info,
								pdev->soc->hal_soc,
								buf);

			rx_tlv = hal_rx_status_get_next_tlv(rx_tlv, 1);

	} while ((tlv_status == HAL_TLV_STATUS_PPDU_NOT_DONE) ||
			(tlv_status == HAL_TLV_STATUS_HEADER) ||
			(tlv_status == HAL_TLV_STATUS_MPDU_END) ||
			(tlv_status == HAL_TLV_STATUS_MSDU_END));

		/* set status buffer pointer to NULL */
		mon_pdev_be->status[idx] = NULL;
		mon_pdev_be->desc_count--;

		qdf_frag_free(buf);
	}

	if (work_done) {
		mon_pdev->rx_mon_stats.mon_rx_bufs_replenished_dest +=
				work_done;
		dp_mon_buffers_replenish(soc, &soc->rxdma_mon_buf_ring[0],
					 rx_mon_desc_pool,
					 work_done,
					 &desc_list, &tail);
	}

	return ppdu_info;
}

static inline uint32_t
dp_rx_mon_srng_process_2_0(struct dp_soc *soc, struct dp_intr *int_ctx,
			   uint32_t mac_id, uint32_t quota)
{
	struct dp_pdev *pdev = dp_get_pdev_for_lmac_id(soc, mac_id);
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);
	struct dp_mon_desc_pool *rx_mon_desc_pool = &mon_soc_be->rx_desc_mon;
	hal_soc_handle_t hal_soc = soc->hal_soc;
	void *rx_mon_dst_ring_desc;
	void *mon_dst_srng;
	uint32_t work_done = 0;
	struct hal_rx_ppdu_info *ppdu_info = NULL;
	QDF_STATUS status;

	if (!pdev) {
		dp_mon_err("%pK: pdev is null for mac_id = %d", soc, mac_id);
		return work_done;
	}

	mon_pdev = pdev->monitor_pdev;
	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	mon_dst_srng = soc->rxdma_mon_dst_ring[mac_id].hal_srng;

	if (!mon_dst_srng || !hal_srng_initialized(mon_dst_srng)) {
		dp_mon_err("%pK: : HAL Monitor Destination Ring Init Failed -- %pK",
			   soc, mon_dst_srng);
		return work_done;
	}

	hal_soc = soc->hal_soc;

	qdf_assert((hal_soc && pdev));

	qdf_spin_lock_bh(&mon_pdev->mon_lock);

	if (qdf_unlikely(dp_srng_access_start(int_ctx, soc, mon_dst_srng))) {
		dp_mon_err("%s %d : HAL Mon Dest Ring access Failed -- %pK",
			   __func__, __LINE__, mon_dst_srng);
		qdf_spin_unlock_bh(&mon_pdev->mon_lock);
		return work_done;
	}

	while (qdf_likely((rx_mon_dst_ring_desc =
			  (void *)hal_srng_dst_peek(hal_soc, mon_dst_srng))
				&& quota--)) {
		struct hal_mon_desc hal_mon_rx_desc = {0};
		struct dp_mon_desc *mon_desc;
		hal_be_get_mon_dest_status(soc->hal_soc,
					   rx_mon_dst_ring_desc,
					   &hal_mon_rx_desc);
		/* If it's empty descriptor, skip processing
		 * and process next hW desc
		 */
		if (hal_mon_rx_desc.empty_descriptor == 1) {
			dp_mon_debug("empty descriptor found mon_pdev: %pK",
				     mon_pdev);
			rx_mon_dst_ring_desc =
				hal_srng_dst_get_next(hal_soc, mon_dst_srng);
			continue;
		}
		mon_desc = (struct dp_mon_desc *)(uintptr_t)(hal_mon_rx_desc.buf_addr);
		qdf_assert_always(mon_desc);

		if (!mon_desc->unmapped) {
			qdf_mem_unmap_page(soc->osdev, mon_desc->paddr,
					   rx_mon_desc_pool->buf_size,
					   QDF_DMA_FROM_DEVICE);
			mon_desc->unmapped = 1;
		}
		mon_desc->end_offset = hal_mon_rx_desc.end_offset;

		/* Flush and truncated status buffers content
		 * need to discarded
		 */
		if (hal_mon_rx_desc.end_reason == HAL_MON_FLUSH_DETECTED ||
		    hal_mon_rx_desc.end_reason == HAL_MON_PPDU_TRUNCATED) {
			dp_mon_debug("end_resaon: %d mon_pdev: %pK",
				     hal_mon_rx_desc.end_reason, mon_pdev);
			dp_rx_mon_handle_flush_n_trucated_ppdu(soc,
							       pdev,
							       mon_desc);
			rx_mon_dst_ring_desc = hal_srng_dst_get_next(hal_soc,
							mon_dst_srng);
			continue;
		}
		if (mon_pdev_be->desc_count >= DP_MON_MAX_STATUS_BUF)
			qdf_assert_always(0);

		mon_pdev_be->status[mon_pdev_be->desc_count++] = mon_desc;

		rx_mon_dst_ring_desc = hal_srng_dst_get_next(hal_soc, mon_dst_srng);

		status = dp_rx_process_pktlog_be(soc, pdev, ppdu_info,
						 mon_desc->buf_addr,
						 hal_mon_rx_desc.end_offset);

		if (hal_mon_rx_desc.end_reason == HAL_MON_STATUS_BUFFER_FULL)
			continue;

		mon_pdev->rx_mon_stats.status_ppdu_done++;

		ppdu_info = dp_rx_mon_process_status_tlv(pdev);

		/* Call enhanced stats update API */
		if (mon_pdev->enhanced_stats_en && ppdu_info)
			dp_rx_handle_ppdu_stats(soc, pdev, ppdu_info);

		/* Call API to add PPDU info workqueue */

		if (ppdu_info)
			qdf_mem_free(ppdu_info);

		work_done++;

		/* desc_count should be zero  after PPDU status processing */
		if (mon_pdev_be->desc_count > 0)
			qdf_assert_always(0);

		mon_pdev_be->desc_count = 0;
	}
	dp_srng_access_end(int_ctx, soc, mon_dst_srng);

	qdf_spin_unlock_bh(&mon_pdev->mon_lock);
	dp_mon_info("mac_id: %d, work_done:%d", mac_id, work_done);
	return work_done;
}

uint32_t
dp_rx_mon_process_2_0(struct dp_soc *soc, struct dp_intr *int_ctx,
		      uint32_t mac_id, uint32_t quota)
{
	uint32_t work_done;

	work_done = dp_rx_mon_srng_process_2_0(soc, int_ctx, mac_id, quota);

	return work_done;
}

void
dp_rx_mon_buf_desc_pool_deinit(struct dp_soc *soc)
{
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	dp_mon_desc_pool_deinit(&mon_soc_be->rx_desc_mon);
}

QDF_STATUS
dp_rx_mon_buf_desc_pool_init(struct dp_soc *soc)
{
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);
	uint32_t num_entries;

	num_entries =
		wlan_cfg_get_dp_soc_rx_mon_buf_ring_size(soc->wlan_cfg_ctx);
	return dp_mon_desc_pool_init(&mon_soc_be->rx_desc_mon, num_entries);
}

void dp_rx_mon_buf_desc_pool_free(struct dp_soc *soc)
{
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	if (mon_soc)
		dp_mon_desc_pool_free(&mon_soc_be->rx_desc_mon);
}

QDF_STATUS
dp_rx_mon_buf_desc_pool_alloc(struct dp_soc *soc)
{
	struct dp_srng *mon_buf_ring;
	struct dp_mon_desc_pool *rx_mon_desc_pool;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);
	int entries;
	struct wlan_cfg_dp_soc_ctxt *soc_cfg_ctx;

	soc_cfg_ctx = soc->wlan_cfg_ctx;

	entries = wlan_cfg_get_dp_soc_rx_mon_buf_ring_size(soc_cfg_ctx);
	mon_buf_ring = &soc->rxdma_mon_buf_ring[0];

	rx_mon_desc_pool = &mon_soc_be->rx_desc_mon;

	qdf_print("%s:%d rx mon buf desc pool entries: %d", __func__, __LINE__, entries);
	return dp_mon_desc_pool_alloc(entries, rx_mon_desc_pool);
}

void
dp_rx_mon_buffers_free(struct dp_soc *soc)
{
	struct dp_mon_desc_pool *rx_mon_desc_pool;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	rx_mon_desc_pool = &mon_soc_be->rx_desc_mon;

	dp_mon_pool_frag_unmap_and_free(soc, rx_mon_desc_pool);
}

QDF_STATUS
dp_rx_mon_buffers_alloc(struct dp_soc *soc, uint32_t size)
{
	struct dp_srng *mon_buf_ring;
	struct dp_mon_desc_pool *rx_mon_desc_pool;
	union dp_mon_desc_list_elem_t *desc_list = NULL;
	union dp_mon_desc_list_elem_t *tail = NULL;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	mon_buf_ring = &soc->rxdma_mon_buf_ring[0];

	rx_mon_desc_pool = &mon_soc_be->rx_desc_mon;

	return dp_mon_buffers_replenish(soc, mon_buf_ring,
					rx_mon_desc_pool,
					size,
					&desc_list, &tail);
}

#ifdef QCA_ENHANCED_STATS_SUPPORT
void
dp_rx_mon_populate_ppdu_usr_info_2_0(struct mon_rx_user_status *rx_user_status,
				     struct cdp_rx_stats_ppdu_user *ppdu_user)
{
	ppdu_user->mpdu_retries = rx_user_status->retry_mpdu;
}

#ifdef WLAN_FEATURE_11BE
void dp_rx_mon_stats_update_2_0(struct dp_mon_peer *mon_peer,
				struct cdp_rx_indication_ppdu *ppdu,
				struct cdp_rx_stats_ppdu_user *ppdu_user)
{
	uint8_t mcs, preamble, ppdu_type;
	uint32_t num_msdu;

	preamble = ppdu->u.preamble;
	ppdu_type = ppdu->u.ppdu_type;
	num_msdu = ppdu_user->num_msdu;

	if (ppdu_type == HAL_RX_TYPE_SU)
		mcs = ppdu->u.mcs;
	else
		mcs = ppdu_user->mcs;

	DP_STATS_INC(mon_peer, rx.mpdu_retry_cnt, ppdu_user->mpdu_retries);
	DP_STATS_INCC(mon_peer,
		      rx.pkt_type[preamble].mcs_count[MAX_MCS - 1], num_msdu,
		      ((mcs >= MAX_MCS_11BE) && (preamble == DOT11_BE)));
	DP_STATS_INCC(mon_peer,
		      rx.pkt_type[preamble].mcs_count[mcs], num_msdu,
		      ((mcs < MAX_MCS_11BE) && (preamble == DOT11_BE)));
	DP_STATS_INCC(mon_peer,
		      rx.su_be_ppdu_cnt.mcs_count[MAX_MCS - 1], 1,
		      ((mcs >= (MAX_MCS_11BE)) && (preamble == DOT11_BE) &&
		      (ppdu_type == HAL_RX_TYPE_SU)));
	DP_STATS_INCC(mon_peer,
		      rx.su_be_ppdu_cnt.mcs_count[mcs], 1,
		      ((mcs < (MAX_MCS_11BE)) && (preamble == DOT11_BE) &&
		      (ppdu_type == HAL_RX_TYPE_SU)));
	DP_STATS_INCC(mon_peer,
		      rx.mu_be_ppdu_cnt[TXRX_TYPE_MU_OFDMA].mcs_count[MAX_MCS - 1],
		      1, ((mcs >= (MAX_MCS_11BE)) &&
		      (preamble == DOT11_BE) &&
		      (ppdu_type == HAL_RX_TYPE_MU_OFDMA)));
	DP_STATS_INCC(mon_peer,
		      rx.mu_be_ppdu_cnt[TXRX_TYPE_MU_OFDMA].mcs_count[mcs],
		      1, ((mcs < (MAX_MCS_11BE)) &&
		      (preamble == DOT11_BE) &&
		      (ppdu_type == HAL_RX_TYPE_MU_OFDMA)));
	DP_STATS_INCC(mon_peer,
		      rx.mu_be_ppdu_cnt[TXRX_TYPE_MU_MIMO].mcs_count[MAX_MCS - 1],
		      1, ((mcs >= (MAX_MCS_11BE)) &&
		      (preamble == DOT11_BE) &&
		      (ppdu_type == HAL_RX_TYPE_MU_MIMO)));
	DP_STATS_INCC(mon_peer,
		      rx.mu_be_ppdu_cnt[TXRX_TYPE_MU_MIMO].mcs_count[mcs],
		      1, ((mcs < (MAX_MCS_11BE)) &&
		      (preamble == DOT11_BE) &&
		      (ppdu_type == HAL_RX_TYPE_MU_MIMO)));
}

void
dp_rx_mon_populate_ppdu_info_2_0(struct hal_rx_ppdu_info *hal_ppdu_info,
				 struct cdp_rx_indication_ppdu *ppdu)
{
	/* Align bw value as per host data structures */
	if (hal_ppdu_info->rx_status.bw == HAL_FULL_RX_BW_320)
		ppdu->u.bw = CMN_BW_320MHZ;
	else
		ppdu->u.bw = hal_ppdu_info->rx_status.bw;
	/* Align preamble value as per host data structures */
	if (hal_ppdu_info->rx_status.preamble_type == HAL_RX_PKT_TYPE_11BE)
		ppdu->u.preamble = DOT11_BE;
	else
		ppdu->u.preamble = hal_ppdu_info->rx_status.preamble_type;

	ppdu->punc_bw = hal_ppdu_info->rx_status.punctured_bw;
}
#else
void dp_rx_mon_stats_update_2_0(struct dp_mon_peer *mon_peer,
				struct cdp_rx_indication_ppdu *ppdu,
				struct cdp_rx_stats_ppdu_user *ppdu_user)
{
	DP_STATS_INC(mon_peer, rx.mpdu_retry_cnt, ppdu_user->mpdu_retries);
}

void
dp_rx_mon_populate_ppdu_info_2_0(struct hal_rx_ppdu_info *hal_ppdu_info,
				 struct cdp_rx_indication_ppdu *ppdu)
{
	ppdu->punc_bw = 0;
}
#endif
#endif
