/*
 * Copyright (c) 2016-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include "cdp_txrx_cmn_struct.h"
#include "hal_hw_headers.h"
#include "dp_types.h"
#include "dp_rx.h"
#include "dp_tx.h"
#include "dp_li_rx.h"
#include "dp_peer.h"
#include "hal_rx.h"
#include "hal_li_rx.h"
#include "hal_api.h"
#include "hal_li_api.h"
#include "qdf_nbuf.h"
#ifdef MESH_MODE_SUPPORT
#include "if_meta_hdr.h"
#endif
#include "dp_internal.h"
#include "dp_ipa.h"
#ifdef WIFI_MONITOR_SUPPORT
#include <dp_mon.h>
#endif
#ifdef FEATURE_WDS
#include "dp_txrx_wds.h"
#endif
#include "dp_hist.h"
#include "dp_rx_buffer_pool.h"
#include "dp_li.h"
#ifdef WLAN_FEATURE_OSRTP
#include "xdp_sock_drv.h"
#endif

static inline
bool is_sa_da_idx_valid(uint32_t max_ast,
			qdf_nbuf_t nbuf, struct hal_rx_msdu_metadata msdu_info)
{
	if ((qdf_nbuf_is_sa_valid(nbuf) && (msdu_info.sa_idx > max_ast)) ||
	    (!qdf_nbuf_is_da_mcbc(nbuf) && qdf_nbuf_is_da_valid(nbuf) &&
	     (msdu_info.da_idx > max_ast)))
		return false;

	return true;
}

#ifndef QCA_HOST_MODE_WIFI_DISABLED
#if defined(FEATURE_MCL_REPEATER) && defined(FEATURE_MEC)
/**
 * dp_rx_mec_check_wrapper() - wrapper to dp_rx_mcast_echo_check
 * @soc: core DP main context
 * @txrx_peer: dp peer handler
 * @rx_tlv_hdr: start of the rx TLV header
 * @nbuf: pkt buffer
 *
 * Return: bool (true if it is a looped back pkt else false)
 */
static inline bool dp_rx_mec_check_wrapper(struct dp_soc *soc,
					   struct dp_txrx_peer *txrx_peer,
					   uint8_t *rx_tlv_hdr,
					   qdf_nbuf_t nbuf)
{
	return dp_rx_mcast_echo_check(soc, txrx_peer, rx_tlv_hdr, nbuf);
}
#else
static inline bool dp_rx_mec_check_wrapper(struct dp_soc *soc,
					   struct dp_txrx_peer *txrx_peer,
					   uint8_t *rx_tlv_hdr,
					   qdf_nbuf_t nbuf)
{
	return false;
}
#endif
#endif

#ifndef QCA_HOST_MODE_WIFI_DISABLE
static bool
dp_rx_intrabss_ucast_check_li(struct dp_soc *soc, qdf_nbuf_t nbuf,
			      struct dp_txrx_peer *ta_txrx_peer,
			      struct hal_rx_msdu_metadata *msdu_metadata,
			      uint8_t *p_tx_vdev_id)
{
	uint16_t da_peer_id;
	struct dp_txrx_peer *da_peer;
	struct dp_ast_entry *ast_entry;
	dp_txrx_ref_handle txrx_ref_handle = NULL;

	if (!qdf_nbuf_is_da_valid(nbuf) || qdf_nbuf_is_da_mcbc(nbuf))
		return false;

	ast_entry = soc->ast_table[msdu_metadata->da_idx];
	if (!ast_entry)
		return false;

	if (ast_entry->type == CDP_TXRX_AST_TYPE_DA) {
		ast_entry->is_active = TRUE;
		return false;
	}

	da_peer_id = ast_entry->peer_id;
	/* TA peer cannot be same as peer(DA) on which AST is present
	 * this indicates a change in topology and that AST entries
	 * are yet to be updated.
	 */
	if (da_peer_id == ta_txrx_peer->peer_id ||
	    da_peer_id == HTT_INVALID_PEER)
		return false;

	da_peer = dp_txrx_peer_get_ref_by_id(soc, da_peer_id,
					     &txrx_ref_handle, DP_MOD_ID_RX);
	if (!da_peer)
		return false;

	*p_tx_vdev_id = da_peer->vdev->vdev_id;
	/* If the source or destination peer in the isolation
	 * list then dont forward instead push to bridge stack.
	 */
	if (dp_get_peer_isolation(ta_txrx_peer) ||
	    dp_get_peer_isolation(da_peer) ||
	    da_peer->vdev->vdev_id != ta_txrx_peer->vdev->vdev_id) {
		dp_txrx_peer_unref_delete(txrx_ref_handle, DP_MOD_ID_RX);
		return false;
	}

	if (da_peer->bss_peer) {
		dp_txrx_peer_unref_delete(txrx_ref_handle, DP_MOD_ID_RX);
		return false;
	}

	dp_txrx_peer_unref_delete(txrx_ref_handle, DP_MOD_ID_RX);
	return true;
}

/*
 * dp_rx_intrabss_fwd_li() - Implements the Intra-BSS forwarding logic
 *
 * @soc: core txrx main context
 * @ta_txrx_peer	: source peer entry
 * @rx_tlv_hdr	: start address of rx tlvs
 * @nbuf	: nbuf that has to be intrabss forwarded
 *
 * Return: bool: true if it is forwarded else false
 */
static bool
dp_rx_intrabss_fwd_li(struct dp_soc *soc,
		      struct dp_txrx_peer *ta_txrx_peer,
		      uint8_t *rx_tlv_hdr,
		      qdf_nbuf_t nbuf,
		      struct hal_rx_msdu_metadata msdu_metadata,
		      struct cdp_tid_rx_stats *tid_stats)
{
	uint8_t tx_vdev_id;

	/* if it is a broadcast pkt (eg: ARP) and it is not its own
	 * source, then clone the pkt and send the cloned pkt for
	 * intra BSS forwarding and original pkt up the network stack
	 * Note: how do we handle multicast pkts. do we forward
	 * all multicast pkts as is or let a higher layer module
	 * like igmpsnoop decide whether to forward or not with
	 * Mcast enhancement.
	 */
	if (qdf_nbuf_is_da_mcbc(nbuf) && !ta_txrx_peer->bss_peer)
		return dp_rx_intrabss_mcbc_fwd(soc, ta_txrx_peer, rx_tlv_hdr,
					       nbuf, tid_stats, 0);

	if (dp_rx_intrabss_eapol_drop_check(soc, ta_txrx_peer, rx_tlv_hdr,
					    nbuf))
		return true;

	if (dp_rx_intrabss_ucast_check_li(soc, nbuf, ta_txrx_peer,
					  &msdu_metadata, &tx_vdev_id))
		return dp_rx_intrabss_ucast_fwd(soc, ta_txrx_peer, tx_vdev_id,
						rx_tlv_hdr, nbuf, tid_stats,
						0);

	return false;
}
#endif

uint32_t dp_rx_process_li(struct dp_intr *int_ctx,
			  hal_ring_handle_t hal_ring_hdl, uint8_t reo_ring_num,
			  uint32_t quota)
{
	hal_ring_desc_t ring_desc;
	hal_ring_desc_t last_prefetched_hw_desc;
	hal_soc_handle_t hal_soc;
	struct dp_rx_desc *rx_desc = NULL;
	struct dp_rx_desc *last_prefetched_sw_desc = NULL;
	qdf_nbuf_t nbuf, next;
	bool near_full;
	union dp_rx_desc_list_elem_t *head[MAX_PDEV_CNT];
	union dp_rx_desc_list_elem_t *tail[MAX_PDEV_CNT];
	uint32_t num_pending = 0;
	uint32_t rx_bufs_used = 0, rx_buf_cookie;
	uint16_t msdu_len = 0;
	uint16_t peer_id;
	uint8_t vdev_id;
	struct dp_txrx_peer *txrx_peer;
	dp_txrx_ref_handle txrx_ref_handle = NULL;
	struct dp_vdev *vdev;
	uint32_t pkt_len = 0;
	struct hal_rx_mpdu_desc_info mpdu_desc_info;
	struct hal_rx_msdu_desc_info msdu_desc_info;
	enum hal_reo_error_status error;
	uint32_t peer_mdata;
	uint8_t *rx_tlv_hdr;
	uint32_t rx_bufs_reaped[MAX_PDEV_CNT];
	uint8_t mac_id = 0;
	struct dp_pdev *rx_pdev;
	struct dp_srng *dp_rxdma_srng;
	struct rx_desc_pool *rx_desc_pool;
	struct dp_soc *soc = int_ctx->soc;
	struct cdp_tid_rx_stats *tid_stats;
	qdf_nbuf_t nbuf_head;
	qdf_nbuf_t nbuf_tail;
	qdf_nbuf_t deliver_list_head;
	qdf_nbuf_t deliver_list_tail;
	uint32_t num_rx_bufs_reaped = 0;
	uint32_t intr_id;
	struct hif_opaque_softc *scn;
	int32_t tid = 0;
	bool is_prev_msdu_last = true;
	uint32_t rx_ol_pkt_cnt = 0;
	uint32_t num_entries = 0;
	struct hal_rx_msdu_metadata msdu_metadata;
	QDF_STATUS status;
	qdf_nbuf_t ebuf_head;
	qdf_nbuf_t ebuf_tail;
	uint8_t pkt_capture_offload = 0;
	int max_reap_limit;
	uint32_t old_tid;
	uint32_t peer_ext_stats;
	uint32_t dsf;
	uint32_t max_ast;
	uint64_t current_time = 0;
#ifdef WLAN_FEATURE_OSRTP
	qdf_xbuf_t xbuf;
	qdf_xbuf_t xnext;
	qdf_xbuf_t xbuf_head;
	qdf_xbuf_t xbuf_tail;
	qdf_xbuf_t deliver_xlist_head;
	qdf_xbuf_t deliver_xlist_tail;
	qdf_nbuf_list_t nbuf_list;
	struct xsk_buff_pool *xsk_pool = NULL;
#endif
	uint16_t buf_size;

	DP_HIST_INIT();

	qdf_assert_always(soc && hal_ring_hdl);
	hal_soc = soc->hal_soc;
	qdf_assert_always(hal_soc);

	scn = soc->hif_handle;
	intr_id = int_ctx->dp_intr_id;
	num_entries = hal_srng_get_num_entries(hal_soc, hal_ring_hdl);
	dp_runtime_pm_mark_last_busy(soc);

more_data:
	/* reset local variables here to be re-used in the function */
	nbuf_head = NULL;
	nbuf_tail = NULL;
	deliver_list_head = NULL;
	deliver_list_tail = NULL;
	txrx_peer = NULL;
	vdev = NULL;
	num_rx_bufs_reaped = 0;
	ebuf_head = NULL;
	ebuf_tail = NULL;
	max_reap_limit = dp_rx_get_loop_pkt_limit(soc);
#ifdef WLAN_FEATURE_OSRTP
	xbuf_head = NULL;
	xbuf_tail = NULL;
	deliver_xlist_head = NULL;
	deliver_xlist_tail = NULL;
	nbuf_list.nbuf_head = &nbuf_head;
	nbuf_list.nbuf_tail = &nbuf_tail;
	nbuf_list.ebuf_head = &ebuf_head;
	nbuf_list.ebuf_tail = &ebuf_tail;
#endif

	qdf_mem_zero(rx_bufs_reaped, sizeof(rx_bufs_reaped));
	qdf_mem_zero(&mpdu_desc_info, sizeof(mpdu_desc_info));
	qdf_mem_zero(&msdu_desc_info, sizeof(msdu_desc_info));
	qdf_mem_zero(head, sizeof(head));
	qdf_mem_zero(tail, sizeof(tail));
	old_tid = 0xff;
	dsf = 0;
	peer_ext_stats = 0;
	max_ast = 0;
	rx_pdev = NULL;
	tid_stats = NULL;

	dp_pkt_get_timestamp(&current_time);

	if (qdf_unlikely(dp_rx_srng_access_start(int_ctx, soc, hal_ring_hdl))) {
		/*
		 * Need API to convert from hal_ring pointer to
		 * Ring Type / Ring Id combo
		 */
		DP_STATS_INC(soc, rx.err.hal_ring_access_fail, 1);
		QDF_TRACE(QDF_MODULE_ID_TXRX, QDF_TRACE_LEVEL_ERROR,
			  FL("HAL RING Access Failed -- %pK"), hal_ring_hdl);
		goto done;
	}

	if (!num_pending)
		num_pending = hal_srng_dst_num_valid(hal_soc, hal_ring_hdl, 0);

	dp_srng_dst_inv_cached_descs(soc, hal_ring_hdl, num_pending);

	if (num_pending > quota)
		num_pending = quota;

	last_prefetched_hw_desc = dp_srng_dst_prefetch(hal_soc, hal_ring_hdl,
						       num_pending);

	peer_ext_stats = wlan_cfg_is_peer_ext_stats_enabled(soc->wlan_cfg_ctx);
	max_ast = wlan_cfg_get_max_ast_idx(soc->wlan_cfg_ctx);
	/*
	 * start reaping the buffers from reo ring and queue
	 * them in per vdev queue.
	 * Process the received pkts in a different per vdev loop.
	 */
	while (qdf_likely(num_pending)) {
		ring_desc = dp_srng_dst_get_next(soc, hal_ring_hdl);

		if (qdf_unlikely(!ring_desc))
			break;

		error = HAL_RX_ERROR_STATUS_GET(ring_desc);
		if (qdf_unlikely(error == HAL_REO_ERROR_DETECTED)) {
			dp_rx_err("%pK: HAL RING 0x%pK:error %d",
				  soc, hal_ring_hdl, error);
			DP_STATS_INC(soc, rx.err.hal_reo_error[reo_ring_num],
				     1);
			/* Don't know how to deal with this -- assert */
			qdf_assert(0);
		}

		dp_rx_ring_record_entry(soc, reo_ring_num, ring_desc);
		rx_buf_cookie = HAL_RX_REO_BUF_COOKIE_GET(ring_desc);
		status = dp_rx_cookie_check_and_invalidate(ring_desc);
		if (qdf_unlikely(QDF_IS_STATUS_ERROR(status))) {
			DP_STATS_INC(soc, rx.err.stale_cookie, 1);
			break;
		}

		rx_desc = dp_rx_cookie_2_va_rxdma_buf(soc, rx_buf_cookie);
		status = dp_rx_desc_sanity(soc, hal_soc, hal_ring_hdl,
					   ring_desc, rx_desc);
		if (QDF_IS_STATUS_ERROR(status)) {
			if (qdf_unlikely(rx_desc && rx_desc->nbuf)) {
				qdf_assert_always(!rx_desc->unmapped);
#ifdef WLAN_FEATURE_OSRTP
				if (rx_desc->xbuf) {
					qdf_xbuf_unmap_nbytes_single(soc->osdev, rx_desc->xbuf, QDF_DMA_FROM_DEVICE, RX_DATA_BUFFER_SIZE);
					dp_rx_buffer_pool_xbuf_free(soc, rx_desc->xbuf);
				} else
#endif
				dp_rx_nbuf_unmap(soc, rx_desc, reo_ring_num);
				dp_rx_buffer_pool_nbuf_free(soc, rx_desc->nbuf,
							    rx_desc->pool_id);
				dp_rx_add_to_free_desc_list(
							&head[rx_desc->pool_id],
							&tail[rx_desc->pool_id],
							rx_desc);
			}
			continue;
		}

		/*
		 * this is a unlikely scenario where the host is reaping
		 * a descriptor which it already reaped just a while ago
		 * but is yet to replenish it back to HW.
		 * In this case host will dump the last 128 descriptors
		 * including the software descriptor rx_desc and assert.
		 */

		if (qdf_unlikely(!rx_desc->in_use)) {
			DP_STATS_INC(soc, rx.err.hal_reo_dest_dup, 1);
			dp_info_rl("Reaping rx_desc not in use!");
			dp_rx_dump_info_and_assert(soc, hal_ring_hdl,
						   ring_desc, rx_desc);
			/* ignore duplicate RX desc and continue to process */
			/* Pop out the descriptor */
			continue;
		}

		status = dp_rx_desc_nbuf_sanity_check(soc, ring_desc, rx_desc);
		if (qdf_unlikely(QDF_IS_STATUS_ERROR(status))) {
			DP_STATS_INC(soc, rx.err.nbuf_sanity_fail, 1);
			dp_info_rl("Nbuf sanity check failure!");
			dp_rx_dump_info_and_assert(soc, hal_ring_hdl,
						   ring_desc, rx_desc);
			rx_desc->in_err_state = 1;
			continue;
		}

		if (qdf_unlikely(!dp_rx_desc_check_magic(rx_desc))) {
			dp_err("Invalid rx_desc cookie=%d", rx_buf_cookie);
			DP_STATS_INC(soc, rx.err.rx_desc_invalid_magic, 1);
			dp_rx_dump_info_and_assert(soc, hal_ring_hdl,
						   ring_desc, rx_desc);
		}

		/* Get MPDU DESC info */
		hal_rx_mpdu_desc_info_get_li(ring_desc, &mpdu_desc_info);

		/* Get MSDU DESC info */
		hal_rx_msdu_desc_info_get_li(ring_desc, &msdu_desc_info);

		if (qdf_unlikely(msdu_desc_info.msdu_flags &
				 HAL_MSDU_F_MSDU_CONTINUATION)) {
			/* previous msdu has end bit set, so current one is
			 * the new MPDU
			 */
			if (is_prev_msdu_last) {
				/* For new MPDU check if we can read complete
				 * MPDU by comparing the number of buffers
				 * available and number of buffers needed to
				 * reap this MPDU
				 */
				if ((msdu_desc_info.msdu_len /
				     (RX_DATA_BUFFER_SIZE -
				      soc->rx_pkt_tlv_size) + 1) >
				    num_pending) {
					DP_STATS_INC(soc,
						     rx.msdu_scatter_wait_break,
						     1);
					dp_rx_cookie_reset_invalid_bit(
								     ring_desc);
					/* As we are going to break out of the
					 * loop because of unavailability of
					 * descs to form complete SG, we need to
					 * reset the TP in the REO destination
					 * ring.
					 */
					hal_srng_dst_dec_tp(hal_soc,
							    hal_ring_hdl);
					break;
				}
				is_prev_msdu_last = false;
			}
		}

		if (mpdu_desc_info.mpdu_flags & HAL_MPDU_F_RETRY_BIT)
			qdf_nbuf_set_rx_retry_flag(rx_desc->nbuf, 1);

		if (qdf_unlikely(mpdu_desc_info.mpdu_flags &
				 HAL_MPDU_F_RAW_AMPDU))
			qdf_nbuf_set_raw_frame(rx_desc->nbuf, 1);

		if (!is_prev_msdu_last &&
		    !(msdu_desc_info.msdu_flags & HAL_MSDU_F_MSDU_CONTINUATION))
			is_prev_msdu_last = true;

		rx_bufs_reaped[rx_desc->pool_id]++;
		peer_mdata = mpdu_desc_info.peer_meta_data;
		QDF_NBUF_CB_RX_PEER_ID(rx_desc->nbuf) =
			dp_rx_peer_metadata_peer_id_get_li(soc, peer_mdata);
		QDF_NBUF_CB_RX_VDEV_ID(rx_desc->nbuf) =
			DP_PEER_METADATA_VDEV_ID_GET_LI(peer_mdata);

		/* to indicate whether this msdu is rx offload */
		pkt_capture_offload =
			DP_PEER_METADATA_OFFLOAD_GET_LI(peer_mdata);

		/*
		 * save msdu flags first, last and continuation msdu in
		 * nbuf->cb, also save mcbc, is_da_valid, is_sa_valid and
		 * length to nbuf->cb. This ensures the info required for
		 * per pkt processing is always in the same cache line.
		 * This helps in improving throughput for smaller pkt
		 * sizes.
		 */
		if (msdu_desc_info.msdu_flags & HAL_MSDU_F_FIRST_MSDU_IN_MPDU)
			qdf_nbuf_set_rx_chfrag_start(rx_desc->nbuf, 1);

		if (msdu_desc_info.msdu_flags & HAL_MSDU_F_MSDU_CONTINUATION)
			qdf_nbuf_set_rx_chfrag_cont(rx_desc->nbuf, 1);

		if (msdu_desc_info.msdu_flags & HAL_MSDU_F_LAST_MSDU_IN_MPDU)
			qdf_nbuf_set_rx_chfrag_end(rx_desc->nbuf, 1);

		if (msdu_desc_info.msdu_flags & HAL_MSDU_F_DA_IS_MCBC)
			qdf_nbuf_set_da_mcbc(rx_desc->nbuf, 1);

		if (msdu_desc_info.msdu_flags & HAL_MSDU_F_DA_IS_VALID)
			qdf_nbuf_set_da_valid(rx_desc->nbuf, 1);

		if (msdu_desc_info.msdu_flags & HAL_MSDU_F_SA_IS_VALID)
			qdf_nbuf_set_sa_valid(rx_desc->nbuf, 1);

		qdf_nbuf_set_tid_val(rx_desc->nbuf,
				     HAL_RX_REO_QUEUE_NUMBER_GET(ring_desc));

		/* set reo dest indication */
		qdf_nbuf_set_rx_reo_dest_ind_or_sw_excpt(
				rx_desc->nbuf,
				HAL_RX_REO_MSDU_REO_DST_IND_GET(ring_desc));

		QDF_NBUF_CB_RX_PKT_LEN(rx_desc->nbuf) = msdu_desc_info.msdu_len;

		QDF_NBUF_CB_RX_CTX_ID(rx_desc->nbuf) = reo_ring_num;

		/*
		 * move unmap after scattered msdu waiting break logic
		 * in case double skb unmap happened.
		 */
#ifdef WLAN_FEATURE_OSRTP
		if (qdf_unlikely(rx_desc->xbuf)) {
			dp_rx_xbuf_umap(soc, rx_desc, reo_ring_num);
		} else
#endif
		dp_rx_nbuf_unmap(soc, rx_desc, reo_ring_num);
		rx_desc->unmapped = 1;
#ifdef WLAN_FEATURE_OSRTP
		/* xbuf must be linear */
		rcu_read_lock();
		xsk_pool = rcu_dereference(soc->osrtp_info.xsk_pool);
		rcu_read_unlock();

		rx_desc_pool = &soc->rx_desc_buf[rx_desc->pool_id];
		if (!xsk_pool || !soc->osrtp_info.in_use || qdf_nbuf_is_rx_chfrag_cont(rx_desc->nbuf)) {
			if (rx_desc->xbuf)
				dp_rx_buffers_xbuf_free(rx_desc->xbuf, rx_desc_pool->buf_size);
			DP_RX_PROCESS_NBUF(soc, nbuf_head, nbuf_tail, ebuf_head, ebuf_tail, rx_desc);
		} else {
			if (rx_desc->xbuf && (qdf_xbuf_is_pool_equal(rx_desc->xbuf, xsk_pool))) {
				DP_RX_XBUF_LIST_APPEND(xbuf_head, xbuf_tail, rx_desc->xbuf);
			} else {
				if (rx_desc->xbuf && (qdf_xbuf_is_pool_equal(rx_desc->xbuf, xsk_pool) == false))
					dp_rx_buffers_xbuf_free(rx_desc->xbuf, rx_desc_pool->buf_size);

				rx_desc->xbuf = dp_rx_buffer_pool_xbuf_alloc(soc, rx_desc->nbuf);
				if (rx_desc->xbuf) {
					rx_desc->xbuf->nbuf = rx_desc->nbuf;
					rx_desc->xbuf->pool_id = rx_desc->pool_id;
					qdf_mem_copy(rx_desc->xbuf->xdp->data, rx_desc->xbuf->orig_ndata, rx_desc_pool->buf_size);
					DP_RX_XBUF_LIST_APPEND(xbuf_head, xbuf_tail, rx_desc->xbuf);
				} else
					DP_RX_PROCESS_NBUF(soc, nbuf_head, nbuf_tail, ebuf_head, ebuf_tail, rx_desc);
			}
		}
#else
		DP_RX_PROCESS_NBUF(soc, nbuf_head, nbuf_tail, ebuf_head,
				   ebuf_tail, rx_desc);
#endif

		quota -= 1;
		num_pending -= 1;

		dp_rx_add_to_free_desc_list(&head[rx_desc->pool_id],
					    &tail[rx_desc->pool_id], rx_desc);
		num_rx_bufs_reaped++;

		dp_rx_prefetch_hw_sw_nbuf_desc(soc, hal_soc, num_pending,
					       hal_ring_hdl,
					       &last_prefetched_hw_desc,
					       &last_prefetched_sw_desc);

		/*
		 * only if complete msdu is received for scatter case,
		 * then allow break.
		 */
		if (is_prev_msdu_last &&
		    dp_rx_reap_loop_pkt_limit_hit(soc, num_rx_bufs_reaped,
						  max_reap_limit))
			break;
	}
done:
	dp_rx_srng_access_end(int_ctx, soc, hal_ring_hdl);

	dp_rx_per_core_stats_update(soc, reo_ring_num, num_rx_bufs_reaped);

	for (mac_id = 0; mac_id < MAX_PDEV_CNT; mac_id++) {
		/*
		 * continue with next mac_id if no pkts were reaped
		 * from that pool
		 */
		if (!rx_bufs_reaped[mac_id])
			continue;

		dp_rxdma_srng = &soc->rx_refill_buf_ring[mac_id];

		rx_desc_pool = &soc->rx_desc_buf[mac_id];

		dp_rx_buffers_replenish_simple(soc, mac_id, dp_rxdma_srng,
					       rx_desc_pool,
					       rx_bufs_reaped[mac_id],
					       &head[mac_id], &tail[mac_id]);
	}

	dp_verbose_debug("replenished %u", rx_bufs_reaped[0]);
	/* Peer can be NULL is case of LFR */
	if (qdf_likely(txrx_peer))
		vdev = NULL;

#ifdef WLAN_FEATURE_OSRTP
	xbuf = xbuf_head;
	while (xbuf) {
		xnext = xbuf->next;
		dp_rx_prefetch_nbuf_data(xbuf->nbuf, xnext ? xnext->nbuf : NULL);
		
		rx_tlv_hdr = xbuf->xdp->data;
		vdev_id = QDF_NBUF_CB_RX_VDEV_ID(xbuf->nbuf);
		peer_id =  QDF_NBUF_CB_RX_PEER_ID(xbuf->nbuf);

		hal_rx_msdu_metadata_get(hal_soc, rx_tlv_hdr, &msdu_metadata);
		xbuf->msdu_len = QDF_NBUF_CB_RX_PKT_LEN(xbuf->nbuf);
		xbuf->pkt_len = xbuf->msdu_len + msdu_metadata.l3_hdr_pad + soc->rx_pkt_tlv_size;

		if (dp_rx_is_xbuf_list_ready(deliver_xlist_head, vdev, txrx_peer, peer_id, vdev_id)) {
			dp_rx_deliver_osrtp_to_stack(soc, vdev, txrx_peer, deliver_xlist_head, deliver_xlist_tail, &nbuf_list);
			deliver_xlist_head = NULL;
			deliver_xlist_tail = NULL;
		}

		if (qdf_unlikely(!txrx_peer)) {
			txrx_peer = dp_rx_get_txrx_peer_and_vdev(soc, nbuf, peer_id,
						     &txrx_ref_handle,
						     pkt_capture_offload,
						     &vdev,
						     &rx_pdev, &dsf,
						     &old_tid);
		} else if (txrx_peer && txrx_peer->peer_id != peer_id) {
			dp_txrx_peer_unref_delete(txrx_ref_handle, DP_MOD_ID_RX);

			txrx_peer = dp_rx_get_txrx_peer_and_vdev(soc, nbuf, peer_id,
						     &txrx_ref_handle,
						     pkt_capture_offload,
						     &vdev,
						     &rx_pdev, &dsf,
						     &old_tid);
		}

		if (qdf_unlikely(!txrx_peer || !vdev)) {
			DP_RX_XBUF_PROCESS_NBUF(soc, nbuf_head, nbuf_tail, ebuf_head, ebuf_tail, xbuf);
			dp_rx_buffers_xbuf_free(xbuf, xbuf->pkt_len);
			xbuf = xnext;
			continue;
		}

		DP_RX_XBUF_LIST_APPEND(deliver_xlist_head, deliver_xlist_tail, xbuf);
		xbuf = xnext;
	}

	if (qdf_likely(deliver_xlist_head)) {
		if (qdf_likely(txrx_peer)) {
			dp_rx_deliver_osrtp_to_stack(soc, vdev, txrx_peer, deliver_xlist_head, deliver_xlist_tail, &nbuf_list);
		} else {
			xbuf = deliver_xlist_head;
			while (xbuf) {
				xnext = xbuf->next;
				xbuf->next = NULL;
				DP_RX_XBUF_PROCESS_NBUF(soc, nbuf_head, nbuf_tail, ebuf_head, ebuf_tail, xbuf);
				dp_rx_buffers_xbuf_free(xbuf, xbuf->pkt_len);
				xbuf = xnext;
			}
		}
	}

	if (qdf_likely(txrx_peer))
		dp_peer_unref_delete(txrx_peer, DP_MOD_ID_RX);

	txrx_peer = NULL;
	vdev = NULL;
	peer_id = 0;
	vdev_id = 0;
#endif

	/*
	 * BIG loop where each nbuf is dequeued from global queue,
	 * processed and queued back on a per vdev basis. These nbufs
	 * are sent to stack as and when we run out of nbufs
	 * or a new nbuf dequeued from global queue has a different
	 * vdev when compared to previous nbuf.
	 */
	nbuf = nbuf_head;
	while (nbuf) {
		next = nbuf->next;
		dp_rx_prefetch_nbuf_data(nbuf, next);

		if (qdf_unlikely(dp_rx_is_raw_frame_dropped(nbuf))) {
			nbuf = next;
			DP_STATS_INC(soc, rx.err.raw_frm_drop, 1);
			continue;
		}

		rx_tlv_hdr = qdf_nbuf_data(nbuf);
		vdev_id = QDF_NBUF_CB_RX_VDEV_ID(nbuf);
		peer_id =  QDF_NBUF_CB_RX_PEER_ID(nbuf);

		if (dp_rx_is_list_ready(deliver_list_head, vdev, txrx_peer,
					peer_id, vdev_id)) {
			dp_rx_deliver_to_stack(soc, vdev, txrx_peer,
					       deliver_list_head,
					       deliver_list_tail);
			deliver_list_head = NULL;
			deliver_list_tail = NULL;
		}

		/* Get TID from struct cb->tid_val, save to tid */
		if (qdf_nbuf_is_rx_chfrag_start(nbuf))
			tid = qdf_nbuf_get_tid_val(nbuf);

		if (qdf_unlikely(tid >= CDP_MAX_DATA_TIDS)) {
			DP_STATS_INC(soc, rx.err.rx_invalid_tid_err, 1);
			dp_rx_nbuf_free(nbuf);
			nbuf = next;
			continue;
		}

		if (qdf_unlikely(!txrx_peer)) {
			txrx_peer =
			dp_rx_get_txrx_peer_and_vdev(soc, nbuf, peer_id,
						     &txrx_ref_handle,
						     pkt_capture_offload,
						     &vdev,
						     &rx_pdev, &dsf,
						     &old_tid);
			if (qdf_unlikely(!txrx_peer) || qdf_unlikely(!vdev)) {
				nbuf = next;
				continue;
			}
		} else if (txrx_peer && txrx_peer->peer_id != peer_id) {
			dp_txrx_peer_unref_delete(txrx_ref_handle,
						  DP_MOD_ID_RX);

			txrx_peer =
			dp_rx_get_txrx_peer_and_vdev(soc, nbuf, peer_id,
						     &txrx_ref_handle,
						     pkt_capture_offload,
						     &vdev,
						     &rx_pdev, &dsf,
						     &old_tid);
			if (qdf_unlikely(!txrx_peer) || qdf_unlikely(!vdev)) {
				nbuf = next;
				continue;
			}
		}

		if (txrx_peer) {
			QDF_NBUF_CB_DP_TRACE_PRINT(nbuf) = false;
			qdf_dp_trace_set_track(nbuf, QDF_RX);
			QDF_NBUF_CB_RX_DP_TRACE(nbuf) = 1;
			QDF_NBUF_CB_RX_PACKET_TRACK(nbuf) =
				QDF_NBUF_RX_PKT_DATA_TRACK;
		}

		rx_bufs_used++;

		/* when hlos tid override is enabled, save tid in
		 * skb->priority
		 */
		if (qdf_unlikely(vdev->skip_sw_tid_classification &
					DP_TXRX_HLOS_TID_OVERRIDE_ENABLED))
			qdf_nbuf_set_priority(nbuf, tid);

		DP_RX_TID_SAVE(nbuf, tid);
		if (qdf_unlikely(dsf) || qdf_unlikely(peer_ext_stats) ||
		    dp_rx_pkt_tracepoints_enabled())
			qdf_nbuf_set_timestamp(nbuf);

		if (qdf_likely(old_tid != tid)) {
			tid_stats =
		&rx_pdev->stats.tid_stats.tid_rx_stats[reo_ring_num][tid];
			old_tid = tid;
		}

		/*
		 * Check if DMA completed -- msdu_done is the last bit
		 * to be written
		 */
		if (qdf_likely(!qdf_nbuf_is_rx_chfrag_cont(nbuf))) {
			if (qdf_unlikely(!hal_rx_attn_msdu_done_get_li(
								 rx_tlv_hdr))) {
				dp_err_rl("MSDU DONE failure");
				DP_STATS_INC(soc, rx.err.msdu_done_fail, 1);
				hal_rx_dump_pkt_tlvs(hal_soc, rx_tlv_hdr,
						     QDF_TRACE_LEVEL_INFO);
				tid_stats->fail_cnt[MSDU_DONE_FAILURE]++;
				qdf_assert(0);
				dp_rx_nbuf_free(nbuf);
				nbuf = next;
				continue;
			} else if (qdf_unlikely(hal_rx_attn_msdu_len_err_get_li(
								 rx_tlv_hdr))) {
				DP_STATS_INC(soc, rx.err.msdu_len_err, 1);
				dp_rx_nbuf_free(nbuf);
				nbuf = next;
				continue;
			}
		}

		DP_HIST_PACKET_COUNT_INC(vdev->pdev->pdev_id);
		/*
		 * First IF condition:
		 * 802.11 Fragmented pkts are reinjected to REO
		 * HW block as SG pkts and for these pkts we only
		 * need to pull the RX TLVS header length.
		 * Second IF condition:
		 * The below condition happens when an MSDU is spread
		 * across multiple buffers. This can happen in two cases
		 * 1. The nbuf size is smaller then the received msdu.
		 *    ex: we have set the nbuf size to 2048 during
		 *        nbuf_alloc. but we received an msdu which is
		 *        2304 bytes in size then this msdu is spread
		 *        across 2 nbufs.
		 *
		 * 2. AMSDUs when RAW mode is enabled.
		 *    ex: 1st MSDU is in 1st nbuf and 2nd MSDU is spread
		 *        across 1st nbuf and 2nd nbuf and last MSDU is
		 *        spread across 2nd nbuf and 3rd nbuf.
		 *
		 * for these scenarios let us create a skb frag_list and
		 * append these buffers till the last MSDU of the AMSDU
		 * Third condition:
		 * This is the most likely case, we receive 802.3 pkts
		 * decapsulated by HW, here we need to set the pkt length.
		 */
		hal_rx_msdu_metadata_get(hal_soc, rx_tlv_hdr, &msdu_metadata);
		if (qdf_unlikely(qdf_nbuf_is_frag(nbuf))) {
			bool is_mcbc, is_sa_vld, is_da_vld;

			is_mcbc = hal_rx_msdu_end_da_is_mcbc_get(soc->hal_soc,
								 rx_tlv_hdr);
			is_sa_vld =
				hal_rx_msdu_end_sa_is_valid_get(soc->hal_soc,
								rx_tlv_hdr);
			is_da_vld =
				hal_rx_msdu_end_da_is_valid_get(soc->hal_soc,
								rx_tlv_hdr);

			qdf_nbuf_set_da_mcbc(nbuf, is_mcbc);
			qdf_nbuf_set_da_valid(nbuf, is_da_vld);
			qdf_nbuf_set_sa_valid(nbuf, is_sa_vld);

			qdf_nbuf_pull_head(nbuf, soc->rx_pkt_tlv_size);
		} else if (qdf_nbuf_is_rx_chfrag_cont(nbuf)) {
			msdu_len = QDF_NBUF_CB_RX_PKT_LEN(nbuf);
			nbuf = dp_rx_sg_create(soc, nbuf);
			next = nbuf->next;

			if (qdf_nbuf_is_raw_frame(nbuf)) {
				DP_STATS_INC(vdev->pdev, rx_raw_pkts, 1);
				DP_PEER_PER_PKT_STATS_INC_PKT(txrx_peer,
							      rx.raw, 1,
							      msdu_len,
							      0);
			} else {
				DP_STATS_INC(soc, rx.err.scatter_msdu, 1);

				if (!dp_rx_is_sg_supported()) {
					dp_rx_nbuf_free(nbuf);
					dp_info_rl("sg msdu len %d, dropped",
						   msdu_len);
					nbuf = next;
					continue;
				}
			}
		} else {
			msdu_len = QDF_NBUF_CB_RX_PKT_LEN(nbuf);
			pkt_len = msdu_len +
				  msdu_metadata.l3_hdr_pad +
				  soc->rx_pkt_tlv_size;

			qdf_nbuf_set_pktlen(nbuf, pkt_len);
			dp_rx_skip_tlvs(soc, nbuf, msdu_metadata.l3_hdr_pad);
		}

		dp_rx_send_pktlog(soc, rx_pdev, nbuf, QDF_TX_RX_STATUS_OK);

		/*
		 * process frame for mulitpass phrase processing
		 */
		if (qdf_unlikely(vdev->multipass_en)) {
			if (dp_rx_multipass_process(txrx_peer, nbuf,
						    tid) == false) {
				DP_PEER_PER_PKT_STATS_INC(txrx_peer,
							  rx.multipass_rx_pkt_drop,
							  1, 0);
				dp_rx_nbuf_free(nbuf);
				nbuf = next;
				continue;
			}
		}

		if (!dp_wds_rx_policy_check(rx_tlv_hdr, vdev, txrx_peer)) {
			dp_rx_err("%pK: Policy Check Drop pkt", soc);
			DP_PEER_PER_PKT_STATS_INC(txrx_peer,
						  rx.policy_check_drop,
						  1, 0);
			tid_stats->fail_cnt[POLICY_CHECK_DROP]++;
			/* Drop & free packet */
			dp_rx_nbuf_free(nbuf);
			/* Statistics */
			nbuf = next;
			continue;
		}

		if (qdf_unlikely(txrx_peer && (txrx_peer->nawds_enabled) &&
				 (qdf_nbuf_is_da_mcbc(nbuf)) &&
				 (hal_rx_get_mpdu_mac_ad4_valid(soc->hal_soc,
								rx_tlv_hdr) ==
				  false))) {
			tid_stats->fail_cnt[NAWDS_MCAST_DROP]++;
			DP_PEER_PER_PKT_STATS_INC(txrx_peer,
						  rx.nawds_mcast_drop,
						  1, 0);
			dp_rx_nbuf_free(nbuf);
			nbuf = next;
			continue;
		}

		/*
		 * Drop non-EAPOL frames from unauthorized peer.
		 */
		if (qdf_likely(txrx_peer) &&
		    qdf_unlikely(!txrx_peer->authorize) &&
		    !qdf_nbuf_is_raw_frame(nbuf)) {
			bool is_eapol = qdf_nbuf_is_ipv4_eapol_pkt(nbuf) ||
					qdf_nbuf_is_ipv4_wapi_pkt(nbuf);

			if (!is_eapol) {
				DP_PEER_PER_PKT_STATS_INC(txrx_peer,
							  rx.peer_unauth_rx_pkt_drop,
							  1, 0);
				dp_rx_nbuf_free(nbuf);
				nbuf = next;
				continue;
			}
		}

		if (soc->process_rx_status)
			dp_rx_cksum_offload(vdev->pdev, nbuf, rx_tlv_hdr);

		/* Update the protocol tag in SKB based on CCE metadata */
		dp_rx_update_protocol_tag(soc, vdev, nbuf, rx_tlv_hdr,
					  reo_ring_num, false, true);

		/* Update the flow tag in SKB based on FSE metadata */
		dp_rx_update_flow_tag(soc, vdev, nbuf, rx_tlv_hdr, true);

		dp_rx_msdu_stats_update(soc, nbuf, rx_tlv_hdr, txrx_peer,
					reo_ring_num, tid_stats, 0);

		if (qdf_unlikely(vdev->mesh_vdev)) {
			if (dp_rx_filter_mesh_packets(vdev, nbuf, rx_tlv_hdr)
					== QDF_STATUS_SUCCESS) {
				dp_rx_info("%pK: mesh pkt filtered", soc);
				tid_stats->fail_cnt[MESH_FILTER_DROP]++;
				DP_STATS_INC(vdev->pdev, dropped.mesh_filter,
					     1);

				dp_rx_nbuf_free(nbuf);
				nbuf = next;
				continue;
			}
			dp_rx_fill_mesh_stats(vdev, nbuf, rx_tlv_hdr,
					      txrx_peer);
		}

		if (qdf_likely(vdev->rx_decap_type ==
			       htt_cmn_pkt_type_ethernet) &&
		    qdf_likely(!vdev->mesh_vdev)) {
			/* Due to HW issue, sometimes we see that the sa_idx
			 * and da_idx are invalid with sa_valid and da_valid
			 * bits set
			 *
			 * in this case we also see that value of
			 * sa_sw_peer_id is set as 0
			 *
			 * Drop the packet if sa_idx and da_idx OOB or
			 * sa_sw_peerid is 0
			 */
			if (!is_sa_da_idx_valid(max_ast, nbuf,
						msdu_metadata)) {
				dp_rx_nbuf_free(nbuf);
				nbuf = next;
				DP_STATS_INC(soc, rx.err.invalid_sa_da_idx, 1);
				continue;
			}
			if (qdf_unlikely(dp_rx_mec_check_wrapper(soc,
								 txrx_peer,
								 rx_tlv_hdr,
								 nbuf))) {
				/* this is a looped back MCBC pkt,drop it */
				DP_PEER_PER_PKT_STATS_INC_PKT(txrx_peer,
							      rx.mec_drop, 1,
							      QDF_NBUF_CB_RX_PKT_LEN(nbuf),
							      0);
				dp_rx_nbuf_free(nbuf);
				nbuf = next;
				continue;
			}
			/* WDS Source Port Learning */
			if (qdf_likely(vdev->wds_enabled))
				dp_rx_wds_srcport_learn(soc,
							rx_tlv_hdr,
							txrx_peer,
							nbuf,
							msdu_metadata);

			/* Intrabss-fwd */
			if (dp_rx_check_ap_bridge(vdev))
				if (dp_rx_intrabss_fwd_li(soc, txrx_peer,
							  rx_tlv_hdr,
							  nbuf,
							  msdu_metadata,
							  tid_stats)) {
					nbuf = next;
					tid_stats->intrabss_cnt++;
					continue; /* Get next desc */
				}
		}

		dp_rx_fill_gro_info(soc, rx_tlv_hdr, nbuf, &rx_ol_pkt_cnt);

		dp_rx_mark_first_packet_after_wow_wakeup(vdev->pdev, rx_tlv_hdr,
							 nbuf);

		dp_rx_update_stats(soc, nbuf);

		dp_pkt_add_timestamp(txrx_peer->vdev, QDF_PKT_RX_DRIVER_ENTRY,
				     current_time, nbuf);

		DP_RX_LIST_APPEND(deliver_list_head,
				  deliver_list_tail,
				  nbuf);
		DP_PEER_STATS_FLAT_INC_PKT(txrx_peer, to_stack, 1,
					   QDF_NBUF_CB_RX_PKT_LEN(nbuf));
		DP_PEER_PER_PKT_STATS_INC_PKT(txrx_peer,
					      rx.rx_success, 1,
					      QDF_NBUF_CB_RX_PKT_LEN(nbuf), 0);
		if (qdf_unlikely(txrx_peer->in_twt))
			DP_PEER_PER_PKT_STATS_INC_PKT(txrx_peer,
						      rx.to_stack_twt, 1,
						      QDF_NBUF_CB_RX_PKT_LEN(nbuf),
						      0);

		tid_stats->delivered_to_stack++;
		nbuf = next;
	}

	DP_RX_DELIVER_TO_STACK(soc, vdev, txrx_peer, peer_id,
			       pkt_capture_offload,
			       deliver_list_head,
			       deliver_list_tail);

	if (qdf_likely(txrx_peer))
		dp_txrx_peer_unref_delete(txrx_ref_handle, DP_MOD_ID_RX);

	if (dp_rx_enable_eol_data_check(soc) && rx_bufs_used) {
		if (quota) {
			num_pending =
				dp_rx_srng_get_num_pending(hal_soc,
							   hal_ring_hdl,
							   num_entries,
							   &near_full);
			if (num_pending) {
				DP_STATS_INC(soc, rx.hp_oos2, 1);

				if (!hif_exec_should_yield(scn, intr_id))
					goto more_data;

				if (qdf_unlikely(near_full)) {
					DP_STATS_INC(soc, rx.near_full, 1);
					goto more_data;
				}
			}
		}

		if (vdev && vdev->osif_fisa_flush)
			vdev->osif_fisa_flush(soc, reo_ring_num);

		if (vdev && vdev->osif_gro_flush && rx_ol_pkt_cnt) {
			vdev->osif_gro_flush(vdev->osif_vdev,
					     reo_ring_num);
		}
	}

	/* Update histogram statistics by looping through pdev's */
	DP_RX_HIST_STATS_PER_PDEV();

	return rx_bufs_used; /* Assume no scale factor for now */
}

QDF_STATUS dp_rx_desc_pool_init_li(struct dp_soc *soc,
				   struct rx_desc_pool *rx_desc_pool,
				   uint32_t pool_id)
{
	return dp_rx_desc_pool_init_generic(soc, rx_desc_pool, pool_id);

}

void dp_rx_desc_pool_deinit_li(struct dp_soc *soc,
			       struct rx_desc_pool *rx_desc_pool,
			       uint32_t pool_id)
{
}

QDF_STATUS dp_wbm_get_rx_desc_from_hal_desc_li(
					struct dp_soc *soc,
					void *ring_desc,
					struct dp_rx_desc **r_rx_desc)
{
	struct hal_buf_info buf_info = {0};
	hal_soc_handle_t hal_soc = soc->hal_soc;

	/* only cookie and rbm will be valid in buf_info */
	hal_rx_buf_cookie_rbm_get(hal_soc, (uint32_t *)ring_desc,
				  &buf_info);

	if (qdf_unlikely(buf_info.rbm !=
				HAL_RX_BUF_RBM_SW3_BM(soc->wbm_sw0_bm_id))) {
		/* TODO */
		/* Call appropriate handler */
		DP_STATS_INC(soc, rx.err.invalid_rbm, 1);
		dp_rx_err("%pK: Invalid RBM %d", soc, buf_info.rbm);
		return QDF_STATUS_E_INVAL;
	}

	if (!dp_rx_is_sw_cookie_valid(soc, buf_info.sw_cookie)) {
		dp_rx_err("invalid sw_cookie 0x%x", buf_info.sw_cookie);
		return QDF_STATUS_E_INVAL;
	}

	*r_rx_desc = dp_rx_cookie_2_va_rxdma_buf(soc, buf_info.sw_cookie);

	return QDF_STATUS_SUCCESS;
}

bool dp_rx_chain_msdus_li(struct dp_soc *soc, qdf_nbuf_t nbuf,
			  uint8_t *rx_tlv_hdr, uint8_t mac_id)
{
	bool mpdu_done = false;
	qdf_nbuf_t curr_nbuf = NULL;
	qdf_nbuf_t tmp_nbuf = NULL;

	/* TODO: Currently only single radio is supported, hence
	 * pdev hard coded to '0' index
	 */
	struct dp_pdev *dp_pdev = dp_get_pdev_for_lmac_id(soc, mac_id);

	if (!dp_pdev) {
		dp_rx_debug("%pK: pdev is null for mac_id = %d", soc, mac_id);
		return mpdu_done;
	}
	/* if invalid peer SG list has max values free the buffers in list
	 * and treat current buffer as start of list
	 *
	 * current logic to detect the last buffer from attn_tlv is not reliable
	 * in OFDMA UL scenario hence add max buffers check to avoid list pile
	 * up
	 */
	if (!dp_pdev->first_nbuf ||
	    (dp_pdev->invalid_peer_head_msdu &&
	    QDF_NBUF_CB_RX_NUM_ELEMENTS_IN_LIST
	    (dp_pdev->invalid_peer_head_msdu) >= DP_MAX_INVALID_BUFFERS)) {
		qdf_nbuf_set_rx_chfrag_start(nbuf, 1);
		dp_pdev->ppdu_id = hal_rx_get_ppdu_id(soc->hal_soc,
						      rx_tlv_hdr);
		dp_pdev->first_nbuf = true;

		/* If the new nbuf received is the first msdu of the
		 * amsdu and there are msdus in the invalid peer msdu
		 * list, then let us free all the msdus of the invalid
		 * peer msdu list.
		 * This scenario can happen when we start receiving
		 * new a-msdu even before the previous a-msdu is completely
		 * received.
		 */
		curr_nbuf = dp_pdev->invalid_peer_head_msdu;
		while (curr_nbuf) {
			tmp_nbuf = curr_nbuf->next;
			dp_rx_nbuf_free(curr_nbuf);
			curr_nbuf = tmp_nbuf;
		}

		dp_pdev->invalid_peer_head_msdu = NULL;
		dp_pdev->invalid_peer_tail_msdu = NULL;

		dp_monitor_get_mpdu_status(dp_pdev, soc, rx_tlv_hdr);
	}

	if (dp_pdev->ppdu_id == hal_rx_attn_phy_ppdu_id_get(soc->hal_soc,
							    rx_tlv_hdr) &&
	    hal_rx_attn_msdu_done_get(soc->hal_soc, rx_tlv_hdr)) {
		qdf_nbuf_set_rx_chfrag_end(nbuf, 1);
		qdf_assert_always(dp_pdev->first_nbuf);
		dp_pdev->first_nbuf = false;
		mpdu_done = true;
	}

	/*
	 * For MCL, invalid_peer_head_msdu and invalid_peer_tail_msdu
	 * should be NULL here, add the checking for debugging purpose
	 * in case some corner case.
	 */
	DP_PDEV_INVALID_PEER_MSDU_CHECK(dp_pdev->invalid_peer_head_msdu,
					dp_pdev->invalid_peer_tail_msdu);
	DP_RX_LIST_APPEND(dp_pdev->invalid_peer_head_msdu,
			  dp_pdev->invalid_peer_tail_msdu,
			  nbuf);

	return mpdu_done;
}

static struct dp_soc *dp_rx_replensih_soc_get_li(struct dp_soc *soc,
						 uint8_t chip_id)
{
	return soc;
}

qdf_nbuf_t
dp_rx_wbm_err_reap_desc_li(struct dp_intr *int_ctx, struct dp_soc *soc,
			   hal_ring_handle_t hal_ring_hdl, uint32_t quota,
			   uint32_t *rx_bufs_used)
{
	hal_ring_desc_t ring_desc;
	hal_soc_handle_t hal_soc;
	struct dp_rx_desc *rx_desc;
	union dp_rx_desc_list_elem_t *head[MAX_PDEV_CNT] = { NULL };
	union dp_rx_desc_list_elem_t *tail[MAX_PDEV_CNT] = { NULL };
	uint32_t rx_bufs_reaped[MAX_PDEV_CNT] = { 0 };
	uint8_t buf_type;
	uint8_t mac_id;
	struct dp_srng *dp_rxdma_srng;
	struct rx_desc_pool *rx_desc_pool;
	qdf_nbuf_t nbuf_head = NULL;
	qdf_nbuf_t nbuf_tail = NULL;
	qdf_nbuf_t nbuf;
	union hal_wbm_err_info_u wbm_err_info = { 0 };
	uint8_t msdu_continuation = 0;
	bool process_sg_buf = false;
	uint32_t wbm_err_src;
	QDF_STATUS status;
	struct dp_soc *replenish_soc;
	uint8_t chip_id = 0;
	struct hal_rx_mpdu_desc_info mpdu_desc_info = { 0 };
	uint8_t *rx_tlv_hdr;
	uint32_t peer_mdata;

	qdf_assert(soc && hal_ring_hdl);
	hal_soc = soc->hal_soc;
	qdf_assert(hal_soc);

	if (qdf_unlikely(dp_srng_access_start(int_ctx, soc, hal_ring_hdl))) {
		/* TODO */
		/*
		 * Need API to convert from hal_ring pointer to
		 * Ring Type / Ring Id combo
		 */
		dp_rx_err_err("%pK: HAL RING Access Failed -- %pK",
			      soc, hal_ring_hdl);
		goto done;
	}

	while (qdf_likely(quota)) {
		ring_desc = hal_srng_dst_get_next(hal_soc, hal_ring_hdl);
		if (qdf_unlikely(!ring_desc))
			break;

		/* XXX */
		buf_type = HAL_RX_WBM_BUF_TYPE_GET(ring_desc);

		if (dp_assert_always_internal_stat(
				buf_type == HAL_RX_WBM_BUF_TYPE_REL_BUF,
				soc, rx.err.wbm_err_buf_rel_type))
			continue;

		wbm_err_src = hal_rx_wbm_err_src_get(hal_soc, ring_desc);
		qdf_assert((wbm_err_src == HAL_RX_WBM_ERR_SRC_RXDMA) ||
			   (wbm_err_src == HAL_RX_WBM_ERR_SRC_REO));

		if (soc->arch_ops.dp_wbm_get_rx_desc_from_hal_desc(soc,
								   ring_desc,
								   &rx_desc)) {
			dp_rx_err_err("get rx desc from hal_desc failed");
			continue;
		}

		if (dp_assert_always_internal_stat(rx_desc, soc,
						   rx.err.rx_desc_null))
			continue;

		if (!dp_rx_desc_check_magic(rx_desc)) {
			dp_rx_err_err("%pk: Invalid rx_desc %pk",
				      soc, rx_desc);
			continue;
		}

		/*
		 * this is a unlikely scenario where the host is reaping
		 * a descriptor which it already reaped just a while ago
		 * but is yet to replenish it back to HW.
		 * In this case host will dump the last 128 descriptors
		 * including the software descriptor rx_desc and assert.
		 */
		if (qdf_unlikely(!rx_desc->in_use)) {
			DP_STATS_INC(soc, rx.err.hal_wbm_rel_dup, 1);
			dp_rx_dump_info_and_assert(soc, hal_ring_hdl,
						   ring_desc, rx_desc);
			continue;
		}

		hal_rx_wbm_err_info_get(ring_desc, &wbm_err_info.info_bit,
					hal_soc);
		nbuf = rx_desc->nbuf;

		status = dp_rx_wbm_desc_nbuf_sanity_check(soc, hal_ring_hdl,
							  ring_desc, rx_desc);
		if (qdf_unlikely(QDF_IS_STATUS_ERROR(status))) {
			DP_STATS_INC(soc, rx.err.nbuf_sanity_fail, 1);
			dp_info_rl("Rx error Nbuf %pk sanity check failure!",
				   nbuf);
			rx_desc->in_err_state = 1;
			rx_desc->unmapped = 1;
			rx_bufs_reaped[rx_desc->pool_id]++;

			dp_rx_add_to_free_desc_list(
				&head[rx_desc->pool_id],
				&tail[rx_desc->pool_id],
				rx_desc);
			continue;
		}

		/* Update peer_id in nbuf cb */
		rx_tlv_hdr = qdf_nbuf_data(nbuf);
		peer_mdata = hal_rx_tlv_peer_meta_data_get(soc->hal_soc,
							   rx_tlv_hdr);
		QDF_NBUF_CB_RX_PEER_ID(rx_desc->nbuf) =
			dp_rx_peer_metadata_peer_id_get(soc, peer_mdata);

		/* Get MPDU DESC info */
		hal_rx_mpdu_desc_info_get(hal_soc, ring_desc, &mpdu_desc_info);

		if (qdf_likely(mpdu_desc_info.mpdu_flags &
			       HAL_MPDU_F_QOS_CONTROL_VALID))
			qdf_nbuf_set_tid_val(rx_desc->nbuf, mpdu_desc_info.tid);

		rx_desc_pool = &soc->rx_desc_buf[rx_desc->pool_id];
		dp_ipa_rx_buf_smmu_mapping_lock(soc);
		dp_rx_nbuf_unmap_pool(soc, rx_desc_pool, nbuf);
		rx_desc->unmapped = 1;
		dp_ipa_rx_buf_smmu_mapping_unlock(soc);

		if (qdf_unlikely(
		    soc->wbm_release_desc_rx_sg_support &&
		    dp_rx_is_sg_formation_required(&wbm_err_info.info_bit))) {
			/* SG is detected from continuation bit */
			msdu_continuation =
				hal_rx_wbm_err_msdu_continuation_get(hal_soc,
								     ring_desc);
			if (msdu_continuation &&
			    !(soc->wbm_sg_param.wbm_is_first_msdu_in_sg)) {
				/* Update length from first buffer in SG */
				soc->wbm_sg_param.wbm_sg_desc_msdu_len =
					hal_rx_msdu_start_msdu_len_get(
						soc->hal_soc,
						qdf_nbuf_data(nbuf));
				soc->wbm_sg_param.wbm_is_first_msdu_in_sg =
									true;
			}

			if (msdu_continuation) {
				/* MSDU continued packets */
				qdf_nbuf_set_rx_chfrag_cont(nbuf, 1);
				QDF_NBUF_CB_RX_PKT_LEN(nbuf) =
					soc->wbm_sg_param.wbm_sg_desc_msdu_len;
			} else {
				/* This is the terminal packet in SG */
				qdf_nbuf_set_rx_chfrag_start(nbuf, 1);
				qdf_nbuf_set_rx_chfrag_end(nbuf, 1);
				QDF_NBUF_CB_RX_PKT_LEN(nbuf) =
					soc->wbm_sg_param.wbm_sg_desc_msdu_len;
				process_sg_buf = true;
			}
		}

		/*
		 * save the wbm desc info in nbuf CB/TLV. We will need this
		 * info when we do the actual nbuf processing
		 */
		wbm_err_info.info_bit.pool_id = rx_desc->pool_id;
		dp_rx_set_wbm_err_info_in_nbuf(soc, nbuf, wbm_err_info);

		rx_bufs_reaped[rx_desc->pool_id]++;

		if (qdf_nbuf_is_rx_chfrag_cont(nbuf) || process_sg_buf) {
			DP_RX_LIST_APPEND(soc->wbm_sg_param.wbm_sg_nbuf_head,
					  soc->wbm_sg_param.wbm_sg_nbuf_tail,
					  nbuf);
			if (process_sg_buf) {
				if (!dp_rx_buffer_pool_refill(
					soc,
					soc->wbm_sg_param.wbm_sg_nbuf_head,
					rx_desc->pool_id))
					DP_RX_MERGE_TWO_LIST(
					  nbuf_head, nbuf_tail,
					  soc->wbm_sg_param.wbm_sg_nbuf_head,
					  soc->wbm_sg_param.wbm_sg_nbuf_tail);
				dp_rx_wbm_sg_list_last_msdu_war(soc);
				dp_rx_wbm_sg_list_reset(soc);
				process_sg_buf = false;
			}
		} else if (!dp_rx_buffer_pool_refill(soc, nbuf,
						     rx_desc->pool_id)) {
			DP_RX_LIST_APPEND(nbuf_head, nbuf_tail, nbuf);
		}

		dp_rx_add_to_free_desc_list
			(&head[rx_desc->pool_id],
			 &tail[rx_desc->pool_id], rx_desc);

		/*
		 * if continuation bit is set then we have MSDU spread
		 * across multiple buffers, let us not decrement quota
		 * till we reap all buffers of that MSDU.
		 */
		if (qdf_likely(!msdu_continuation))
			quota -= 1;
	}
done:
	dp_srng_access_end(int_ctx, soc, hal_ring_hdl);

	for (mac_id = 0; mac_id < MAX_PDEV_CNT; mac_id++) {
		/*
		 * continue with next mac_id if no pkts were reaped
		 * from that pool
		 */
		if (!rx_bufs_reaped[mac_id])
			continue;

		replenish_soc =
		dp_rx_replensih_soc_get_li(soc, chip_id);
		dp_rxdma_srng =
			&replenish_soc->rx_refill_buf_ring[mac_id];

		rx_desc_pool = &replenish_soc->rx_desc_buf[mac_id];

		dp_rx_buffers_replenish_simple(
					replenish_soc, mac_id,
					dp_rxdma_srng,
					rx_desc_pool,
					rx_bufs_reaped[mac_id],
					&head[mac_id],
					&tail[mac_id]);
		*rx_bufs_used += rx_bufs_reaped[mac_id];
	}
	return nbuf_head;
}

QDF_STATUS
dp_rx_null_q_desc_handle_li(struct dp_soc *soc, qdf_nbuf_t nbuf,
			    uint8_t *rx_tlv_hdr, uint8_t pool_id,
			    struct dp_txrx_peer *txrx_peer,
			    bool is_reo_exception,
			    uint8_t link_id)
{
	uint32_t pkt_len;
	uint16_t msdu_len;
	struct dp_vdev *vdev;
	uint8_t tid;
	qdf_ether_header_t *eh;
	struct hal_rx_msdu_metadata msdu_metadata;
	uint16_t sa_idx = 0;
	bool is_eapol = 0;
	bool enh_flag;

	qdf_nbuf_set_rx_chfrag_start(
				nbuf,
				hal_rx_msdu_end_first_msdu_get(soc->hal_soc,
							       rx_tlv_hdr));
	qdf_nbuf_set_rx_chfrag_end(nbuf,
				   hal_rx_msdu_end_last_msdu_get(soc->hal_soc,
								 rx_tlv_hdr));
	qdf_nbuf_set_da_mcbc(nbuf, hal_rx_msdu_end_da_is_mcbc_get(soc->hal_soc,
								  rx_tlv_hdr));
	qdf_nbuf_set_da_valid(nbuf,
			      hal_rx_msdu_end_da_is_valid_get(soc->hal_soc,
							      rx_tlv_hdr));
	qdf_nbuf_set_sa_valid(nbuf,
			      hal_rx_msdu_end_sa_is_valid_get(soc->hal_soc,
							      rx_tlv_hdr));

	tid = hal_rx_tid_get(soc->hal_soc, rx_tlv_hdr);
	hal_rx_msdu_metadata_get(soc->hal_soc, rx_tlv_hdr, &msdu_metadata);
	msdu_len = hal_rx_msdu_start_msdu_len_get(soc->hal_soc, rx_tlv_hdr);
	pkt_len = msdu_len + msdu_metadata.l3_hdr_pad + soc->rx_pkt_tlv_size;

	if (qdf_likely(!qdf_nbuf_is_frag(nbuf))) {
		if (dp_rx_check_pkt_len(soc, pkt_len))
			goto drop_nbuf;

		/* Set length in nbuf */
		qdf_nbuf_set_pktlen(
			nbuf, qdf_min(pkt_len, (uint32_t)RX_DATA_BUFFER_SIZE));
	}

	/*
	 * Check if DMA completed -- msdu_done is the last bit
	 * to be written
	 */
	if (!hal_rx_attn_msdu_done_get(soc->hal_soc, rx_tlv_hdr)) {
		dp_err_rl("MSDU DONE failure");
		hal_rx_dump_pkt_tlvs(soc->hal_soc, rx_tlv_hdr,
				     QDF_TRACE_LEVEL_INFO);
		qdf_assert(0);
	}

	if (!txrx_peer &&
	    dp_rx_null_q_handle_invalid_peer_id_exception(soc, pool_id,
							  rx_tlv_hdr, nbuf))
		return QDF_STATUS_E_FAILURE;

	if (!txrx_peer) {
		bool mpdu_done = false;
		struct dp_pdev *pdev = dp_get_pdev_for_lmac_id(soc, pool_id);

		if (!pdev) {
			dp_err_rl("pdev is null for pool_id = %d", pool_id);
			return QDF_STATUS_E_FAILURE;
		}

		dp_err_rl("txrx_peer is NULL");
		DP_STATS_INC_PKT(soc, rx.err.rx_invalid_peer, 1,
				 qdf_nbuf_len(nbuf));

		/* QCN9000 has the support enabled */
		if (qdf_unlikely(soc->wbm_release_desc_rx_sg_support)) {
			mpdu_done = true;
			nbuf->next = NULL;
			/* Trigger invalid peer handler wrapper */
			dp_rx_process_invalid_peer_wrapper(soc,
							   nbuf,
							   mpdu_done,
							   pool_id);
		} else {
			mpdu_done = soc->arch_ops.dp_rx_chain_msdus(soc, nbuf,
								    rx_tlv_hdr,
								    pool_id);
			/* Trigger invalid peer handler wrapper */
			dp_rx_process_invalid_peer_wrapper(
					soc,
					pdev->invalid_peer_head_msdu,
					mpdu_done, pool_id);
		}

		if (mpdu_done) {
			pdev->invalid_peer_head_msdu = NULL;
			pdev->invalid_peer_tail_msdu = NULL;
		}

		return QDF_STATUS_E_FAILURE;
	}

	vdev = txrx_peer->vdev;
	if (!vdev) {
		dp_err_rl("Null vdev!");
		DP_STATS_INC(soc, rx.err.invalid_vdev, 1);
		goto drop_nbuf;
	}

	/*
	 * Advance the packet start pointer by total size of
	 * pre-header TLV's
	 */
	if (qdf_nbuf_is_frag(nbuf))
		qdf_nbuf_pull_head(nbuf, soc->rx_pkt_tlv_size);
	else
		qdf_nbuf_pull_head(nbuf, (msdu_metadata.l3_hdr_pad +
				   soc->rx_pkt_tlv_size));

	DP_STATS_INC_PKT(vdev, rx_i.null_q_desc_pkt, 1, qdf_nbuf_len(nbuf));

	dp_vdev_peer_stats_update_protocol_cnt(vdev, nbuf, NULL, 0, 1);

	if (dp_rx_err_drop_3addr_mcast(vdev, rx_tlv_hdr)) {
		DP_PEER_PER_PKT_STATS_INC(txrx_peer, rx.mcast_3addr_drop, 1,
					  0);
		goto drop_nbuf;
	}

	if (hal_rx_msdu_end_sa_is_valid_get(soc->hal_soc, rx_tlv_hdr)) {
		sa_idx = hal_rx_msdu_end_sa_idx_get(soc->hal_soc, rx_tlv_hdr);

		if ((sa_idx < 0) ||
		    (sa_idx >= wlan_cfg_get_max_ast_idx(soc->wlan_cfg_ctx))) {
			DP_STATS_INC(soc, rx.err.invalid_sa_da_idx, 1);
			goto drop_nbuf;
		}
	}

	if ((!soc->mec_fw_offload) &&
	    dp_rx_mcast_echo_check(soc, txrx_peer, rx_tlv_hdr, nbuf)) {
		/* this is a looped back MCBC pkt, drop it */
		DP_PEER_PER_PKT_STATS_INC_PKT(txrx_peer, rx.mec_drop, 1,
					      qdf_nbuf_len(nbuf), 0);
		goto drop_nbuf;
	}

	/*
	 * In qwrap mode if the received packet matches with any of the vdev
	 * mac addresses, drop it. Donot receive multicast packets originated
	 * from any proxysta.
	 */
	if (check_qwrap_multicast_loopback(vdev, nbuf)) {
		DP_PEER_PER_PKT_STATS_INC_PKT(txrx_peer, rx.mec_drop, 1,
					      qdf_nbuf_len(nbuf), 0);
		goto drop_nbuf;
	}

	if (qdf_unlikely(txrx_peer->nawds_enabled &&
			 hal_rx_msdu_end_da_is_mcbc_get(soc->hal_soc,
							rx_tlv_hdr))) {
		dp_err_rl("free buffer for multicast packet");
		DP_PEER_PER_PKT_STATS_INC(txrx_peer, rx.nawds_mcast_drop, 1,
					  0);
		goto drop_nbuf;
	}

	if (!dp_wds_rx_policy_check(rx_tlv_hdr, vdev, txrx_peer)) {
		dp_err_rl("mcast Policy Check Drop pkt");
		DP_PEER_PER_PKT_STATS_INC(txrx_peer, rx.policy_check_drop, 1,
					  0);
		goto drop_nbuf;
	}
	/* WDS Source Port Learning */
	if (!soc->ast_offload_support &&
	    qdf_likely(vdev->rx_decap_type == htt_cmn_pkt_type_ethernet &&
		       vdev->wds_enabled))
		dp_rx_wds_srcport_learn(soc, rx_tlv_hdr, txrx_peer, nbuf,
					msdu_metadata);

	if (hal_rx_is_unicast(soc->hal_soc, rx_tlv_hdr)) {
		struct dp_peer *peer;
		struct dp_rx_tid *rx_tid;

		peer = dp_peer_get_ref_by_id(soc, txrx_peer->peer_id,
					     DP_MOD_ID_RX_ERR);
		if (peer) {
			rx_tid = &peer->rx_tid[tid];
			qdf_spin_lock_bh(&rx_tid->tid_lock);
			if (!peer->rx_tid[tid].hw_qdesc_vaddr_unaligned) {
			/* For Mesh peer, if on one of the mesh AP the
			 * mesh peer is not deleted, the new addition of mesh
			 * peer on other mesh AP doesn't do BA negotiation
			 * leading to mismatch in BA windows.
			 * To avoid this send max BA window during init.
			 */
				if (qdf_unlikely(vdev->mesh_vdev) ||
				    qdf_unlikely(txrx_peer->nawds_enabled))
					dp_rx_tid_setup_wifi3(
						peer, tid,
						hal_get_rx_max_ba_window(soc->hal_soc,tid),
						IEEE80211_SEQ_MAX);
				else
					dp_rx_tid_setup_wifi3(peer, tid, 1,
							      IEEE80211_SEQ_MAX);
			}
			qdf_spin_unlock_bh(&rx_tid->tid_lock);
			/* IEEE80211_SEQ_MAX indicates invalid start_seq */
			dp_peer_unref_delete(peer, DP_MOD_ID_RX_ERR);
		}
	}

	eh = (qdf_ether_header_t *)qdf_nbuf_data(nbuf);

	if (!txrx_peer->authorize) {
		is_eapol = qdf_nbuf_is_ipv4_eapol_pkt(nbuf);

		if (is_eapol || qdf_nbuf_is_ipv4_wapi_pkt(nbuf)) {
			if (!dp_rx_err_match_dhost(eh, vdev))
				goto drop_nbuf;
		} else {
			goto drop_nbuf;
		}
	}

	/*
	 * Drop packets in this path if cce_match is found. Packets will come
	 * in following path depending on whether tidQ is setup.
	 * 1. If tidQ is setup: WIFILI_HAL_RX_WBM_REO_PSH_RSN_ROUTE and
	 * cce_match = 1
	 *    Packets with WIFILI_HAL_RX_WBM_REO_PSH_RSN_ROUTE are already
	 *    dropped.
	 * 2. If tidQ is not setup: WIFILI_HAL_RX_WBM_REO_PSH_RSN_ERROR and
	 * cce_match = 1
	 *    These packets need to be dropped and should not get delivered
	 *    to stack.
	 */
	if (qdf_unlikely(dp_rx_err_cce_drop(soc, vdev, nbuf, rx_tlv_hdr)))
		goto drop_nbuf;

	if (qdf_unlikely(vdev->rx_decap_type == htt_cmn_pkt_type_raw)) {
		qdf_nbuf_set_raw_frame(nbuf, 1);
		qdf_nbuf_set_next(nbuf, NULL);
		dp_rx_deliver_raw(vdev, nbuf, txrx_peer, 0);
	} else {
		enh_flag = vdev->pdev->enhanced_stats_en;
		qdf_nbuf_set_next(nbuf, NULL);
		DP_PEER_TO_STACK_INCC_PKT(txrx_peer, 1, qdf_nbuf_len(nbuf),
					  enh_flag);

		DP_PEER_PER_PKT_STATS_INC_PKT(txrx_peer,
					      rx.rx_success, 1,
					      qdf_nbuf_len(nbuf), 0);
		/*
		 * Update the protocol tag in SKB based on
		 * CCE metadata
		 */
		dp_rx_update_protocol_tag(soc, vdev, nbuf, rx_tlv_hdr,
					  EXCEPTION_DEST_RING_ID,
					  true, true);

		/* Update the flow tag in SKB based on FSE metadata */
		dp_rx_update_flow_tag(soc, vdev, nbuf,
				      rx_tlv_hdr, true);

		if (qdf_unlikely(hal_rx_msdu_end_da_is_mcbc_get(
				 soc->hal_soc, rx_tlv_hdr) &&
				 (vdev->rx_decap_type ==
				  htt_cmn_pkt_type_ethernet))) {
			DP_PEER_MC_INCC_PKT(txrx_peer, 1, qdf_nbuf_len(nbuf),
					    enh_flag, 0);

			if (QDF_IS_ADDR_BROADCAST(eh->ether_dhost))
				DP_PEER_BC_INCC_PKT(txrx_peer, 1,
						    qdf_nbuf_len(nbuf),
						    enh_flag, 0);
		} else {
			DP_PEER_UC_INCC_PKT(txrx_peer, 1,
					    qdf_nbuf_len(nbuf),
					    enh_flag,
					    0);
		}

		qdf_nbuf_set_exc_frame(nbuf, 1);

		if (qdf_unlikely(vdev->multipass_en)) {
			if (dp_rx_multipass_process(txrx_peer, nbuf,
						    tid) == false) {
				DP_PEER_PER_PKT_STATS_INC
					(txrx_peer,
					 rx.multipass_rx_pkt_drop,
					 1, link_id);
				goto drop_nbuf;
			}
		}

		dp_rx_deliver_to_osif_stack(soc, vdev, txrx_peer, nbuf, NULL,
					    is_eapol);
	}
	return QDF_STATUS_SUCCESS;

drop_nbuf:
	dp_rx_nbuf_free(nbuf);
	return QDF_STATUS_E_FAILURE;
}
