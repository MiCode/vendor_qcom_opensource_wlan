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
#include "hal_be_tx.h"
#include "hal_api.h"
#include "qdf_trace.h"
#include "hal_be_api_mon.h"
#include "dp_internal.h"
#include "qdf_mem.h"   /* qdf_mem_malloc,free */
#include "dp_mon.h"
#include <dp_mon_2.0.h>
#include <dp_tx_mon_2.0.h>
#include <dp_be.h>
#include <hal_be_api_mon.h>
#include <dp_mon_filter_2.0.h>

static inline uint32_t
dp_tx_mon_srng_process_2_0(struct dp_soc *soc, struct dp_intr *int_ctx,
			   uint32_t mac_id, uint32_t quota)
{
	struct dp_pdev *pdev = dp_get_pdev_for_lmac_id(soc, mac_id);
	void *tx_mon_dst_ring_desc;
	hal_soc_handle_t hal_soc;
	void *mon_dst_srng;
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	uint32_t work_done = 0;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);
	union dp_mon_desc_list_elem_t *desc_list = NULL;
	union dp_mon_desc_list_elem_t *tail = NULL;
	struct dp_mon_desc_pool *tx_mon_desc_pool = &mon_soc_be->tx_desc_mon;
	uint32_t tx_monitor_reap_cnt = 0;

	if (!pdev) {
		dp_mon_err("%pK: pdev is null for mac_id = %d", soc, mac_id);
		return work_done;
	}

	mon_pdev = pdev->monitor_pdev;
	mon_dst_srng = mon_soc_be->tx_mon_dst_ring[mac_id].hal_srng;

	if (!mon_dst_srng || !hal_srng_initialized(mon_dst_srng)) {
		dp_mon_err("%pK: : HAL Monitor Destination Ring Init Failed -- %pK",
			   soc, mon_dst_srng);
		return work_done;
	}

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return work_done;

	hal_soc = soc->hal_soc;

	qdf_assert((hal_soc && pdev));

	qdf_spin_lock_bh(&mon_pdev->mon_lock);

	if (qdf_unlikely(dp_srng_access_start(int_ctx, soc, mon_dst_srng))) {
		dp_mon_err("%s %d : HAL Mon Dest Ring access Failed -- %pK",
			   __func__, __LINE__, mon_dst_srng);
		qdf_spin_unlock_bh(&mon_pdev->mon_lock);
		return work_done;
	}

	while (qdf_likely((tx_mon_dst_ring_desc =
		(void *)hal_srng_dst_peek(hal_soc, mon_dst_srng))
				&& quota--)) {
		struct hal_mon_desc hal_mon_tx_desc = {0};
		struct dp_mon_desc *mon_desc = NULL;
		uint32_t end_offset = DP_MON_DATA_BUFFER_SIZE;

		hal_be_get_mon_dest_status(soc->hal_soc,
					   tx_mon_dst_ring_desc,
					   &hal_mon_tx_desc);

		if (hal_mon_tx_desc.empty_descriptor) {
			/* update stats counter */
			dp_mon_debug("P_ID:%d INIT:%d E_DESC:%d R_ID:%d L_CNT:%d  DROP[PPDU:%d MPDU:%d TLV:%d] E_O_PPDU:%d",
				    hal_mon_tx_desc.ppdu_id,
				    hal_mon_tx_desc.initiator,
				    hal_mon_tx_desc.empty_descriptor,
				    hal_mon_tx_desc.ring_id,
				    hal_mon_tx_desc.looping_count,
				    hal_mon_tx_desc.ppdu_drop_count,
				    hal_mon_tx_desc.mpdu_drop_count,
				    hal_mon_tx_desc.tlv_drop_count,
				    hal_mon_tx_desc.end_of_ppdu_dropped);

			work_done++;
			hal_srng_dst_get_next(hal_soc, mon_dst_srng);
			continue;
		}

		dp_mon_debug("P_ID:%d INIT:%d E_DESC:%d R_ID:%d L_CNT:%d BUF_ADDR: 0x%llx E_OFF: %d E_REA: %d",
			    hal_mon_tx_desc.ppdu_id,
			    hal_mon_tx_desc.initiator,
			    hal_mon_tx_desc.empty_descriptor,
			    hal_mon_tx_desc.ring_id,
			    hal_mon_tx_desc.looping_count,
			    hal_mon_tx_desc.buf_addr,
			    hal_mon_tx_desc.end_offset,
			    hal_mon_tx_desc.end_reason);

		mon_desc = (struct dp_mon_desc *)(uintptr_t)(hal_mon_tx_desc.buf_addr);
		qdf_assert_always(mon_desc);

		if (!mon_desc->unmapped) {
			qdf_mem_unmap_page(soc->osdev, mon_desc->paddr,
					   DP_MON_DATA_BUFFER_SIZE,
					   QDF_DMA_FROM_DEVICE);
			mon_desc->unmapped = 1;
		}

		if (mon_desc->magic != DP_MON_DESC_MAGIC) {
			dp_mon_err("Invalid monitor descriptor");
			qdf_assert_always(0);
		}

		if (qdf_likely(hal_mon_tx_desc.end_offset))
			end_offset = hal_mon_tx_desc.end_offset;

		if ((hal_mon_tx_desc.end_reason == HAL_MON_FLUSH_DETECTED) ||
		    (hal_mon_tx_desc.end_reason == HAL_MON_PPDU_TRUNCATED)) {
			dp_tx_mon_update_end_reason(mon_pdev,
						    hal_mon_tx_desc.ppdu_id,
						    hal_mon_tx_desc.end_reason);

			qdf_frag_free(mon_desc->buf_addr);
			mon_desc->buf_addr = NULL;
			++tx_monitor_reap_cnt;
			dp_mon_add_to_free_desc_list(&desc_list,
						     &tail, mon_desc);

			work_done++;
			hal_srng_dst_get_next(hal_soc, mon_dst_srng);
			continue;
		}

		if (qdf_unlikely(!mon_desc->buf_addr)) {
			dp_mon_debug("P_ID:%d INIT:%d E_DESC:%d R_ID:%d L_CNT:%d BUF_ADDR: 0x%llx E_OFF: %d E_REA: %d",
				     hal_mon_tx_desc.ppdu_id,
				     hal_mon_tx_desc.initiator,
				     hal_mon_tx_desc.empty_descriptor,
				     hal_mon_tx_desc.ring_id,
				     hal_mon_tx_desc.looping_count,
				     hal_mon_tx_desc.buf_addr,
				     hal_mon_tx_desc.end_offset,
				     hal_mon_tx_desc.end_reason);

			++tx_monitor_reap_cnt;
			dp_mon_add_to_free_desc_list(&desc_list,
						     &tail, mon_desc);

			work_done++;
			hal_srng_dst_get_next(hal_soc, mon_dst_srng);
			continue;
		}

		dp_tx_mon_process_status_tlv(soc, pdev,
					     &hal_mon_tx_desc,
					     mon_desc->buf_addr, end_offset);

		mon_desc->buf_addr = NULL;
		++tx_monitor_reap_cnt;
		dp_mon_add_to_free_desc_list(&desc_list, &tail, mon_desc);

		work_done++;
		hal_srng_dst_get_next(hal_soc, mon_dst_srng);
	}
	dp_srng_access_end(int_ctx, soc, mon_dst_srng);

	if (tx_monitor_reap_cnt) {
		dp_mon_buffers_replenish(soc, &mon_soc_be->tx_mon_buf_ring,
					 tx_mon_desc_pool,
					 tx_monitor_reap_cnt,
					 &desc_list, &tail);
	}
	qdf_spin_unlock_bh(&mon_pdev->mon_lock);
	dp_mon_debug("mac_id: %d, work_done:%d tx_monitor_reap_cnt:%d",
		     mac_id, work_done, tx_monitor_reap_cnt);
	return work_done;
}

uint32_t
dp_tx_mon_process_2_0(struct dp_soc *soc, struct dp_intr *int_ctx,
		      uint32_t mac_id, uint32_t quota)
{
	uint32_t work_done;

	work_done = dp_tx_mon_srng_process_2_0(soc, int_ctx, mac_id, quota);

	return work_done;
}

void
dp_tx_mon_buf_desc_pool_deinit(struct dp_soc *soc)
{
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be =
		dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	dp_mon_desc_pool_deinit(&mon_soc_be->tx_desc_mon);
}

QDF_STATUS
dp_tx_mon_buf_desc_pool_init(struct dp_soc *soc)
{
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be =
		dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);
	uint32_t num_entries;

	num_entries =
		wlan_cfg_get_dp_soc_rx_mon_buf_ring_size(soc->wlan_cfg_ctx);
	return dp_mon_desc_pool_init(&mon_soc_be->tx_desc_mon, num_entries);
}

void dp_tx_mon_buf_desc_pool_free(struct dp_soc *soc)
{
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be =
		dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	if (mon_soc_be)
		dp_mon_desc_pool_free(&mon_soc_be->tx_desc_mon);
}

QDF_STATUS
dp_tx_mon_buf_desc_pool_alloc(struct dp_soc *soc)
{
	struct dp_srng *mon_buf_ring;
	struct dp_mon_desc_pool *tx_mon_desc_pool;
	int entries;
	struct wlan_cfg_dp_soc_ctxt *soc_cfg_ctx;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be =
		dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	soc_cfg_ctx = soc->wlan_cfg_ctx;

	entries = wlan_cfg_get_dp_soc_tx_mon_buf_ring_size(soc_cfg_ctx);

	mon_buf_ring = &mon_soc_be->tx_mon_buf_ring;

	tx_mon_desc_pool = &mon_soc_be->tx_desc_mon;

	qdf_print("%s:%d tx mon buf desc pool entries: %d", __func__, __LINE__, entries);
	return dp_mon_desc_pool_alloc(entries, tx_mon_desc_pool);
}

void
dp_tx_mon_buffers_free(struct dp_soc *soc)
{
	struct dp_mon_desc_pool *tx_mon_desc_pool;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be =
		dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	tx_mon_desc_pool = &mon_soc_be->tx_desc_mon;

	dp_mon_pool_frag_unmap_and_free(soc, tx_mon_desc_pool);
}

QDF_STATUS
dp_tx_mon_buffers_alloc(struct dp_soc *soc, uint32_t size)
{
	struct dp_srng *mon_buf_ring;
	struct dp_mon_desc_pool *tx_mon_desc_pool;
	union dp_mon_desc_list_elem_t *desc_list = NULL;
	union dp_mon_desc_list_elem_t *tail = NULL;
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be =
		dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);

	mon_buf_ring = &mon_soc_be->tx_mon_buf_ring;

	tx_mon_desc_pool = &mon_soc_be->tx_desc_mon;

	return dp_mon_buffers_replenish(soc, mon_buf_ring,
					tx_mon_desc_pool,
					size,
					&desc_list, &tail);
}

#ifdef WLAN_TX_PKT_CAPTURE_ENH_BE
/*
 * dp_tx_mon_free_usr_mpduq() - API to free user mpduq
 * @tx_ppdu_info - pointer to tx_ppdu_info
 * @usr_idx - user index
 *
 * Return: void
 */
void dp_tx_mon_free_usr_mpduq(struct dp_tx_ppdu_info *tx_ppdu_info,
			      uint8_t usr_idx)
{
	qdf_nbuf_queue_t *mpdu_q;

	if (qdf_unlikely(!tx_ppdu_info))
		return;

	mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, usr_idx, mpdu_q);
	qdf_nbuf_queue_remove(mpdu_q);
}

/*
 * dp_tx_mon_free_ppdu_info() - API to free dp_tx_ppdu_info
 * @tx_ppdu_info - pointer to tx_ppdu_info
 *
 * Return: void
 */
void dp_tx_mon_free_ppdu_info(struct dp_tx_ppdu_info *tx_ppdu_info)
{
	uint32_t user = 0;

	for (; user < TXMON_PPDU_HAL(tx_ppdu_info, num_users); user++) {
		qdf_nbuf_queue_t *mpdu_q;

		mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, user, mpdu_q);
		qdf_nbuf_queue_free(mpdu_q);
	}

	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 0;
	qdf_mem_free(tx_ppdu_info);
}

/*
 * dp_tx_mon_get_ppdu_info() - API to allocate dp_tx_ppdu_info
 * @pdev - pdev handle
 * @type - type of ppdu_info data or protection
 * @num_user - number user in a ppdu_info
 * @ppdu_id - ppdu_id number
 *
 * Return: pointer to dp_tx_ppdu_info
 */
struct dp_tx_ppdu_info *dp_tx_mon_get_ppdu_info(struct dp_pdev *pdev,
						enum tx_ppdu_info_type type,
						uint8_t num_user,
						uint32_t ppdu_id)
{
	struct dp_mon_pdev *mon_pdev = pdev->monitor_pdev;
	struct dp_mon_pdev_be *mon_pdev_be =
			dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	struct dp_pdev_tx_capture_be *tx_cap_be =
			&mon_pdev_be->tx_capture_be;
	struct dp_tx_ppdu_info *tx_ppdu_info;
	size_t sz_ppdu_info = 0;
	uint8_t i;

	if (type == TX_PROT_PPDU_INFO) {
		tx_ppdu_info = tx_cap_be->tx_prot_ppdu_info;
		if (tx_ppdu_info &&
		    TXMON_PPDU_HAL(tx_ppdu_info, is_used) != 1) {
			return tx_ppdu_info;
		} else if (tx_ppdu_info) {
			dp_tx_mon_free_ppdu_info(tx_ppdu_info);
			tx_ppdu_info = NULL;
		}

		/* for protection frame num_user is always 1 */
		num_user = 1;
	} else {
		tx_ppdu_info = tx_cap_be->tx_data_ppdu_info;
		if (tx_ppdu_info &&
		    TXMON_PPDU_HAL(tx_ppdu_info, is_used) != 1 &&
		    num_user == TXMON_PPDU_HAL(tx_ppdu_info, num_users)) {
			/* number of user matched */
			return tx_ppdu_info;
		} else if (tx_ppdu_info) {
			dp_tx_mon_free_ppdu_info(tx_ppdu_info);
			tx_ppdu_info = NULL;
		}
	}

	/* allocate new tx_ppdu_info */
	sz_ppdu_info = (sizeof(struct dp_tx_ppdu_info) +
			(sizeof(struct mon_rx_user_status) * num_user));

	tx_ppdu_info = (struct dp_tx_ppdu_info *)qdf_mem_malloc(sz_ppdu_info);
	if (!tx_ppdu_info) {
		dp_mon_err("allocation of tx_ppdu_info type[%d] failed!!!",
			   type);
		return NULL;
	}

	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 0;
	TXMON_PPDU_HAL(tx_ppdu_info, num_users) = num_user;
	TXMON_PPDU_HAL(tx_ppdu_info, ppdu_id) = ppdu_id;

	for (i = 0; i < num_user; i++) {
		qdf_nbuf_queue_t *mpdu_q;

		mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, i, mpdu_q);
		if (qdf_unlikely(qdf_nbuf_queue_len(mpdu_q)))
			qdf_nbuf_queue_free(mpdu_q);

		qdf_nbuf_queue_init(mpdu_q);
	}

	/* assign tx_ppdu_info to monitor pdev for reference */
	if (type == TX_PROT_PPDU_INFO) {
		tx_cap_be->tx_prot_ppdu_info = tx_ppdu_info;
		TXMON_PPDU_HAL(tx_ppdu_info, is_data) = 0;
	} else {
		tx_cap_be->tx_data_ppdu_info = tx_ppdu_info;
		TXMON_PPDU_HAL(tx_ppdu_info, is_data) = 1;
	}

	return tx_ppdu_info;
}

/*
 * dp_print_pdev_tx_capture_stats_2_0: print tx capture stats
 * @pdev: DP PDEV handle
 *
 * return: void
 */
void dp_print_pdev_tx_capture_stats_2_0(struct dp_pdev *pdev)
{
	/* TX monitor stats needed for beryllium */
}

/*
 * dp_config_enh_tx_capture_be()- API to enable/disable enhanced tx capture
 * @pdev_handle: DP_PDEV handle
 * @val: user provided value
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
dp_config_enh_tx_capture_2_0(struct dp_pdev *pdev, uint8_t val)
{
	struct dp_mon_pdev *mon_pdev = pdev->monitor_pdev;
	struct dp_mon_pdev_be *mon_pdev_be =
			dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	struct dp_pdev_tx_capture_be *tx_cap_be =
			&mon_pdev_be->tx_capture_be;

	switch (val) {
	case TX_MON_BE_DISABLE:
	{
		/* TODO: send HTT msg to configure TLV based on mode */
		tx_cap_be->mode = TX_MON_BE_DISABLE;
		mon_pdev_be->tx_mon_mode = 0;
		mon_pdev_be->tx_mon_filter_length = DMA_LENGTH_64B;
		break;
	}
	case TX_MON_BE_FULL_CAPTURE:
	{
		/* TODO: send HTT msg to configure TLV based on mode */
		tx_cap_be->mode = TX_MON_BE_FULL_CAPTURE;
		mon_pdev_be->tx_mon_mode = 1;
		mon_pdev_be->tx_mon_filter_length = DMA_LENGTH_256B;
		break;
	}
	case TX_MON_BE_PEER_FILTER:
	{
		/* TODO: send HTT msg to configure TLV based on mode */
		tx_cap_be->mode = TX_MON_BE_PEER_FILTER;
		mon_pdev_be->tx_mon_mode = 1;
		mon_pdev_be->tx_mon_filter_length = DMA_LENGTH_256B;
		break;
	}
	default:
	{
		/* TODO: do we need to set to disable ? */
		return QDF_STATUS_E_INVAL;
	}
	}

	dp_mon_info("Tx monitor mode:%d mon_mode_flag:%d config_length:%d",
		    tx_cap_be->mode, mon_pdev_be->tx_mon_mode,
		    mon_pdev_be->tx_mon_filter_length);

	dp_mon_filter_setup_tx_mon_mode(pdev);
	dp_tx_mon_filter_update(pdev);

	return QDF_STATUS_SUCCESS;
}

/*
 * dp_peer_set_tx_capture_enabled_2_0() -  add tx monitor peer filter
 * @pdev: Datapath PDEV handle
 * @peer: Datapath PEER handle
 * @is_tx_pkt_cap_enable: flag for tx capture enable/disable
 * @peer_mac: peer mac address
 *
 * Return: status
 */
QDF_STATUS dp_peer_set_tx_capture_enabled_2_0(struct dp_pdev *pdev_handle,
					      struct dp_peer *peer_handle,
					      uint8_t is_tx_pkt_cap_enable,
					      uint8_t *peer_mac)
{
	return QDF_STATUS_SUCCESS;
}

/**
 * dp_tx_mon_send_to_stack() - API to send to stack
 * @pdev: pdev Handle
 * @mpdu: pointer to mpdu
 *
 * Return: void
 */
static void
dp_tx_mon_send_to_stack(struct dp_pdev *pdev, qdf_nbuf_t mpdu)
{
	struct cdp_tx_indication_info tx_capture_info;

	qdf_mem_set(&tx_capture_info,
		    sizeof(struct cdp_tx_indication_info),
		    0);
	tx_capture_info.radiotap_done = 1;
	tx_capture_info.mpdu_nbuf = mpdu;
	dp_wdi_event_handler(WDI_EVENT_TX_PKT_CAPTURE,
			     pdev->soc,
			     &tx_capture_info,
			     HTT_INVALID_PEER,
			     WDI_NO_VAL,
			     pdev->pdev_id);
}

/**
 * dp_tx_mon_send_per_usr_mpdu() - API to send per usr mpdu to stack
 * @pdev: pdev Handle
 * @ppdu_info: pointer to dp_tx_ppdu_info
 * @user_id: current user index
 * @radiota_hdr_ref: pointer to radiotap ref
 *
 * Return: void
 */
static void
dp_tx_mon_send_per_usr_mpdu(struct dp_pdev *pdev,
			    struct dp_tx_ppdu_info *ppdu_info,
			    uint8_t user_id,
			    qdf_nbuf_t *radiotap_hdr_ref)
{
	uint32_t mpdu_queue_len = 0;
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;
	qdf_nbuf_t buf = NULL;
	qdf_nbuf_t radiotap_copy = NULL;

	usr_mpdu_q = &TXMON_PPDU_USR(ppdu_info, user_id, mpdu_q);

	if (!usr_mpdu_q) {
		qdf_nbuf_free(*radiotap_hdr_ref);
		*radiotap_hdr_ref = NULL;
		/* free radiotap hdr */
		return;
	}

	while ((buf = qdf_nbuf_queue_remove(usr_mpdu_q)) != NULL) {
		mpdu_queue_len = qdf_nbuf_queue_len(usr_mpdu_q);
		/*
		 * In an aggregated frame, each mpdu is send individualy to
		 * stack. caller of the function already allocate
		 * and update radiotap header information. We copy the
		 * same radiotap header until we reach the end of mpdu.
		 * Once we reached end of mpdu we use the buffer allocated
		 * for radiotap hdr.
		 */
		if (mpdu_queue_len) {
			radiotap_copy = qdf_nbuf_copy_expand(*radiotap_hdr_ref,
							     0, 0);
		} else {
			radiotap_copy = *radiotap_hdr_ref;
			*radiotap_hdr_ref = NULL;
		}

		/* add msdu as a fraglist of mpdu */
		qdf_nbuf_append_ext_list(radiotap_copy,
					 buf, qdf_nbuf_len(buf));
		dp_tx_mon_send_to_stack(pdev, radiotap_copy);
	}
}

/**
 * dp_tx_mon_alloc_radiotap_hdr() - API to allocate radiotap header
 * @pdev: pdev Handle
 * @nbuf_ref: reference to nbuf
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
dp_tx_mon_alloc_radiotap_hdr(struct dp_pdev *pdev, qdf_nbuf_t *nbuf_ref)
{
	*nbuf_ref = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_MONITOR_HEADER,
				   MAX_MONITOR_HEADER,
				   4, FALSE);
	if (!*nbuf_ref)
		return QDF_STATUS_E_NOMEM;

	return QDF_STATUS_SUCCESS;
}

/**
 * dp_tx_mon_update_radiotap() - API to update radiotap information
 * @pdev: pdev Handle
 * @ppdu_info: pointer to dp_tx_ppdu_info
 *
 * Return: void
 */
static void
dp_tx_mon_update_radiotap(struct dp_pdev *pdev,
			  struct dp_tx_ppdu_info *ppdu_info)
{
	uint32_t i = 0;
	uint32_t num_users = 0;
	qdf_nbuf_t radiotap_hdr = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct dp_mon_pdev *mon_pdev;

	mon_pdev = pdev->monitor_pdev;

	num_users = TXMON_PPDU_HAL(ppdu_info, num_users);

	if (qdf_unlikely(TXMON_PPDU_COM(ppdu_info, chan_num) == 0))
		TXMON_PPDU_COM(ppdu_info, chan_num) =
				pdev->operating_channel.num;

	if (qdf_unlikely(TXMON_PPDU_COM(ppdu_info, chan_freq) == 0))
		TXMON_PPDU_COM(ppdu_info, chan_freq) =
				pdev->operating_channel.freq;

	for (i = 0; i < num_users; i++) {
		/* allocate radiotap_hdr */
		status = dp_tx_mon_alloc_radiotap_hdr(pdev, &radiotap_hdr);
		if (status != QDF_STATUS_SUCCESS) {
			/* free ppdu_info per user */
			dp_tx_mon_free_usr_mpduq(ppdu_info, i);
			continue;
		}

		/* copy rx_status to rx_status and invoke update radiotap */
		ppdu_info->hal_txmon.rx_status.rx_user_status =
					&ppdu_info->hal_txmon.rx_user_status[i];
		qdf_nbuf_update_radiotap(&ppdu_info->hal_txmon.rx_status,
					 radiotap_hdr, MAX_MONITOR_HEADER);

		/* radiotap header will be free in below function */
		dp_tx_mon_send_per_usr_mpdu(pdev, ppdu_info, i, &radiotap_hdr);

		/*
		 * radiotap_hdr will be free in above function
		 * if not free here
		 */
		if (!!radiotap_hdr)
			qdf_nbuf_free(radiotap_hdr);
	}
}

/**
 * dp_tx_mon_ppdu_process - Deferred PPDU stats handler
 * @context: Opaque work context (PDEV)
 *
 * Return: none
 */
void dp_tx_mon_ppdu_process(void *context)
{
	struct dp_pdev *pdev = (struct dp_pdev *)context;
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_tx_ppdu_info *defer_ppdu_info = NULL;
	struct dp_tx_ppdu_info *defer_ppdu_info_next = NULL;
	struct dp_pdev_tx_capture_be *tx_cap_be;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;

	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_cap_be = &mon_pdev_be->tx_capture_be;
	if (qdf_unlikely(TX_MON_BE_DISABLE == tx_cap_be->mode))
		return;

	/* take lock here */
	qdf_spin_lock_bh(&tx_cap_be->tx_mon_list_lock);
	STAILQ_CONCAT(&tx_cap_be->defer_tx_ppdu_info_queue,
		      &tx_cap_be->tx_ppdu_info_queue);
	tx_cap_be->defer_ppdu_info_list_depth +=
		tx_cap_be->tx_ppdu_info_list_depth;
	tx_cap_be->tx_ppdu_info_list_depth = 0;
	qdf_spin_unlock_bh(&tx_cap_be->tx_mon_list_lock);

	STAILQ_FOREACH_SAFE(defer_ppdu_info,
			    &tx_cap_be->defer_tx_ppdu_info_queue,
			    tx_ppdu_info_queue_elem, defer_ppdu_info_next) {
		/* remove dp_tx_ppdu_info from the list */
		STAILQ_REMOVE(&tx_cap_be->defer_tx_ppdu_info_queue,
			      defer_ppdu_info,
			      dp_tx_ppdu_info,
			      tx_ppdu_info_queue_elem);
		tx_cap_be->defer_ppdu_info_list_depth--;

		dp_tx_mon_update_radiotap(pdev, defer_ppdu_info);

		/* free the ppdu_info */
		dp_tx_mon_free_ppdu_info(defer_ppdu_info);
		defer_ppdu_info = NULL;
	}
}

/**
 * dp_tx_ppdu_stats_attach_2_0 - Initialize Tx PPDU stats and enhanced capture
 * @pdev: DP PDEV
 *
 * Return: none
 */
void dp_tx_ppdu_stats_attach_2_0(struct dp_pdev *pdev)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;

	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;

	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_cap_be = &mon_pdev_be->tx_capture_be;

	STAILQ_INIT(&tx_cap_be->tx_ppdu_info_queue);
	tx_cap_be->tx_ppdu_info_list_depth = 0;

	STAILQ_INIT(&tx_cap_be->defer_tx_ppdu_info_queue);
	tx_cap_be->defer_ppdu_info_list_depth = 0;

	qdf_spinlock_create(&tx_cap_be->tx_mon_list_lock);
	/* Work queue setup for TX MONITOR post handling */
	qdf_create_work(0, &tx_cap_be->post_ppdu_work,
			dp_tx_mon_ppdu_process, pdev);

	tx_cap_be->post_ppdu_workqueue =
			qdf_alloc_unbound_workqueue("tx_mon_ppdu_work_queue");
}

/**
 * dp_tx_ppdu_stats_detach_be - Cleanup Tx PPDU stats and enhanced capture
 * @pdev: DP PDEV
 *
 * Return: none
 */
void dp_tx_ppdu_stats_detach_2_0(struct dp_pdev *pdev)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct dp_tx_ppdu_info *tx_ppdu_info = NULL;
	struct dp_tx_ppdu_info *tx_ppdu_info_next = NULL;

	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;

	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_cap_be = &mon_pdev_be->tx_capture_be;
	/* TODO: disable tx_monitor, to avoid further packet from HW */
	dp_monitor_config_enh_tx_capture(pdev, TX_MON_BE_DISABLE);

	/* flush workqueue */
	qdf_flush_workqueue(0, tx_cap_be->post_ppdu_workqueue);
	qdf_destroy_workqueue(0, tx_cap_be->post_ppdu_workqueue);

	/*
	 * TODO: iterate both tx_ppdu_info and defer_ppdu_info_list
	 * free the tx_ppdu_info and decrement depth
	 */
	qdf_spin_lock_bh(&tx_cap_be->tx_mon_list_lock);
	STAILQ_FOREACH_SAFE(tx_ppdu_info,
			    &tx_cap_be->tx_ppdu_info_queue,
			    tx_ppdu_info_queue_elem, tx_ppdu_info_next) {
		/* remove dp_tx_ppdu_info from the list */
		STAILQ_REMOVE(&tx_cap_be->tx_ppdu_info_queue, tx_ppdu_info,
			      dp_tx_ppdu_info, tx_ppdu_info_queue_elem);
		/* decrement list length */
		tx_cap_be->tx_ppdu_info_list_depth--;
		/* free tx_ppdu_info */
		dp_tx_mon_free_ppdu_info(tx_ppdu_info);
	}
	qdf_spin_unlock_bh(&tx_cap_be->tx_mon_list_lock);

	qdf_spin_lock_bh(&tx_cap_be->tx_mon_list_lock);
	STAILQ_FOREACH_SAFE(tx_ppdu_info,
			    &tx_cap_be->defer_tx_ppdu_info_queue,
			    tx_ppdu_info_queue_elem, tx_ppdu_info_next) {
		/* remove dp_tx_ppdu_info from the list */
		STAILQ_REMOVE(&tx_cap_be->defer_tx_ppdu_info_queue,
			      tx_ppdu_info,
			      dp_tx_ppdu_info, tx_ppdu_info_queue_elem);
		/* decrement list length */
		tx_cap_be->defer_ppdu_info_list_depth--;
		/* free tx_ppdu_info */
		dp_tx_mon_free_ppdu_info(tx_ppdu_info);
	}
	qdf_spin_unlock_bh(&tx_cap_be->tx_mon_list_lock);

	qdf_spinlock_destroy(&tx_cap_be->tx_mon_list_lock);
}
#endif /* WLAN_TX_PKT_CAPTURE_ENH_BE */

#if (defined(WIFI_MONITOR_SUPPORT) && !defined(WLAN_TX_PKT_CAPTURE_ENH_BE))
/*
 * dp_config_enh_tx_core_capture_2_0()- API to validate core framework
 * @pdev_handle: DP_PDEV handle
 * @val: user provided value
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
dp_config_enh_tx_core_capture_2_0(struct dp_pdev *pdev, uint8_t val)
{
	struct dp_mon_pdev *mon_pdev = pdev->monitor_pdev;
	struct dp_mon_pdev_be *mon_pdev_be =
			dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	struct dp_pdev_tx_capture_be *tx_cap_be =
			&mon_pdev_be->tx_capture_be;

	switch (val) {
	case TX_MON_BE_FRM_WRK_DISABLE:
	{
		tx_cap_be->mode = val;
		mon_pdev_be->tx_mon_mode = 0;
		mon_pdev_be->tx_mon_filter_length = DMA_LENGTH_64B;
		break;
	}
	case TX_MON_BE_FRM_WRK_FULL_CAPTURE:
	{
		tx_cap_be->mode = val;
		mon_pdev_be->tx_mon_mode = 1;
		mon_pdev_be->tx_mon_filter_length = DEFAULT_DMA_LENGTH;
		break;
	}
	case TX_MON_BE_FRM_WRK_128B_CAPTURE:
	{
		tx_cap_be->mode = val;
		mon_pdev_be->tx_mon_mode = 1;
		mon_pdev_be->tx_mon_filter_length = DMA_LENGTH_128B;
		break;
	}
	default:
	{
		return QDF_STATUS_E_INVAL;
	}
	}

	dp_mon_debug("Tx monitor mode:%d mon_mode_flag:%d config_length:%d",
		    tx_cap_be->mode, mon_pdev_be->tx_mon_mode,
		    mon_pdev_be->tx_mon_filter_length);

	/* send HTT msg to configure TLV based on mode */
	dp_mon_filter_setup_tx_mon_mode(pdev);
	dp_tx_mon_filter_update(pdev);

	return QDF_STATUS_SUCCESS;
}
#endif
