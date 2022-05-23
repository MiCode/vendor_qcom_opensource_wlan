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
#include <dp_rx_mon.h>
#include <dp_rx_mon_2.0.h>
#include <dp_rx.h>
#include <dp_be.h>
#include <hal_be_api_mon.h>
#ifdef QCA_SUPPORT_LITE_MONITOR
#include "dp_lite_mon.h"
#endif

#define F_MASK 0xFFFF

#ifdef QCA_TEST_MON_PF_TAGS_STATS

/**
 * dp_mon_rx_pf_update_stats() - update protocol flow tags stats
 *
 * @pdev: pdev
 * @flow_idx: Protocol index for which the stats should be incremented
 * @cce_metadata: Cached CCE metadata value received from MSDU_END TLV
 *
 * Return: void
 */
static void
dp_rx_mon_pf_update_stats(struct dp_pdev *dp_pdev, uint32_t flow_idx,
			  uint16_t cce_metadata)
{
	dp_mon_rx_update_rx_flow_tag_stats(pdev, flow_idx);
	dp_mon_rx_update_rx_err_protocol_tag_stats(pdev, cce_metadata);
	dp_mon_rx_update_rx_protocol_tag_stats(pdev, cce_metada,
					       MAX_REO_DEST_RINGS);
}

#else
static void
dp_rx_mon_pf_update_stats(struct dp_pdev *dp_pdev, uint32_t flow_idx,
			  uint16_t cce_metadata)
{
}
#endif

void
dp_rx_mon_shift_pf_tag_in_headroom(qdf_nbuf_t nbuf, struct dp_soc *soc)
{
	if (qdf_unlikely(!soc)) {
		dp_mon_err("Soc[%pK] Null. Can't update pftag to nbuf headroom",
			   soc);
		qdf_assert_always(0);
	}

	if (!wlan_cfg_is_rx_mon_protocol_flow_tag_enabled(soc->wlan_cfg_ctx))
		return;

	if (qdf_unlikely(!nbuf))
		return;

	if (qdf_unlikely(qdf_nbuf_headroom(nbuf) <
			 (DP_RX_MON_TOT_PF_TAG_LEN * 2))) {
		dp_mon_err("Headroom[%d] < 2 *DP_RX_MON_PF_TAG_TOT_LEN[%lu]",
			   qdf_nbuf_headroom(nbuf), DP_RX_MON_TOT_PF_TAG_LEN);
		return;
	}

	qdf_nbuf_push_head(nbuf, DP_RX_MON_TOT_PF_TAG_LEN);
	qdf_mem_copy(qdf_nbuf_data(nbuf), qdf_nbuf_head(nbuf),
		     DP_RX_MON_TOT_PF_TAG_LEN);
	qdf_nbuf_pull_head(nbuf, DP_RX_MON_TOT_PF_TAG_LEN);
}

void
dp_rx_mon_pf_tag_to_buf_headroom_2_0(void *nbuf,
				     struct hal_rx_ppdu_info *ppdu_info,
				     struct dp_pdev *pdev, struct dp_soc *soc)
{
	uint8_t *nbuf_head = NULL;
	uint8_t user_id = ppdu_info->user_id;
	struct hal_rx_mon_msdu_info *msdu_info = &ppdu_info->msdu[user_id];
	uint16_t flow_id = ppdu_info->rx_msdu_info[user_id].flow_idx;
	uint16_t cce_metadata = ppdu_info->rx_msdu_info[user_id].cce_metadata -
				RX_PROTOCOL_TAG_START_OFFSET;
	uint16_t protocol_tag = pdev->rx_proto_tag_map[cce_metadata].tag;
	uint32_t flow_tag = ppdu_info->rx_msdu_info[user_id].fse_metadata &
			    F_MASK;

	if (qdf_unlikely(!soc)) {
		dp_mon_err("Soc[%pK] Null. Can't update pftag to nbuf headroom",
			   soc);
		qdf_assert_always(0);
	}

	if (!wlan_cfg_is_rx_mon_protocol_flow_tag_enabled(soc->wlan_cfg_ctx))
		return;

	if (qdf_unlikely(!nbuf))
		return;

	/* Headroom must be double of PF_TAG_SIZE as we copy it 1stly to head */
	if (qdf_unlikely(qdf_nbuf_headroom(nbuf) <
			 (DP_RX_MON_TOT_PF_TAG_LEN * 2))) {
		dp_mon_err("Headroom[%d] < 2 * DP_RX_MON_PF_TAG_TOT_LEN[%lu]",
			   qdf_nbuf_headroom(nbuf), DP_RX_MON_TOT_PF_TAG_LEN);
		return;
	}

	if (msdu_info->msdu_index >= QDF_NBUF_MAX_FRAGS) {
		dp_mon_err("msdu_index causes overflow in headroom");
		return;
	}

	dp_rx_mon_pf_update_stats(pdev, flow_id, cce_metadata);

	nbuf_head = qdf_nbuf_head(nbuf);
	nbuf_head += (msdu_info->msdu_index * DP_RX_MON_PF_TAG_SIZE);
	*((uint16_t *)nbuf_head) = protocol_tag;
	nbuf_head += sizeof(uint16_t);
	*((uint16_t *)nbuf_head) = flow_tag;
}

/**
 * dp_rx_mon_free_ppdu_info () - Free PPDU info
 * @pdev: DP pdev
 * @ppdu_info: PPDU info
 *
 * Return: Void
 */
static void
dp_rx_mon_free_ppdu_info(struct dp_pdev *pdev,
			 struct hal_rx_ppdu_info *ppdu_info)
{
	uint8_t user;

	for (user = 0; user < ppdu_info->com_info.num_users; user++) {
		uint16_t mpdu_count  = ppdu_info->mpdu_count[user];
		uint16_t mpdu_idx;
		qdf_nbuf_t mpdu;

		for (mpdu_idx = 0; mpdu_idx < mpdu_count; mpdu_idx++) {
			mpdu = (qdf_nbuf_t)ppdu_info->mpdu_q[user][mpdu_idx];

			if (!mpdu)
				continue;
			qdf_nbuf_free(mpdu);
		}
	}
}

void dp_rx_mon_drain_wq(struct dp_pdev *pdev)
{
	struct dp_mon_pdev *mon_pdev;
	struct hal_rx_ppdu_info *ppdu_info = NULL;
	struct hal_rx_ppdu_info *temp_ppdu_info = NULL;
	struct dp_mon_pdev_be *mon_pdev_be;

	if (qdf_unlikely(!pdev)) {
		dp_mon_debug("Pdev is NULL");
		return;
	}

	mon_pdev = (struct dp_mon_pdev *)pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev)) {
		dp_mon_debug("monitor pdev is NULL");
		return;
	}

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);

	qdf_spin_lock_bh(&mon_pdev_be->rx_mon_wq_lock);
	if (!TAILQ_EMPTY(&mon_pdev_be->rx_mon_queue)) {
		TAILQ_FOREACH_SAFE(ppdu_info,
				   &mon_pdev_be->rx_mon_queue,
				   ppdu_list_elem,
				   temp_ppdu_info) {
			TAILQ_REMOVE(&mon_pdev_be->rx_mon_queue,
				     ppdu_info, ppdu_list_elem);

			dp_rx_mon_free_ppdu_info(pdev, ppdu_info);
			qdf_mem_free(ppdu_info);
		}
	}
	qdf_spin_unlock_bh(&mon_pdev_be->rx_mon_wq_lock);
}

/**
 * dp_rx_mon_deliver_mpdu() - Deliver MPDU to osif layer
 *
 * @mon_pdev: monitor pdev
 * @mpdu: MPDU nbuf
 * @status: monitor status
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
dp_rx_mon_deliver_mpdu(struct dp_mon_pdev *mon_pdev,
		       qdf_nbuf_t mpdu,
		       struct mon_rx_status *rx_status)
{
	if (mon_pdev->mvdev && mon_pdev->mvdev->monitor_vdev->osif_rx_mon) {
		mon_pdev->mvdev->monitor_vdev->osif_rx_mon(mon_pdev->mvdev->osif_vdev,
							   mpdu,
							   rx_status);
	} else {
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * dp_rx_mon_process_ppdu_info () - Process PPDU info
 * @pdev: DP pdev
 * @ppdu_info: PPDU info
 *
 * Return: Void
 */
static void
dp_rx_mon_process_ppdu_info(struct dp_pdev *pdev,
			    struct hal_rx_ppdu_info *ppdu_info)
{
	struct dp_mon_pdev *mon_pdev = (struct dp_mon_pdev *)pdev->monitor_pdev;
	uint8_t user;

	for (user = 0; user < ppdu_info->com_info.num_users; user++) {
		uint16_t mpdu_count  = ppdu_info->mpdu_count[user];
		uint16_t mpdu_idx;
		qdf_nbuf_t mpdu;
		struct hal_rx_mon_mpdu_info *mpdu_meta;
		QDF_STATUS status;

		for (mpdu_idx = 0; mpdu_idx < mpdu_count; mpdu_idx++) {
			mpdu = (qdf_nbuf_t)ppdu_info->mpdu_q[user][mpdu_idx];

			if (!mpdu)
				continue;

			mpdu_meta = (struct hal_rx_mon_mpdu_info *)qdf_nbuf_data(mpdu);

			if (dp_lite_mon_is_rx_enabled(mon_pdev)) {
				status = dp_lite_mon_rx_mpdu_process(pdev, ppdu_info,
								     mpdu, mpdu_idx, user);
				if (status != QDF_STATUS_SUCCESS) {
					qdf_nbuf_free(mpdu);
					continue;
				}
			} else {
				if (mpdu_meta->full_pkt) {
					if (qdf_unlikely(mpdu_meta->truncated)) {
						qdf_nbuf_free(mpdu);
						continue;
					}

					dp_rx_mon_handle_full_mon(pdev,
								  ppdu_info, mpdu);
				} else {
					qdf_nbuf_free(mpdu);
					continue;
				}

				/* reset mpdu metadata and apply radiotap header over MPDU */
				qdf_mem_zero(mpdu_meta, sizeof(struct hal_rx_mon_mpdu_info));
				if (!qdf_nbuf_update_radiotap(&ppdu_info->rx_status,
							      mpdu,
							      qdf_nbuf_headroom(mpdu))) {
					dp_mon_err("failed to update radiotap pdev: %pK",
						   pdev);
				}

				dp_rx_mon_shift_pf_tag_in_headroom(mpdu,
								   pdev->soc);

				/* Deliver MPDU to osif layer */
				status = dp_rx_mon_deliver_mpdu(mon_pdev,
								mpdu,
								&ppdu_info->rx_status);

				if (status != QDF_STATUS_SUCCESS)
					qdf_nbuf_free(mpdu);
			}
		}
	}
}

/**
 * dp_rx_mon_process_ppdu ()-  Deferred monitor processing
 * This workqueue API handles:
 * a. Full monitor
 * b. Lite monitor
 *
 * @context: Opaque work context
 *
 * Return: none
 */
void dp_rx_mon_process_ppdu(void *context)
{
	struct dp_pdev *pdev = (struct dp_pdev *)context;
	struct dp_mon_pdev *mon_pdev;
	struct hal_rx_ppdu_info *ppdu_info = NULL;
	struct hal_rx_ppdu_info *temp_ppdu_info = NULL;
	struct dp_mon_pdev_be *mon_pdev_be;

	if (qdf_unlikely(!pdev)) {
		dp_mon_debug("Pdev is NULL");
		return;
	}

	mon_pdev = (struct dp_mon_pdev *)pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev)) {
		dp_mon_debug("monitor pdev is NULL");
		return;
	}

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);

	qdf_spin_lock_bh(&mon_pdev_be->rx_mon_wq_lock);
	if (!TAILQ_EMPTY(&mon_pdev_be->rx_mon_queue)) {
		TAILQ_FOREACH_SAFE(ppdu_info,
				   &mon_pdev_be->rx_mon_queue,
				   ppdu_list_elem,
				   temp_ppdu_info) {
			TAILQ_REMOVE(&mon_pdev_be->rx_mon_queue,
				     ppdu_info, ppdu_list_elem);

			mon_pdev_be->rx_mon_queue_depth--;
			dp_rx_mon_process_ppdu_info(pdev, ppdu_info);
			qdf_mem_free(ppdu_info);
		}
	}
	qdf_spin_unlock_bh(&mon_pdev_be->rx_mon_wq_lock);
}

/**
 * dp_rx_mon_add_ppdu_info_to_wq () - Add PPDU info to workqueue
 *
 * @mon_pdev: monitor pdev
 * @ppdu_info: ppdu info to be added to workqueue
 *
 * Return: SUCCESS or FAILIRE
 */

static QDF_STATUS
dp_rx_mon_add_ppdu_info_to_wq(struct dp_mon_pdev *mon_pdev,
			      struct hal_rx_ppdu_info *ppdu_info)
{
	struct dp_mon_pdev_be *mon_pdev_be =
		dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);

	/* Full monitor or lite monitor mode is not enabled, return */
	if (!mon_pdev->monitor_configured &&
	    !dp_lite_mon_is_rx_enabled(mon_pdev))
		return QDF_STATUS_E_FAILURE;

	if (qdf_likely(ppdu_info)) {
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
	return QDF_STATUS_SUCCESS;
}

void
dp_rx_mon_handle_full_mon(struct dp_pdev *pdev,
			  struct hal_rx_ppdu_info *ppdu_info,
			  qdf_nbuf_t mpdu)
{
	uint32_t wifi_hdr_len, sec_hdr_len, msdu_llc_len,
		 mpdu_buf_len, decap_hdr_pull_bytes, dir,
		 is_amsdu, amsdu_pad, frag_size, tot_msdu_len;
	struct hal_rx_mon_mpdu_info *mpdu_meta;
	struct hal_rx_mon_msdu_info *msdu_meta;
	char *hdr_desc;
	uint8_t num_frags, frag_iter, l2_hdr_offset;
	struct ieee80211_frame *wh;
	struct ieee80211_qoscntl *qos;
	void *hdr_frag_addr;
	uint32_t hdr_frag_size, frag_page_offset, pad_byte_pholder,
		 msdu_len;
	qdf_nbuf_t head_msdu, msdu_cur;
	void *frag_addr;
	bool prev_msdu_end_received = false;
	bool is_nbuf_head = true;

	/***************************************************************************
	 *********************** Non-raw packet ************************************
	 ---------------------------------------------------------------------------
	 |      | frag-0   | frag-1    | frag - 2 | frag - 3  | frag - 4 | frag - 5  |
	 | skb  | rx_hdr-1 | rx_msdu-1 | rx_hdr-2 | rx_msdu-2 | rx_hdr-3 | rx-msdu-3 |
	 ---------------------------------------------------------------------------
	 **************************************************************************/

	if (!mpdu) {
		dp_mon_debug("nbuf is NULL, return");
		return;
	}

	head_msdu = mpdu;

	mpdu_meta = (struct hal_rx_mon_mpdu_info *)qdf_nbuf_data(mpdu);

	if (mpdu_meta->decap_type == HAL_HW_RX_DECAP_FORMAT_RAW) {
		qdf_nbuf_trim_add_frag_size(mpdu,
					    qdf_nbuf_get_nr_frags(mpdu) - 1,
					    -HAL_RX_FCS_LEN, 0);
		return;
	}

	l2_hdr_offset = DP_RX_MON_NONRAW_L2_HDR_PAD_BYTE;

	/* hdr_desc points to 80211 hdr */
	hdr_desc = qdf_nbuf_get_frag_addr(mpdu, 0);

	/* Calculate Base header size */
	wifi_hdr_len = sizeof(struct ieee80211_frame);
	wh = (struct ieee80211_frame *)hdr_desc;

	dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

	if (dir == IEEE80211_FC1_DIR_DSTODS)
		wifi_hdr_len += 6;

	is_amsdu = 0;
	if (wh->i_fc[0] & QDF_IEEE80211_FC0_SUBTYPE_QOS) {
		qos = (struct ieee80211_qoscntl *)
			(hdr_desc + wifi_hdr_len);
		wifi_hdr_len += 2;

		is_amsdu = (qos->i_qos[0] & IEEE80211_QOS_AMSDU);
	}

	/*Calculate security header length based on 'Protected'
	 * and 'EXT_IV' flag
	 */
	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		char *iv = (char *)wh + wifi_hdr_len;

		if (iv[3] & KEY_EXTIV)
			sec_hdr_len = 8;
		else
			sec_hdr_len = 4;
	} else {
		sec_hdr_len = 0;
	}
	wifi_hdr_len += sec_hdr_len;

	/* MSDU related stuff LLC - AMSDU subframe header etc */
	msdu_llc_len = is_amsdu ? (DP_RX_MON_DECAP_HDR_SIZE +
				   DP_RX_MON_LLC_SIZE +
				   DP_RX_MON_SNAP_SIZE) :
				   (DP_RX_MON_LLC_SIZE + DP_RX_MON_SNAP_SIZE);

	mpdu_buf_len = wifi_hdr_len + msdu_llc_len;

	/* "Decap" header to remove from MSDU buffer */
	decap_hdr_pull_bytes = DP_RX_MON_DECAP_HDR_SIZE;

	amsdu_pad = 0;
	tot_msdu_len = 0;
	tot_msdu_len = 0;

	/*
	 * Update protocol and flow tag for MSDU
	 * update frag index in ctx_idx field.
	 * Reset head pointer data of nbuf before updating.
	 */
	QDF_NBUF_CB_RX_CTX_ID(mpdu) = 0;

	/* Construct destination address */
	hdr_frag_addr = qdf_nbuf_get_frag_addr(mpdu, 0);
	hdr_frag_size = qdf_nbuf_get_frag_size_by_idx(mpdu, 0);

	/* Adjust page frag offset to point to 802.11 header */
	qdf_nbuf_trim_add_frag_size(head_msdu, 0, -(hdr_frag_size - mpdu_buf_len), 0);

	msdu_meta = (struct hal_rx_mon_msdu_info *)(qdf_nbuf_get_frag_addr(mpdu, 1) - DP_RX_MON_PACKET_OFFSET + DP_RX_MON_NONRAW_L2_HDR_PAD_BYTE);

	msdu_len = msdu_meta->msdu_len;

	/* Adjust page frag offset to appropriate after decap header */
	frag_page_offset =
		decap_hdr_pull_bytes;
	qdf_nbuf_move_frag_page_offset(head_msdu, 1, frag_page_offset);

	frag_size = qdf_nbuf_get_frag_size_by_idx(head_msdu, 1);
	pad_byte_pholder =
		RX_MONITOR_BUFFER_SIZE - (frag_size + DP_RX_MON_PACKET_OFFSET + DP_RX_MON_NONRAW_L2_HDR_PAD_BYTE);

	if (msdu_meta->first_buffer && msdu_meta->last_buffer) {
		/* MSDU with single bufffer */
		amsdu_pad = frag_size & 0x3;
		amsdu_pad = amsdu_pad ? (4 - amsdu_pad) : 0;
		if (amsdu_pad && (amsdu_pad <= pad_byte_pholder)) {
			char *frag_addr_temp;

			qdf_nbuf_trim_add_frag_size(mpdu, 1, amsdu_pad, 0);
			frag_addr_temp =
				(char *)qdf_nbuf_get_frag_addr(mpdu, 1);
			frag_addr_temp = (frag_addr_temp +
					  qdf_nbuf_get_frag_size_by_idx(mpdu, 1)) -
				amsdu_pad;
			qdf_mem_zero(frag_addr_temp, amsdu_pad);
			amsdu_pad = 0;
		}
	} else {
		tot_msdu_len = frag_size;
		amsdu_pad = 0;
	}

	pad_byte_pholder = 0;
	for (msdu_cur = mpdu; msdu_cur;) {
		/* frag_iter will start from 0 for second skb onwards */
		if (msdu_cur == mpdu)
			frag_iter = 2;
		else
			frag_iter = 0;

		num_frags = qdf_nbuf_get_nr_frags(msdu_cur);

		for (; frag_iter < num_frags; frag_iter++) {
			/* Construct destination address
			 *  ----------------------------------------------------------
			 * |            | L2_HDR_PAD   |   Decap HDR | Payload | Pad  |
			 * |            | (First buffer)             |         |      |
			 * |            |                            /        /       |
			 * |            >Frag address points here   /        /        |
			 * |            \                          /        /         |
			 * |             \ This bytes needs to    /        /          |
			 * |              \  removed to frame pkt/        /           |
			 * |               ----------------------        /            |
			 * |                                     |     /     Add      |
			 * |                                     |    /   amsdu pad   |
			 * |   LLC HDR will be added here      <-|    |   Byte for    |
			 * |        |                            |    |   last frame  |
			 * |         >Dest addr will point       |    |    if space   |
			 * |            somewhere in this area   |    |    available  |
			 * |  And amsdu_pad will be created if   |    |               |
			 * | dint get added in last buffer       |    |               |
			 * |       (First Buffer)                |    |               |
			 *  ----------------------------------------------------------
			 */
			/* If previous msdu end has received, modify next frag's offset to point to LLC */
			if (prev_msdu_end_received) {
				hdr_frag_size = qdf_nbuf_get_frag_size_by_idx(msdu_cur, frag_iter);
				/* Adjust page frag offset to point to llc/snap header */
				qdf_nbuf_trim_add_frag_size(msdu_cur, frag_iter, -(hdr_frag_size - msdu_llc_len), 0);
				prev_msdu_end_received = false;
				continue;
			}

			frag_addr =
				qdf_nbuf_get_frag_addr(msdu_cur, frag_iter) -
						       (DP_RX_MON_PACKET_OFFSET +
						       DP_RX_MON_NONRAW_L2_HDR_PAD_BYTE);
			msdu_meta = (struct hal_rx_mon_msdu_info *)frag_addr;

			/*
			 * Update protocol and flow tag for MSDU
			 * update frag index in ctx_idx field
			 */
			QDF_NBUF_CB_RX_CTX_ID(msdu_cur) = frag_iter;

			frag_size = qdf_nbuf_get_frag_size_by_idx(msdu_cur,
					frag_iter);

			/* If Middle buffer, dont add any header */
			if ((!msdu_meta->first_buffer) &&
					(!msdu_meta->last_buffer)) {
				tot_msdu_len += frag_size;
				amsdu_pad = 0;
				pad_byte_pholder = 0;
				continue;
			}

			/* Calculate if current buffer has placeholder
			 * to accommodate amsdu pad byte
			 */
			pad_byte_pholder =
				RX_MONITOR_BUFFER_SIZE - (frag_size + (DP_RX_MON_PACKET_OFFSET +
							  DP_RX_MON_NONRAW_L2_HDR_PAD_BYTE));
			/*
			 * We will come here only only three condition:
			 * 1. Msdu with single Buffer
			 * 2. First buffer in case MSDU is spread in multiple
			 *    buffer
			 * 3. Last buffer in case MSDU is spread in multiple
			 *    buffer
			 *
			 *         First buffER | Last buffer
			 * Case 1:      1       |     1
			 * Case 2:      1       |     0
			 * Case 3:      0       |     1
			 *
			 * In 3rd case only l2_hdr_padding byte will be Zero and
			 * in other case, It will be 2 Bytes.
			 */
			if (msdu_meta->first_buffer)
				l2_hdr_offset =
					DP_RX_MON_NONRAW_L2_HDR_PAD_BYTE;
			else
				l2_hdr_offset = DP_RX_MON_RAW_L2_HDR_PAD_BYTE;

			if (msdu_meta->first_buffer) {
				/* Adjust page frag offset to point to 802.11 header */
				hdr_frag_size = qdf_nbuf_get_frag_size_by_idx(msdu_cur, frag_iter-1);
				qdf_nbuf_trim_add_frag_size(msdu_cur, frag_iter - 1, -(hdr_frag_size - (msdu_llc_len + amsdu_pad)), 0);

				/* Adjust page frag offset to appropriate after decap header */
				frag_page_offset =
					(decap_hdr_pull_bytes + l2_hdr_offset);
				if (frag_size > (decap_hdr_pull_bytes + l2_hdr_offset)) {
					qdf_nbuf_move_frag_page_offset(msdu_cur, frag_iter, frag_page_offset);
					frag_size = frag_size - (l2_hdr_offset + decap_hdr_pull_bytes);
				}


				/*
				 * Calculate new page offset and create hole
				 * if amsdu_pad required.
				 */
				tot_msdu_len = frag_size;
				/*
				 * No amsdu padding required for first frame of
				 * continuation buffer
				 */
				if (!msdu_meta->last_buffer) {
					amsdu_pad = 0;
					continue;
				}
			} else {
				tot_msdu_len += frag_size;
			}

			/* Will reach to this place in only two case:
			 * 1. Single buffer MSDU
			 * 2. Last buffer of MSDU in case of multiple buf MSDU
			 */

			/* This flag is used to identify msdu boundry */
			prev_msdu_end_received = true;
			/* Check size of buffer if amsdu padding required */
			amsdu_pad = tot_msdu_len & 0x3;
			amsdu_pad = amsdu_pad ? (4 - amsdu_pad) : 0;

			/* Create placeholder if current bufer can
			 * accommodate padding.
			 */
			if (amsdu_pad && (amsdu_pad <= pad_byte_pholder)) {
				char *frag_addr_temp;

				qdf_nbuf_trim_add_frag_size(msdu_cur,
						frag_iter,
						amsdu_pad, 0);
				frag_addr_temp = (char *)qdf_nbuf_get_frag_addr(msdu_cur,
						frag_iter);
				frag_addr_temp = (frag_addr_temp +
						qdf_nbuf_get_frag_size_by_idx(msdu_cur, frag_iter)) -
					amsdu_pad;
				qdf_mem_zero(frag_addr_temp, amsdu_pad);
				amsdu_pad = 0;
			}

			/* reset tot_msdu_len */
			tot_msdu_len = 0;
		}
		if (is_nbuf_head) {
			msdu_cur = qdf_nbuf_get_ext_list(msdu_cur);
			is_nbuf_head = false;
		} else {
			msdu_cur = qdf_nbuf_queue_next(msdu_cur);
		}
	}
}

/**
 * dp_rx_mon_flush_status_buf_queue () - Flush status buffer queue
 *
 * @pdev: DP pdev handle
 *
 *Return: void
 */
static inline void
dp_rx_mon_flush_status_buf_queue(struct dp_pdev *pdev)
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
	struct dp_mon_soc *mon_soc = soc->monitor_soc;
	struct dp_mon_soc_be *mon_soc_be = dp_get_be_mon_soc_from_dp_mon_soc(mon_soc);
	struct dp_mon_desc_pool *rx_mon_desc_pool = &mon_soc_be->rx_desc_mon;
	uint8_t work_done = 0;
	uint16_t status_buf_count;

	if (!mon_pdev_be->desc_count) {
		dp_mon_info("no of status buffer count is zero: %pK", pdev);
		return;
	}

	status_buf_count = mon_pdev_be->desc_count;
	for (idx = 0; idx < status_buf_count; idx++) {
		mon_desc = mon_pdev_be->status[idx];
		if (!mon_desc) {
			qdf_assert_always(0);
			return;
		}

		buf = mon_desc->buf_addr;

		dp_mon_add_to_free_desc_list(&desc_list, &tail, mon_desc);
		work_done++;

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

	/* Flush status buffers in queue */
	dp_rx_mon_flush_status_buf_queue(pdev);
	qdf_frag_free(mon_desc->buf_addr);
	dp_mon_add_to_free_desc_list(&desc_list, &tail, mon_desc);
	work_done = 1;
	dp_mon_buffers_replenish(soc, &soc->rxdma_mon_buf_ring[0],
				 rx_mon_desc_pool,
				 work_done,
				 &desc_list, &tail);
}

uint8_t dp_rx_mon_process_tlv_status(struct dp_pdev *pdev,
				     struct hal_rx_ppdu_info *ppdu_info,
				     void *status_frag,
				     uint16_t tlv_status,
				     union dp_mon_desc_list_elem_t **desc_list,
				     union dp_mon_desc_list_elem_t **tail)
{
	struct dp_soc *soc  = pdev->soc;
	struct dp_mon_pdev *mon_pdev = pdev->monitor_pdev;
	qdf_nbuf_t nbuf, tmp_nbuf;
	qdf_frag_t addr;
	uint8_t user_id = ppdu_info->user_id;
	uint8_t mpdu_idx = ppdu_info->mpdu_count[user_id];
	uint16_t num_frags;
	uint8_t num_buf_reaped = 0;

	if (!mon_pdev->monitor_configured &&
	    !dp_lite_mon_is_rx_enabled(mon_pdev)) {
		return num_buf_reaped;
	}

	switch (tlv_status) {
	case HAL_TLV_STATUS_HEADER: {
		/* If this is first RX_HEADER for MPDU, allocate skb
		 * else add frag to already allocated skb
		 */

		if (!ppdu_info->mpdu_info[user_id].mpdu_start_received) {

			nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
					      DP_RX_MON_MAX_MONITOR_HEADER,
					      DP_RX_MON_MAX_MONITOR_HEADER,
					      4, FALSE);

			/* Set *head_msdu->next as NULL as all msdus are
			 *                          * mapped via nr frags
			 *                                                   */
			if (!nbuf) {
				dp_mon_err("malloc failed pdev: %pK ", pdev);
				return num_buf_reaped;
			}

			qdf_nbuf_set_next(nbuf, NULL);

			ppdu_info->mpdu_q[user_id][mpdu_idx] = nbuf;

			num_frags = qdf_nbuf_get_nr_frags(nbuf);
			if (num_frags < QDF_NBUF_MAX_FRAGS) {
				qdf_nbuf_add_rx_frag(status_frag, nbuf,
						     ppdu_info->data - (unsigned char *)status_frag + 4,
						     ppdu_info->hdr_len - DP_RX_MON_RX_HDR_OFFSET,
						     DP_MON_DATA_BUFFER_SIZE,
						     true);



			} else {
				dp_mon_err("num_frags exceeding MAX frags");
				qdf_assert_always(0);
			}
			ppdu_info->mpdu_info[ppdu_info->user_id].mpdu_start_received = true;
			ppdu_info->mpdu_info[user_id].first_rx_hdr_rcvd = true;
		} else {
			if (ppdu_info->mpdu_info[user_id].decap_type ==
					HAL_HW_RX_DECAP_FORMAT_RAW) {
				return num_buf_reaped;
			}

			if (dp_lite_mon_is_rx_enabled(mon_pdev) &&
			    !dp_lite_mon_is_level_msdu(mon_pdev))
				break;

			nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];
			if (qdf_unlikely(!nbuf)) {
				dp_mon_err("nbuf is NULL");
				qdf_assert_always(0);
			}

			tmp_nbuf = qdf_get_nbuf_valid_frag(nbuf);

			if (!tmp_nbuf) {
				tmp_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
							  DP_RX_MON_MAX_MONITOR_HEADER,
							  DP_RX_MON_MAX_MONITOR_HEADER,
							  4, FALSE);
				if (qdf_unlikely(!tmp_nbuf)) {
					dp_mon_err("nbuf is NULL");
					qdf_assert_always(0);
				}
				/* add new skb to frag list */
				qdf_nbuf_append_ext_list(nbuf, tmp_nbuf,
							 qdf_nbuf_len(tmp_nbuf));
			}

			num_frags = qdf_nbuf_get_nr_frags(tmp_nbuf);
			if (num_frags < QDF_NBUF_MAX_FRAGS) {
				qdf_nbuf_add_rx_frag(status_frag,
						     tmp_nbuf,
						     ppdu_info->data - (unsigned char *)status_frag + 4,
						     ppdu_info->hdr_len - DP_RX_MON_RX_HDR_OFFSET,
						     DP_MON_DATA_BUFFER_SIZE,
						     true);
			} else {
				dp_mon_err("num_frags exceeding MAX frags");
				qdf_assert_always(0);
			}
		}
	}
	break;
	case HAL_TLV_STATUS_MON_BUF_ADDR:
	{
		struct hal_rx_mon_msdu_info *buf_info;
		struct hal_mon_packet_info *packet_info = &ppdu_info->packet_info;
		struct dp_mon_desc *mon_desc = (struct dp_mon_desc *)(uintptr_t)ppdu_info->packet_info.sw_cookie;
		struct hal_rx_mon_mpdu_info *mpdu_info;
		uint16_t frag_idx = 0;

		qdf_assert_always(mon_desc);

		if (mon_desc->magic != DP_MON_DESC_MAGIC)
			qdf_assert_always(0);

		addr = mon_desc->buf_addr;
		qdf_assert_always(addr);

		mpdu_info = &ppdu_info->mpdu_info[user_id];
		if (!mon_desc->unmapped) {
			qdf_mem_unmap_page(soc->osdev,
					   (qdf_dma_addr_t)mon_desc->paddr,
				   DP_MON_DATA_BUFFER_SIZE,
					   QDF_DMA_FROM_DEVICE);
			mon_desc->unmapped = 1;
		}
		dp_mon_add_to_free_desc_list(desc_list, tail, mon_desc);
		num_buf_reaped++;

		nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];

		mpdu_info->full_pkt = true;
		if (qdf_unlikely(!nbuf)) {
			nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
					      DP_RX_MON_MAX_MONITOR_HEADER,
					      DP_RX_MON_MAX_MONITOR_HEADER,
					      4, FALSE);

			if (!nbuf) {
				dp_mon_err("nbuf allocation failed ...");
				qdf_frag_free(addr);
				return num_buf_reaped;
			}
		}

		if (mpdu_info->decap_type == HAL_HW_RX_DECAP_FORMAT_RAW) {
			if (mpdu_info->first_rx_hdr_rcvd) {
				qdf_nbuf_remove_frag(nbuf, frag_idx, DP_MON_DATA_BUFFER_SIZE);
				qdf_nbuf_add_rx_frag(addr, nbuf,
						DP_RX_MON_PACKET_OFFSET,
						packet_info->dma_length,
						DP_MON_DATA_BUFFER_SIZE,
						false);
				mpdu_info->first_rx_hdr_rcvd = false;
			} else {
				num_frags = qdf_nbuf_get_nr_frags(nbuf);
				if (num_frags < QDF_NBUF_MAX_FRAGS) {
					qdf_nbuf_add_rx_frag(addr, nbuf,
							DP_RX_MON_PACKET_OFFSET,
							packet_info->dma_length,
							RX_MONITOR_BUFFER_SIZE,
							false);
				}
			}
		} else {
			num_frags = qdf_nbuf_get_nr_frags(nbuf);
			if (num_frags < QDF_NBUF_MAX_FRAGS) {
				qdf_nbuf_add_rx_frag(addr, nbuf,
						DP_RX_MON_NONRAW_L2_HDR_PAD_BYTE +
						DP_RX_MON_PACKET_OFFSET,
						packet_info->dma_length,
						RX_MONITOR_BUFFER_SIZE,
						false);
			}
			buf_info = addr;

			if (!ppdu_info->msdu[user_id].first_buffer) {
				buf_info->first_buffer = true;
				ppdu_info->msdu[user_id].first_buffer = true;
			} else {
				buf_info->first_buffer = false;
			}

			if (packet_info->msdu_continuation)
				buf_info->last_buffer = false;
			else
				buf_info->last_buffer = true;

			buf_info->frag_len = packet_info->dma_length;
		}

		if (qdf_unlikely(packet_info->truncated))
			mpdu_info->truncated = true;
	}
	break;
	case HAL_TLV_STATUS_MSDU_END:
	{
		struct hal_rx_mon_msdu_info *msdu_info = &ppdu_info->msdu[user_id];
		struct hal_rx_mon_msdu_info *last_buf_info;
		/* update msdu metadata at last buffer of msdu in MPDU */
		nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];
		if (!nbuf) {
			dp_mon_err(" <%d> nbuf is NULL, return user: %d mpdu_idx: %d", __LINE__, user_id, mpdu_idx);
			break;
		}
		num_frags = qdf_nbuf_get_nr_frags(nbuf);
		if (ppdu_info->mpdu_info[user_id].decap_type ==
				HAL_HW_RX_DECAP_FORMAT_RAW) {
			break;
		}
		/* This points to last buffer of MSDU . update metadata here */
		addr = qdf_nbuf_get_frag_addr(nbuf, num_frags - 1) -
					      (DP_RX_MON_PACKET_OFFSET +
					       DP_RX_MON_NONRAW_L2_HDR_PAD_BYTE);
		last_buf_info = addr;

		last_buf_info->first_msdu = msdu_info->first_msdu;
		last_buf_info->last_msdu = msdu_info->last_msdu;
		last_buf_info->decap_type = msdu_info->decap_type;
		last_buf_info->msdu_index = msdu_info->msdu_index;
		last_buf_info->user_rssi = msdu_info->user_rssi;
		last_buf_info->reception_type = msdu_info->reception_type;
		last_buf_info->msdu_len = msdu_info->msdu_len;

		dp_rx_mon_pf_tag_to_buf_headroom_2_0(nbuf, ppdu_info, pdev,
						     soc);
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
		if (!nbuf) {
			dp_mon_err(" <%d> nbuf is NULL, return user: %d mpdu_idx: %d", __LINE__, user_id, mpdu_idx);
			break;
		}
		mpdu_meta = (struct hal_rx_mon_mpdu_info *)qdf_nbuf_data(nbuf);
		mpdu_info = &ppdu_info->mpdu_info[user_id];
		mpdu_meta->decap_type = mpdu_info->decap_type;
		ppdu_info->mpdu_info[ppdu_info->user_id].mpdu_start_received = true;
	break;
	}
	case HAL_TLV_STATUS_MPDU_END:
	{
		struct hal_rx_mon_mpdu_info *mpdu_info, *mpdu_meta;
		mpdu_info = &ppdu_info->mpdu_info[user_id];
		nbuf = ppdu_info->mpdu_q[user_id][mpdu_idx];
		if (!nbuf) {
			dp_mon_err(" <%d> nbuf is NULL, return user: %d mpdu_idx: %d", __LINE__, user_id, mpdu_idx);
			break;
		}
		mpdu_meta = (struct hal_rx_mon_mpdu_info *)qdf_nbuf_data(nbuf);
		mpdu_meta->mpdu_length_err = mpdu_info->mpdu_length_err;
		mpdu_meta->fcs_err = mpdu_info->fcs_err;
		ppdu_info->rx_status.rs_fcs_err = mpdu_info->fcs_err;
		mpdu_meta->overflow_err = mpdu_info->overflow_err;
		mpdu_meta->decrypt_err = mpdu_info->decrypt_err;
		mpdu_meta->full_pkt = mpdu_info->full_pkt;
		num_frags = qdf_nbuf_get_nr_frags(nbuf);

		num_frags = qdf_nbuf_get_nr_frags(nbuf);
		ppdu_info->mpdu_q[user_id][mpdu_idx] = nbuf;
		/* reset msdu info for next msdu for same user */
		qdf_mem_zero(mpdu_info, sizeof(mpdu_info));
		ppdu_info->mpdu_info[ppdu_info->user_id].mpdu_start_received = false;
		ppdu_info->mpdu_count[user_id]++;
	}
	break;
	}
	return num_buf_reaped;
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

			work_done += dp_rx_mon_process_tlv_status(pdev,
								  ppdu_info,
								  buf,
								  tlv_status,
								  &desc_list,
								  &tail);
			rx_tlv = hal_rx_status_get_next_tlv(rx_tlv, 1);

			/* HW provides end_offset (how many bytes HW DMA'ed)
			 * as part of descriptor, use this as delimiter for
			 * status buffer
			 */
			if ((rx_tlv - rx_tlv_start) >= (end_offset + 1))
				break;

	} while ((tlv_status == HAL_TLV_STATUS_PPDU_NOT_DONE) ||
			(tlv_status == HAL_TLV_STATUS_HEADER) ||
			(tlv_status == HAL_TLV_STATUS_MPDU_END) ||
			(tlv_status == HAL_TLV_STATUS_MSDU_END) ||
			(tlv_status == HAL_TLV_STATUS_MON_BUF_ADDR) ||
			(tlv_status == HAL_TLV_STATUS_MPDU_START));

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

/**
 * dp_rx_mon_update_peer_id() - Update sw_peer_id with link peer_id
 *
 * @pdev: DP pdev handle
 * @ppdu_info: HAL PPDU Info buffer
 *
 * Return: none
 */
#ifdef WLAN_FEATURE_11BE_MLO
#define DP_PEER_ID_MASK 0x3FFF
static inline
void dp_rx_mon_update_peer_id(struct dp_pdev *pdev,
			      struct hal_rx_ppdu_info *ppdu_info)
{
	uint32_t i;
	uint16_t peer_id;
	struct dp_soc *soc = pdev->soc;
	uint32_t num_users = ppdu_info->com_info.num_users;

	for (i = 0; i < num_users; i++) {
		peer_id = ppdu_info->rx_user_status[i].sw_peer_id;
		if (peer_id == HTT_INVALID_PEER)
			continue;
		/*
		+---------------------------------------------------------------------+
		| 15 | 14 | 13 | 12 | 11 | 10 | 9 | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
		+---------------------------------------------------------------------+
		| CHIP ID | ML |                     PEER ID                          |
		+---------------------------------------------------------------------+
		*/
		peer_id &= DP_PEER_ID_MASK;
		peer_id = dp_get_link_peer_id_by_lmac_id(soc, peer_id,
							 pdev->lmac_id);
		ppdu_info->rx_user_status[i].sw_peer_id = peer_id;
	}
}
#else
static inline
void dp_rx_mon_update_peer_id(struct dp_pdev *pdev,
			      struct hal_rx_ppdu_info *ppdu_info)
{
}
#endif

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

		if ((mon_desc == mon_pdev_be->prev_rxmon_desc) &&
		    (mon_desc->cookie == mon_pdev_be->prev_rxmon_cookie)) {
			dp_mon_err("duplicate descritout found mon_pdev: %pK mon_desc: %pK cookie: %d",
				   mon_pdev, mon_desc, mon_desc->cookie);
			mon_pdev->rx_mon_stats.dup_mon_buf_cnt++;
			hal_srng_dst_get_next(hal_soc, mon_dst_srng);
			continue;
		}
		mon_pdev_be->prev_rxmon_desc = mon_desc;
		mon_pdev_be->prev_rxmon_cookie = mon_desc->cookie;

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

		if (ppdu_info)
			dp_rx_mon_update_peer_id(pdev, ppdu_info);

		/* Call enhanced stats update API */
		if (mon_pdev->enhanced_stats_en && ppdu_info)
			dp_rx_handle_ppdu_stats(soc, pdev, ppdu_info);

		/* Call API to add PPDU info workqueue */
		status = dp_rx_mon_add_ppdu_info_to_wq(mon_pdev, ppdu_info);

		if (status != QDF_STATUS_SUCCESS) {
			if (ppdu_info)
				qdf_mem_free(ppdu_info);
		}

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
	uint8_t mcs, preamble, ppdu_type, punc_mode;
	uint32_t num_msdu;

	preamble = ppdu->u.preamble;
	ppdu_type = ppdu->u.ppdu_type;
	num_msdu = ppdu_user->num_msdu;
	punc_mode = ppdu->punc_bw;

	if (ppdu_type == HAL_RX_TYPE_SU)
		mcs = ppdu->u.mcs;
	else
		mcs = ppdu_user->mcs;

	DP_STATS_INC(mon_peer, rx.mpdu_retry_cnt, ppdu_user->mpdu_retries);
	DP_STATS_INC(mon_peer, rx.punc_bw[punc_mode], num_msdu);
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
	uint16_t puncture_pattern;
	enum cdp_punctured_modes punc_mode;

	/* Align bw value as per host data structures */
	if (hal_ppdu_info->rx_status.bw == HAL_FULL_RX_BW_320)
		ppdu->u.bw = CMN_BW_320MHZ;
	else
		ppdu->u.bw = hal_ppdu_info->rx_status.bw;
	if (hal_ppdu_info->rx_status.preamble_type == HAL_RX_PKT_TYPE_11BE) {
		/* Align preamble value as per host data structures */
		ppdu->u.preamble = DOT11_BE;
		ppdu->u.stbc = hal_ppdu_info->rx_status.is_stbc;
		ppdu->u.dcm = hal_ppdu_info->rx_status.dcm;
	} else {
		ppdu->u.preamble = hal_ppdu_info->rx_status.preamble_type;
	}

	puncture_pattern = hal_ppdu_info->rx_status.punctured_pattern;
	punc_mode = dp_mon_get_puncture_type(puncture_pattern,
					     ppdu->u.bw);
	ppdu->punc_bw = punc_mode;
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
	ppdu->punc_bw = NO_PUNCTURE;
}
#endif
#endif
#ifdef QCA_RSSI_DB2DBM
void
dp_mon_rx_stats_update_rssi_dbm_params_2_0(struct dp_soc *soc,
					   struct dp_mon_pdev *mon_pdev)
{
	struct dp_mon_pdev_be *mon_pdev_be =
				dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	mon_pdev->ppdu_info.rx_status.rssi_temp_offset =
		mon_pdev_be->rssi_temp_offset;
	mon_pdev->ppdu_info.rx_status.xlna_bypass_offset =
		mon_pdev_be->xlna_bypass_offset;
	mon_pdev->ppdu_info.rx_status.xlna_bypass_threshold =
		mon_pdev_be->xlna_bypass_threshold;
	mon_pdev->ppdu_info.rx_status.min_nf_dbm =
		mon_pdev_be->min_nf_dbm;
	mon_pdev->ppdu_info.rx_status.xbar_config =
		mon_pdev_be->xbar_config;
	mon_pdev->ppdu_info.rx_status.rssi_dbm_conv_support =
		soc->features.rssi_dbm_conv_support;
}
#endif
