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
#include "dp_types.h"
#include "qdf_nbuf.h"
#include "dp_internal.h"
#include "qdf_mem.h"   /* qdf_mem_malloc,free */
#include <dp_be.h>
#include <qdf_nbuf_frag.h>
#include <hal_be_api_mon.h>
#include <dp_mon.h>
#include <dp_tx_mon_2.0.h>
#include <dp_mon_2.0.h>

#if defined(WLAN_TX_PKT_CAPTURE_ENH_BE) && defined(QCA_MONITOR_2_0_SUPPORT)
/**
 * dp_tx_mon_status_queue_free() - API to free status buffer
 * @pdev: pdev Handle
 * @tx_cap_be: pointer to tx_capture
 *
 * Return: void
 */
static void
dp_tx_mon_status_queue_free(struct dp_pdev *pdev,
			    struct dp_pdev_tx_capture_be *tx_cap_be)
{
	uint8_t last_frag_q_idx = tx_cap_be->last_frag_q_idx;
	qdf_frag_t status_frag = NULL;
	uint8_t i = tx_cap_be->cur_frag_q_idx;
	uint32_t end_offset = 0;

	for (; i < last_frag_q_idx; i++) {
		status_frag = tx_cap_be->frag_q_vec[i].frag_buf;

		if (qdf_unlikely(!status_frag))
			continue;

		end_offset = tx_cap_be->frag_q_vec[i].end_offset;
		hal_txmon_status_free_buffer(pdev->soc->hal_soc, status_frag,
					     end_offset);
		qdf_frag_free(status_frag);
		tx_cap_be->frag_q_vec[i].frag_buf = NULL;
		tx_cap_be->frag_q_vec[i].end_offset = 0;
	}
	tx_cap_be->last_frag_q_idx = 0;
	tx_cap_be->cur_frag_q_idx = 0;
}

/**
 * dp_tx_mon_enqueue_mpdu_nbuf() - API to enqueue nbuf from per user mpdu queue
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @user_id: user index
 * @mpdu_nbuf: nbuf to be enqueue
 *
 * Return: void
 */
static void
dp_tx_mon_enqueue_mpdu_nbuf(struct dp_tx_ppdu_info *tx_ppdu_info,
			    uint8_t user_id, qdf_nbuf_t mpdu_nbuf)
{
	/* enqueue mpdu_nbuf to the per user mpdu_q */
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;

	if (!TXMON_PPDU_HAL(tx_ppdu_info, rx_user_status) ||
	    !TXMON_PPDU_HAL(tx_ppdu_info, num_users))
		QDF_BUG(0);

	usr_mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, user_id, mpdu_q);

	qdf_nbuf_queue_add(usr_mpdu_q, mpdu_nbuf);
}

/*
 * TX MONITOR
 *
 * frame format
 * -------------------------------------------------------------------------
 *  FUNC   | ToDS | FromDS | ADDRESS 1 | ADDRESS 2 | ADDRESS 3 | ADDRESS 4 |
 *  ------------------------------------------------------------------------
 *  IBSS   |  0   |    0   | DA        | SA        | BSSID     | NOT USED  |
 *  TO AP  |  1   |    0   | BSSID     | SA        | DA        | NOT USED  |
 *  From AP|  0   |    1   | DA        | BSSID     | SA        | NOT USED  |
 *  WDS    |  1   |    1   | RA        | TA        | DA        | SA        |
 *  ------------------------------------------------------------------------
 *
 *  HOST GENERATED FRAME:
 *  =====================
 *     1. RTS
 *     2. CTS
 *     3. ACK
 *     4. BA
 *     5. Multi STA BA
 *
 *  control frame
 *  ------------------------------------------------------------
 *  | protocol 2b | Type 2b | subtype 4b | ToDS 1b | FromDS 1b |
 *                | Morefrag 1b | Retry 1b | pwr_mgmt 1b | More data 1b |
 *                              | protected frm 1b | order 1b |
 *  -----------------------------------------------------------
 *  control frame originated from wireless station so ToDS = FromDS = 0,
 *
 *  RTS
 *  ---------------------------------------------------------------------------
 *  | FrameCtl 2 | Duration 2 | Receiver Address 6 | Transmit address 6 | FCS |
 *  ---------------------------------------------------------------------------
 *  subtype in FC is RTS - 1101
 *  type in FC is control frame - 10
 *
 *  CTS
 *  --------------------------------------------------------
 *  | FrameCtl 2 | Duration 2 | Receiver Address 6 | FCS 4 |
 *  --------------------------------------------------------
 *  subtype in FC is CTS - 0011
 *  type in FC is control frame - 10
 *
 *  ACK
 *  --------------------------------------------------------
 *  | FrameCtl 2 | Duration 2 | Receiver Address 6 | FCS 4 |
 *  --------------------------------------------------------
 *  subtype in FC is ACK - 1011
 *  type in FC is control frame - 10
 *
 *  Block ACK
 *  --------------------------------------------------------------------------
 *  | FC 2 | Dur 2 | RA 6 | TA 6 | BA CTRL 2 | BA Information variable | FCS |
 *  --------------------------------------------------------------------------
 *
 *	Block Ack control
 *	---------------------------------------------------------------
 *	| BA ACK POLICY B0 | BA TYPE B1-B4 | Rsv B5-B11 | TID B12-B15 |
 *	---------------------------------------------------------------
 *
 *	BA ack policy
 *	0 - Normal Ack
 *	1 - No Ack
 *
 *	Block Ack Type
 *	0     - Reserved
 *	1     - extended compressed
 *	2     - compressed
 *	3     - Multi TID
 *	4-5   - Reserved
 *	6     - GCR
 *	7-9   - Reserved
 *	10    - GLK-GCR
 *	11    - Multi-STA
 *	12-15 - Reserved
 *
 *	Block Ack information
 *	----------------------------------------------------------
 *	| Block ack start seq ctrl 2 | Block ack bitmap variable |
 *	----------------------------------------------------------
 *
 *	Multi STA Block Ack Information
 *	-----------------------------------------------------------------
 *	| Per STA TID info 2 | BA start seq ctrl 2 | BA bitmap variable |
 *	-----------------------------------------------------------------
 *
 *		Per STA TID info
 *		------------------------------------
 *		| AID11 11b | Ack Type 1b | TID 4b |
 *		------------------------------------
 *		AID11 - 2045 means unassociated STA, then ACK Type and TID 0, 15
 *
 *		Mgmt/PS-POLL frame ack
 *		Ack type - 1 and TID - 15, BA_seq_ctrl & BA_bitmap - not present
 *
 *		All ack context - with no bitmap (all AMPDU success)
 *		Ack type - 1 and TID - 14, BA_seq_ctrl & BA_bitmap - not present
 *
 *		Block ack context
 *		Ack type - 0 and  TID - 0~7 BA_seq_ctrl & BA_bitmap - present
 *
 *		Ack context
 *		Ack type - 1 and TID - 0~7 BA_seq_ctrl & BA_bitmap - not present
 *
 *
 */

/**
 * dp_tx_mon_generate_cts2self_frm() - API to generate cts2self frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_cts2self_frm(struct dp_pdev *pdev,
				struct dp_tx_ppdu_info *tx_ppdu_info)
{
	/* allocate and populate CTS/ CTS2SELF frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	uint16_t duration_le = 0;
	struct ieee80211_frame_min_one *wh_min = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;

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
	tx_status_info = &tx_cap_be->prot_status_info;

	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_min = (struct ieee80211_frame_min_one *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_min, MAX_DUMMY_FRM_BODY);

	wh_min->i_fc[1] = 0;
	wh_min->i_fc[0] = (IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL |
			   IEEE80211_FC0_SUBTYPE_CTS);
	duration_le = qdf_cpu_to_le16(TXMON_PPDU_COM(tx_ppdu_info, duration));
	wh_min->i_dur[1] = (duration_le & 0xFF00) >> 8;
	wh_min->i_dur[0] = (duration_le & 0xFF);

	qdf_mem_copy(wh_min->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_min));
	dp_tx_mon_enqueue_mpdu_nbuf(tx_ppdu_info, 0, mpdu_nbuf);
}

/**
 * dp_tx_mon_generate_rts_frm() - API to generate rts frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_rts_frm(struct dp_pdev *pdev,
			   struct dp_tx_ppdu_info *tx_ppdu_info)
{
	/* allocate and populate RTS frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	uint16_t duration_le = 0;
	struct ieee80211_ctlframe_addr2 *wh_min = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;

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
	tx_status_info = &tx_cap_be->prot_status_info;
	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_min = (struct ieee80211_ctlframe_addr2 *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_min, MAX_DUMMY_FRM_BODY);

	wh_min->i_fc[1] = 0;
	wh_min->i_fc[0] = (IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL |
			   IEEE80211_FC0_SUBTYPE_RTS);
	duration_le = qdf_cpu_to_le16(TXMON_PPDU_COM(tx_ppdu_info, duration));
	wh_min->i_aidordur[1] = (duration_le & 0xFF00) >> 8;
	wh_min->i_aidordur[0] = (duration_le & 0xFF);

	if (!tx_status_info->protection_addr)
		tx_status_info = &tx_cap_be->data_status_info;
	qdf_mem_copy(wh_min->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_min->i_addr2,
		     TXMON_STATUS_INFO(tx_status_info, addr2),
		     QDF_MAC_ADDR_SIZE);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_min));
	dp_tx_mon_enqueue_mpdu_nbuf(tx_ppdu_info, 0, mpdu_nbuf);
}

/**
 * dp_tx_mon_generate_ack_frm() - API to generate ack frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_ack_frm(struct dp_pdev *pdev,
			   struct dp_tx_ppdu_info *tx_ppdu_info)
{
	/* allocate and populate ACK frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_frame_min_one *wh_addr1 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint8_t user_id = TXMON_PPDU(tx_ppdu_info, cur_usr_idx);

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
	tx_status_info = &tx_cap_be->data_status_info;
	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_addr1 = (struct ieee80211_frame_min_one *)qdf_nbuf_data(mpdu_nbuf);
	wh_addr1->i_fc[1] = 0;
	wh_addr1->i_fc[0] = (IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL |
			     IEEE80211_FC0_SUBTYPE_ACK);
	qdf_mem_copy(wh_addr1->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);
	/* set duration zero for ack frame */
	*(u_int16_t *)(&wh_addr1->i_dur) = qdf_cpu_to_le16(0x0000);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_addr1));

	dp_tx_mon_enqueue_mpdu_nbuf(tx_ppdu_info, user_id, mpdu_nbuf);
}

/**
 * dp_tx_mon_generate_3addr_qos_null_frm() - API to generate
 * 3 address qosnull frame
 *
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_3addr_qos_null_frm(struct dp_pdev *pdev,
				      struct dp_tx_ppdu_info *tx_ppdu_info)
{
	/* allocate and populate 3 address qos null frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_qosframe *wh_addr3 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint16_t duration_le = 0;
	uint8_t num_users = 0;

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
	tx_status_info = &tx_cap_be->data_status_info;
	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_addr3 = (struct ieee80211_qosframe *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_addr3, sizeof(struct ieee80211_qosframe));
	wh_addr3->i_fc[0] = 0;
	wh_addr3->i_fc[1] = 0;
	wh_addr3->i_fc[0] = (IEEE80211_FC0_VERSION_0 |
			     IEEE80211_FC0_TYPE_DATA |
			     IEEE80211_FC0_SUBTYPE_QOS_NULL);

	duration_le = qdf_cpu_to_le16(TXMON_PPDU_COM(tx_ppdu_info, duration));
	wh_addr3->i_dur[1] = (duration_le & 0xFF00) >> 8;
	wh_addr3->i_dur[0] = (duration_le & 0xFF);

	qdf_mem_copy(wh_addr3->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr3->i_addr2,
		     TXMON_STATUS_INFO(tx_status_info, addr2),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr3->i_addr3,
		     TXMON_STATUS_INFO(tx_status_info, addr3),
		     QDF_MAC_ADDR_SIZE);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_addr3));
	dp_tx_mon_enqueue_mpdu_nbuf(tx_ppdu_info, num_users, mpdu_nbuf);
}

/**
 * dp_tx_mon_generate_4addr_qos_null_frm() - API to generate
 * 4 address qos null frame
 *
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_4addr_qos_null_frm(struct dp_pdev *pdev,
				      struct dp_tx_ppdu_info *tx_ppdu_info)
{
	/* allocate and populate 4 address qos null frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_qosframe_addr4 *wh_addr4 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint16_t duration_le = 0;
	uint8_t num_users = 0;

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
	tx_status_info = &tx_cap_be->data_status_info;
	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_addr4 = (struct ieee80211_qosframe_addr4 *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_addr4, sizeof(struct ieee80211_qosframe_addr4));
	wh_addr4->i_fc[1] = 0;
	wh_addr4->i_fc[0] = (IEEE80211_FC0_VERSION_0 |
			     IEEE80211_FC0_TYPE_DATA |
			     IEEE80211_FC0_SUBTYPE_QOS_NULL);

	duration_le = qdf_cpu_to_le16(TXMON_PPDU_COM(tx_ppdu_info, duration));
	wh_addr4->i_dur[1] = (duration_le & 0xFF00) >> 8;
	wh_addr4->i_dur[0] = (duration_le & 0xFF);

	qdf_mem_copy(wh_addr4->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr4->i_addr2,
		     TXMON_STATUS_INFO(tx_status_info, addr2),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr4->i_addr3,
		     TXMON_STATUS_INFO(tx_status_info, addr3),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr4->i_addr4,
		     TXMON_STATUS_INFO(tx_status_info, addr4),
		     QDF_MAC_ADDR_SIZE);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_addr4));
	dp_tx_mon_enqueue_mpdu_nbuf(tx_ppdu_info, num_users, mpdu_nbuf);
}

#define TXMON_BA_CTRL_SZ		2
#define TXMON_BA_INFO_SZ(bitmap_sz)	((4 * (bitmap_sz)) + 6)
#define TXMON_MU_BA_ACK_FRAME_SZ(bitmap_sz)		\
		(sizeof(struct ieee80211_ctlframe_addr2) +\
		 TXMON_BA_CTRL_SZ + (bitmap_sz))

#define TXMON_BA_ACK_FRAME_SZ(bitmap_sz)		\
		(sizeof(struct ieee80211_ctlframe_addr2) +\
		 TXMON_BA_CTRL_SZ + TXMON_BA_INFO_SZ(bitmap_sz))

/**
 * dp_tx_mon_generate_mu_block_ack_frm() - API to generate MU block ack frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_mu_block_ack_frm(struct dp_pdev *pdev,
				    struct dp_tx_ppdu_info *tx_ppdu_info)
{
	/* allocate and populate MU block ack frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_ctlframe_addr2 *wh_addr2 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint8_t *frm = NULL;
	uint32_t ba_sz = 0;
	uint8_t num_users = TXMON_PPDU_HAL(tx_ppdu_info, num_users);
	uint8_t i = 0;

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
	tx_status_info = &tx_cap_be->data_status_info;
	for (i = 0; i < num_users; i++)
		ba_sz += (4 << TXMON_BA_INFO_SZ(TXMON_PPDU_USR(tx_ppdu_info,
							       i,
							       ba_bitmap_sz)));

	/*
	 * for multi sta block ack, do we need to increase the size
	 * or copy info on subsequent frame offset
	 *
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   TXMON_MU_BA_ACK_FRAME_SZ(ba_sz), 0, 4,
				   FALSE);
	if (!mpdu_nbuf) {
		/* TODO: update status and break */
		return;
	}

	wh_addr2 = (struct ieee80211_ctlframe_addr2 *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_addr2, DP_BA_ACK_FRAME_SIZE);

	wh_addr2->i_fc[0] = 0;
	wh_addr2->i_fc[1] = 0;
	wh_addr2->i_fc[0] = (IEEE80211_FC0_VERSION_0 |
			     IEEE80211_FC0_TYPE_CTL |
			     IEEE80211_FC0_BLOCK_ACK);
	*(u_int16_t *)(&wh_addr2->i_aidordur) = qdf_cpu_to_le16(0x0000);

	qdf_mem_copy(wh_addr2->i_addr2,
		     TXMON_STATUS_INFO(tx_status_info, addr2),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr2->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);

	frm = (uint8_t *)&wh_addr2[6];

	frm += 1;
	/* BA control */
	*((uint16_t *)frm) = qdf_cpu_to_le16(TXMON_PPDU_USR(tx_ppdu_info,
							    0, ba_control));
	frm += 2;

	for (i = 0; i < num_users; i++) {
		*((uint16_t *)frm) =
			qdf_cpu_to_le16((TXMON_PPDU_USR(tx_ppdu_info, i, tid) <<
					 DP_IEEE80211_BAR_CTL_TID_S) |
					(TXMON_PPDU_USR(tx_ppdu_info, i,
							aid) & 0x7FF));
		frm += 2;
		*((uint16_t *)frm) = TXMON_PPDU_USR(tx_ppdu_info,
						    i, start_seq) & 0xFFF;
		frm += 2;
		qdf_mem_copy(frm,
			     TXMON_PPDU_USR(tx_ppdu_info, i, ba_bitmap),
					    4 <<
					    TXMON_PPDU_USR(tx_ppdu_info,
							   i, ba_bitmap_sz));
		frm += 4 << TXMON_PPDU_USR(tx_ppdu_info, i, ba_bitmap_sz);
	}

	qdf_nbuf_set_pktlen(mpdu_nbuf,
			    (frm - (uint8_t *)qdf_nbuf_data(mpdu_nbuf)));

	/* always enqueue to first active user */
	dp_tx_mon_enqueue_mpdu_nbuf(tx_ppdu_info, 0, mpdu_nbuf);
}

/**
 * dp_tx_mon_generate_block_ack_frm() - API to generate block ack frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_block_ack_frm(struct dp_pdev *pdev,
				 struct dp_tx_ppdu_info *tx_ppdu_info)
{
	/* allocate and populate block ack frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_ctlframe_addr2 *wh_addr2 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint8_t *frm = NULL;
	uint8_t user_id = TXMON_PPDU(tx_ppdu_info, cur_usr_idx);
	uint32_t ba_bitmap_sz = TXMON_PPDU_USR(tx_ppdu_info,
					       user_id, ba_bitmap_sz);

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
	tx_status_info = &tx_cap_be->data_status_info;
	/*
	 * for multi sta block ack, do we need to increase the size
	 * or copy info on subsequent frame offset
	 *
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   TXMON_BA_ACK_FRAME_SZ(ba_bitmap_sz),
				   0, 4, FALSE);
	if (!mpdu_nbuf) {
		/* TODO: update status and break */
		return;
	}

	/*
	 * BA CONTROL
	 * fields required to construct block ack information
	 * B0 - BA ACK POLICY
	 *	0 - Normal ACK
	 *	1 - No ACK
	 * B1 - MULTI TID
	 * B2 - COMPRESSED BITMAP
	 *	B12
	 *	00 - Basic block ack
	 *	01 - Compressed block ack
	 *	10 - Reserved
	 *	11 - Multi tid block ack
	 * B3-B11 - Reserved
	 * B12-B15 - TID info
	 *
	 * BA INFORMATION
	 * Per sta tid info
	 *	AID: 11 bits
	 *	ACK type: 1 bit
	 *	TID: 4 bits
	 *
	 * BA SEQ CTRL
	 *
	 * BA bitmap
	 *
	 */

	wh_addr2 = (struct ieee80211_ctlframe_addr2 *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_addr2, DP_BA_ACK_FRAME_SIZE);

	wh_addr2->i_fc[0] = 0;
	wh_addr2->i_fc[1] = 0;
	wh_addr2->i_fc[0] = (IEEE80211_FC0_VERSION_0 |
			     IEEE80211_FC0_TYPE_CTL |
			     IEEE80211_FC0_BLOCK_ACK);
	*(u_int16_t *)(&wh_addr2->i_aidordur) = qdf_cpu_to_le16(0x0000);

	qdf_mem_copy(wh_addr2->i_addr2,
		     TXMON_STATUS_INFO(tx_status_info, addr2),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr2->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);

	frm = (uint8_t *)&wh_addr2[6];

	frm += 1;
	/* BA control */
	*((uint16_t *)frm) = qdf_cpu_to_le16(TXMON_PPDU_USR(tx_ppdu_info,
							    0, ba_control));
	frm += 2;
	*((uint16_t *)frm) = qdf_cpu_to_le16((TXMON_PPDU_USR(tx_ppdu_info,
							     user_id, tid) <<
					      DP_IEEE80211_BAR_CTL_TID_S) |
					     (TXMON_PPDU_USR(tx_ppdu_info,
							     user_id,
							     aid) & 0x7FF));
	frm += 2;
	*((uint16_t *)frm) = TXMON_PPDU_USR(tx_ppdu_info, user_id,
					    start_seq) & 0xFFF;

	frm += 2;
	qdf_mem_copy(frm,
		     TXMON_PPDU_USR(tx_ppdu_info, user_id, ba_bitmap),
		     4 << TXMON_PPDU_USR(tx_ppdu_info, user_id, ba_bitmap_sz));

	frm += 4 << TXMON_PPDU_USR(tx_ppdu_info, user_id, ba_bitmap_sz);

	qdf_nbuf_set_pktlen(mpdu_nbuf,
			    (frm - (uint8_t *)qdf_nbuf_data(mpdu_nbuf)));

	dp_tx_mon_enqueue_mpdu_nbuf(tx_ppdu_info, 0, mpdu_nbuf);
}

/**
 * dp_tx_mon_alloc_mpdu() - API to allocate mpdu and add that current
 * user index
 *
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_alloc_mpdu(struct dp_pdev *pdev, struct dp_tx_ppdu_info *tx_ppdu_info)
{
	qdf_nbuf_t mpdu_nbuf = NULL;
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;
	uint32_t usr_idx = 0;

	/*
	 * payload will be added as a frag to buffer
	 * and we allocate new skb for radiotap header
	 * we allocate a dummy bufffer size
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   TXMON_NO_BUFFER_SZ,
				   TXMON_NO_BUFFER_SZ,
				   4, FALSE);
	if (!mpdu_nbuf) {
		qdf_err("%s: %d No memory to allocate mpdu_nbuf!!!!!\n",
			__func__, __LINE__);
	}

	usr_idx = TXMON_PPDU(tx_ppdu_info, cur_usr_idx);
	usr_mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, usr_idx, mpdu_q);

	qdf_nbuf_queue_add(usr_mpdu_q, mpdu_nbuf);
}

/**
 * dp_tx_mon_generate_data_frm() - API to generate data frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_data_frm(struct dp_pdev *pdev,
			    struct dp_tx_ppdu_info *tx_ppdu_info)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	qdf_nbuf_t mpdu_nbuf = NULL;
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;
	uint32_t usr_idx = 0;

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

	tx_status_info = &tx_cap_be->data_status_info;
	usr_idx = TXMON_PPDU(tx_ppdu_info, cur_usr_idx);
	usr_mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, usr_idx, mpdu_q);
	mpdu_nbuf = qdf_nbuf_queue_last(usr_mpdu_q);

	if (!mpdu_nbuf)
		QDF_BUG(0);

	/* add function to either copy or add frag to frag_list */
	qdf_nbuf_add_frag(pdev->soc->osdev,
			  TXMON_STATUS_INFO(tx_status_info, buffer),
			  mpdu_nbuf,
			  TXMON_STATUS_INFO(tx_status_info, offset),
			  TXMON_STATUS_INFO(tx_status_info, length),
			  TX_MON_STATUS_BUF_SIZE,
			  true, TXMON_NO_BUFFER_SZ);
}

/**
 * dp_tx_mon_generate_prot_frm() - API to generate protection frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_generate_prot_frm(struct dp_pdev *pdev,
			    struct dp_tx_ppdu_info *tx_ppdu_info)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;

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
	tx_status_info = &tx_cap_be->prot_status_info;

	/* update medium prot type from data */
	TXMON_STATUS_INFO(tx_status_info, medium_prot_type) =
		tx_cap_be->data_status_info.medium_prot_type;

	switch (TXMON_STATUS_INFO(tx_status_info, medium_prot_type)) {
	case TXMON_MEDIUM_NO_PROTECTION:
	{
		/* no protection frame - do nothing */
		break;
	}
	case TXMON_MEDIUM_RTS_LEGACY:
	case TXMON_MEDIUM_RTS_11AC_STATIC_BW:
	case TXMON_MEDIUM_RTS_11AC_DYNAMIC_BW:
	{
		dp_tx_mon_generate_rts_frm(pdev, tx_ppdu_info);
		break;
	}
	case TXMON_MEDIUM_CTS2SELF:
	{
		dp_tx_mon_generate_cts2self_frm(pdev, tx_ppdu_info);
		break;
	}
	case TXMON_MEDIUM_QOS_NULL_NO_ACK_3ADDR:
	{
		dp_tx_mon_generate_3addr_qos_null_frm(pdev, tx_ppdu_info);
		break;
	}
	case TXMON_MEDIUM_QOS_NULL_NO_ACK_4ADDR:
	{
		dp_tx_mon_generate_4addr_qos_null_frm(pdev, tx_ppdu_info);
		break;
	}
	}
}

/**
 * dp_tx_mon_update_ppdu_info_status() - API to update frame as information
 * is stored only for that processing
 *
 * @pdev: pdev Handle
 * @tx_data_ppdu_info: pointer to data tx ppdu info
 * @tx_prot_ppdu_info: pointer to protection tx ppdu info
 * @tx_tlv_hdr: pointer to tx_tlv_hdr
 * @status_frag: pointer to fragment
 * @tlv_status: tlv status return from hal api
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
dp_tx_mon_update_ppdu_info_status(struct dp_pdev *pdev,
				  struct dp_tx_ppdu_info *tx_data_ppdu_info,
				  struct dp_tx_ppdu_info *tx_prot_ppdu_info,
				  void *tx_tlv_hdr,
				  qdf_frag_t status_frag,
				  uint32_t tlv_status)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct hal_tx_status_info *tx_status_info;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return QDF_STATUS_E_NOMEM;

	tx_cap_be = &mon_pdev_be->tx_capture_be;

	switch (tlv_status) {
	case HAL_MON_TX_FES_SETUP:
	{
		/*
		 * start of initiator window
		 *
		 * got number of user count from  fes setup tlv
		 */
		break;
	}
	case HAL_MON_RX_RESPONSE_REQUIRED_INFO:
	{
		/*
		 * start of Response window
		 *
		 * response window start and follow with
		 * RTS(sta) - cts(AP)
		 * BlockAckReq(sta) - BlockAck(AP)
		 */
		tx_status_info = &tx_cap_be->data_status_info;
		if (TXMON_STATUS_INFO(tx_status_info, reception_type) ==
		    TXMON_RESP_CTS)
			dp_tx_mon_generate_cts2self_frm(pdev,
							tx_data_ppdu_info);
		break;
	}
	case HAL_MON_TX_FES_STATUS_PROT:
	{
		TXMON_PPDU_HAL(tx_prot_ppdu_info, is_used) = 1;
		/* update timestamp */
		TXMON_PPDU_COM(tx_prot_ppdu_info,
			       tsft) = TXMON_PPDU_COM(tx_prot_ppdu_info,
						      tsft) << 1;
		TXMON_PPDU_COM(tx_prot_ppdu_info, ppdu_timestamp) =
			TXMON_PPDU_COM(tx_prot_ppdu_info, ppdu_timestamp) << 1;
		TXMON_PPDU_USR(tx_prot_ppdu_info, 0, duration) =
			TXMON_PPDU_USR(tx_prot_ppdu_info, 0, duration) << 1;

		/* based on medium protection type we need to generate frame */
		dp_tx_mon_generate_prot_frm(pdev, tx_prot_ppdu_info);
		break;
	}
	case HAL_MON_RX_FRAME_BITMAP_ACK:
	{
		/* this comes for each user */
		dp_tx_mon_generate_ack_frm(pdev, tx_data_ppdu_info);
		break;
	}
	case HAL_MON_RX_FRAME_BITMAP_BLOCK_ACK_256:
	case HAL_MON_RX_FRAME_BITMAP_BLOCK_ACK_1K:
	{
		/*
		 * this comes for each user
		 * BlockAck is not same as ACK, single frame can hold
		 * multiple BlockAck info
		 */
		tx_status_info = &tx_cap_be->data_status_info;
		if (TXMON_STATUS_INFO(tx_status_info, transmission_type) ==
		    TXMON_SU_TRANSMISSION)
			dp_tx_mon_generate_block_ack_frm(pdev,
							 tx_data_ppdu_info);
		else
			dp_tx_mon_generate_mu_block_ack_frm(pdev,
							    tx_data_ppdu_info);

		break;
	}
	case HAL_MON_TX_MPDU_START:
	{
		dp_tx_mon_alloc_mpdu(pdev, tx_data_ppdu_info);
		TXMON_PPDU_HAL(tx_data_ppdu_info, is_used) = 1;
		break;
	}
	case HAL_MON_TX_MSDU_START:
	{
		break;
	}
	case HAL_MON_TX_DATA:
	case HAL_MON_TX_BUFFER_ADDR:
	{
		TXMON_PPDU_HAL(tx_data_ppdu_info, is_used) = 1;
		dp_tx_mon_generate_data_frm(pdev, tx_data_ppdu_info);
		break;
	}
	case HAL_MON_TX_FES_STATUS_END:
	{
		break;
	}
	case HAL_MON_RESPONSE_END_STATUS_INFO:
	{
		break;
	}
	case HAL_MON_TX_FES_STATUS_START:
	{
		/* update the medium protection type */
		break;
	}
	default:
	{
		/* return or break in default case */
		break;
	}
	};

	return status;
}

/*
 * dp_tx_mon_process_tlv_2_0() - API to parse PPDU worth information
 * @pdev_handle: DP_PDEV handle
 *
 * Return: status
 */
QDF_STATUS dp_tx_mon_process_tlv_2_0(struct dp_pdev *pdev)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	struct dp_tx_ppdu_info *tx_prot_ppdu_info = NULL;
	struct dp_tx_ppdu_info *tx_data_ppdu_info = NULL;
	struct hal_tx_status_info *tx_status_prot;
	struct hal_tx_status_info *tx_status_data;
	qdf_frag_t status_frag = NULL;
	uint8_t *tx_tlv;
	uint8_t *tx_tlv_start;
	uint32_t tlv_status;
	uint32_t status;
	uint8_t num_users = 0;
	uint8_t cur_frag_q_idx;
	uint32_t end_offset = 0;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return QDF_STATUS_E_NOMEM;

	tx_cap_be = &mon_pdev_be->tx_capture_be;
	cur_frag_q_idx = tx_cap_be->cur_frag_q_idx;

	tx_status_prot = &tx_cap_be->prot_status_info;
	tx_status_data = &tx_cap_be->data_status_info;

	tx_prot_ppdu_info = dp_tx_mon_get_ppdu_info(pdev, TX_PROT_PPDU_INFO,
						    1, tx_cap_be->be_ppdu_id);

	if (!tx_prot_ppdu_info) {
		dp_mon_info("tx prot ppdu info alloc got failed!!");
		return QDF_STATUS_E_NOMEM;
	}

	status_frag = tx_cap_be->frag_q_vec[cur_frag_q_idx].frag_buf;
	end_offset = tx_cap_be->frag_q_vec[cur_frag_q_idx].end_offset;
	tx_tlv = status_frag;
	dp_mon_debug("last_frag_q_idx: %d status_frag:%pK",
		     tx_cap_be->last_frag_q_idx, status_frag);

	/* get number of user from tlv window */
	tlv_status = hal_txmon_status_get_num_users(pdev->soc->hal_soc,
						    tx_tlv, &num_users);
	if (tlv_status == HAL_MON_TX_STATUS_PPDU_NOT_DONE || !num_users) {
		dp_mon_err("window open with tlv_tag[0x%x] num_users[%d]!\n",
			   hal_tx_status_get_tlv_tag(tx_tlv), num_users);
		return QDF_STATUS_E_INVAL;
	}

	/* allocate tx_data_ppdu_info based on num_users */
	tx_data_ppdu_info = dp_tx_mon_get_ppdu_info(pdev, TX_DATA_PPDU_INFO,
						    num_users,
						    tx_cap_be->be_ppdu_id);
	if (!tx_data_ppdu_info) {
		dp_mon_info("tx prot ppdu info alloc got failed!!");
		return QDF_STATUS_E_NOMEM;
	}

	/* iterate status buffer queue */
	while (tx_cap_be->cur_frag_q_idx < tx_cap_be->last_frag_q_idx) {
		/* get status buffer from frag_q_vec */
		status_frag = tx_cap_be->frag_q_vec[cur_frag_q_idx].frag_buf;
		end_offset = tx_cap_be->frag_q_vec[cur_frag_q_idx].end_offset;
		if (qdf_unlikely(!status_frag)) {
			dp_mon_err("status frag is NULL\n");
			QDF_BUG(0);
		}

		tx_tlv = status_frag;
		tx_tlv_start = tx_tlv;
		/*
		 * parse each status buffer and populate the information to
		 * dp_tx_ppdu_info
		 */
		do {
			tlv_status = hal_txmon_status_parse_tlv(
					pdev->soc->hal_soc,
					&tx_data_ppdu_info->hal_txmon,
					&tx_prot_ppdu_info->hal_txmon,
					tx_status_data,
					tx_status_prot,
					tx_tlv, status_frag);

			status =
				dp_tx_mon_update_ppdu_info_status(
							pdev,
							tx_data_ppdu_info,
							tx_prot_ppdu_info,
							tx_tlv,
							status_frag,
							tlv_status);
			/* need api definition for hal_tx_status_get_next_tlv */
			tx_tlv = hal_tx_status_get_next_tlv(tx_tlv);
			if ((tx_tlv - tx_tlv_start) >= end_offset)
				break;
		} while ((tx_tlv - tx_tlv_start) < end_offset);

		/*
		 * free status buffer after parsing
		 * is status_frag mapped to mpdu if so make sure
		 */
		qdf_frag_free(status_frag);
		tx_cap_be->frag_q_vec[cur_frag_q_idx].frag_buf = NULL;
		tx_cap_be->frag_q_vec[cur_frag_q_idx].end_offset = 0;
		cur_frag_q_idx = ++tx_cap_be->cur_frag_q_idx;
	}

	/* clear the unreleased frag array */
	dp_tx_mon_status_queue_free(pdev, tx_cap_be);

	if (TXMON_PPDU_HAL(tx_prot_ppdu_info, is_used)) {
		if (qdf_unlikely(!TXMON_PPDU_COM(tx_prot_ppdu_info,
						 chan_num))) {
			/* update channel number, if not fetched properly */
			TXMON_PPDU_COM(tx_prot_ppdu_info,
				       chan_num) = mon_pdev->mon_chan_num;
		}

		if (qdf_unlikely(!TXMON_PPDU_COM(tx_prot_ppdu_info,
						 chan_freq))) {
			/* update channel frequency, if not fetched properly */
			TXMON_PPDU_COM(tx_prot_ppdu_info,
				       chan_freq) = mon_pdev->mon_chan_freq;
		}

		/*
		 * add dp_tx_ppdu_info to pdev queue
		 * for post processing
		 *
		 * TODO: add a threshold check and drop the ppdu info
		 */
		qdf_spin_lock_bh(&tx_cap_be->tx_mon_list_lock);
		tx_cap_be->last_prot_ppdu_info =
					tx_cap_be->tx_prot_ppdu_info;
		STAILQ_INSERT_TAIL(&tx_cap_be->tx_ppdu_info_queue,
				   tx_prot_ppdu_info,
				   tx_ppdu_info_queue_elem);
		tx_cap_be->tx_ppdu_info_list_depth++;

		tx_cap_be->tx_prot_ppdu_info = NULL;
		qdf_spin_unlock_bh(&tx_cap_be->tx_mon_list_lock);
	} else {
		/*
		 * TODO : we can also save
		 * allocated buffer for future use
		 */
		tx_prot_ppdu_info = NULL;
	}

	if (TXMON_PPDU_HAL(tx_data_ppdu_info, is_used)) {
		if (qdf_unlikely(!TXMON_PPDU_COM(tx_data_ppdu_info,
						 chan_num))) {
			/* update channel number, if not fetched properly */
			TXMON_PPDU_COM(tx_data_ppdu_info,
				       chan_num) = mon_pdev->mon_chan_num;
		}

		if (qdf_unlikely(!TXMON_PPDU_COM(tx_data_ppdu_info,
						 chan_freq))) {
			/* update channel frequency, if not fetched properly */
			TXMON_PPDU_COM(tx_data_ppdu_info,
				       chan_freq) = mon_pdev->mon_chan_freq;
		}

		/*
		 * add dp_tx_ppdu_info to pdev queue
		 * for post processing
		 *
		 * TODO: add a threshold check and drop the ppdu info
		 */
		qdf_spin_lock_bh(&tx_cap_be->tx_mon_list_lock);
		tx_cap_be->last_data_ppdu_info =
					tx_cap_be->tx_data_ppdu_info;
		STAILQ_INSERT_TAIL(&tx_cap_be->tx_ppdu_info_queue,
				   tx_data_ppdu_info,
				   tx_ppdu_info_queue_elem);
		tx_cap_be->tx_ppdu_info_list_depth++;

		tx_cap_be->tx_data_ppdu_info = NULL;
		qdf_spin_unlock_bh(&tx_cap_be->tx_mon_list_lock);
	} else {
		/*
		 * TODO : we can also save
		 * allocated buffer for future use
		 */
		tx_data_ppdu_info = NULL;
	}

	/*
	 * TODO: iterate status buffer queue and free
	 * need a wrapper function to free the status buffer
	 */
	qdf_queue_work(0, tx_cap_be->post_ppdu_workqueue,
		       &tx_cap_be->post_ppdu_work);

	return QDF_STATUS_SUCCESS;
}

/**
 * dp_tx_mon_update_end_reason() - API to update end reason
 *
 * @mon_pdev - DP_MON_PDEV handle
 * @ppdu_id - ppdu_id
 * @end_reason - monitor destiantion descriptor end reason
 *
 * Return: void
 */
void dp_tx_mon_update_end_reason(struct dp_mon_pdev *mon_pdev,
				 int ppdu_id, int end_reason)
{
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_cap_be = &mon_pdev_be->tx_capture_be;

	if (tx_cap_be->be_ppdu_id != ppdu_id)
		return;

	tx_cap_be->be_end_reason_bitmap |= (1 << end_reason);
}

/*
 * dp_tx_mon_process_status_tlv() - API to processed TLV
 * invoked from interrupt handler
 *
 * @soc - DP_SOC handle
 * @pdev - DP_PDEV handle
 * @mon_ring_desc - descriptor status info
 * @addr - status buffer frag address
 * @end_offset - end offset of buffer that has valid buffer
 *
 * Return: QDF_STATUS
 */
QDF_STATUS dp_tx_mon_process_status_tlv(struct dp_soc *soc,
					struct dp_pdev *pdev,
					struct hal_mon_desc *mon_ring_desc,
					qdf_frag_t status_frag,
					uint32_t end_offset)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be;
	uint8_t last_frag_q_idx = 0;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		goto free_status_buffer;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		goto free_status_buffer;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		goto free_status_buffer;

	tx_cap_be = &mon_pdev_be->tx_capture_be;

	if (qdf_unlikely(tx_cap_be->last_frag_q_idx >
			 MAX_STATUS_BUFFER_IN_PPDU)) {
		dp_mon_err("status frag queue for a ppdu[%d] exceed %d\n",
			   tx_cap_be->be_ppdu_id,
			   MAX_STATUS_BUFFER_IN_PPDU);
		dp_tx_mon_status_queue_free(pdev, tx_cap_be);
		goto free_status_buffer;
	}

	if (tx_cap_be->mode == TX_MON_BE_DISABLE)
		goto free_status_buffer;

	if (tx_cap_be->be_ppdu_id != mon_ring_desc->ppdu_id &&
	    tx_cap_be->last_frag_q_idx) {
		if (tx_cap_be->be_end_reason_bitmap &
		    (1 << HAL_MON_FLUSH_DETECTED)) {
			dp_tx_mon_status_queue_free(pdev, tx_cap_be);
		} else if (tx_cap_be->be_end_reason_bitmap &
			   (1 << HAL_MON_PPDU_TRUNCATED)) {
			dp_tx_mon_status_queue_free(pdev, tx_cap_be);
		} else {
			dp_mon_err("End of ppdu not seen PID:%d cur_pid:%d idx:%d",
				   tx_cap_be->be_ppdu_id,
				   mon_ring_desc->ppdu_id,
				   tx_cap_be->last_frag_q_idx);
			/* schedule ppdu worth information */
			dp_tx_mon_status_queue_free(pdev, tx_cap_be);
		}

		/* reset end reason bitmap */
		tx_cap_be->be_end_reason_bitmap = 0;
		tx_cap_be->last_frag_q_idx = 0;
		tx_cap_be->cur_frag_q_idx = 0;
	}

	tx_cap_be->be_ppdu_id = mon_ring_desc->ppdu_id;
	tx_cap_be->be_end_reason_bitmap |= (1 << mon_ring_desc->end_reason);

	last_frag_q_idx = tx_cap_be->last_frag_q_idx;

	tx_cap_be->frag_q_vec[last_frag_q_idx].frag_buf = status_frag;
	tx_cap_be->frag_q_vec[last_frag_q_idx].end_offset = end_offset;
	tx_cap_be->last_frag_q_idx++;

	if (mon_ring_desc->end_reason == HAL_MON_END_OF_PPDU) {
		if (dp_tx_mon_process_tlv_2_0(pdev) != QDF_STATUS_SUCCESS)
			dp_tx_mon_status_queue_free(pdev, tx_cap_be);
	}

	return QDF_STATUS_SUCCESS;

free_status_buffer:
	hal_txmon_status_free_buffer(pdev->soc->hal_soc,
				     status_frag, end_offset);
	qdf_frag_free(status_frag);

	return QDF_STATUS_E_NOMEM;
}

#else

/**
 * dp_tx_mon_process_status_tlv() - API to processed TLV
 * invoked from interrupt handler
 *
 * @soc - DP_SOC handle
 * @pdev - DP_PDEV handle
 * @mon_ring_desc - descriptor status info
 * @addr - status buffer frag address
 * @end_offset - end offset of buffer that has valid buffer
 *
 * Return: QDF_STATUS
 */
QDF_STATUS dp_tx_mon_process_status_tlv(struct dp_soc *soc,
					struct dp_pdev *pdev,
					struct hal_mon_desc *mon_ring_desc,
					qdf_frag_t status_frag,
					uint32_t end_offset)
{
	hal_txmon_status_free_buffer(pdev->soc->hal_soc,
				     status_frag, end_offset);
	qdf_frag_free(status_frag);

	return QDF_STATUS_E_INVAL;
}

/**
 * dp_tx_mon_update_end_reason() - API to update end reason
 *
 * @mon_pdev - DP_MON_PDEV handle
 * @ppdu_id - ppdu_id
 * @end_reason - monitor destiantion descriptor end reason
 *
 * Return: void
 */
void dp_tx_mon_update_end_reason(struct dp_mon_pdev *mon_pdev,
				 int ppdu_id, int end_reason)
{
}
#endif
