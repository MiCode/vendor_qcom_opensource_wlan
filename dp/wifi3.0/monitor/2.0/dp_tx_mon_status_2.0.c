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
#include <dp_mon_2.0.h>
#include <dp_tx_mon_2.0.h>

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
	uint8_t i = 0;

	for (; i < last_frag_q_idx; i++) {
		status_frag = tx_cap_be->status_frag_queue[last_frag_q_idx];
		hal_txmon_status_free_buffer(pdev->soc->hal_soc, status_frag);
		qdf_frag_free(status_frag);
		tx_cap_be->status_frag_queue[last_frag_q_idx] = NULL;
	}
	tx_cap_be->last_frag_q_idx = 0;
}

/**
 * dp_tx_mon_dequeue_mpdu_nbuf() - API to dequeue nbuf from per user mpdu queue
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @user_id: user index
 *
 * Return: qdf_nbuf_t
 */
static qdf_nbuf_t
dp_tx_mon_dequeue_mpdu_nbuf(struct dp_tx_ppdu_info *tx_ppdu_info,
			    uint8_t user_id)
{
	/* dequeue mpdu_nbuf to the per user mpdu_q */
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;

	if (!TXMON_PPDU_HAL(tx_ppdu_info, rx_user_status) ||
	    !TXMON_PPDU_HAL(tx_ppdu_info, num_users))
		QDF_BUG(0);

	usr_mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, user_id, mpdu_q);

	return qdf_nbuf_queue_remove(usr_mpdu_q);
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
}

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
	struct dp_pdev_be *be_pdev = dp_get_be_pdev_from_dp_pdev(pdev);
	struct dp_mon_pdev_be *mpdev = be_pdev->monitor_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be = &mpdev->tx_capture_be;
	struct hal_tx_status_info *tx_status_info;
	qdf_nbuf_t mpdu_nbuf = NULL;
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;
	uint32_t usr_idx = 0;

	tx_status_info = &tx_cap_be->data_status_info;
	usr_idx = TXMON_PPDU(tx_ppdu_info, cur_usr_idx);
	usr_mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, usr_idx, mpdu_q);
	mpdu_nbuf = qdf_nbuf_queue_last(usr_mpdu_q);

	if (!mpdu_nbuf)
		QDF_BUG(0);

	qdf_nbuf_add_frag(pdev->soc->osdev,
			  TXMON_STATUS_INFO(tx_status_info, buffer),
			  mpdu_nbuf,
			  TXMON_STATUS_INFO(tx_status_info, offset),
			  TXMON_STATUS_INFO(tx_status_info, len_bytes),
			  TX_MON_STATUS_BUF_SIZE,
			  TRUE, TXMON_NO_BUFFER_SZ);
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
	struct dp_pdev_be *be_pdev = dp_get_be_pdev_from_dp_pdev(pdev);
	struct dp_mon_pdev_be *mpdev = be_pdev->monitor_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be = &mpdev->tx_capture_be;
	struct hal_tx_status_info *tx_status_info;

	tx_status_info = &tx_cap_be->prot_status_info;

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
	struct dp_pdev_be *be_pdev = dp_get_be_pdev_from_dp_pdev(pdev);
	struct dp_mon_pdev_be *mpdev = be_pdev->monitor_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be = &mpdev->tx_capture_be;
	struct hal_tx_status_info *tx_status_info;

	QDF_STATUS status = QDF_STATUS_SUCCESS;

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
	struct dp_pdev_be *be_pdev = dp_get_be_pdev_from_dp_pdev(pdev);
	struct dp_mon_pdev_be *mpdev = be_pdev->monitor_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be = &mpdev->tx_capture_be;
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
	uint8_t cur_frag_q_idx = tx_cap_be->cur_frag_q_idx;

	tx_status_prot = &tx_cap_be->prot_status_info;
	tx_status_data = &tx_cap_be->data_status_info;

	tx_prot_ppdu_info = dp_tx_mon_get_ppdu_info(pdev, TX_PROT_PPDU_INFO,
						    1, tx_cap_be->be_ppdu_id);

	if (!tx_prot_ppdu_info)
		return QDF_STATUS_E_NOMEM;

	status_frag = tx_cap_be->status_frag_queue[cur_frag_q_idx];
	tx_tlv = status_frag;

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
	if (!tx_data_ppdu_info)
		return QDF_STATUS_E_NOMEM;

	/* iterate status buffer queue */
	while (tx_cap_be->cur_frag_q_idx < tx_cap_be->last_frag_q_idx) {
		/* get status buffer from status_frag_queue */
		status_frag = tx_cap_be->status_frag_queue[cur_frag_q_idx];
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
			if ((tx_tlv - tx_tlv_start) >= TX_MON_STATUS_BUF_SIZE)
				break;

		} while (tlv_status == HAL_MON_TX_STATUS_PPDU_NOT_DONE);

		/*
		 * free status buffer after parsing
		 * is status_frag mapped to mpdu if so make sure
		 */
		qdf_frag_free(status_frag);
		tx_cap_be->status_frag_queue[cur_frag_q_idx] = NULL;
		cur_frag_q_idx = ++tx_cap_be->cur_frag_q_idx;
	}
	/* clear the frag array */
	dp_tx_mon_status_queue_free(pdev, tx_cap_be);

	if (TXMON_PPDU_HAL(tx_prot_ppdu_info, is_used)) {
		/*
		 * add dp_tx_ppdu_info to pdev queue
		 * for post processing
		 *
		 * TODO: add a threshold check and drop the ppdu info
		 */
		qdf_spin_lock_bh(&tx_cap_be->tx_mon_list_lock);
		tx_cap_be->last_prot_ppdu_info =
					tx_cap_be->tx_prot_ppdu_info;
		TAILQ_INSERT_TAIL(&tx_cap_be->tx_ppdu_info_list,
				  tx_prot_ppdu_info,
				  tx_ppdu_info_list_elem);
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
		/*
		 * add dp_tx_ppdu_info to pdev queue
		 * for post processing
		 *
		 * TODO: add a threshold check and drop the ppdu info
		 */
		qdf_spin_lock_bh(&tx_cap_be->tx_mon_list_lock);
		tx_cap_be->last_data_ppdu_info =
					tx_cap_be->tx_data_ppdu_info;
		TAILQ_INSERT_TAIL(&tx_cap_be->tx_ppdu_info_list,
				  tx_data_ppdu_info,
				  tx_ppdu_info_list_elem);
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

/*
 * dp_tx_mon_process_status_tlv() - API to processed TLV
 * invoked from interrupt handler
 *
 * @soc - DP_SOC handle
 * @pdev - DP_PDEV handle
 * @mon_ring_desc - descriptor status info
 * @addr - status buffer frag address
 *
 * Return: QDF_STATUS
 */
QDF_STATUS dp_tx_mon_process_status_tlv(struct dp_soc *soc,
					struct dp_pdev *pdev,
					struct hal_mon_desc *mon_ring_desc,
					qdf_dma_addr_t addr)
{
	struct dp_pdev_be *be_pdev = dp_get_be_pdev_from_dp_pdev(pdev);
	struct dp_mon_pdev_be *mpdev = be_pdev->monitor_pdev_be;
	struct dp_pdev_tx_capture_be *tx_cap_be = &mpdev->tx_capture_be;
	uint8_t last_frag_q_idx = tx_cap_be->last_frag_q_idx;

	if (tx_cap_be->mode == TX_MON_BE_DISABLE)
		return QDF_STATUS_E_INVAL;

	if (tx_cap_be->be_ppdu_id != mon_ring_desc->ppdu_id) {
		if (tx_cap_be->be_end_reason_bitmap &
		    (1 << HAL_TX_MON_FLUSH_DETECTED)) {
			dp_tx_mon_status_queue_free(pdev, tx_cap_be);
		} else if (tx_cap_be->be_end_reason_bitmap &
			   (1 << HAL_TX_MON_PPDU_TRUNCATED)) {
			dp_tx_mon_status_queue_free(pdev, tx_cap_be);
		} else {
			/* schedule ppdu worth information */
			dp_tx_mon_process_tlv_2_0(pdev);
		}

		/* reset end reason bitmap */
		tx_cap_be->be_end_reason_bitmap = 0;
	}

	tx_cap_be->be_ppdu_id = mon_ring_desc->ppdu_id;
	tx_cap_be->be_end_reason_bitmap |= (1 << mon_ring_desc->end_reason);

	/* get ppdu id from destination descriptor and store it in mon pdev */
	if (mon_ring_desc->empty_descriptor == 1 ||
	    mon_ring_desc->end_reason == HAL_TX_MON_FLUSH_DETECTED ||
	    mon_ring_desc->end_reason == HAL_TX_MON_PPDU_TRUNCATED) {
		/*
		 * free all page frags maintained  at pdev level queue
		 * update stats counter
		 */
		tx_cap_be->status_frag_queue[last_frag_q_idx] = (void *)addr;
		last_frag_q_idx = ++tx_cap_be->last_frag_q_idx;
		/* TODO: stats counter need to be updated */
		return QDF_STATUS_SUCCESS;
	}

	if (mon_ring_desc->end_reason == HAL_TX_MON_STATUS_BUFFER_FULL ||
	    mon_ring_desc->end_reason == HAL_TX_MON_END_OF_PPDU) {
		/*
		 * Get 64 bits sw desc virtual address from
		 * stats_buf_virtual_address,
		 * unmap status page frag
		 * add status page frag to pdev level queue
		 * add sw descriptor to local free list
		 */
		tx_cap_be->status_frag_queue[last_frag_q_idx] = (void *)addr;
		last_frag_q_idx = ++tx_cap_be->last_frag_q_idx;
		return QDF_STATUS_SUCCESS;
	}

	return QDF_STATUS_E_INVAL;
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
 *
 * Return: QDF_STATUS
 */
QDF_STATUS dp_tx_mon_process_status_tlv(struct dp_soc *soc,
					struct dp_pdev *pdev,
					struct hal_mon_desc *mon_ring_desc,
					qdf_dma_addr_t addr)
{
	return QDF_STATUS_E_INVAL;
}
#endif
