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

#ifndef _DP_TX_MON_2_0_H_
#define _DP_TX_MON_2_0_H_

#include <qdf_nbuf_frag.h>
#include <hal_be_api_mon.h>

/*
 * dp_tx_mon_buffers_alloc() - allocate tx monitor buffers
 * @soc: DP soc handle
 *
 * Return: QDF_STATUS_SUCCESS: Success
 *         QDF_STATUS_E_FAILURE: Error
 */
QDF_STATUS
dp_tx_mon_buffers_alloc(struct dp_soc *soc, uint32_t size);

/*
 * dp_tx_mon_buffers_free() - free tx monitor buffers
 * @soc: dp soc handle
 *
 */
void
dp_tx_mon_buffers_free(struct dp_soc *soc);

/*
 * dp_tx_mon_desc_pool_deinit() - deinit tx monitor descriptor pool
 * @soc: dp soc handle
 *
 */
void
dp_tx_mon_buf_desc_pool_deinit(struct dp_soc *soc);

/*
 * dp_tx_mon_desc_pool_deinit() - deinit tx monitor descriptor pool
 * @soc: dp soc handle
 *
 * Return: QDF_STATUS_SUCCESS: Success
 *         QDF_STATUS_E_FAILURE: Error
 */
QDF_STATUS
dp_tx_mon_buf_desc_pool_init(struct dp_soc *soc);

/*
 * dp_tx_mon_buf_desc_pool_free() - free tx monitor descriptor pool
 * @soc: dp soc handle
 *
 */
void dp_tx_mon_buf_desc_pool_free(struct dp_soc *soc);

/*
 * dp_tx_mon_buf_desc_pool_alloc() - allocate tx monitor descriptor pool
 * @soc: DP soc handle
 *
 * Return: QDF_STATUS_SUCCESS: Success
 *         QDF_STATUS_E_FAILURE: Error
 */
QDF_STATUS
dp_tx_mon_buf_desc_pool_alloc(struct dp_soc *soc);

/*
 * dp_tx_mon_process_status_tlv() - process status tlv
 * @soc: dp soc handle
 * @pdev: dp pdev handle
 * @mon_ring_desc: monitor ring descriptor
 * @frag_addr: frag address
 *
 */
QDF_STATUS dp_tx_mon_process_status_tlv(struct dp_soc *soc,
					struct dp_pdev *pdev,
					struct hal_mon_desc *mon_ring_desc,
					qdf_dma_addr_t addr);

/*
 * dp_tx_mon_process_2_0() - tx monitor interrupt process
 * @soc: dp soc handle
 * @int_ctx: interrupt context
 * @mac_id: mac id
 * @quota: quota to process
 *
 */
uint32_t
dp_tx_mon_process_2_0(struct dp_soc *soc, struct dp_intr *int_ctx,
		      uint32_t mac_id, uint32_t quota);

/* The maximum buffer length allocated for radiotap for monitor status buffer */
#define MAX_MONITOR_HEADER (512)
#define MAX_DUMMY_FRM_BODY (128)

#define TXMON_NO_BUFFER_SZ (64)

#define TXMON_PPDU(ppdu_info, field) ppdu_info->field
#define TXMON_PPDU_USR(ppdu_info, user_index, field) \
			ppdu_info->hal_txmon.rx_user_status[user_index].field
#define TXMON_PPDU_COM(ppdu_info, field) ppdu_info->hal_txmon.rx_status.field
#define TXMON_PPDU_HAL(ppdu_info, field) ppdu_info->hal_txmon.field

/**
 * response_type_expected - expected response type
 */
enum response_type_expected {
	TXMON_RESP_NO_RESP = 0,
	TXMON_RESP_ACK,
	TXMON_RESP_BA_64_BITMAP,
	TXMON_RESP_BA_256,
	TXMON_RESP_ACTIONNOACK,
	TXMON_RESP_ACK_BA,
	TXMON_RESP_CTS,
	TXMON_RESP_ACK_DATA,
	TXMON_RESP_NDP_ACK,
	TXMON_RESP_NDP_MODIFIED_ACK,
	TXMON_RESP_NDP_BA,
	TXMON_RESP_NDP_CTS,
	TXMON_RESP_NDP_ACK_OR_NDP_MODIFIED_ACK,
	TXMON_RESP_UL_MU_BA,
	TXMON_RESP_UL_MU_BA_AND_DATA,
	TXMON_RESP_UL_MU_CBF,
	TXMON_RESP_UL_MU_FRAMES,
	TXMON_RESP_ANY_RESP_TO_DEVICE,
	TXMON_RESP_ANY_RESP_ACCEPTED,
	TXMON_RESP_FRAMELESS_PHYRX_RESP_ACCEPTED,
	TXMON_RESP_RANGING_NDP_AND_LMR,
	TXMON_RESP_BA_512,
	TXMON_RESP_BA_1024,
	TXMON_RESP_UL_MU_RANGING_CTS2S,
	TXMON_RESP_UL_MU_RANGING_NDP,
	TXMON_RESP_UL_MU_RANGING_LMR
};

/**
 * medium_protection_type - tx monitor supported protection type
 */
enum medium_protection_type {
	TXMON_MEDIUM_NO_PROTECTION,
	TXMON_MEDIUM_RTS_LEGACY,
	TXMON_MEDIUM_RTS_11AC_STATIC_BW,
	TXMON_MEDIUM_RTS_11AC_DYNAMIC_BW,
	TXMON_MEDIUM_CTS2SELF,
	TXMON_MEDIUM_QOS_NULL_NO_ACK_3ADDR,
	TXMON_MEDIUM_QOS_NULL_NO_ACK_4ADDR,
};

/**
 * tx_ppdu_info_type - tx monitor supported ppdu type
 */
enum tx_ppdu_info_type {
	TX_PROT_PPDU_INFO,
	TX_DATA_PPDU_INFO
};

/**
 * dp_tx_ppdu_info - structure to store tx ppdu info
 * @ppdu_id: current ppdu info ppdu id
 * @frametype: ppdu info frame type
 * @cur_usr_idx: current user index of ppdu info
 * @tx_ppdu_info_dlist_elem: support adding to double linked list
 * @tx_ppdu_info_slist_elem: support adding to single linked list
 * @hal_txmon: hal tx monitor info for that ppdu
 */
struct dp_tx_ppdu_info {
	uint32_t ppdu_id;
	uint8_t frame_type;
	uint8_t cur_usr_idx;

	union {
		TAILQ_ENTRY(dp_tx_ppdu_info) tx_ppdu_info_dlist_elem;
		STAILQ_ENTRY(dp_tx_ppdu_info) tx_ppdu_info_slist_elem;
	} ulist;

	#define tx_ppdu_info_list_elem ulist.tx_ppdu_info_dlist_elem
	#define tx_ppdu_info_queue_elem ulist.tx_ppdu_info_slist_elem

	struct hal_tx_ppdu_info hal_txmon;
};

/**
 * dp_tx_monitor_drop_stats - structure to store tx monitor drop statistic
 * @ppdu_drop_cnt: ppdu drop counter
 * @mpdu_drop_cnt: mpdu drop counter
 * @tlv_drop_cnt: tlv drop counter
 */
struct dp_tx_monitor_drop_stats {
	uint64_t ppdu_drop_cnt;
	uint64_t mpdu_drop_cnt;
	uint64_t tlv_drop_cnt;
};

/**
 * dp_tx_monitor_mode - tx monitor supported mode
 * @TX_MON_BE_DISABLE: tx monitor disable
 * @TX_MON_BE_FULL_CAPTURE: tx monitor mode to capture full packet
 * @TX_MON_BE_PEER_FILTER: tx monitor mode to capture peer filter
 */
enum dp_tx_monitor_mode {
	TX_MON_BE_DISABLE,
	TX_MON_BE_FULL_CAPTURE,
	TX_MON_BE_PEER_FILTER,
};

#define TX_TAILQ_INSERT_TAIL(pdev, tx_ppdu_info)			\
	do {								\
		STAILQ_INSERT_TAIL(&pdev->tx_ppdu_info_list,		\
				   tx_ppdu_info, tx_ppdu_info_list_elem);\
		pdev->tx_ppdu_info_queue_depth++;			\
	} while (0)

#define TX_TAILQ_REMOVE(pdev, tx_ppdu_info)				\
	do {								\
		TAILQ_REMOVE(&pdev->tx_ppdu_info_list, tx_ppdu_info,	\
			     tx_ppdu_info_list_elem);			\
		pdev->tx_ppdu_info_queue_depth--;			\
	} while (0)

#define TX_TAILQ_FIRST(pdev) TAILQ_FIRST(&pdev->tx_ppdu_info_list)

#define TX_TAILQ_FOREACH_SAFE(pdev, tx_ppdu_info)			\
	do {								\
		struct dp_tx_ppdu_info *tx_ppdu_info_next = NULL;	\
		TAILQ_FOREACH_SAFE(tx_ppdu_info,			\
				   &pdev->tx_ppdu_info_list,		\
				   tx_ppdu_info_list_elem,		\
				   tx_ppdu_info_next);			\
	} while (0)

#ifndef WLAN_TX_PKT_CAPTURE_ENH_BE
/**
 * dp_pdev_tx_capture_be - info to store tx capture information in pdev
 *
 * This is a dummy structure
 */
struct dp_pdev_tx_capture_be {
};

/**
 * dp_peer_tx_capture_be: Tx monitor peer structure
 *
 * This is a dummy structure
 */
struct dp_peer_tx_capture_be {
};
#else

/**
 * dp_pdev_tx_capture_be - info to store tx capture information in pdev
 * @be_ppdu_id: current ppdu id
 * @be_end_reason_bitmap: current end reason bitmap
 * @mode: tx monitor current mode
 * @tx_mon_list_lock: spinlock protection to list
 * @post_ppdu_workqueue: tx monitor workqueue representation
 * @post_ppdu_work: tx monitor post ppdu work
 * @tx_ppdu_info_list_depth: list depth counter
 * @tx_ppdu_info_list: ppdu info list to hold ppdu
 * @defer_ppdu_info_list_depth: defer ppdu list depth counter
 * @defer_ppdu_info_list: defer ppdu info list to hold defer ppdu
 * @tx_stats: tx monitor drop stats for that mac
 * @tx_prot_ppdu_info: tx monitor protection ppdu info
 * @tx_data_ppdu_info: tx monitor data ppdu info
 * @last_prot_ppdu_info: last tx monitor protection ppdu info
 * @last_data_ppdu_info: last tx monitor data ppdu info
 * @prot_status_info: protection status info
 * @data_status_info: data status info
 * @last_frag_q_idx: last index of frag buffer
 * @cur_frag_q_idx: current index of frag buffer
 * @status_frag_queue: array of status frag queue to hold 64 status buffer
 */
struct dp_pdev_tx_capture_be {
	uint32_t be_ppdu_id;
	uint32_t be_end_reason_bitmap;
	uint32_t mode;

	qdf_spinlock_t tx_mon_list_lock;

	qdf_work_t post_ppdu_work;
	qdf_workqueue_t *post_ppdu_workqueue;

	uint32_t tx_ppdu_info_list_depth;

	TAILQ_HEAD(, dp_tx_ppdu_info) tx_ppdu_info_list;

	uint32_t defer_ppdu_info_list_depth;

	TAILQ_HEAD(, dp_tx_ppdu_info) defer_ppdu_info_list;

	struct dp_tx_monitor_drop_stats tx_stats;

	struct dp_tx_ppdu_info *tx_prot_ppdu_info;
	struct dp_tx_ppdu_info *tx_data_ppdu_info;

	struct dp_tx_ppdu_info *last_prot_ppdu_info;
	struct dp_tx_ppdu_info *last_data_ppdu_info;

	struct hal_tx_status_info prot_status_info;
	struct hal_tx_status_info data_status_info;

	uint8_t last_frag_q_idx;
	uint8_t cur_frag_q_idx;
	qdf_frag_t status_frag_queue[MAX_STATUS_BUFFER_IN_PPDU];
};

/**
 * dp_peer_tx_capture_be: Tx monitor peer structure
 *
 * need to be added here
 */
struct dp_peer_tx_capture_be {
};
#endif /* WLAN_TX_PKT_CAPTURE_ENH_BE */
#endif /* _DP_TX_MON_2_0_H_ */
