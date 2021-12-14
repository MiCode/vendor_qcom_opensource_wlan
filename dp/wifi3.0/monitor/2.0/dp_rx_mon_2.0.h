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

#ifndef _DP_RX_MON_2_0_H_
#define _DP_RX_MON_2_0_H_

#include <qdf_nbuf_frag.h>
#include <hal_be_api_mon.h>

/*
 * dp_rx_mon_buffers_alloc() - allocate rx monitor buffers
 * @soc: DP soc handle
 *
 * Return: QDF_STATUS_SUCCESS: Success
 *         QDF_STATUS_E_FAILURE: Error
 */
QDF_STATUS
dp_rx_mon_buffers_alloc(struct dp_soc *soc, uint32_t size);

/*
 * dp_rx_mon_buffers_free() - free rx monitor buffers
 * @soc: dp soc handle
 *
 */
void
dp_rx_mon_buffers_free(struct dp_soc *soc);

/*
 * dp_rx_mon_desc_pool_deinit() - deinit rx monitor descriptor pool
 * @soc: dp soc handle
 *
 */
void
dp_rx_mon_buf_desc_pool_deinit(struct dp_soc *soc);

/*
 * dp_rx_mon_desc_pool_deinit() - deinit rx monitor descriptor pool
 * @soc: dp soc handle
 *
 * Return: QDF_STATUS_SUCCESS: Success
 *         QDF_STATUS_E_FAILURE: Error
 */
QDF_STATUS
dp_rx_mon_buf_desc_pool_init(struct dp_soc *soc);

/*
 * dp_rx_mon_buf_desc_pool_free() - free rx monitor descriptor pool
 * @soc: dp soc handle
 *
 */
void dp_rx_mon_buf_desc_pool_free(struct dp_soc *soc);

/*
 * dp_rx_mon_buf_desc_pool_alloc() - allocate rx monitor descriptor pool
 * @soc: DP soc handle
 *
 * Return: QDF_STATUS_SUCCESS: Success
 *         QDF_STATUS_E_FAILURE: Error
 */
QDF_STATUS
dp_rx_mon_buf_desc_pool_alloc(struct dp_soc *soc);

/**
 * dp_rx_mon_stats_update_2_0 () - update rx stats
 *
 * @peer: monitor peer handle
 * @ppdu: Rx PPDU status metadata object
 * @ppdu_user: Rx PPDU user status metadata object
 *
 * Return: Void
 */
void dp_rx_mon_stats_update_2_0(struct dp_mon_peer *mon_peer,
				struct cdp_rx_indication_ppdu *ppdu,
				struct cdp_rx_stats_ppdu_user *ppdu_user);

/**
 * dp_rx_mon_populate_ppdu_usr_info_2_0 () - Populate ppdu user info
 *
 * @rx_user_status: Rx user status
 * @ppdu_user: ppdu user metadata
 *
 * Return: void
 */
void
dp_rx_mon_populate_ppdu_usr_info_2_0(struct mon_rx_user_status *rx_user_status,
				     struct cdp_rx_stats_ppdu_user *ppdu_user);

/**
 * dp_rx_mon_populate_ppdu_info_2_0 () --  Populate ppdu info
 *
 * @hal_ppdu_info: HAL PPDU info
 * @ppdu: Rx PPDU status metadata object
 *
 * Return: void
 */
void
dp_rx_mon_populate_ppdu_info_2_0(struct hal_rx_ppdu_info *hal_ppdu_info,
				 struct cdp_rx_indication_ppdu *ppdu);

/*
 * dp_rx_process_pktlog_be() - process pktlog
 * @soc: dp soc handle
 * @pdev: dp pdev handle
 * @ppdu_info: HAL PPDU info
 * @status_frag: frag pointer which needs to be added to nbuf
 * @end_offset: Offset in frag to be added to nbuf_frags
 *
 * Return: SUCCESS or Failure
 */
QDF_STATUS dp_rx_process_pktlog_be(struct dp_soc *soc, struct dp_pdev *pdev,
				   struct hal_rx_ppdu_info *ppdu_info,
				   void *status_frag, uint32_t end_offset);

#if !defined(DISABLE_MON_CONFIG)
/*
 * dp_rx_mon_process_2_0 () - Process Rx monitor interrupt
 *
 * @soc: DP soc handle
 * @int_ctx: Interrupt context
 * @mac_id: LMAC id
 * @quota: quota to reap
 */
uint32_t
dp_rx_mon_process_2_0(struct dp_soc *soc, struct dp_intr *int_ctx,
		      uint32_t mac_id, uint32_t quota);

/**
 * dp_rx_mon_process_ppdu () - RxMON Workqueue processing API
 *
 * @context: workqueue context
 */
void dp_rx_mon_process_ppdu(void *context);
#else
static uint32_t
dp_rx_mon_process_2_0(struct dp_soc *soc, struct dp_intr *int_ctx,
		      uint32_t mac_id, uint32_t quota)
{
	return 0;
}

static inline void dp_rx_mon_process_ppdu(void *context)
{
}
#endif /* DISABLE_MON_CONFIG */
#endif /* _DP_RX_MON_2_0_H_ */
