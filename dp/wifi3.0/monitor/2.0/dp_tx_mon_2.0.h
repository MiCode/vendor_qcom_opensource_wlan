/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021,2022 Qualcomm Innovation Center, Inc. All rights reserved.
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
void dp_tx_mon_process_status_tlv(struct dp_soc *soc,
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

#endif /* _DP_TX_MON_2_0_H_ */
