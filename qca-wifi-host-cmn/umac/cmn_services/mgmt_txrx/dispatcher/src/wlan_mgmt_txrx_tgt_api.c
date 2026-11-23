/*
 * Copyright (c) 2016-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

/**
 *  DOC:    wlan_mgmt_txrx_tgt_api.c
 *  This file contains mgmt txrx public API definitions for
 *  southbound interface.
 */

#include <wmi_unified_param.h>

#include "wlan_mgmt_txrx_tgt_api.h"
#include "wlan_mgmt_txrx_utils_api.h"
#include "../../core/src/wlan_mgmt_txrx_main_i.h"
#include "wlan_objmgr_psoc_obj.h"
#include "wlan_objmgr_peer_obj.h"
#include "wlan_objmgr_pdev_obj.h"
#include "wlan_mgmt_txrx_rx_reo_tgt_api.h"

void mgmt_txrx_frame_hex_dump(void *frame_data, int frame_len, bool is_tx)
{
	wlan_mgmt_txrx_frame_hex_dump(frame_data, frame_len, is_tx);
}

QDF_STATUS tgt_mgmt_txrx_rx_frame_handler(
			struct wlan_objmgr_psoc *psoc,
			qdf_nbuf_t buf,
			struct mgmt_rx_event_params *mgmt_rx_params)
{
	return wlan_mgmt_txrx_rx_frame_handler(psoc, buf, mgmt_rx_params);
}

QDF_STATUS tgt_mgmt_txrx_tx_completion_handler(
			struct wlan_objmgr_pdev *pdev,
			uint32_t desc_id, uint32_t status,
			void *tx_compl_params)
{
	return wlan_mgmt_txrx_tx_completion_handler(pdev, desc_id, status,
					       tx_compl_params);
}

qdf_nbuf_t tgt_mgmt_txrx_get_nbuf_from_desc_id(
			struct wlan_objmgr_pdev *pdev,
			uint32_t desc_id)
{
	return mgmt_txrx_get_nbuf_from_desc_id(pdev, desc_id);
}

struct wlan_objmgr_peer *
tgt_mgmt_txrx_get_peer_from_desc_id(
			struct wlan_objmgr_pdev *pdev,
			uint32_t desc_id)
{
	return mgmt_txrx_get_peer_from_desc_id(pdev, desc_id);
}

uint8_t tgt_mgmt_txrx_get_vdev_id_from_desc_id(
			struct wlan_objmgr_pdev *pdev,
			uint32_t desc_id)
{
	struct mgmt_txrx_priv_pdev_context *mgmt_txrx_pdev_ctx;
	struct mgmt_txrx_desc_elem_t *mgmt_desc;
	uint8_t vdev_id;

	mgmt_txrx_pdev_ctx = (struct mgmt_txrx_priv_pdev_context *)
			wlan_objmgr_pdev_get_comp_private_obj(pdev,
				WLAN_UMAC_COMP_MGMT_TXRX);
	if (!mgmt_txrx_pdev_ctx) {
		mgmt_txrx_err("Mgmt txrx context empty for pdev %pK", pdev);
		goto fail;
	}
	if (desc_id >= MGMT_DESC_POOL_MAX) {
		mgmt_txrx_err("desc_id:%u is out of bounds", desc_id);
		goto fail;
	}

	mgmt_desc = &mgmt_txrx_pdev_ctx->mgmt_desc_pool.pool[desc_id];
	if (!mgmt_desc || !mgmt_desc->in_use) {
		mgmt_txrx_err("Mgmt descriptor unavailable for id %d pdev %pK",
				desc_id, pdev);
		goto fail;
	}

	vdev_id = mgmt_desc->vdev_id;
	return vdev_id;

fail:
	return WLAN_UMAC_VDEV_ID_MAX;
}

uint32_t tgt_mgmt_txrx_get_free_desc_pool_count(
			struct wlan_objmgr_pdev *pdev)
{
	struct mgmt_txrx_priv_pdev_context *mgmt_txrx_pdev_ctx;
	uint32_t free_desc_count = WLAN_INVALID_MGMT_DESC_COUNT;

	mgmt_txrx_pdev_ctx = (struct mgmt_txrx_priv_pdev_context *)
			wlan_objmgr_pdev_get_comp_private_obj(pdev,
			WLAN_UMAC_COMP_MGMT_TXRX);
	if (!mgmt_txrx_pdev_ctx) {
		mgmt_txrx_err("Mgmt txrx context empty for pdev %pK", pdev);
		goto fail;
	}

	free_desc_count = qdf_list_size(
		&(mgmt_txrx_pdev_ctx->mgmt_desc_pool.free_list));

fail:
	return free_desc_count;
}

QDF_STATUS
tgt_mgmt_txrx_register_ev_handler(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_mgmt_txrx_tx_ops *mgmt_txrx_tx_ops;

	mgmt_txrx_tx_ops = wlan_psoc_get_mgmt_txrx_txops(psoc);
	if (!mgmt_txrx_tx_ops) {
		mgmt_txrx_err("txops is null for mgmt txrx module");
		return QDF_STATUS_E_NULL_VALUE;
	}

	if (mgmt_txrx_tx_ops->reg_ev_handler)
		return mgmt_txrx_tx_ops->reg_ev_handler(psoc);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
tgt_mgmt_txrx_unregister_ev_handler(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_mgmt_txrx_tx_ops *mgmt_txrx_tx_ops;

	mgmt_txrx_tx_ops = wlan_psoc_get_mgmt_txrx_txops(psoc);
	if (!mgmt_txrx_tx_ops) {
		mgmt_txrx_err("txops is null for mgmt txrx module");
		return QDF_STATUS_E_NULL_VALUE;
	}

	if (mgmt_txrx_tx_ops->unreg_ev_handler)
		return mgmt_txrx_tx_ops->unreg_ev_handler(psoc);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS tgt_mgmt_txrx_process_rx_frame(
			struct wlan_objmgr_pdev *pdev,
			qdf_nbuf_t buf,
			struct mgmt_rx_event_params *mgmt_rx_params)
{
	QDF_STATUS status;
	struct wlan_lmac_if_mgmt_txrx_tx_ops *mgmt_txrx_tx_ops;

	mgmt_txrx_tx_ops = wlan_pdev_get_mgmt_txrx_txops(pdev);
	if (!mgmt_txrx_tx_ops) {
		mgmt_txrx_err("txops is null for mgmt txrx module");
		qdf_nbuf_free(buf);
		free_mgmt_rx_event_params(mgmt_rx_params);
		return QDF_STATUS_E_NULL_VALUE;
	}

	/* Call the legacy handler to actually process and deliver frames */
	status = mgmt_txrx_tx_ops->rx_frame_legacy_handler(pdev, buf,
							   mgmt_rx_params);
	/**
	 * Free up the mgmt rx params.
	 * nbuf shouldn't be freed here as it is taken care by
	 * rx_frame_legacy_handler.
	 */
	free_mgmt_rx_event_params(mgmt_rx_params);

	return status;
}

QDF_STATUS tgt_mgmt_txrx_rx_frame_entry(
			struct wlan_objmgr_pdev *pdev,
			qdf_nbuf_t buf,
			struct mgmt_rx_event_params *mgmt_rx_params)
{
	/* Call the MGMT Rx REO handler */
	return tgt_mgmt_rx_reo_frame_handler(pdev, buf, mgmt_rx_params);
}
