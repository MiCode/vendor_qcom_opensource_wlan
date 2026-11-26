/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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
 *
 */

/**
 * DOC: contains mlme target if declarations
 */

#include "target_if_mlme.h"
#include <wmi_unified_mlme_api.h>

static struct wmi_unified
*target_if_mlme_get_wmi_handle_from_vdev(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_objmgr_pdev *pdev;
	struct wmi_unified *wmi_handle;

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		target_if_err("PDEV is NULL");
		return NULL;
	}

	wmi_handle = get_wmi_unified_hdl_from_pdev(pdev);
	if (!wmi_handle) {
		target_if_err("wmi_handle is null");
		return NULL;
	}

	return wmi_handle;
}

static QDF_STATUS
target_if_mlme_send_csa_event_status_ind(struct wlan_objmgr_vdev *vdev,
					 uint8_t csa_status)
{
	wmi_unified_t wmi_handle;
	struct csa_event_status_ind params = {0};

	params.vdev_id = wlan_vdev_get_id(vdev);
	params.status = csa_status;

	wmi_handle = target_if_mlme_get_wmi_handle_from_vdev(vdev);
	if (!wmi_handle)
		return QDF_STATUS_E_FAILURE;

	return wmi_send_csa_event_status_ind(wmi_handle, params);
}

void
target_if_mlme_register_tx_ops(struct wlan_mlme_tx_ops *tx_ops)
{
	if (!tx_ops) {
		target_if_err("target if tx ops is NULL!");
		return;
	}

	tx_ops->send_csa_event_status_ind =
		target_if_mlme_send_csa_event_status_ind;
}

uint32_t target_if_fw_cck_support(struct wlan_objmgr_psoc *psoc)
{
	uint32_t cck_rx_tx_support = 0;
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("wmi handle is NULL");
		return cck_rx_tx_support;
	}

	if (wmi_service_enabled(wmi_handle,
				wmi_service_cck_rx_support_5g))
		cck_rx_tx_support |= BIT(CCK_RX_BIT);
	if (wmi_service_enabled(wmi_handle,
				wmi_service_cck_tx_support_5g))
		cck_rx_tx_support |= BIT(CCK_TX_BIT);

	return cck_rx_tx_support;
}

