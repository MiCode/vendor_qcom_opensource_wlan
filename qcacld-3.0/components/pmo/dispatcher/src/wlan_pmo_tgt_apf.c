/*
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
 * DOC: Implements public API for pmo to interact with target/WMI
 */

#include "wlan_pmo_tgt_api.h"
#include "wlan_pmo_obj_mgmt_public_struct.h"
#include "wlan_pmo_main.h"

QDF_STATUS pmo_tgt_set_apf_mode_req(struct wlan_objmgr_psoc *psoc,
				    uint32_t apf_mode,
				    uint32_t vdev_id)
{
	QDF_STATUS status;
	struct wlan_pmo_tx_ops pmo_tx_ops;

	pmo_debug("vdev_id: %d: APF mode:  %d",
		  vdev_id, apf_mode);

	pmo_tx_ops = GET_PMO_TX_OPS_FROM_PSOC(psoc);
	if (!pmo_tx_ops.send_apf_mode_req) {
		pmo_err("send_apf_mode_req is null");
		status = QDF_STATUS_E_NULL_VALUE;
		return status;
	}

	status = pmo_tx_ops.send_apf_mode_req(psoc, apf_mode, vdev_id);

	if (QDF_IS_STATUS_ERROR(status))
		pmo_err("Failed to send APF mode");

	return status;
}
