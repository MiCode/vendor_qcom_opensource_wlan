/*
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 *
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

#include <target_if_spatial_reuse.h>
#include <wlan_lmac_if_def.h>
#include <wmi_unified_api.h>
#include <target_if_vdev_mgr_tx_ops.h>

static QDF_STATUS spatial_reuse_send_cfg(struct wlan_objmgr_vdev *vdev,
					 uint8_t sr_ctrl,
					 uint8_t non_srg_max_pd_offset)
{
	struct pdev_params pparam;
	wmi_unified_t wmi_handle;

	wmi_handle = target_if_vdev_mgr_wmi_handle_get(vdev);
	if (!wmi_handle) {
		mlme_err("Failed to get WMI handle!");
		return QDF_STATUS_E_INVAL;
	}

	qdf_mem_zero(&pparam, sizeof(pparam));
	pparam.param_id = WMI_PDEV_PARAM_SET_CMD_OBSS_PD_THRESHOLD;
	if (!(sr_ctrl & NON_SRG_PD_SR_DISALLOWED) &&
	    (sr_ctrl & NON_SRG_OFFSET_PRESENT)) {
		QDF_SET_BITS(pparam.param_value, NON_SRG_SPR_ENABLE_POS,
			     NON_SRG_SPR_ENABLE_SIZE, NON_SRG_SPR_ENABLE);
		QDF_SET_BITS(pparam.param_value, NON_SRG_PARAM_VAL_DBM_POS,
			     NON_SRG_PARAM_VAL_DBM_SIZE,
			     NON_SRG_PARAM_VAL_DBM_UNIT);
		QDF_SET_BITS(pparam.param_value, NON_SRG_MAX_PD_OFFSET_POS,
			     NON_SRG_MAX_PD_OFFSET_SIZE,
			     non_srg_max_pd_offset);
	}

	return wmi_unified_pdev_param_send(wmi_handle, &pparam,
					   WILDCARD_PDEV_ID);
}

void target_if_spatial_reuse_register_tx_ops(struct wlan_lmac_if_tx_ops *tx_ops)
{
	tx_ops->spatial_reuse_tx_ops.send_cfg = spatial_reuse_send_cfg;
}

