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
 * DOC: target_if_pmo_apf.c
 *
 * Target interface file for pmo component to
 * send arp offload related cmd and process event.
 */

#include "target_if.h"
#include "target_if_pmo.h"
#include "wmi_unified_api.h"

QDF_STATUS
target_if_pmo_send_apf_mode_req(struct wlan_objmgr_psoc *psoc,
				uint32_t apf_mode,
				uint32_t vdev_id)
{
	QDF_STATUS status;
	wmi_unified_t wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("Invalid wmi handle");
		return QDF_STATUS_E_NULL_VALUE;
	}

	status = wmi_unified_set_apf_mode_bitmap_cmd(wmi_handle,
						     vdev_id, apf_mode);
	if (QDF_IS_STATUS_ERROR(status))
		target_if_err("Failed to set apf mode");

	return status;
}
