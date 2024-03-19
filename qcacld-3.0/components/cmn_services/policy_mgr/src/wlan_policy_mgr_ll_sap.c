/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
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

/**
 * DOC: contains policy manager ll_sap definitions specific to the ll_sap module
 */

#include "wlan_policy_mgr_ll_sap.h"
#include "wlan_policy_mgr_public_struct.h"
#include "wlan_policy_mgr_api.h"
#include "wlan_policy_mgr_i.h"
#include "wlan_cmn.h"

struct wlan_objmgr_vdev *
wlan_policy_mgr_get_ll_lt_sap_vdev(struct wlan_objmgr_psoc *psoc)
{
	uint8_t ll_lt_sap_cnt;
	uint8_t vdev_id_list[MAX_NUMBER_OF_CONC_CONNECTIONS];
	struct wlan_objmgr_vdev *vdev;

	ll_lt_sap_cnt = policy_mgr_get_mode_specific_conn_info(
							psoc, NULL,
							vdev_id_list,
							PM_LL_LT_SAP_MODE);

	/* Currently only 1 ll_lt_sap is supported */
	if (ll_lt_sap_cnt != 1) {
		policy_mgr_err("invalid number of ll_lt_sap %d", ll_lt_sap_cnt);
		return NULL;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id_list[0],
						    WLAN_LL_SAP_ID);
	if (!vdev)
		policy_mgr_err("vdev is NULL");
	return vdev;
}
