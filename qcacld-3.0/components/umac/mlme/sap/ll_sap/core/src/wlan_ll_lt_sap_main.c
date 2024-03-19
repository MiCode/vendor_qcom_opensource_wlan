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

#include "wlan_ll_lt_sap_main.h"
#include "wlan_scan_ucfg_api.h"
#include "wlan_mlme_vdev_mgr_interface.h"
#include "wlan_ll_sap_main.h"
#include "wlan_ll_lt_sap_bearer_switch.h"

bool ll_lt_sap_is_supported(void)
{
	/* To do, check the FW capability to decide if this is supported
	 * or not supported.
	 */
	return true;
}

QDF_STATUS
ll_lt_sap_get_sorted_user_config_acs_ch_list(struct wlan_objmgr_psoc *psoc,
					     uint8_t vdev_id,
					     struct sap_sel_ch_info *ch_info)
{
	struct scan_filter *filter;
	qdf_list_t *list = NULL;
	struct wlan_objmgr_pdev *pdev;
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_LL_SAP_ID);

	if (!vdev) {
		ll_sap_err("Invalid vdev for vdev_id %d", vdev_id);
		return QDF_STATUS_E_FAILURE;
	}

	pdev = wlan_vdev_get_pdev(vdev);

	filter = qdf_mem_malloc(sizeof(*filter));
	if (!filter)
		goto rel_ref;

	wlan_sap_get_user_config_acs_ch_list(vdev_id, filter);

	list = wlan_scan_get_result(pdev, filter);

	qdf_mem_free(filter);

	if (!list)
		goto rel_ref;

	status = wlan_ll_sap_sort_channel_list(vdev_id, list, ch_info);

	wlan_scan_purge_results(list);

rel_ref:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LL_SAP_ID);

	return status;
}

QDF_STATUS ll_lt_sap_init(struct wlan_objmgr_vdev *vdev)
{
	struct ll_sap_vdev_priv_obj *ll_sap_obj;
	QDF_STATUS status;

	ll_sap_obj = ll_sap_get_vdev_priv_obj(vdev);

	if (!ll_sap_obj) {
		ll_sap_err("vdev %d ll_sap obj null",
			   wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_INVAL;
	}

	ll_sap_obj->bearer_switch_ctx =
			qdf_mem_malloc(sizeof(struct bearer_switch_info));
	if (!ll_sap_obj->bearer_switch_ctx)
		return QDF_STATUS_E_NOMEM;

	qdf_atomic_init(&ll_sap_obj->bearer_switch_ctx->request_id);

	ll_sap_obj->bearer_switch_ctx->vdev = vdev;

	status = bs_sm_create(ll_sap_obj->bearer_switch_ctx);

	if (QDF_IS_STATUS_ERROR(status))
		goto bs_sm_failed;

	ll_sap_debug("vdev %d", wlan_vdev_get_id(vdev));

	return QDF_STATUS_SUCCESS;

bs_sm_failed:
	qdf_mem_free(ll_sap_obj->bearer_switch_ctx);
	return status;
}

QDF_STATUS ll_lt_sap_deinit(struct wlan_objmgr_vdev *vdev)
{
	struct ll_sap_vdev_priv_obj *ll_sap_obj;

	ll_sap_obj = ll_sap_get_vdev_priv_obj(vdev);

	if (!ll_sap_obj) {
		ll_sap_err("vdev %d ll_sap obj null",
			   wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_INVAL;
	}

	if (!ll_sap_obj->bearer_switch_ctx) {
		ll_sap_debug("vdev %d Bearer switch context is NULL",
			     wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_INVAL;
	}

	bs_sm_destroy(ll_sap_obj->bearer_switch_ctx);
	qdf_mem_free(ll_sap_obj->bearer_switch_ctx);
	ll_sap_obj->bearer_switch_ctx = NULL;

	ll_sap_debug("vdev %d", wlan_vdev_get_id(vdev));

	return QDF_STATUS_SUCCESS;
}
