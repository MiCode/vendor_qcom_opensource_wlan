/*
 * Copyright (c) 2017-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 *
 */

/**
 * DOC: contains nan public API function definitions
 */

#include "wlan_nan_cfg.h"
#include "nan_main_i.h"
#include "cfg_nan.h"
#include "cfg_ucfg_api.h"
#include "wlan_nan_api.h"

/**
 * nan_cfg_init() - Initialize NAN config params
 * @psoc: Pointer to PSOC Object
 * @nan_obj: Pointer to NAN private object
 *
 * This function initialize NAN config params
 */
static void nan_cfg_init(struct wlan_objmgr_psoc *psoc,
			 struct nan_psoc_priv_obj *nan_obj)
{
	nan_obj->cfg_param.enable = cfg_get(psoc, CFG_NAN_ENABLE);
	nan_obj->cfg_param.support_mp0_discovery =
					cfg_get(psoc,
						CFG_SUPPORT_MP0_DISCOVERY);
	nan_obj->cfg_param.ndp_keep_alive_period =
					cfg_get(psoc,
						CFG_NDP_KEEP_ALIVE_PERIOD);
	nan_obj->cfg_param.max_ndp_sessions = cfg_get(psoc,
						      CFG_NDP_MAX_SESSIONS);
	nan_obj->cfg_param.max_ndi = cfg_get(psoc, CFG_NDI_MAX_SUPPORT);
	nan_obj->cfg_param.nan_feature_config =
					cfg_get(psoc, CFG_NAN_FEATURE_CONFIG);
	nan_obj->cfg_param.disable_6g_nan = cfg_get(psoc, CFG_DISABLE_6G_NAN);
	nan_obj->cfg_param.enable_nan_eht_cap =
					cfg_get(psoc, CFG_NAN_ENABLE_EHT_CAP);
	nan_obj->cfg_param.support_sta_sap_ndp = cfg_get(
						psoc,
						CFG_SAP_STA_NDP_CONCURRENCY);
	nan_obj->cfg_param.support_sta_p2p_ndp =
				cfg_get(psoc, CFG_STA_P2P_NDP_CONCURRENCY);
	nan_obj->cfg_param.prefer_nan_chan_for_p2p =
				cfg_get(psoc, CFG_PREFER_NAN_CHAN_FOR_P2P);
	nan_obj->cfg_param.nan_config = cfg_get(psoc, CFG_NAN_CONFIG);
}

/**
 * nan_cfg_dp_init() - Initialize NAN Datapath config params
 * @psoc: Pointer to PSOC Object
 * @nan_obj: Pointer to NAN private object
 *
 * This function initialize NAN config params
 */
static void nan_cfg_dp_init(struct wlan_objmgr_psoc *psoc,
			    struct nan_psoc_priv_obj *nan_obj)
{
	nan_obj->cfg_param.dp_enable = cfg_get(psoc,
					       CFG_NAN_DATAPATH_ENABLE);
	nan_obj->cfg_param.ndi_mac_randomize =
				cfg_get(psoc, CFG_NAN_RANDOMIZE_NDI_MAC);
	nan_obj->cfg_param.ndp_inactivity_timeout =
				cfg_get(psoc, CFG_NAN_NDP_INACTIVITY_TIMEOUT);
	nan_obj->cfg_param.nan_separate_iface_support =
				cfg_get(psoc, CFG_NAN_SEPARATE_IFACE_SUPP);
}

QDF_STATUS nan_cfg_psoc_open(struct wlan_objmgr_psoc *psoc)
{
	struct nan_psoc_priv_obj *nan_obj = nan_get_psoc_priv_obj(psoc);

	if (!nan_obj) {
		nan_err("nan psoc priv object is NULL");
		return QDF_STATUS_E_NULL_VALUE;
	}

	nan_cfg_init(psoc, nan_obj);
	nan_cfg_dp_init(psoc, nan_obj);

	return QDF_STATUS_SUCCESS;
}
