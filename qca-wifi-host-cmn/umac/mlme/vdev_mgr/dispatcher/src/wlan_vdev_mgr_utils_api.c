/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
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
 * DOC: wlan_vdev_mgr_utils_api.c
 *
 * This file provide definition for APIs to enable Tx Ops and Rx Ops registered
 * through LMAC
 */
#include <wlan_vdev_mgr_utils_api.h>
#include <wlan_vdev_mgr_tgt_if_tx_api.h>
#include <cdp_txrx_cmn_struct.h>
#include <wlan_mlme_dbg.h>
#include <qdf_module.h>
#include <wlan_vdev_mgr_tgt_if_tx_api.h>
#include <wlan_dfs_mlme_api.h>
#ifndef MOBILE_DFS_SUPPORT
#include <wlan_dfs_utils_api.h>
#endif /* MOBILE_DFS_SUPPORT */
#ifdef WLAN_FEATURE_11BE_MLO
#include <wlan_utility.h>
#include <wlan_mlo_mgr_sta.h>
#endif

static QDF_STATUS vdev_mgr_config_ratemask_update(
				uint8_t vdev_id,
				struct vdev_ratemask_params *rate_params,
				struct config_ratemask_params *param,
				uint8_t index)
{
	param->vdev_id = vdev_id;
	param->type = index;
	param->lower32 = rate_params->lower32;
	param->lower32_2 = rate_params->lower32_2;
	param->higher32 = rate_params->higher32;
	param->higher32_2 = rate_params->higher32_2;

	return QDF_STATUS_SUCCESS;
}

enum wlan_op_subtype
wlan_util_vdev_get_cdp_txrx_subtype(struct wlan_objmgr_vdev *vdev)
{
	enum QDF_OPMODE qdf_opmode;
	enum wlan_op_subtype cdp_txrx_subtype;

	qdf_opmode = wlan_vdev_mlme_get_opmode(vdev);
	switch (qdf_opmode) {
	case QDF_P2P_DEVICE_MODE:
		cdp_txrx_subtype = wlan_op_subtype_p2p_device;
		break;
	case QDF_P2P_CLIENT_MODE:
		cdp_txrx_subtype = wlan_op_subtype_p2p_cli;
		break;
	case QDF_P2P_GO_MODE:
		cdp_txrx_subtype = wlan_op_subtype_p2p_go;
		break;
	default:
		cdp_txrx_subtype = wlan_op_subtype_none;
	};

	return cdp_txrx_subtype;
}

enum wlan_op_mode
wlan_util_vdev_get_cdp_txrx_opmode(struct wlan_objmgr_vdev *vdev)
{
	enum QDF_OPMODE qdf_opmode;
	enum wlan_op_mode cdp_txrx_opmode;

	qdf_opmode = wlan_vdev_mlme_get_opmode(vdev);
	switch (qdf_opmode) {
	case QDF_STA_MODE:
		cdp_txrx_opmode = wlan_op_mode_sta;
		break;
	case QDF_SAP_MODE:
		cdp_txrx_opmode = wlan_op_mode_ap;
		break;
	case QDF_MONITOR_MODE:
		cdp_txrx_opmode = wlan_op_mode_monitor;
		break;
	case QDF_P2P_DEVICE_MODE:
		cdp_txrx_opmode = wlan_op_mode_ap;
		break;
	case QDF_P2P_CLIENT_MODE:
		cdp_txrx_opmode = wlan_op_mode_sta;
		break;
	case QDF_P2P_GO_MODE:
		cdp_txrx_opmode = wlan_op_mode_ap;
		break;
	case QDF_OCB_MODE:
		cdp_txrx_opmode = wlan_op_mode_ocb;
		break;
	case QDF_IBSS_MODE:
		cdp_txrx_opmode = wlan_op_mode_ibss;
		break;
	case QDF_NDI_MODE:
		cdp_txrx_opmode = wlan_op_mode_ndi;
		break;
	case QDF_PASSTHRU_MODE:
		cdp_txrx_opmode = wlan_op_mode_passthru;
		break;
	default:
		cdp_txrx_opmode = wlan_op_mode_unknown;
	};

	return cdp_txrx_opmode;
}

/**
 * wlan_util_vdev_mlme_set_ratemask_config() - common MLME API to fill
 * ratemask parameters of vdev_mlme object
 * @vdev_mlme: pointer to vdev_mlme object
 * @index: array index of ratemask_params
 */
QDF_STATUS
wlan_util_vdev_mlme_set_ratemask_config(struct vdev_mlme_obj *vdev_mlme,
					uint8_t index)
{
	struct config_ratemask_params rm_param = {0};
	uint8_t vdev_id;
	struct vdev_mlme_rate_info *rate_info;
	struct vdev_ratemask_params *rate_params;

	if (!vdev_mlme) {
		mlme_err("VDEV MLME is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev_id = wlan_vdev_get_id(vdev_mlme->vdev);
	rate_info = &vdev_mlme->mgmt.rate_info;
	rate_params = &rate_info->ratemask_params[index];
	vdev_mgr_config_ratemask_update(vdev_id,
					rate_params,
					&rm_param, index);

	return tgt_vdev_mgr_config_ratemask_cmd_send(vdev_mlme,
						    &rm_param);
}

qdf_export_symbol(wlan_util_vdev_mlme_set_ratemask_config);

void wlan_util_vdev_mlme_get_param(struct vdev_mlme_obj *vdev_mlme,
				   enum wlan_mlme_cfg_id param_id,
				   uint32_t *value)
{
	struct vdev_mlme_proto *mlme_proto;
	struct vdev_mlme_mgmt *mlme_mgmt;
	struct vdev_mlme_inactivity_params *inactivity_params;

	if (!vdev_mlme) {
		mlme_err("VDEV MLME is NULL");
		return;
	}
	mlme_proto = &vdev_mlme->proto;
	mlme_mgmt = &vdev_mlme->mgmt;
	inactivity_params = &mlme_mgmt->inactivity_params;

	switch (param_id) {
	case WLAN_MLME_CFG_BEACON_INTERVAL:
		*value = mlme_proto->generic.beacon_interval;
		break;
	case WLAN_MLME_CFG_SUBFER:
		*value = mlme_proto->vht_info.subfer;
		break;
	case WLAN_MLME_CFG_MUBFER:
		*value = mlme_proto->vht_info.mubfer;
		break;
	case WLAN_MLME_CFG_SUBFEE:
		*value = mlme_proto->vht_info.subfee;
		break;
	case WLAN_MLME_CFG_MUBFEE:
		*value = mlme_proto->vht_info.mubfee;
		break;
	case WLAN_MLME_CFG_IMLICIT_BF:
		*value = mlme_proto->vht_info.implicit_bf;
		break;
	case WLAN_MLME_CFG_SOUNDING_DIM:
		*value = mlme_proto->vht_info.sounding_dimension;
		break;
	case WLAN_MLME_CFG_BFEE_STS_CAP:
		*value = mlme_proto->vht_info.bfee_sts_cap;
		break;
	case WLAN_MLME_CFG_MIN_IDLE_INACTIVE_TIME:
		*value =
		      inactivity_params->keepalive_min_idle_inactive_time_secs;
		break;
	case WLAN_MLME_CFG_MAX_IDLE_INACTIVE_TIME:
		*value =
		      inactivity_params->keepalive_max_idle_inactive_time_secs;
		break;
	case WLAN_MLME_CFG_MAX_UNRESPONSIVE_INACTIVE_TIME:
		*value =
		      inactivity_params->keepalive_max_unresponsive_time_secs;
		break;
	case WLAN_MLME_CFG_RATE_FLAGS:
		*value = mlme_mgmt->rate_info.rate_flags;
		break;
	default:
		break;
	}
}

qdf_export_symbol(wlan_util_vdev_mlme_get_param);

void wlan_util_vdev_get_param(struct wlan_objmgr_vdev *vdev,
			      enum wlan_mlme_cfg_id param_id,
			      uint32_t *value)
{
	ucfg_wlan_vdev_mgr_get_param(vdev, param_id, value);
}

qdf_export_symbol(wlan_util_vdev_get_param);

#ifndef MOBILE_DFS_SUPPORT
int wlan_util_vdev_mgr_get_cac_timeout_for_vdev(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_channel *des_chan = NULL;
	struct wlan_channel *bss_chan = NULL;
	bool continue_current_cac = 0;
	int dfs_cac_timeout = 0;

	des_chan = wlan_vdev_mlme_get_des_chan(vdev);
	if (!des_chan)
		return 0;

	bss_chan = wlan_vdev_mlme_get_bss_chan(vdev);
	if (!bss_chan)
		return 0;

	if (!utils_dfs_is_cac_required(wlan_vdev_get_pdev(vdev), des_chan,
				       bss_chan, &continue_current_cac))
		return 0;

	dfs_cac_timeout = dfs_mlme_get_cac_timeout_for_freq(
				wlan_vdev_get_pdev(vdev), des_chan->ch_freq,
				des_chan->ch_cfreq2, des_chan->ch_flags);
	/* Seconds to milliseconds */
	return SECONDS_TO_MS(dfs_cac_timeout);
}
#else
int wlan_util_vdev_mgr_get_cac_timeout_for_vdev(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_err("vdev_mlme is null");
		return 0;
	}

	return vdev_mlme->mgmt.ap.cac_duration_ms;
}

void wlan_util_vdev_mgr_set_cac_timeout_for_vdev(struct wlan_objmgr_vdev *vdev,
						 uint32_t new_chan_cac_ms)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_err("vdev_mlme is null");
		return;
	}

	vdev_mlme->mgmt.ap.cac_duration_ms = new_chan_cac_ms;
}
#endif /* MOBILE_DFS_SUPPORT */

void wlan_util_vdev_mgr_set_acs_mode_for_vdev(struct wlan_objmgr_vdev *vdev,
					      bool is_acs_mode)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_err("vdev_mlme is null");
		return;
	}

	vdev_mlme->mgmt.ap.is_acs_mode = is_acs_mode;
}

bool wlan_util_vdev_mgr_get_acs_mode_for_vdev(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_err("vdev_mlme is null");
		return false;
	}

	return vdev_mlme->mgmt.ap.is_acs_mode;
}

#define FW_RESTART_TIMEOUT 30
/* This value is derived based on the 16 MLDs */
#define HOST_RESTART_TIMEOUT 520

QDF_STATUS wlan_util_vdev_mgr_get_csa_channel_switch_time(
		struct wlan_objmgr_vdev *vdev,
		uint32_t *chan_switch_time)
{
	struct vdev_mlme_obj *vdev_mlme = NULL;

	*chan_switch_time = 0;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_err("vdev_mlme is null");
		return QDF_STATUS_E_FAILURE;
	}

	/* Time between CSA count 1 and CSA count 0 is one beacon interval. */
	*chan_switch_time = vdev_mlme->proto.generic.beacon_interval;

	/* Host and FW vdev restart time */
	*chan_switch_time += FW_RESTART_TIMEOUT + HOST_RESTART_TIMEOUT;

	/* Add one beacon interval time required to send beacon on the
	 * new channel after switching to the new channel.
	 */
	*chan_switch_time += vdev_mlme->proto.generic.beacon_interval;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_util_vdev_mgr_compute_max_channel_switch_time(
		struct wlan_objmgr_vdev *vdev, uint32_t *max_chan_switch_time)
{
	QDF_STATUS status;

	status = wlan_util_vdev_mgr_get_csa_channel_switch_time(
			vdev, max_chan_switch_time);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Failed to get the CSA channel switch time");
		return status;
	}

	/* Plus the CAC time */
	*max_chan_switch_time +=
			wlan_util_vdev_mgr_get_cac_timeout_for_vdev(vdev);

	return QDF_STATUS_SUCCESS;
}

uint32_t
wlan_utils_get_vdev_remaining_channel_switch_time(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_obj *vdev_mlme = NULL;
	int32_t remaining_chan_switch_time;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme)
		return 0;

	if (!vdev_mlme->mgmt.ap.last_bcn_ts_ms)
		return 0;

	/* Remaining channel switch time is equal to the time when last beacon
	 * sent on the CSA triggered vap plus max channel switch time minus
	 * current time.
	 */
	remaining_chan_switch_time =
	    ((vdev_mlme->mgmt.ap.last_bcn_ts_ms +
	      vdev_mlme->mgmt.ap.max_chan_switch_time) -
	     qdf_mc_timer_get_system_time());

	return (remaining_chan_switch_time > 0) ?
		remaining_chan_switch_time : 0;
}

#ifdef WLAN_FEATURE_11BE_MLO
QDF_STATUS wlan_util_vdev_mgr_quiet_offload(
				struct wlan_objmgr_psoc *psoc,
				struct vdev_sta_quiet_event *quiet_event)
{
	uint8_t vdev_id;
	bool connected;
	struct wlan_objmgr_vdev *vdev;

	if (qdf_is_macaddr_zero(&quiet_event->mld_mac) &&
	    qdf_is_macaddr_zero(&quiet_event->link_mac)) {
		mlme_err("mld_mac and link mac are invalid");
		return QDF_STATUS_E_INVAL;
	}

	if (!qdf_is_macaddr_zero(&quiet_event->mld_mac)) {
		connected = wlan_get_connected_vdev_by_mld_addr(
				psoc, quiet_event->mld_mac.bytes, &vdev_id);
		if (!connected) {
			mlme_err("Can't find vdev with mld " QDF_MAC_ADDR_FMT,
				 QDF_MAC_ADDR_REF(quiet_event->mld_mac.bytes));
			return QDF_STATUS_E_INVAL;
		}
		vdev = wlan_objmgr_get_vdev_by_id_from_psoc(
				psoc, vdev_id, WLAN_MLME_OBJMGR_ID);
		if (!vdev) {
			mlme_err("Null vdev");
			return QDF_STATUS_E_INVAL;
		}
		if (wlan_vdev_mlme_is_mlo_vdev(vdev))
			mlo_sta_save_quiet_status(vdev->mlo_dev_ctx,
						  quiet_event->link_id,
						  quiet_event->quiet_status);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
	} else if (!qdf_is_macaddr_zero(&quiet_event->link_mac)) {
		connected = wlan_get_connected_vdev_from_psoc_by_bssid(
				psoc, quiet_event->link_mac.bytes, &vdev_id);
		if (!connected) {
			mlme_err("Can't find vdev with BSSID" QDF_MAC_ADDR_FMT,
				 QDF_MAC_ADDR_REF(quiet_event->link_mac.bytes));
			return QDF_STATUS_E_INVAL;
		}
		vdev = wlan_objmgr_get_vdev_by_id_from_psoc(
				psoc, vdev_id, WLAN_MLME_OBJMGR_ID);
		if (!vdev) {
			mlme_err("Null vdev");
			return QDF_STATUS_E_INVAL;
		}
		if (wlan_vdev_mlme_is_mlo_vdev(vdev))
			mlo_sta_save_quiet_status(vdev->mlo_dev_ctx,
						  wlan_vdev_get_link_id(vdev),
						  quiet_event->quiet_status);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
	}

	return QDF_STATUS_SUCCESS;
}
#endif /* WLAN_FEATURE_11BE_MLO */

QDF_STATUS wlan_util_vdev_peer_set_param_send(struct wlan_objmgr_vdev *vdev,
					      uint8_t *peer_mac_addr,
					      uint32_t param_id,
					      uint32_t param_value)
{
	return tgt_vdev_peer_set_param_send(vdev, peer_mac_addr,
					    param_id, param_value);
}

qdf_export_symbol(wlan_util_vdev_peer_set_param_send);
