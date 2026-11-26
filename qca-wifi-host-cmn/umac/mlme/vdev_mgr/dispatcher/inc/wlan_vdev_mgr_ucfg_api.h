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
 * DOC: wlan_vdev_mgr_ucfg_api.h
 *
 * This header file provides definitions to data structures required
 * for mlme ucfg and declarations for ucfg public APIs
 */

#ifndef __WLAN_VDEV_MGR_UCFG_API_H__
#define __WLAN_VDEV_MGR_UCFG_API_H__

#include <wlan_objmgr_vdev_obj.h>
#include <wlan_vdev_mgr_tgt_if_tx_defs.h>
#include <qdf_nbuf.h>
#include <include/wlan_vdev_mlme.h>

enum wlan_mlme_cfg_id {
	WLAN_MLME_CFG_BEACON_INTERVAL,
	WLAN_MLME_CFG_SUBFER,
	WLAN_MLME_CFG_MUBFER,
	WLAN_MLME_CFG_SUBFEE,
	WLAN_MLME_CFG_MUBFEE,
	WLAN_MLME_CFG_IMLICIT_BF,
	WLAN_MLME_CFG_SOUNDING_DIM,
	WLAN_MLME_CFG_BFEE_STS_CAP,
	WLAN_MLME_CFG_MIN_IDLE_INACTIVE_TIME,
	WLAN_MLME_CFG_MAX_IDLE_INACTIVE_TIME,
	WLAN_MLME_CFG_MAX_UNRESPONSIVE_INACTIVE_TIME,
	WLAN_MLME_CFG_RATE_FLAGS,
	WLAN_MLME_CFG_UAPSD,
	WLAN_MLME_CFG_TX_ENCAP_TYPE,
	WLAN_MLME_CFG_RX_DECAP_TYPE,
	WLAN_MLME_CFG_MAX
};

/**
 * ucfg_wlan_vdev_mgr_get_param() - ucfg MLME API to
 * get value from mlme vdev mgr component
 * @vdev: pointer to vdev object
 * @param_id: param of type wlan_mlme_cfg_id
 * @param_value: pointer to store the value of mlme vdev mgr
 *
 * Return: void
 */
void ucfg_wlan_vdev_mgr_get_param(struct wlan_objmgr_vdev *vdev,
				  enum wlan_mlme_cfg_id param_id,
				  uint32_t *param_value);

/**
 * ucfg_wlan_vdev_mgr_get_param_ssid() - ucfg MLME API to
 * get ssid from mlme vdev mgr component
 * @vdev: pointer to vdev object
 * @ssid: pointer to store the ssid
 * @ssid_len: pointer to store the ssid length value
 *
 * Return: void
 */
void ucfg_wlan_vdev_mgr_get_param_ssid(struct wlan_objmgr_vdev *vdev,
				       uint8_t *ssid,
				       uint8_t *ssid_len);

/**
 * ucfg_wlan_vdev_mgr_get_param_bssid() - ucfg MLME API to
 * get bssid from mlme vdev mgr component
 * @vdev: pointer to vdev object
 * @bssid: pointer to store the bssid
 *
 */
void ucfg_wlan_vdev_mgr_get_param_bssid(
				struct wlan_objmgr_vdev *vdev,
				uint8_t *bssid);

/**
 * ucfg_wlan_vdev_mgr_get_beacon_buffer() - ucfg MLME API to
 * get beacon buffer from mlme vdev mgr component
 * @vdev: pointer to vdev object
 * @buf: pointer to store the beacon buffer
 *
 * Return: void
 */
void ucfg_wlan_vdev_mgr_get_beacon_buffer(struct wlan_objmgr_vdev *vdev,
					  qdf_nbuf_t buf);

/**
 * ucfg_wlan_vdev_mgr_get_trans_bssid() - ucfg MLME API to
 * get transmission bssid from mlme vdev mgr component
 * @vdev: pointer to vdev object
 * @addr: pointer to store the transmission bssid
 *
 * Return: void
 */
void ucfg_wlan_vdev_mgr_get_trans_bssid(struct wlan_objmgr_vdev *vdev,
					uint8_t *addr);

/**
 * ucfg_wlan_vdev_mgr_get_tsf_adjust() - ucfg MLME API to
 * get tsf_adjust from mlme vdev mgr component
 * @vdev: pointer to vdev object
 * @tsf_adjust: pointer to store the tsf adjust value
 *
 * Return: void
 */
void ucfg_wlan_vdev_mgr_get_tsf_adjust(struct wlan_objmgr_vdev *vdev,
				       uint64_t *tsf_adjust);

#ifdef WLAN_FEATURE_DYNAMIC_MAC_ADDR_UPDATE
/**
 * ucfg_vdev_mgr_cdp_vdev_attach() - ucfg MLME API to attach CDP vdev
 * @vdev: pointer to vdev object
 *
 * Return: QDF_STATUS - Success or Failure
 */
QDF_STATUS ucfg_vdev_mgr_cdp_vdev_attach(struct wlan_objmgr_vdev *vdev);

/**
 * ucfg_vdev_mgr_cdp_vdev_detach() - ucfg MLME API to detach CDP vdev
 * @vdev: pointer to vdev object
 *
 * Return: QDF_STATUS - Success or Failure
 */
QDF_STATUS ucfg_vdev_mgr_cdp_vdev_detach(struct wlan_objmgr_vdev *vdev);
#endif

/**
 * ucfg_util_vdev_mgr_set_acs_mode_for_vdev() - ucfg API to set SAP start mode
 * @vdev: pointer to vdev object
 * @is_acs_mode: Carries true if SAP is started in ACS
 *
 * Return: None
 */
void
ucfg_util_vdev_mgr_set_acs_mode_for_vdev(struct wlan_objmgr_vdev *vdev,
					 bool is_acs_mode);
#endif /* __WLAN_VDEV_MLME_UCFG_H__ */
