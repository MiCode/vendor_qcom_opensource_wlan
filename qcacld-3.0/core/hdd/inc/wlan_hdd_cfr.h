/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
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
 */

/**
 * DOC: wlan_hdd_cfr.h
 *
 * WLAN Host Device Driver cfr capture implementation
 *
 */

#if !defined(_WLAN_HDD_CFR_H)
#define _WLAN_HDD_CFR_H

#ifdef WLAN_CFR_ENABLE

#include "wlan_cfr_utils_api.h"

#define HDD_INVALID_GROUP_ID MAX_TA_RA_ENTRIES
#define LEGACY_CFR_VERSION 1
#define ENHANCED_CFR_VERSION 2

/* IEEE 802.11 Frame Type and Subtype definitions for CFR */
#define CFR_MAX_FRAME_TYPE 2        /* 0=Management, 1=Control, 2=Data */
#define CFR_MAX_FRAME_SUBTYPE 15    /* Frame subtype range: 0-15 */

/* CFR Report Interval limits in milliseconds */
#define CFR_MIN_REPORT_INTERVAL 100     /* Minimum report interval: 100ms */
#define CFR_MAX_REPORT_INTERVAL 10000   /* Maximum report interval: 10000ms */

/* CFR Format Version limits */
#define CFR_MIN_FORMAT_VERSION 1        /* Minimum format version: 1 */
#define CFR_MAX_FORMAT_VERSION 255      /* Maximum format version: 255 */

/*
 * hdd_cfr_data_send_nl_event() - send cfr data through nl event
 * @vdev_id: vdev id
 * @pid: process pid to which send data event unicast way
 * @data: pointer to the cfr data
 * @data_len: length of data
 *
 * Return: void
 */
void hdd_cfr_data_send_nl_event(uint8_t vdev_id, uint32_t pid,
				const void *data, uint32_t data_len);

#define FEATURE_CFR_DATA_VENDOR_EVENTS                                  \
[QCA_NL80211_VENDOR_SUBCMD_PEER_CFR_CAPTURE_CFG_INDEX] = {              \
	.vendor_id = QCA_NL80211_VENDOR_ID,                             \
	.subcmd = QCA_NL80211_VENDOR_SUBCMD_PEER_CFR_CAPTURE_CFG,       \
},

/**
 * hdd_cfr_indicate_last_report_interval() - send last report event to userspace
 * @vdev_id: vdev id
 */
void hdd_cfr_indicate_last_report_interval(uint8_t vdev_id);

/*
 * hdd_cfr_data_send_nl_event_v3() - send cfr data through nl event
 * for version v3
 * @vdev_id: vdev id
 * @struct cfr_enhanced_event_data: cfr enhanced data
 * @data: pointer to the cfr data
 * @data_len: length of data
 *
 * Return: void
 */
void hdd_cfr_data_send_nl_event_v3(uint8_t vdev_id,
				   struct cfr_enhanced_event_data event_data,
				  const void *data, uint32_t data_len);

/**
 * wlan_hdd_stop_cfr() - stop cfr
 * @vdev_id: vdev id
 * @reason: reason
 */
void wlan_hdd_stop_cfr(uint8_t vdev_id, uint32_t reason);

/**
 * struct cfr_v3_params - CFR v3 configuration parameters
 * @is_start_capture: Flag to start/stop CFR capture
 * @tx_capture: Flag indicating TX capture mode
 * @rx_capture: Flag indicating RX capture mode
 * @method: CFR capture method
 * @frame_type: Frame type for CFR capture
 * @frame_subtype: Frame subtype for CFR capture
 * @freq: Frequency for CFR capture
 * @report_interval: Report interval in milliseconds
 * @bandwidth: Capture bandwidth
 * @transport_mode: Data transport mode
 * @oui_length: OUI length
 * @oui: vendor OUI
 * @format_version: Format version
 */
struct cfr_v3_params {
	bool is_start_capture;
	bool tx_capture;
	bool rx_capture;
	uint8_t method;
	uint8_t frame_type;
	uint8_t frame_subtype;
	uint32_t freq;
	uint32_t report_interval;
	uint8_t bandwidth;
	uint8_t transport_mode;
	uint8_t oui_length;
	uint8_t oui[MAX_CFR_OUI_LEN];
	uint8_t format_version;
};

/**
 * wlan_hdd_cfg80211_peer_cfr_capture_cfg() - configure peer cfr capture
 * @wiphy:    WIPHY structure pointer
 * @wdev:     Wireless device structure pointer
 * @data:     Pointer to the data received
 * @data_len: Length of the data received
 *
 * This function starts CFR capture
 *
 * Return: 0 on success and errno on failure
 */
int
wlan_hdd_cfg80211_peer_cfr_capture_cfg(struct wiphy *wiphy,
				       struct wireless_dev *wdev,
				       const void *data,
				       int data_len);

#ifdef WLAN_ENH_CFR_ENABLE
/**
 * hdd_cfr_disconnect() - Handle disconnection event in CFR
 * @vdev: Pointer to vdev object
 *
 * Handle disconnection event in CFR. Stop CFR if it started and get
 * disconnection event.
 *
 * Return: QDF status
 */
QDF_STATUS hdd_cfr_disconnect(struct wlan_objmgr_vdev *vdev);
#else
static inline QDF_STATUS
hdd_cfr_disconnect(struct wlan_objmgr_vdev *vdev)
{
	return QDF_STATUS_SUCCESS;
}
#endif

extern const struct nla_policy cfr_config_policy[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_MAX + 1];

#define FEATURE_CFR_VENDOR_COMMANDS \
{ \
	.info.vendor_id = QCA_NL80211_VENDOR_ID, \
	.info.subcmd = QCA_NL80211_VENDOR_SUBCMD_PEER_CFR_CAPTURE_CFG, \
	.flags = WIPHY_VENDOR_CMD_NEED_WDEV | \
			WIPHY_VENDOR_CMD_NEED_NETDEV, \
	.doit = wlan_hdd_cfg80211_peer_cfr_capture_cfg, \
	vendor_command_policy(cfr_config_policy, \
			      QCA_WLAN_VENDOR_ATTR_PEER_CFR_MAX) \
},
#else
#define FEATURE_CFR_VENDOR_COMMANDS
static inline QDF_STATUS
hdd_cfr_disconnect(struct wlan_objmgr_vdev *vdev)
{
	return QDF_STATUS_SUCCESS;
}

#define FEATURE_CFR_DATA_VENDOR_EVENTS
#endif /* WLAN_CFR_ENABLE */
#endif /* _WLAN_HDD_CFR_H */

