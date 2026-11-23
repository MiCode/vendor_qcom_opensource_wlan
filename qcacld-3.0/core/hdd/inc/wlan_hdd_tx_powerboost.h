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
 * DOC: wlan_hdd_tx_powerboost.h
 *
 * WLAN Host Device Driver Tx powerboost API implementation
 */
#ifndef __WLAN_HDD_TX_POWERBOOST_H
#define __WLAN_HDD_TX_POWERBOOST_H

#ifdef FEATURE_WLAN_TX_POWERBOOST
/**
 * hdd_tx_powerboost_target_config() - Configure Tx Powerboost feature
 * @hdd_ctx: Pointer to HDD context
 * @tgt_cfg: Pointer to target device capability information
 *
 * Tx powerboost functionality is enabled if it is enabled in
 * .ini file and also supported on target device.
 *
 * Return: None
 */
void hdd_tx_powerboost_target_config(struct hdd_context *hdd_ctx,
				     struct wma_tgt_cfg *tgt_cfg);

/**
 * hdd_tx_powerboost_init() - HDD Tx powerboost initialization
 * @hdd_ctx: Pointer to HDD context
 *
 * Return: QDF_STATUS
 */
QDF_STATUS hdd_tx_powerboost_init(struct hdd_context *hdd_ctx);

/**
 * hdd_tx_powerboost_deinit() - HDD Tx powerboost de-initialization
 * @hdd_ctx: Pointer to HDD context
 *
 * Return: void
 */
void hdd_tx_powerboost_deinit(struct hdd_context *hdd_ctx);

/*
 * wlan_hdd_cfg80211_tx_power_boost_config() - Tx power boost configuration
 * vendor command
 * @wiphy: wiphy device pointer
 * @wdev: wireless device pointer
 * @data: Vendor command data buffer
 * @data_len: Buffer length
 *
 * Handles QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE
 *
 * Return: 0 for success, negative errno for failure.
 */
int wlan_hdd_cfg80211_tx_power_boost_config(struct wiphy *wiphy,
					    struct wireless_dev *wdev,
					    const void *data,
					    int data_len);

extern const struct nla_policy
qca_wlan_vendor_power_boost_policy[QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MAX + 1];

#define FEATURE_TX_POWER_BOOST_EVENTS                                 \
	[QCA_NL80211_VENDOR_SUBCMD_TX_POWER_BOOST_INDEX] = {          \
		.vendor_id = QCA_NL80211_VENDOR_ID,                   \
		.subcmd = QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE,\
	},                                                            \

#define FEATURE_VENDOR_SUBCMD_CONFIG_TX_POWER_BOOST                      \
{                                                                        \
	.info.vendor_id = QCA_NL80211_VENDOR_ID,                         \
	.info.subcmd =                                                   \
		QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE,             \
	.flags = WIPHY_VENDOR_CMD_NEED_WDEV |                            \
		WIPHY_VENDOR_CMD_NEED_NETDEV |                           \
		WIPHY_VENDOR_CMD_NEED_RUNNING,                           \
	.doit = wlan_hdd_cfg80211_tx_power_boost_config,                 \
	vendor_command_policy(qca_wlan_vendor_power_boost_policy,        \
			      QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MAX)\
},

/**
 * wlan_hdd_cfg80211_tx_pb_callback() - Callback for Tx Powerboost
 * @arg: HDD context
 * @params: event params
 *
 * This function extracts the Tx Powerboost metadata params and
 * constructs the NL event to the kernel/upper layers
 *
 * Return: None
 */
void wlan_hdd_cfg80211_tx_pb_callback(void *arg,
				      struct reg_txpb_evt_params *params);

/**
 * hdd_tx_powerboost_reinit() - Tx powerboost reinit after SSR
 * @hdd_ctx: HDD context
 *
 * This function is called after the SSR reinit to send the boost ready
 * WMI command to the firmware if before SSR user space app was launched
 *
 * Return: QDF_STATUS
 */
QDF_STATUS hdd_tx_powerboost_reinit(struct hdd_context *hdd_ctx);

/**
 * wlan_hdd_tx_power_boost_dev_create() - Create tx powerboost dev entry
 *
 * This function creates the /dev/txpb entry which is used for mmap to
 * copy the IQ samples from kernel to user space app
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wlan_hdd_tx_power_boost_dev_create(void);

/**
 * wlan_hdd_tx_power_boost_dev_destroy() - Destroy tx powerboost dev entry
 *
 * This function deletes the /dev/txpb entry
 *
 * Return: void
 */
void wlan_hdd_tx_power_boost_dev_destroy(void);

/**
 * hdd_txpb_wifi_off_app_stop() - Send App stop upon Wifi Off
 * @hdd_ctx: HDD context
 *
 * This function sends APP stop to the firmware upon Wifi Off and
 * APP start will be sent again upon Wifi ON (user space sends NL command)
 *
 * Return: QDF_STATUS
 */
QDF_STATUS hdd_txpb_wifi_off_app_stop(struct hdd_context *hdd_ctx);
#else
#define FEATURE_VENDOR_SUBCMD_CONFIG_TX_POWER_BOOST
#define FEATURE_TX_POWER_BOOST_EVENTS

static inline
void hdd_tx_powerboost_target_config(struct hdd_context *hdd_ctx,
				     struct wma_tgt_cfg *tgt_cfg)
{
}

static inline
QDF_STATUS hdd_tx_powerboost_init(struct hdd_context *hdd_ctx)
{
	return QDF_STATUS_SUCCESS;
}

static inline
void hdd_tx_powerboost_deinit(struct hdd_context *hdd_ctx)
{
}

static inline
void wlan_hdd_cfg80211_tx_pb_callback(void *arg,
				      struct reg_txpb_evt_params *params)
{
}

static inline
QDF_STATUS hdd_tx_powerboost_reinit(struct hdd_context *hdd_ctx)
{
	return QDF_STATUS_SUCCESS;
}

static inline
QDF_STATUS wlan_hdd_tx_power_boost_dev_create(void)
{
	return QDF_STATUS_SUCCESS;
}

static inline
void wlan_hdd_tx_power_boost_dev_destroy(void)
{
}

static inline
QDF_STATUS hdd_txpb_wifi_off_app_stop(struct hdd_context *hdd_ctx)
{
	return QDF_STATUS_SUCCESS;
}
#endif /* FEATURE_WLAN_TX_POWERBOOST */
#endif /* __WLAN_HDD_TX_POWERBOOST_H */
