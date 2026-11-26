/*
 * Copyright (c) 2023-2025 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include "qdf_types.h"
#include <net/cfg80211.h>
#include "wlan_cfg80211.h"
#include "wlan_objmgr_psoc_obj.h"
#include "wlan_objmgr_pdev_obj.h"
#include "wlan_objmgr_vdev_obj.h"
#include "os_if_dp_local_pkt_capture.h"
#include "wlan_dp_ucfg_api.h"
#include "wlan_dp_main.h"
#include "cdp_txrx_mon.h"
#include "wlan_policy_mgr_api.h"
#include <ol_defines.h>
#include "wlan_osif_priv.h"

/* Short name for QCA_NL80211_VENDOR_SUBCMD_SET_MONITOR_MODE command */
#define SET_MONITOR_MODE_CONFIG_MAX \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_MAX
#define SET_MONITOR_MODE_INVALID \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_INVALID
#define SET_MONITOR_MODE_DATA_TX_FRAME_TYPE \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_DATA_TX_FRAME_TYPE
#define SET_MONITOR_MODE_DATA_RX_FRAME_TYPE \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_DATA_RX_FRAME_TYPE
#define SET_MONITOR_MODE_MGMT_TX_FRAME_TYPE \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_MGMT_TX_FRAME_TYPE
#define SET_MONITOR_MODE_MGMT_RX_FRAME_TYPE \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_MGMT_RX_FRAME_TYPE
#define SET_MONITOR_MODE_CTRL_TX_FRAME_TYPE \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_CTRL_TX_FRAME_TYPE
#define SET_MONITOR_MODE_CTRL_RX_FRAME_TYPE \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_CTRL_RX_FRAME_TYPE
#define SET_MONITOR_MODE_OPERATING_TYPE \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_OPERATING_TYPE
#define SET_MONITOR_MODE_CONNECTED_BEACON_INTERVAL \
	QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_CONNECTED_BEACON_INTERVAL

/* Short name for QCA_NL80211_VENDOR_SUBCMD_GET_MONITOR_MODE command */
#define GET_MONITOR_MODE_CONFIG_MAX \
	QCA_WLAN_VENDOR_ATTR_GET_MONITOR_MODE_MAX
#define GET_MONITOR_MODE_INVALID \
	QCA_WLAN_VENDOR_ATTR_GET_MONITOR_MODE_INVALID
#define GET_MONITOR_MODE_STATUS \
	QCA_WLAN_VENDOR_ATTR_GET_MONITOR_MODE_STATUS

#define MGMT_FRAME_TYPE    0
#define DATA_FRAME_TYPE    1
#define CTRL_FRAME_TYPE    2
#define BIT_FRAME_TYPE_ALL \
	(BIT(MGMT_FRAME_TYPE) | BIT(DATA_FRAME_TYPE) | BIT(CTRL_FRAME_TYPE))

#define DATA_MAX_FILTER BIT(18)
#define MGMT_MAX_FILTER BIT(5)
#define CTRL_MAX_FILTER BIT(3)

const struct nla_policy
set_monitor_mode_policy[SET_MONITOR_MODE_CONFIG_MAX + 1] = {
	[SET_MONITOR_MODE_DATA_TX_FRAME_TYPE] = { .type = NLA_U32 },
	[SET_MONITOR_MODE_DATA_RX_FRAME_TYPE] = { .type = NLA_U32 },
	[SET_MONITOR_MODE_MGMT_TX_FRAME_TYPE] = { .type = NLA_U32 },
	[SET_MONITOR_MODE_MGMT_RX_FRAME_TYPE] = { .type = NLA_U32 },
	[SET_MONITOR_MODE_CTRL_TX_FRAME_TYPE] = { .type = NLA_U32 },
	[SET_MONITOR_MODE_CTRL_RX_FRAME_TYPE] = { .type = NLA_U32 },
	[SET_MONITOR_MODE_CONNECTED_BEACON_INTERVAL] = { .type = NLA_U32 },
	[SET_MONITOR_MODE_OPERATING_TYPE] = { .type = NLA_U32 },
};

static
bool os_if_local_pkt_capture_concurrency_allowed(struct wlan_objmgr_psoc *psoc)
{
	uint32_t num_connections, sta_count;

	num_connections = policy_mgr_get_connection_count_with_mlo(psoc);
	osif_debug("Total connections %d", num_connections);

	/*
	 * No connections, local packet capture is allowed
	 * Only 1 connection and its STA, then local packet capture is allowed
	 * 2+ port concurrency, local packet capture is not allowed
	 */
	if (!num_connections)
		return true;

	if (num_connections > 1)
		return false;

	sta_count = policy_mgr_mode_specific_connection_count(psoc,
							      PM_STA_MODE,
							      NULL);
	osif_debug("sta_count %d", sta_count);
	if (sta_count)
		return true;

	return false;
}

bool os_if_lpc_mon_intf_creation_allowed(struct wlan_objmgr_psoc *psoc)
{
	if (ucfg_dp_is_local_pkt_capture_enabled(psoc)) {
		if (!os_if_local_pkt_capture_concurrency_allowed(psoc)) {
			osif_err("Concurrency check failed, lpc interface creation not allowed");
			return false;
		}
	}

	return true;
}

static QDF_STATUS os_if_start_capture_allowed(struct wlan_objmgr_vdev *vdev)
{
	enum QDF_OPMODE mode = wlan_vdev_mlme_get_opmode(vdev);
	struct wlan_objmgr_psoc *psoc;

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		osif_err("NULL psoc");
		return QDF_STATUS_E_INVAL;
	}

	if (!ucfg_dp_is_local_pkt_capture_enabled(psoc)) {
		osif_warn("local pkt capture feature not enabled");
		return QDF_STATUS_E_NOSUPPORT;
	}

	if (mode != QDF_MONITOR_MODE) {
		osif_err("Operation not permitted in mode: %d", mode);
		return QDF_STATUS_E_PERM;
	}

	if (!os_if_local_pkt_capture_concurrency_allowed(psoc)) {
		osif_err("Concurrency check failed, start capture not allowed");
		return QDF_STATUS_E_PERM;
	}

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
os_if_stop_capture_allowed(struct wlan_objmgr_psoc *psoc,
			   enum QDF_OPMODE opmode)
{
	void *soc;

	soc = cds_get_context(QDF_MODULE_ID_SOC);
	if (!soc)
		return QDF_STATUS_E_INVAL;

	if (opmode != QDF_MONITOR_MODE) {
		osif_warn("Operation not permitted in opmode: %d", opmode);
		return QDF_STATUS_E_PERM;
	}

	if (!ucfg_dp_is_local_pkt_capture_enabled(psoc)) {
		osif_err("local pkt capture feature not enabled");
		return QDF_STATUS_E_NOSUPPORT;
	}

	if (!cdp_is_local_pkt_capture_running(soc, OL_TXRX_PDEV_ID)) {
		osif_debug("local pkt capture not running, no need to stop");
		return QDF_STATUS_E_PERM;
	}

	return QDF_STATUS_SUCCESS;
}

#ifndef WLAN_LOCAL_PKT_CAPTURE_SUBFILTER
static
QDF_STATUS os_if_dp_local_pkt_capture_start(struct wlan_objmgr_vdev *vdev,
					    struct nlattr **tb)
{
	QDF_STATUS status;
	struct cdp_monitor_filter filter = {0};
	uint32_t pkt_type = 0, val;
	void *soc;
	bool is_coc_mode = false;

	status = os_if_start_capture_allowed(vdev);
	if (QDF_IS_STATUS_ERROR(status))
		goto error;

	soc = cds_get_context(QDF_MODULE_ID_SOC);
	if (!soc)
		return QDF_STATUS_E_INVAL;

	if (tb[SET_MONITOR_MODE_MGMT_TX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_MGMT_TX_FRAME_TYPE]);

		if (val != QCA_WLAN_VENDOR_MONITOR_MGMT_FRAME_TYPE_ALL) {
			osif_err("Invalid value: %d Expected: %d",
				val,
				QCA_WLAN_VENDOR_MONITOR_MGMT_FRAME_TYPE_ALL);
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		pkt_type |= BIT(MGMT_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_MGMT_RX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_MGMT_RX_FRAME_TYPE]);

		if (val != QCA_WLAN_VENDOR_MONITOR_MGMT_FRAME_TYPE_ALL) {
			osif_err("Invalid value: %d Expected: %d",
				val,
				QCA_WLAN_VENDOR_MONITOR_MGMT_FRAME_TYPE_ALL);
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		pkt_type |= BIT(MGMT_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_DATA_TX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_DATA_TX_FRAME_TYPE]);

		if (val != QCA_WLAN_VENDOR_MONITOR_DATA_FRAME_TYPE_ALL) {
			osif_err("Invalid value: %d Expected: %d",
				val,
				QCA_WLAN_VENDOR_MONITOR_DATA_FRAME_TYPE_ALL);
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		pkt_type |= BIT(DATA_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_DATA_RX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_DATA_RX_FRAME_TYPE]);

		if (val != QCA_WLAN_VENDOR_MONITOR_DATA_FRAME_TYPE_ALL) {
			osif_err("Invalid value: %d Expected: %d",
				val,
				QCA_WLAN_VENDOR_MONITOR_DATA_FRAME_TYPE_ALL);
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		pkt_type |= BIT(DATA_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_CTRL_TX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_CTRL_TX_FRAME_TYPE]);

		if (val != QCA_WLAN_VENDOR_MONITOR_CTRL_FRAME_TYPE_ALL) {
			osif_err("Invalid value: %d Expected: %d",
				val,
				QCA_WLAN_VENDOR_MONITOR_CTRL_FRAME_TYPE_ALL);
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		pkt_type |= BIT(CTRL_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_CTRL_RX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_CTRL_RX_FRAME_TYPE]);

		if (val != QCA_WLAN_VENDOR_MONITOR_CTRL_FRAME_TYPE_ALL) {
			osif_err("Invalid value: %d Expected: %d",
				val,
				QCA_WLAN_VENDOR_MONITOR_CTRL_FRAME_TYPE_ALL);
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		pkt_type |= BIT(CTRL_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_OPERATING_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_OPERATING_TYPE]);

		if (val == QCA_WLAN_VENDOR_MONITOR_OPERATING_TYPE_OCC) {
			is_coc_mode = true;
		} else if (val !=
			   QCA_WLAN_VENDOR_MONITOR_OPERATING_TYPE_LPC) {
			osif_err("Invalid operating type value: %d", val);
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
	}

	if (pkt_type == 0) {
		osif_err("Invalid config, pkt_type: %d", pkt_type);
		status = QDF_STATUS_E_INVAL;
		goto error;
	}

	if (is_coc_mode) {
		if (pkt_type == BIT_FRAME_TYPE_ALL) {
			filter.fp_mgmt = FILTER_MGMT_ALL;
			filter.fp_data = FILTER_DATA_ALL;
			filter.fp_ctrl = FILTER_CTRL_ALL;
			filter.mo_mgmt = FILTER_MGMT_ALL;
			filter.mo_data = FILTER_DATA_ALL;
			filter.mo_ctrl = FILTER_CTRL_ALL;
		} else {
			osif_err("Invalid config for coc mode, pkt_type: %d",
				 pkt_type);
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
	} else {
		filter.fp_mgmt = pkt_type & BIT(MGMT_FRAME_TYPE) ?
					FILTER_MGMT_ALL : 0;
		filter.fp_data = pkt_type & BIT(DATA_FRAME_TYPE) ?
					FILTER_DATA_ALL : 0;
		filter.fp_ctrl = pkt_type & BIT(CTRL_FRAME_TYPE) ?
					FILTER_CTRL_ALL : 0;
	}

	osif_debug("start capture mode %s, config pkt_type:0x%x",
		   (is_coc_mode ? "coc" : "lpc"), pkt_type);

	filter.mode = is_coc_mode ? MON_FILTER_ALL : MON_FILTER_PASS;

	status = cdp_start_local_pkt_capture(soc, OL_TXRX_PDEV_ID, &filter);

error:
	return status;
}
#else
static
QDF_STATUS os_if_dp_local_pkt_capture_start(struct wlan_objmgr_vdev *vdev,
					    struct nlattr **tb)
{
	QDF_STATUS status;
	struct cdp_monitor_filter filter = {0};
	uint32_t pkt_type = 0, val;
	void *soc;

	status = os_if_start_capture_allowed(vdev);
	if (QDF_IS_STATUS_ERROR(status))
		goto error;

	soc = cds_get_context(QDF_MODULE_ID_SOC);
	if (!soc)
		return QDF_STATUS_E_INVAL;

	if (tb[SET_MONITOR_MODE_MGMT_TX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_MGMT_TX_FRAME_TYPE]);
		if (!val && val > MGMT_MAX_FILTER) {
			osif_err("Invalid value Mgmt filter");
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		filter.fp_subfilter.mgmt_tx_frame_filter = val;
		pkt_type |= BIT(MGMT_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_MGMT_RX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_MGMT_RX_FRAME_TYPE]);
		if (!val && val > MGMT_MAX_FILTER) {
			osif_err("Invalid value Mgmt filter");
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		filter.fp_subfilter.mgmt_rx_frame_filter = val;
		pkt_type |= BIT(MGMT_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_DATA_TX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_DATA_TX_FRAME_TYPE]);
		if (!val && val > DATA_MAX_FILTER) {
			osif_err("Invalid value Data filter");
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		filter.fp_subfilter.data_tx_frame_filter = val;
		pkt_type |= BIT(DATA_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_DATA_RX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_DATA_RX_FRAME_TYPE]);
		if (!val && val > DATA_MAX_FILTER) {
			osif_err("Invalid value Data filter");
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		filter.fp_subfilter.data_rx_frame_filter = val;
		pkt_type |= BIT(DATA_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_CTRL_TX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_CTRL_TX_FRAME_TYPE]);
		if (!val && val > CTRL_MAX_FILTER) {
			osif_err("Invalid value Ctrl filter");
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		filter.fp_subfilter.ctrl_tx_frame_filter = val;
		pkt_type |= BIT(CTRL_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_CTRL_RX_FRAME_TYPE]) {
		val = nla_get_u32(tb[SET_MONITOR_MODE_CTRL_RX_FRAME_TYPE]);
		if (!val && val > CTRL_MAX_FILTER) {
			osif_err("Invalid value Ctrl filter");
			status = QDF_STATUS_E_INVAL;
			goto error;
		}
		filter.fp_subfilter.ctrl_rx_frame_filter = val;
		pkt_type |= BIT(CTRL_FRAME_TYPE);
	}

	if (tb[SET_MONITOR_MODE_CONNECTED_BEACON_INTERVAL]) {
		filter.fp_subfilter.connected_beacon_interval =
		nla_get_u32(tb[SET_MONITOR_MODE_CONNECTED_BEACON_INTERVAL]);
	}

	if (pkt_type == 0) {
		osif_err("Invalid config, pkt_type: %d", pkt_type);
		status = QDF_STATUS_E_INVAL;
		goto error;
	}
	osif_debug("start capture config pkt_type:0x%x", pkt_type);

	filter.mode = MON_FILTER_PASS;
	filter.fp_mgmt = pkt_type & BIT(MGMT_FRAME_TYPE) ? FILTER_MGMT_ALL : 0;
	filter.fp_data = pkt_type & BIT(DATA_FRAME_TYPE) ? FILTER_DATA_ALL : 0;
	filter.fp_ctrl = pkt_type & BIT(CTRL_FRAME_TYPE) ? FILTER_CTRL_ALL : 0;

	status = cdp_start_local_pkt_capture(soc, OL_TXRX_PDEV_ID, &filter);

error:
	return status;
}
#endif /* End of WLAN_LOCAL_PKT_CAPTURE_SUBFILTER */

QDF_STATUS os_if_dp_set_lpc_configure(struct wlan_objmgr_vdev *vdev,
				      const void *data, int data_len)
{
	struct nlattr *tb[SET_MONITOR_MODE_CONFIG_MAX + 1];
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (wlan_cfg80211_nla_parse(tb, SET_MONITOR_MODE_CONFIG_MAX,
				    data, data_len, set_monitor_mode_policy)) {
		osif_err("Invalid monitor attr");
		status = QDF_STATUS_E_INVAL;
		goto error;
	}

	status = os_if_dp_local_pkt_capture_start(vdev, tb);

error:
	return status;
}

QDF_STATUS
os_if_dp_local_pkt_capture_stop(struct wlan_objmgr_psoc *psoc,
				enum QDF_OPMODE opmode)
{
	QDF_STATUS status;
	void *soc;

	soc = cds_get_context(QDF_MODULE_ID_SOC);
	if (!soc || !psoc)
		return QDF_STATUS_E_INVAL;

	status = os_if_stop_capture_allowed(psoc, opmode);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	return cdp_stop_local_pkt_capture(soc, OL_TXRX_PDEV_ID);
}

QDF_STATUS os_if_dp_get_lpc_state(struct wlan_objmgr_vdev *vdev,
				  const void *data, int data_len)
{
	struct wlan_objmgr_psoc *psoc;
	struct vdev_osif_priv *osif_priv;
	struct sk_buff *reply_skb;
	uint32_t skb_len = NLMSG_HDRLEN, val;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct wireless_dev *wdev;
	bool running;
	void *soc;

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc)
		return QDF_STATUS_E_INVAL;

	osif_priv = wlan_vdev_get_ospriv(vdev);
	if (!osif_priv) {
		osif_err("osif_priv is null");
		return QDF_STATUS_E_INVAL;
	}

	wdev = osif_priv->wdev;
	if (!wdev) {
		osif_err("wireless dev is null");
		return QDF_STATUS_E_INVAL;
	}

	soc = cds_get_context(QDF_MODULE_ID_SOC);
	if (!soc)
		return QDF_STATUS_E_INVAL;

	/* Length of attribute QCA_WLAN_VENDOR_ATTR_SET_MONITOR_MODE_STATUS */
	skb_len += nla_total_size(sizeof(u32));

	reply_skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(wdev->wiphy,
							     skb_len);
	if (!reply_skb) {
		osif_err("alloc reply skb failed");
		return QDF_STATUS_E_NOMEM;
	}

	running = cdp_is_local_pkt_capture_running(soc, OL_TXRX_PDEV_ID);
	val = running ? QCA_WLAN_VENDOR_MONITOR_MODE_CAPTURE_RUNNING :
			QCA_WLAN_VENDOR_MONITOR_MODE_NO_CAPTURE_RUNNING;

	if (nla_put_u32(reply_skb, GET_MONITOR_MODE_STATUS, val)) {
		osif_err("nla put failed");
		status = QDF_STATUS_E_INVAL;
		goto fail;
	}

	if (wlan_cfg80211_vendor_cmd_reply(reply_skb))
		status = QDF_STATUS_E_INVAL;

	return status;
fail:
	wlan_cfg80211_vendor_free_skb(reply_skb);
	return status;
}

