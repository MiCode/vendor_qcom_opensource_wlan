/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: wlan_hdd_cfr.c
 *
 * WLAN Host Device Driver CFR capture Implementation
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/cfg80211.h>
#include "wlan_hdd_includes.h"
#include "osif_sync.h"
#include "wlan_hdd_cfr.h"
#include "wlan_cfr_ucfg_api.h"
#include "wlan_hdd_object_manager.h"
#include "wlan_cmn.h"
#include "wlan_policy_mgr_ll_sap.h"
#include "wlan_hdd_cfg80211.h"
#include "target_if.h"

#define FRAME_CTRL 2
#define SUB_TYPE_QOS_NULL 8

void hdd_cfr_data_send_nl_event(uint8_t vdev_id, uint32_t pid,
				const void *data, uint32_t data_len)
{
	uint32_t len, ret;
	struct sk_buff *vendor_event;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	struct wlan_hdd_link_info *link_info;
	struct nlmsghdr *nlhdr;

	if (wlan_hdd_validate_context(hdd_ctx)) {
		hdd_err("HDD context is NULL");
		return;
	}

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, vdev_id);
	if (!link_info) {
		hdd_err("adapter NULL for vdev id %d", vdev_id);
		return;
	}

	hdd_debug("vdev id %d pid %d data len %d", vdev_id, pid, data_len);
	len = nla_total_size(data_len) + NLMSG_HDRLEN;
	vendor_event = wlan_cfg80211_vendor_event_alloc(
			hdd_ctx->wiphy, &link_info->adapter->wdev, len,
			QCA_NL80211_VENDOR_SUBCMD_PEER_CFR_CAPTURE_CFG_INDEX,
			qdf_mem_malloc_flags());

	if (!vendor_event) {
		hdd_err("wlan_cfg80211_vendor_event_alloc failed vdev id %d, data len %d",
			vdev_id, data_len);
		return;
	}

	ret = nla_put(vendor_event,
		      QCA_WLAN_VENDOR_ATTR_PEER_CFR_RESP_DATA,
		      data_len, data);
	if (ret) {
		hdd_err("CFR event put fails status %d", ret);
		wlan_cfg80211_vendor_free_skb(vendor_event);
		return;
	}

	if (pid) {
		nlhdr = nlmsg_hdr(vendor_event);
		if (nlhdr)
			nlhdr->nlmsg_pid = pid;
		else
			hdd_err_rl("nlhdr is null");
	}

	wlan_cfg80211_vendor_event(vendor_event, qdf_mem_malloc_flags());
}

static uint32_t
hdd_get_cfr_nl_event_len(struct cfr_enhanced_event_data event_data,
			 uint32_t data_len)
{
	uint32_t total_len;

	total_len = data_len;

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_TIMESTAMP_US].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_TYPE].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_SUBTYPE].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_SEQUENCE_NUMBER].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_CFR_PEER_MAC_ADDR].len);

	/* QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_INFO */
	total_len += NLA_HDRLEN;

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_INDEX].len) *
		HOST_MAX_CHAINS;

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_RSSI].len) *
		HOST_MAX_CHAINS;

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_AGC].len) *
		HOST_MAX_CHAINS;

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_NUM_SPATIAL_STREAMS].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_FREQ].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_BANDWIDTH].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_CHIP_ID].len);

	total_len += nla_total_size(cfr_config_policy[
	       QCA_WLAN_VENDOR_ATTR_PEER_CFR_CAPTURE_TSF].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_CFO].len);

	total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_VERSION].len);

	/* QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_OUI */
	if (event_data.oui_length) {
		total_len += nla_total_size(
			event_data.oui_length * sizeof(u8));
		total_len += nla_total_size(cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_VERSION].len);
	}

	total_len += nla_total_size(cfr_config_policy[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_CSI_LTF_TYPE].len);

	return total_len;
}

static int
hdd_cfr_nl_put_common_info(struct sk_buff *vendor_event,
			   struct cfr_enhanced_event_data *event_data)
{
	if (nla_put_u64_64bit(vendor_event,
			      QCA_WLAN_VENDOR_ATTR_PEER_CFR_TIMESTAMP_US,
			      event_data->timestamp_us, NL80211_ATTR_PAD)) {
		cfr_err("Failed to put timestamp");
		return -EINVAL;
	}

	if (nla_put_u8(vendor_event, QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_TYPE,
		       event_data->frame_type)) {
		cfr_err("Failed to put frame type");
		return -EINVAL;
	}

	if (nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_SUBTYPE,
		       event_data->frame_sub_type)) {
		cfr_err("Failed to put frame subtype");
		return -EINVAL;
	}

	if (nla_put_u16(vendor_event,
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_SEQUENCE_NUMBER,
			event_data->frame_sequence_number)) {
		cfr_err("Failed to put sequence number");
		return -EINVAL;
	}

	if (nla_put(vendor_event, QCA_WLAN_VENDOR_ATTR_CFR_PEER_MAC_ADDR,
		    QDF_MAC_ADDR_SIZE, event_data->peer_mac_addr)) {
		cfr_err("Failed to put peer mac addr");
		return -EINVAL;
	}

	return 0;
}

static enum
nl80211_chan_width convert_ucode_bw_to_nl_bw(uint8_t bw)
{
	switch (bw) {
	case 0:
		return NL80211_CHAN_WIDTH_20;
	case 1:
		return NL80211_CHAN_WIDTH_40;
	case 2:
		return NL80211_CHAN_WIDTH_80;
	case 3:
		return NL80211_CHAN_WIDTH_160;
	case 4:
		return NL80211_CHAN_WIDTH_320;
	default:
		hdd_err("invalid capture bw");
		return NL80211_CHAN_WIDTH_20;
	}
}

static int
hdd_cfr_nl_put_phy_info(struct sk_buff *vendor_event,
			struct cfr_enhanced_event_data *event_data)
{
	struct nlattr *info, *entry;
	uint8_t i;

	info = nla_nest_start(vendor_event,
			      QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_INFO);
	if (!info) {
		cfr_err("Failed to start antenna info nesting");
		return -EINVAL;
	}

	/* convert ucode bw to nl bw */
	event_data->bandwidth =
		convert_ucode_bw_to_nl_bw(event_data->bandwidth);

	for (i = 0; i < event_data->antenna_count && i < HOST_MAX_CHAINS; i++) {
		entry = nla_nest_start(vendor_event, i);
		if (!entry) {
			cfr_err("Failed to start antenna entry %d", i);
			nla_nest_cancel(vendor_event, info);
			return -EINVAL;
		}

		if (nla_put_u8(vendor_event,
			       QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_INDEX,
			       i)) {
			cfr_err("Failed to add antenna %d index", i);
			goto err_phy_info;
		}

		if (nla_put_s8(vendor_event,
			       QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_RSSI,
			       event_data->antenna_info[i].rssi)) {
			cfr_err("Failed to add antenna %d rssi", i);
			goto err_phy_info;
		}

		if (nla_put_u8(vendor_event,
			       QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_AGC,
			       event_data->antenna_info[i].agc)) {
			cfr_err("Failed to add antenna %d agc", i);
			goto err_phy_info;
		}

		nla_nest_end(vendor_event, entry);
	}

	nla_nest_end(vendor_event, info);

	if (nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_PEER_CFR_NUM_SPATIAL_STREAMS,
		       event_data->num_spatial_streams)) {
		cfr_err("Failed to put num spatial streams");
		return -EINVAL;
	}

	if (nla_put_u32(vendor_event, QCA_WLAN_VENDOR_ATTR_PEER_CFR_FREQ,
			event_data->freq)) {
		cfr_err("Failed to put freq");
		return -EINVAL;
	}

	if (nla_put_u8(vendor_event, QCA_WLAN_VENDOR_ATTR_PEER_CFR_BANDWIDTH,
		       event_data->bandwidth)) {
		cfr_err("Failed to put bandwidth");
		return -EINVAL;
	}

	if (nla_put_u16(vendor_event, QCA_WLAN_VENDOR_ATTR_PEER_CFR_CHIP_ID,
			event_data->chip_id)) {
		cfr_err("Failed to put chip id");
		return -EINVAL;
	}

	if (nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_PEER_CFR_CSI_LTF_TYPE,
		       event_data->ltf_type)) {
		cfr_err("Failed to put ltf_type");
		return -EINVAL;
	}

	return 0;

err_phy_info:
	nla_nest_cancel(vendor_event, entry);
	nla_nest_cancel(vendor_event, info);
	return -EINVAL;
}

static int
hdd_cfr_nl_put_vendor_info(struct sk_buff *vendor_event,
			   struct cfr_enhanced_event_data *event_data)
{
	if (nla_put_u64_64bit(vendor_event,
			      QCA_WLAN_VENDOR_ATTR_PEER_CFR_CAPTURE_TSF,
			      event_data->capture_tsf, NL80211_ATTR_PAD)) {
		cfr_err("Failed to put capture tsf");
		return -EINVAL;
	}

	if (nla_put_s16(vendor_event,
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_CFO,
			event_data->cfo)) {
		cfr_err("Failed to put cfo");
		return -EINVAL;
	}
	if (nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_PEER_CFR_VERSION,
		       event_data->cfr_version)) {
		cfr_err("Failed to put format version");
		return -EINVAL;
	}

	if (event_data->oui_length &&
	    event_data->oui_length < MAX_CFR_OUI_LEN &&
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_OUI,
		    event_data->oui_length, event_data->oui)) {
		cfr_err("Failed to put oui");
		return -EINVAL;
	}

	if (event_data->oui_length &&
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_VERSION,
		       event_data->format_version)) {
		cfr_err("Failed to put data format version");
		return -EINVAL;
	}

	return 0;
}

void hdd_cfr_data_send_nl_event_v3(uint8_t vdev_id,
				   struct cfr_enhanced_event_data event_data,
				   const void *data, uint32_t data_len)
{
	uint32_t len;
	struct sk_buff *vendor_event;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	struct wlan_hdd_link_info *link_info;

	if (wlan_hdd_validate_context(hdd_ctx)) {
		cfr_err("HDD context is NULL");
		return;
	}

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, vdev_id);
	if (!link_info) {
		cfr_err("adapter NULL for vdev id %d", vdev_id);
		return;
	}

	len = hdd_get_cfr_nl_event_len(event_data, data_len);
	cfr_debug("vdev id %d data_len %d total_len %d",
		  vdev_id, data_len, len);
	len = nla_total_size(len + NLMSG_HDRLEN);

	vendor_event = wlan_cfg80211_vendor_event_alloc(
			hdd_ctx->wiphy, &link_info->adapter->wdev, len,
			QCA_NL80211_VENDOR_SUBCMD_PEER_CFR_CAPTURE_CFG_INDEX,
			qdf_mem_malloc_flags());

	if (!vendor_event) {
		cfr_err("alloc failed vdev id %d, total_len %d",
			vdev_id, len);
		return;
	}

	if (hdd_cfr_nl_put_common_info(vendor_event, &event_data) ||
	    hdd_cfr_nl_put_phy_info(vendor_event, &event_data) ||
	    hdd_cfr_nl_put_vendor_info(vendor_event, &event_data))
		goto free_skb;

	if (nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_PEER_CFR_RESP_DATA,
		    data_len, data)) {
		cfr_err("CFR event put fails");
		goto free_skb;
	}

	wlan_cfg80211_vendor_event(vendor_event, qdf_mem_malloc_flags());
	return;

free_skb:
	wlan_cfg80211_vendor_free_skb(vendor_event);
}

void hdd_cfr_indicate_last_report_interval(uint8_t vdev_id)
{
	uint32_t total_len;
	struct sk_buff *vendor_event;
	struct wlan_objmgr_vdev *vdev;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	struct wlan_hdd_link_info *link_info;
	struct pdev_cfr *pcfr = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;

	if (wlan_hdd_validate_context(hdd_ctx)) {
		cfr_err("HDD context is NULL");
		return;
	}

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, vdev_id);
	if (!link_info) {
		cfr_err("adapter NULL for vdev id %d", vdev_id);
		return;
	}

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_CFR_ID);
	if (!vdev) {
		cfr_err("Invalid vdev");
		return;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		cfr_err("Failed to get pdev object");
		goto put_vdev;
	}

	pcfr = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);
	if (!pcfr) {
		cfr_err("CFR private object is NULL");
		goto put_vdev;
	}

	cfr_debug("vdev id %d", vdev_id);
	total_len = NLMSG_HDRLEN;
	total_len += nla_total_size(sizeof(u8)); /* vesrion attribute*/
	total_len += nla_total_size(0); /* flag attribute */

	if (pcfr->oui_length) {
		total_len += nla_total_size(pcfr->oui_length * sizeof(u8));
		total_len += nla_total_size(sizeof(u8));
	}

	vendor_event = wlan_cfg80211_vendor_event_alloc(
			hdd_ctx->wiphy, &link_info->adapter->wdev, total_len,
			QCA_NL80211_VENDOR_SUBCMD_PEER_CFR_CAPTURE_CFG_INDEX,
			qdf_mem_malloc_flags());

	if (!vendor_event) {
		cfr_err("wlan_cfg80211_vendor_event_alloc failed vdev id %d",
			vdev_id);
		goto put_vdev;
	}

	if (nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_PEER_CFR_VERSION,
		       ENHANCED_CFR_VERSION_V3)) {
		cfr_err("Failed to put format version");
		wlan_cfg80211_vendor_free_skb(vendor_event);
		goto put_vdev;
	}

	if (pcfr->oui_length &&
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_OUI,
		    pcfr->oui_length, pcfr->oui)) {
		cfr_err("Failed to put oui");
		wlan_cfg80211_vendor_free_skb(vendor_event);
		goto put_vdev;
	}

	if (pcfr->oui_length &&
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_VERSION,
		       pcfr->format_version)) {
		cfr_err("Failed to put data format version");
		wlan_cfg80211_vendor_free_skb(vendor_event);
		goto put_vdev;
	}

	if (nla_put_flag(vendor_event,
			 QCA_WLAN_VENDOR_ATTR_PEER_CFR_IS_LAST_REPORT)) {
		cfr_err("Failed to put last report flag");
		wlan_cfg80211_vendor_free_skb(vendor_event);
		goto put_vdev;
	}

	wlan_cfg80211_vendor_event(vendor_event, qdf_mem_malloc_flags());

put_vdev:
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
}

const struct nla_policy cfr_config_policy[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_CFR_PEER_MAC_ADDR] =
		VENDOR_NLA_POLICY_MAC_ADDR,
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE] = {
					.type = NLA_FLAG,
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_BANDWIDTH] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_PERIODICITY] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_METHOD] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_VERSION] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PERIODIC_CFR_CAPTURE_ENABLE] = {
					.type = NLA_FLAG,
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE_GROUP_BITMAP] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DURATION] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_INTERVAL] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_CAPTURE_TYPE] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_UL_MU_MASK] = {
					.type = NLA_U64,
					.len = sizeof(uint64_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FREEZE_TLV_DELAY_COUNT] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TABLE] = {
					.type = NLA_NESTED,
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_ENTRY] = {
					.type = NLA_NESTED,
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_NUMBER] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TA] =
		VENDOR_NLA_POLICY_MAC_ADDR,
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_RA] =
		VENDOR_NLA_POLICY_MAC_ADDR,
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TA_MASK] =
		VENDOR_NLA_POLICY_MAC_ADDR,
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_RA_MASK] =
		VENDOR_NLA_POLICY_MAC_ADDR,
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_NSS] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_BW] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_MGMT_FILTER] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_CTRL_FILTER] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_DATA_FILTER] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_TRANSPORT_MODE] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_RECEIVER_PID] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_RESP_DATA] = {
					.type = NLA_BINARY,
					.len = WLAN_CFR_DATA_MAX_LEN
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FREQ] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_TYPE] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_SUBTYPE] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_REPORT_INTERVAL] = {
					.type = NLA_U32,
					.len = sizeof(uint32_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_OUI] = {
					.type = NLA_BINARY
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_VERSION] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_TIMESTAMP_US] = {
					.type = NLA_U64,
					.len = sizeof(uint64_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_INFO] = {
					.type = NLA_NESTED,
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_INDEX] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_RSSI] = {
					.type = NLA_S8,
					.len = sizeof(int8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_RX_ANTENNA_AGC] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_IS_LAST_REPORT] = {
					.type = NLA_FLAG,
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_SEQUENCE_NUMBER] = {
					.type = NLA_U16,
					.len = sizeof(uint16_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_CHIP_ID] = {
					.type = NLA_U16,
					.len = sizeof(uint16_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_CAPTURE_TSF] = {
					.type = NLA_U64,
					.len = sizeof(uint64_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_CFO] = {
					.type = NLA_S16,
					.len = sizeof(int16_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_CSI_LTF_TYPE] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
	[QCA_WLAN_VENDOR_ATTR_PEER_CFR_NUM_SPATIAL_STREAMS] = {
					.type = NLA_U8,
					.len = sizeof(uint8_t)
	},
};

#ifdef WLAN_ENH_CFR_ENABLE
static void
wlan_hdd_transport_mode_cfg(struct wlan_objmgr_pdev *pdev,
			    uint8_t vdev_id, uint32_t pid,
			    enum qca_wlan_vendor_cfr_data_transport_modes tx_mode)
{
	struct pdev_cfr *pa;

	if (!pdev) {
		hdd_err("failed to %s transport mode cb for cfr, pdev is NULL for vdev id %d",
			tx_mode ? "register" : "deregister", vdev_id);
		return;
	}

	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);
	if (!pa) {
		hdd_err("cfr private obj is NULL for vdev id %d", vdev_id);
		return;
	}
	pa->nl_cb.vdev_id = vdev_id;
	pa->nl_cb.pid = pid;
	if (tx_mode != QCA_WLAN_VENDOR_CFR_DATA_NETLINK_EVENTS)
		return;

	pa->nl_cb.cfr_nl_cb = NULL;
	pa->nl_cb.cfr_nl_cb_v3 = NULL;
	pa->nl_cb.cfr_nl_cb_report_interval = NULL;

	if (pa->is_cfr_version_v3) {
		pa->nl_cb.cfr_nl_cb_v3 =
			hdd_cfr_data_send_nl_event_v3;
		pa->nl_cb.cfr_nl_cb_report_interval =
			hdd_cfr_indicate_last_report_interval;
	} else {
		pa->nl_cb.cfr_nl_cb = hdd_cfr_data_send_nl_event;
	}
}

#define DEFAULT_CFR_NSS 0xff
#define DEFAULT_CFR_BW  0xf
static QDF_STATUS
wlan_cfg80211_cfr_set_group_config(struct wlan_objmgr_vdev *vdev,
				   struct nlattr *tb[])
{
	struct cfr_wlanconfig_param params = { 0 };

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_NUMBER]) {
		params.grp_id = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_NUMBER]);
		hdd_debug("group_id %d", params.grp_id);
	}

	if (params.grp_id >= HDD_INVALID_GROUP_ID) {
		hdd_err("invalid group id");
		return QDF_STATUS_E_INVAL;
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TA]) {
		nla_memcpy(&params.ta[0],
			   tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TA],
			   QDF_MAC_ADDR_SIZE);
		hdd_debug("ta " QDF_MAC_ADDR_FMT,
			  QDF_MAC_ADDR_REF(&params.ta[0]));
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TA_MASK]) {
		nla_memcpy(&params.ta_mask[0],
			   tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TA_MASK],
			   QDF_MAC_ADDR_SIZE);
		hdd_debug("ta_mask " QDF_MAC_ADDR_FMT,
			  QDF_MAC_ADDR_REF(&params.ta_mask[0]));
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_RA]) {
		nla_memcpy(&params.ra[0],
			   tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_RA],
			   QDF_MAC_ADDR_SIZE);
		hdd_debug("ra " QDF_MAC_ADDR_FMT,
			  QDF_MAC_ADDR_REF(&params.ra[0]));
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_RA_MASK]) {
		nla_memcpy(&params.ra_mask[0],
			   tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_RA_MASK],
			   QDF_MAC_ADDR_SIZE);
		hdd_debug("ra_mask " QDF_MAC_ADDR_FMT,
			  QDF_MAC_ADDR_REF(&params.ra_mask[0]));
	}

	if (!qdf_is_macaddr_zero((struct qdf_mac_addr *)&params.ta) ||
	    !qdf_is_macaddr_zero((struct qdf_mac_addr *)&params.ra) ||
	    !qdf_is_macaddr_zero((struct qdf_mac_addr *)&params.ta_mask) ||
	    !qdf_is_macaddr_zero((struct qdf_mac_addr *)&params.ra_mask)) {
		hdd_debug("set tara config");
		ucfg_cfr_set_tara_config(vdev, &params);
	}

	params.nss = DEFAULT_CFR_NSS;
	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_NSS]) {
		params.nss = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_NSS]);
		hdd_debug("nss %d", params.nss);
	}

	params.bw = DEFAULT_CFR_BW;
	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_BW]) {
		params.bw = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_BW]);
		hdd_debug("bw %d", params.bw);
	}

	if (params.nss || params.bw) {
		hdd_debug("set bw nss");
		ucfg_cfr_set_bw_nss(vdev, &params);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_MGMT_FILTER]) {
		params.expected_mgmt_subtype = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_MGMT_FILTER]);
		hdd_debug("expected_mgmt_subtype %d(%x)",
			  params.expected_mgmt_subtype,
			  params.expected_mgmt_subtype);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_CTRL_FILTER]) {
		params.expected_ctrl_subtype = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_CTRL_FILTER]);
		hdd_debug("expected_ctrl_subtype %d(%x)",
			  params.expected_ctrl_subtype,
			  params.expected_ctrl_subtype);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_DATA_FILTER]) {
		params.expected_data_subtype = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_DATA_FILTER]);
		hdd_debug("expected_data_subtype %d(%x)",
			  params.expected_data_subtype,
			  params.expected_data_subtype);
	}

	if (!params.expected_mgmt_subtype ||
	    !params.expected_ctrl_subtype ||
		!params.expected_data_subtype) {
		hdd_debug("set frame type");
		ucfg_cfr_set_frame_type_subtype(vdev, &params);
	}

	return QDF_STATUS_SUCCESS;
}

static enum capture_type convert_vendor_cfr_capture_type(
			enum qca_wlan_vendor_cfr_capture_type type)
{
	switch (type) {
	case QCA_WLAN_VENDOR_CFR_DIRECT_FTM:
		return RCC_DIRECTED_FTM_FILTER;
	case QCA_WLAN_VENDOR_CFR_ALL_FTM_ACK:
		return RCC_ALL_FTM_ACK_FILTER;
	case QCA_WLAN_VENDOR_CFR_DIRECT_NDPA_NDP:
		return RCC_DIRECTED_NDPA_NDP_FILTER;
	case QCA_WLAN_VENDOR_CFR_TA_RA:
		return RCC_TA_RA_FILTER;
	case QCA_WLAN_VENDOR_CFR_ALL_PACKET:
		return RCC_NDPA_NDP_ALL_FILTER;
	default:
		hdd_err("invalid capture type");
		return RCC_DIS_ALL_MODE;
	}
}

static int
wlan_cfg80211_cfr_set_config(struct wlan_objmgr_vdev *vdev,
			     struct nlattr *tb[])
{
	struct nlattr *group[QCA_WLAN_VENDOR_ATTR_PEER_CFR_MAX + 1];
	struct nlattr *group_list;
	struct cfr_wlanconfig_param params = { 0 };
	enum capture_type type;
	enum qca_wlan_vendor_cfr_capture_type vendor_capture_type;
	int rem = 0;
	int maxtype;
	int attr;
	uint64_t ul_mu_user_mask = 0;

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DURATION]) {
		params.cap_dur = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_DURATION]);
		ucfg_cfr_set_capture_duration(vdev, &params);
		hdd_debug("params.cap_dur %d", params.cap_dur);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_INTERVAL]) {
		params.cap_intvl = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_INTERVAL]);
		ucfg_cfr_set_capture_interval(vdev, &params);
		hdd_debug("params.cap_intvl %d", params.cap_intvl);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_CAPTURE_TYPE]) {
		vendor_capture_type = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_CAPTURE_TYPE]);
		if ((vendor_capture_type < QCA_WLAN_VENDOR_CFR_DIRECT_FTM) ||
		    (vendor_capture_type > QCA_WLAN_VENDOR_CFR_ALL_PACKET)) {
			hdd_err_rl("invalid capture type %d",
				   vendor_capture_type);
			return -EINVAL;
		}
		type = convert_vendor_cfr_capture_type(vendor_capture_type);
		ucfg_cfr_set_rcc_mode(vdev, type, 1);
		hdd_debug("type %d", type);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_UL_MU_MASK]) {
		ul_mu_user_mask = nla_get_u64(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_UL_MU_MASK]);
		hdd_debug("ul_mu_user_mask_lower %d",
			  params.ul_mu_user_mask_lower);
	}

	if (ul_mu_user_mask) {
		params.ul_mu_user_mask_lower =
				(uint32_t)(ul_mu_user_mask & 0xffffffff);
		params.ul_mu_user_mask_lower =
				(uint32_t)(ul_mu_user_mask >> 32);
		hdd_debug("set ul mu user mask");
		ucfg_cfr_set_ul_mu_user_mask(vdev, &params);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FREEZE_TLV_DELAY_COUNT]) {
		params.freeze_tlv_delay_cnt_thr = nla_get_u32(tb[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_FREEZE_TLV_DELAY_COUNT]);
		if (params.freeze_tlv_delay_cnt_thr) {
			params.freeze_tlv_delay_cnt_en = 1;
			ucfg_cfr_set_freeze_tlv_delay_cnt(vdev, &params);
			hdd_debug("freeze_tlv_delay_cnt_thr %d",
				  params.freeze_tlv_delay_cnt_thr);
		}
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TABLE]) {
		maxtype = QCA_WLAN_VENDOR_ATTR_PEER_CFR_MAX;
		attr = QCA_WLAN_VENDOR_ATTR_PEER_CFR_GROUP_TABLE;
		nla_for_each_nested(group_list, tb[attr], rem) {
			if (wlan_cfg80211_nla_parse(group, maxtype,
						    nla_data(group_list),
						    nla_len(group_list),
						    cfr_config_policy)) {
				hdd_err("nla_parse failed for cfr config group");
				return -EINVAL;
			}
			wlan_cfg80211_cfr_set_group_config(vdev, group);
		}
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_TRANSPORT_MODE]) {
		uint8_t transport_mode = 0xff;
		uint32_t pid = 0;

		if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_RECEIVER_PID])
			pid = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_RECEIVER_PID]);
		else
			hdd_debug("No PID received");

		transport_mode = nla_get_u8(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_TRANSPORT_MODE]);

		hdd_debug("tx mode attr %d, pid %d", transport_mode, pid);
		if (transport_mode == QCA_WLAN_VENDOR_CFR_DATA_RELAY_FS ||
		    transport_mode == QCA_WLAN_VENDOR_CFR_DATA_NETLINK_EVENTS) {
			wlan_hdd_transport_mode_cfg(vdev->vdev_objmgr.wlan_pdev,
						    vdev->vdev_objmgr.vdev_id,
						    pid, transport_mode);
		} else {
			hdd_debug("invalid transport mode %d for vdev id %d",
				  transport_mode, vdev->vdev_objmgr.vdev_id);
		}
	}

	return 0;
}

static QDF_STATUS hdd_stop_enh_cfr(struct wlan_objmgr_vdev *vdev)
{
	if (!ucfg_cfr_get_rcc_enabled(vdev))
		return QDF_STATUS_SUCCESS;

	hdd_debug("cleanup rcc mode");
	wlan_objmgr_vdev_try_get_ref(vdev, WLAN_CFR_ID);
	ucfg_cfr_set_rcc_mode(vdev, RCC_DIS_ALL_MODE, 0);
	ucfg_cfr_subscribe_ppdu_desc(wlan_vdev_get_pdev(vdev),
				     false);
	ucfg_cfr_committed_rcc_config(vdev);
	ucfg_cfr_stop_indication(vdev);
	ucfg_cfr_suspend(wlan_vdev_get_pdev(vdev));
	hdd_debug("stop indication done");
	wlan_objmgr_vdev_release_ref(vdev, WLAN_CFR_ID);

	return QDF_STATUS_SUCCESS;
}

static enum
phy_ch_width convert_capture_bw(enum nl80211_chan_width capture_bw)
{
	switch (capture_bw) {
	case NL80211_CHAN_WIDTH_20_NOHT:
	case NL80211_CHAN_WIDTH_20:
		return CH_WIDTH_20MHZ;
	case NL80211_CHAN_WIDTH_40:
		return CH_WIDTH_40MHZ;
	case NL80211_CHAN_WIDTH_80:
		return CH_WIDTH_80MHZ;
	case NL80211_CHAN_WIDTH_80P80:
		return CH_WIDTH_80P80MHZ;
	case NL80211_CHAN_WIDTH_160:
		return CH_WIDTH_160MHZ;
	case NL80211_CHAN_WIDTH_5:
		return CH_WIDTH_5MHZ;
	case NL80211_CHAN_WIDTH_10:
		return CH_WIDTH_10MHZ;
	case NL80211_CHAN_WIDTH_320:
		return CH_WIDTH_320MHZ;
	default:
		cfr_err("invalid capture bw");
		return CH_WIDTH_INVALID;
	}
}

static void wlan_cfg80211_reset_cfr(struct pdev_cfr *pcfr, uint8_t value)
{
	if (!pcfr)
		return;
	pcfr->is_associated = value;
	pcfr->freq = value;
	pcfr->report_interval = value;
	pcfr->format_version = value;
	pcfr->oui_length = value;
	qdf_mem_zero(pcfr->oui, MAX_CFR_OUI_LEN);
	pcfr->is_cfr_version_v3 = value;
	pcfr->frame_type = value;
	pcfr->frame_sub_type = value;
	pcfr->unassoc_capture_config = value;
	pcfr->unassoc_channel_mhz = value;
	pcfr->unassoc_phy_mode = value;
	pcfr->bandwidth = value;
	pcfr->is_cfr_data_present = value;
}

static QDF_STATUS wlan_cfg80211_stop_enh_cfr_v3(
			struct wlan_objmgr_vdev *vdev,
			uint8_t value)
{
	struct pdev_cfr *pcfr = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;
	struct wlan_objmgr_peer *peer = NULL;
	struct wlan_objmgr_psoc *psoc = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	bool pdev_ref_taken = false;

	if (!vdev) {
		cfr_err("Invalid vdev");
		return QDF_STATUS_E_INVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		cfr_err("Failed to get pdev object");
		return QDF_STATUS_E_INVAL;
	}

	status = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		cfr_err("Failed to get pdev reference");
		return status;
	}
	pdev_ref_taken = true;

	pcfr = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);
	if (!pcfr) {
		cfr_err("CFR private object is NULL");
		status = QDF_STATUS_E_INVAL;
		goto cleanup;
	}

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		cfr_err("Failed to get psoc");
		status = QDF_STATUS_E_INVAL;
		goto cleanup;
	}

	ucfg_cfr_stop_report_interval_timer(vdev);

	/* Handle TX CFR capture cleanup */
	if (pcfr->is_cfr_tx &&
	    !qdf_is_macaddr_zero((struct qdf_mac_addr *)pcfr->peer_addr)) {
		peer = wlan_objmgr_get_peer_by_mac(psoc, pcfr->peer_addr,
						   WLAN_CFR_ID);
		if (!peer) {
			cfr_err("No peer object found for TX CFR cleanup");
			/* Continue with cleanup even if peer not found */
		} else {
			cfr_debug("clean up CFR TX");
			ucfg_cfr_stop_capture(pdev, peer);
			wlan_objmgr_peer_release_ref(peer, WLAN_CFR_ID);
		}

		pcfr->is_cfr_tx = value;
		memset(pcfr->peer_addr, value, QDF_MAC_ADDR_SIZE);
	}

	/* Handle RX CFR capture cleanup */
	if (pcfr->is_cfr_rx) {
		pcfr->is_cfr_rx = value;
		cfr_debug("clean up CFR RX");
		status = hdd_stop_enh_cfr(vdev);
		if (QDF_IS_STATUS_ERROR(status))
			cfr_err("Failed to stop enhanced CFR RX capture");
	}

	wlan_cfg80211_reset_cfr(pcfr, 0);
cleanup:
	if (pdev_ref_taken)
		wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);

	return status;
}

QDF_STATUS hdd_cfr_disconnect(struct wlan_objmgr_vdev *vdev)
{
	struct pdev_cfr *pcfr = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!vdev) {
		cfr_err("Invalid vdev");
		return QDF_STATUS_E_INVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		cfr_err("Failed to get pdev object");
		return QDF_STATUS_E_INVAL;
	}

	pcfr = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);
	if (!pcfr) {
		cfr_err("CFR private object is NULL");
		return QDF_STATUS_E_INVAL;
	}

	cfr_debug("Disconnecting CFR capture, version_v3: %s",
		  pcfr->is_cfr_version_v3 ? "true" : "false");

	if (pcfr->is_cfr_version_v3) {
		status = wlan_cfg80211_stop_enh_cfr_v3(vdev, 0);
		if (QDF_IS_STATUS_ERROR(status)) {
			cfr_err("Failed to stop enhanced CFR v3, status: %d",
				status);
		}
	} else {
		status = hdd_stop_enh_cfr(vdev);
		if (QDF_IS_STATUS_ERROR(status)) {
			cfr_err("Failed to stop enhanced CFR, status: %d",
				status);
		}
	}

	return status;
}

void wlan_hdd_stop_cfr(uint8_t vdev_id, uint32_t reason)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	struct wlan_hdd_link_info *link_info;

	if (wlan_hdd_validate_context(hdd_ctx)) {
		cfr_err("HDD context is NULL");
		return;
	}

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, vdev_id);
	if (!link_info) {
		cfr_err("adapter NULL for vdev id %d", vdev_id);
		return;
	}

	cfr_debug("stop CFR vdev id %d reason %d ", vdev_id, reason);

	status = hdd_cfr_disconnect(link_info->vdev);
	if (QDF_IS_STATUS_ERROR(status)) {
		cfr_err("Failed to stop CFR V3, status: %d",
			status);
	}
}

static void wlan_cfg80211_register_stop_cfr(struct pdev_cfr *pcfr,
					    uint8_t vdev_id)
{
	if (!pcfr) {
		cfr_err("Invalid pcfr");
		return;
	}

	pcfr->cfr_stop_cb = wlan_hdd_stop_cfr;
	pcfr->vdev_id = vdev_id;
}

static int wlan_enh_cfr_capture_v3_tx(struct hdd_adapter *adapter,
				      struct nlattr **tb,
				      struct wlan_objmgr_vdev *vdev,
				      struct wlan_objmgr_pdev *pdev,
				      struct pdev_cfr *pcfr)
{
	struct cfr_capture_params params = { 0 };
	struct wlan_objmgr_peer *peer = NULL;
	struct wlan_objmgr_psoc *psoc = NULL;
	struct qdf_mac_addr peer_addr = { 0 };
	enum phy_ch_width peer_bw;
	enum wlan_phymode peer_phymode;
	QDF_STATUS status;
	int ret = 0;
	struct wlan_channel *bss_chan;

	if (!adapter) {
		cfr_err("Invalid adapter pointer");
		return -EINVAL;
	}

	if (!tb) {
		cfr_err("Invalid netlink attribute array");
		return -EINVAL;
	}

	if (!vdev) {
		cfr_err("Invalid vdev pointer");
		return -EINVAL;
	}

	if (!pdev) {
		cfr_err("Invalid pdev pointer");
		return -EINVAL;
	}

	if (!pcfr) {
		cfr_err("Invalid CFR private object pointer");
		return -EINVAL;
	}

	if (!tb[QCA_WLAN_VENDOR_ATTR_CFR_PEER_MAC_ADDR]) {
		cfr_err("Peer MAC address attribute not provided");
		return -EINVAL;
	}

	nla_memcpy(peer_addr.bytes, tb[QCA_WLAN_VENDOR_ATTR_CFR_PEER_MAC_ADDR],
		   QDF_MAC_ADDR_SIZE);

	if (qdf_is_macaddr_zero(&peer_addr)) {
		cfr_err("Invalid zero MAC address provided");
		return -EINVAL;
	}

	if (qdf_is_macaddr_broadcast(&peer_addr)) {
		cfr_err("Broadcast MAC address not allowed for TX capture");
		return -EINVAL;
	}

	qdf_mem_copy(pcfr->peer_addr, peer_addr.bytes, QDF_MAC_ADDR_SIZE);

	cfr_debug("CFR TX capture for peer " QDF_MAC_ADDR_FMT,
		  QDF_MAC_ADDR_REF(peer_addr.bytes));

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		cfr_err("Failed to get PSOC object from vdev");
		return -EINVAL;
	}

	peer = wlan_objmgr_get_peer_by_mac(psoc, peer_addr.bytes, WLAN_CFR_ID);
	if (!peer) {
		cfr_err("No peer object found for MAC " QDF_MAC_ADDR_FMT,
			QDF_MAC_ADDR_REF(peer_addr.bytes));
		return -ENOENT;
	}

	peer_phymode = wlan_peer_get_phymode(peer);
	peer_bw = wlan_mlme_get_ch_width_from_phymode(peer_phymode);
	if (pcfr->bandwidth > peer_bw) {
		cfr_err("Invalid peer bw %d cfr bw %d", peer_bw,
			pcfr->bandwidth);
		ret = -EINVAL;
		goto release_peer;
	}

	bss_chan = wlan_vdev_mlme_get_bss_chan(wlan_peer_get_vdev(peer));
	if (!bss_chan) {
		cfr_err("Invalid bss chan");
		ret = -EINVAL;
		goto release_peer;
	}

	if (pcfr->freq != bss_chan->ch_freq) {
		cfr_err("Invalid CFR freq %d bss freq %d",
			pcfr->freq, bss_chan->ch_freq);
		ret = -EINVAL;
		goto release_peer;
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_PERIODICITY]) {
		params.period = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_PERIODICITY]);
		cfr_debug("CFR capture periodicity: %u ms", params.period);

		if (params.period > 0 && params.period < 10) {
			cfr_err("Invalid periodicity %u ms, minimum is 10ms",
				params.period);
			ret = -EINVAL;
			goto release_peer;
		}
	}

	params.method = pcfr->method;
	params.bandwidth = pcfr->bandwidth;

	/* Check frame type and subtype QOS is only valid for TX CFR */
	if (pcfr->frame_type != FRAME_CTRL ||
	    pcfr->frame_sub_type != SUB_TYPE_QOS_NULL) {
		cfr_err("Invalid frame_type %d frame_subtype %d",
			pcfr->frame_type, pcfr->frame_sub_type);
		ret = -EINVAL;
		goto release_peer;
	}

	cfr_debug("Starting CFR TX capture with method: %u, bandwidth: %u",
		  params.method, params.bandwidth);

	wlan_hdd_transport_mode_cfg(pdev, vdev->vdev_objmgr.vdev_id,
				    0, QCA_WLAN_VENDOR_CFR_DATA_NETLINK_EVENTS);

	status = ucfg_cfr_start_capture(pdev, peer, &params);
	if (QDF_IS_STATUS_ERROR(status)) {
		cfr_err("Failed to start CFR capture, status: %d", status);
		ret = qdf_status_to_os_return(status);
		goto release_peer;
	}

	pcfr->is_cfr_tx = true;

	cfr_debug("CFR TX capture started for peer " QDF_MAC_ADDR_FMT,
		  QDF_MAC_ADDR_REF(peer_addr.bytes));

release_peer:
	wlan_objmgr_peer_release_ref(peer, WLAN_CFR_ID);

	return ret;
}

static bool cfr_validate_method_tx(uint8_t method)
{
	switch (method) {
	case QCA_WLAN_VENDOR_CFR_METHOD_QOS_NULL:
		return true;
	default:
		cfr_err("Invalid CFR method: %d", method);
		return false;
	}
}

static bool cfr_validate_transport_mode(uint8_t transport_mode)
{
	switch (transport_mode) {
	case QCA_WLAN_VENDOR_CFR_DATA_NETLINK_EVENTS:
		return true;
	default:
		cfr_err("Invalid CFR transport mode: %d", transport_mode);
		return false;
	}
}

static int cfr_extract_enable_flag(struct nlattr **tb,
				   struct cfr_v3_params *cfr_params)
{
	if (!tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE])
		return 0;

	cfr_params->is_start_capture = nla_get_flag(tb[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE]);
	cfr_debug("CFR capture %s",
		  cfr_params->is_start_capture ? "enable" : "disable");
	return 0;
}

static int cfr_extract_method_tx(struct nlattr **tb,
				 struct cfr_v3_params *cfr_params)
{
	if (!tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_METHOD]) {
		cfr_params->rx_capture = true;
		return 0;
	}

	cfr_params->method = nla_get_u8(tb[
		QCA_WLAN_VENDOR_ATTR_PEER_CFR_METHOD]);

	if (!cfr_validate_method_tx(cfr_params->method)) {
		cfr_err("CFR method validation failed: %d",
			cfr_params->method);
		return -EINVAL;
	}

	cfr_params->tx_capture = (cfr_params->method ==
				  QCA_WLAN_VENDOR_CFR_METHOD_QOS_NULL);

	cfr_debug("CFR method: %d (%s), TX capture: %s",
		  cfr_params->method,
		  (cfr_params->method ==
		   QCA_WLAN_VENDOR_CFR_METHOD_QOS_NULL) ?
		  "QoS NULL" : "Probe Response",
		  cfr_params->tx_capture ? "start" : "stop");

	return 0;
}

static int cfr_extract_frame_info(struct nlattr **tb,
				  struct cfr_v3_params *cfr_params)
{
	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_TYPE]) {
		cfr_params->frame_type = nla_get_u8(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_TYPE]);
		cfr_debug("CFR Frame type: %d", cfr_params->frame_type);

		/* Validate frame type (0=Management, 1=Control, 2=Data) */
		if (cfr_params->frame_type > CFR_MAX_FRAME_TYPE) {
			cfr_err("Invalid frame type: %d",
				cfr_params->frame_type);
			return -EINVAL;
		}
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_SUBTYPE]) {
		cfr_params->frame_subtype = nla_get_u8(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_FRAME_SUBTYPE]);
		cfr_debug("CFR Frame subtype: %d", cfr_params->frame_subtype);

		if (cfr_params->frame_subtype > CFR_MAX_FRAME_SUBTYPE) {
			cfr_err("Invalid frame subtype: %d",
				cfr_params->frame_subtype);
			return -EINVAL;
		}
	}

	return 0;
}

static int cfr_extract_rf_params(struct nlattr **tb,
				 struct cfr_v3_params *cfr_params,
				 struct wlan_objmgr_pdev *pdev)
{
	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_FREQ]) {
		cfr_params->freq = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_FREQ]);

		if (!wlan_reg_is_freq_enabled(pdev, cfr_params->freq,
					      REG_CURRENT_PWR_MODE)) {
			cfr_err("CFR frequency validation failed: %d MHz",
				cfr_params->freq);
			return -EINVAL;
		}

		cfr_debug("CFR Frequency: %d MHz", cfr_params->freq);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_BANDWIDTH]) {
		cfr_params->bandwidth = nla_get_u8(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_BANDWIDTH]);
		cfr_params->bandwidth =
			convert_capture_bw(cfr_params->bandwidth);
		if (cfr_params->bandwidth == CH_WIDTH_INVALID) {
			cfr_err("CFR bandwidth validation failed: %d",
				cfr_params->bandwidth);
			return -EINVAL;
		}
		cfr_debug("CFR Capture bandwidth: %d", cfr_params->bandwidth);
	}

	return 0;
}

static int cfr_extract_transport_params(struct nlattr **tb,
					struct cfr_v3_params *cfr_params)
{
	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_REPORT_INTERVAL]) {
		cfr_params->report_interval = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_REPORT_INTERVAL]);

		if (cfr_params->report_interval < CFR_MIN_REPORT_INTERVAL ||
		    cfr_params->report_interval > CFR_MAX_REPORT_INTERVAL) {
			cfr_err("Invalid report interval: %d ms (valid range: %d-%d)",
				cfr_params->report_interval,
				CFR_MIN_REPORT_INTERVAL,
				CFR_MAX_REPORT_INTERVAL);
			return -EINVAL;
		}

		cfr_debug("CFR Report interval: %d ms",
			  cfr_params->report_interval);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_TRANSPORT_MODE]) {
		cfr_params->transport_mode = nla_get_u8(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_TRANSPORT_MODE]);

		if (!cfr_validate_transport_mode(cfr_params->transport_mode)) {
			cfr_err("CFR transport mode validation failed: %d",
				cfr_params->transport_mode);
			return -EINVAL;
		}

		cfr_debug("CFR Transport mode: %d (%s)",
			  cfr_params->transport_mode,
			  (cfr_params->transport_mode ==
			   QCA_WLAN_VENDOR_CFR_DATA_NETLINK_EVENTS) ?
			  "Netlink Events" : "Relay FS");
	}

	return 0;
}

static int cfr_extract_format_params(struct nlattr **tb,
				     struct cfr_v3_params *cfr_params)
{
	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_VERSION]) {
		cfr_params->format_version = nla_get_u8(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_VERSION]);

		if (cfr_params->format_version < CFR_MIN_FORMAT_VERSION ||
		    cfr_params->format_version > CFR_MAX_FORMAT_VERSION) {
			cfr_err("Invalid format version: %d (valid range: %d-%d)",
				cfr_params->format_version,
				CFR_MIN_FORMAT_VERSION, CFR_MAX_FORMAT_VERSION);
			return -EINVAL;
		}

		cfr_debug("CFR Format version: %d", cfr_params->format_version);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_OUI]) {
		cfr_params->oui_length = nla_len(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_OUI]);

		if (cfr_params->oui_length == 0) {
			cfr_err("Empty OUI provided");
			return -EINVAL;
		}

		if (cfr_params->oui_length > MAX_CFR_OUI_LEN) {
			cfr_err("OUI length %d exceeds maximum %d, truncating",
				cfr_params->oui_length, MAX_CFR_OUI_LEN);
			cfr_params->oui_length = MAX_CFR_OUI_LEN;
		}

		nla_memcpy(cfr_params->oui,
			   tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_DATA_FORMAT_OUI],
			   cfr_params->oui_length);

		cfr_debug("CFR OUI length: %d bytes", cfr_params->oui_length);
	}

	return 0;
}

static int wlan_cfg80211_extract_cfr_params(struct nlattr **tb,
					    struct cfr_v3_params *cfr_params,
					    struct wlan_objmgr_pdev *pdev)
{
	int ret = 0;

	if (!tb) {
		cfr_err("Invalid netlink attribute array pointer");
		return -EINVAL;
	}

	if (!cfr_params) {
		cfr_err("Invalid CFR parameters structure pointer");
		return -EINVAL;
	}

	qdf_mem_zero(cfr_params, sizeof(*cfr_params));

	ret = cfr_extract_enable_flag(tb, cfr_params);
	if (ret) {
		cfr_err("Failed to extract enable flag, ret: %d", ret);
		return ret;
	}

	ret = cfr_extract_method_tx(tb, cfr_params);
	if (ret) {
		cfr_err("Failed to extract method, ret: %d", ret);
		return ret;
	}

	ret = cfr_extract_frame_info(tb, cfr_params);
	if (ret) {
		cfr_err("Failed to extract frame info, ret: %d", ret);
		return ret;
	}

	ret = cfr_extract_rf_params(tb, cfr_params, pdev);
	if (ret) {
		cfr_err("Failed to extract RF parameters, ret: %d", ret);
		return ret;
	}

	ret = cfr_extract_transport_params(tb, cfr_params);
	if (ret) {
		cfr_err("Failed to extract transport parameters, ret: %d", ret);
		return ret;
	}

	ret = cfr_extract_format_params(tb, cfr_params);
	if (ret) {
		cfr_err("Failed to extract format parameters, ret: %d", ret);
		return ret;
	}

	cfr_debug("CFR v3 parameters extracted successfully: enable=%d, method=%d, tx_capture=%d, freq=%d, bw=%d, interval=%d",
		  cfr_params->is_start_capture, cfr_params->method,
		  cfr_params->tx_capture, cfr_params->freq,
		  cfr_params->bandwidth, cfr_params->report_interval);

	return 0;
}

static void wlan_cfg80211_configure_cfr_v3(
		struct pdev_cfr *pcfr,
		const struct cfr_v3_params *cfr_params,
		bool is_sta_connected)
{
	if (!pcfr || !cfr_params) {
		cfr_err("Invalid input parameters");
		return;
	}

	pcfr->frame_type = cfr_params->frame_type;
	pcfr->frame_sub_type = cfr_params->frame_subtype;
	pcfr->is_cfr_version_v3 = true;
	pcfr->report_interval = cfr_params->report_interval;
	pcfr->is_associated = is_sta_connected;
	pcfr->is_cfr_tx = cfr_params->tx_capture;
	pcfr->is_cfr_rx = cfr_params->rx_capture;
	pcfr->method = cfr_params->method;
	pcfr->bandwidth = cfr_params->bandwidth;
	pcfr->freq = cfr_params->freq;
	pcfr->oui_length = cfr_params->oui_length;
	pcfr->format_version = cfr_params->format_version;
	qdf_mem_copy(pcfr->oui, cfr_params->oui, cfr_params->oui_length);
	cfr_debug("CFR v3 configured: frame_type=%d, frame_subtype=%d, report_interval=%d, bandwidth=%d, freq=%d, associated=%d",
		  pcfr->frame_type, pcfr->frame_sub_type, pcfr->report_interval,
		  pcfr->bandwidth, pcfr->freq, pcfr->is_associated);
}

static int wlan_cfg80211_start_cfr_rx_capture(struct wlan_objmgr_vdev *vdev,
					      struct nlattr **tb)
{
	struct cfr_wlanconfig_param params = { 0 };
	struct pdev_cfr *pcfr = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;
	int status = 0;
	uint8_t grp_id, grp_id_supported = 0;
	bool pdev_ref_taken = false;
	enum phy_ch_width peer_bw;
	uint32_t bss_freq;

	if (!vdev || !tb) {
		cfr_err("Invalid input parameters");
		return -EINVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		cfr_err("Failed to get pdev object");
		return -ENODEV;
	}

	status = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		cfr_err("Failed to get pdev reference");
		return -EBUSY;
	}
	pdev_ref_taken = true;

	pcfr = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);
	if (!pcfr) {
		cfr_err("CFR private object is NULL");
		status = -ENOENT;
		goto cleanup;
	}

	if (!tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE_GROUP_BITMAP]) {
		cfr_err("Group bitmap attribute missing for CFR RX capture start");
		status = -EINVAL;
		goto cleanup;
	}

	/* Set CFR configuration */
	status = wlan_cfg80211_cfr_set_config(vdev, tb);
	if (status) {
		cfr_err("Failed to set CFR config, status=%d", status);
		status = -EINVAL;
		goto cleanup;
	}

	ucfg_cfr_get_peer_info(vdev, &peer_bw, &bss_freq);

	/* Count supported group IDs */
	for (grp_id = 0; grp_id < MAX_TA_RA_ENTRIES; grp_id++) {
		if (qdf_atomic_test_bit(
				grp_id,
				pcfr->rcc_param.modified_in_curr_session)) {
			grp_id_supported++;
		}
	}

	/* if more than one mac is there its RX un assoc */
	if (pcfr->is_associated && grp_id_supported > 1)
		pcfr->is_associated = false;

	/* Validate bandwidth for unassociated mode */
	if (!pcfr->is_associated && pcfr->bandwidth != CH_WIDTH_20MHZ) {
		cfr_err("Invalid bandwidth %d for unassociated RX mode",
			pcfr->bandwidth);
		status = -EINVAL;
		goto cleanup;
	}

	/* Validate bandwidth for associated mode */
	if (pcfr->is_associated && pcfr->bandwidth > peer_bw) {
		cfr_err("Invalid peer bw %d  cfr bw %d for assoc RX mode",
			peer_bw, pcfr->bandwidth);
		status = -EINVAL;
		goto cleanup;
	}

	 /* Validate freq for associated mode */
	if (pcfr->is_associated && pcfr->freq != bss_freq) {
		cfr_err("Invalid bss freq %d cfr freq %d for assoc RX mode",
			bss_freq, pcfr->freq);
		status = -EINVAL;
		goto cleanup;
	}

	if (!pcfr->is_associated) {
		pcfr->unassoc_capture_config = 1;
		pcfr->unassoc_channel_mhz = pcfr->freq;
		cfr_debug("Configured unassociated capture: freq=%d MHz",
			  pcfr->freq);
	}

	params.en_cfg =
	nla_get_u32(tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE_GROUP_BITMAP]);
	if (!params.en_cfg) {
		cfr_err("Invalid group bitmap value: 0x%x", params.en_cfg);
		status = -EINVAL;
		goto cleanup;
	}

	cfr_debug("Starting CFR RX capture with bitmap: 0x%x", params.en_cfg);

	/* Start CFR RX capture sequence */
	ucfg_cfr_set_en_bitmap(vdev, &params);
	ucfg_cfr_resume(wlan_vdev_get_pdev(vdev));
	ucfg_cfr_subscribe_ppdu_desc(wlan_vdev_get_pdev(vdev), true);
	ucfg_cfr_committed_rcc_config(vdev);

	cfr_info("CFR RX capture started: mode=%s, groups=%d, bitmap=0x%x",
		 pcfr->is_associated ? "associated" : "unassociated",
		 grp_id_supported, params.en_cfg);

cleanup:
	if (pdev_ref_taken)
		wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);

	return status;
}

static int
wlan_cfg80211_enh_cfr_capture_v3(struct hdd_adapter *adapter,
				 struct nlattr **tb)
{
	struct cfr_v3_params cfr_params = { 0 };
	struct wlan_objmgr_vdev *vdev = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;
	struct wmi_unified *wmi_handle = NULL;
	struct pdev_cfr *pcfr = NULL;
	bool is_sta_connected = false;
	int ret = 0;

	if (!adapter) {
		cfr_err("Invalid adapter pointer");
		return -EINVAL;
	}

	if (!tb) {
		cfr_err("Invalid netlink attribute array");
		return -EINVAL;
	}

	if (!adapter->hdd_ctx) {
		cfr_err("Invalid HDD context pointer");
		return -EINVAL;
	}

	if (!adapter->hdd_ctx->psoc) {
		cfr_err("Invalid PSOC pointer");
		return -EINVAL;
	}

	wmi_handle = get_wmi_unified_hdl_from_psoc(adapter->hdd_ctx->psoc);
	if (!wmi_handle) {
		cfr_err("wmi handle is NULL");
		return -EINVAL;
	}

	if (!wmi_service_enabled(wmi_handle,
				 wmi_service_cfr_assoc_tx_capture_support) &&
	    !wmi_service_enabled(wmi_handle,
				 wmi_service_cfr_unassoc_rx_capture_support)) {
		cfr_err("CFR V3 not supported by fw");
		return -EINVAL;
	}

	if (!policy_mgr_is_cfr_allowed(adapter->hdd_ctx->psoc)) {
		cfr_err("CFR V3 rejected due to concurrency");
		return -EINVAL;
	}

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_CFR_ID);
	if (!vdev) {
		cfr_err("Failed to get vdev object");
		return -EINVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		cfr_err("Failed to get pdev object");
		ret = -EINVAL;
		goto release_vdev;
	}

	pcfr = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);
	if (!pcfr) {
		cfr_err("CFR private object is NULL");
		ret = -EINVAL;
		goto release_vdev;
	}

	ret = wlan_cfg80211_extract_cfr_params(tb, &cfr_params, pdev);
	if (ret) {
		cfr_err("Failed to extract CFR parameters, ret: %d", ret);
		goto release_vdev;
	}

	if (!cfr_params.is_start_capture) {
		cfr_debug("Stopping CFR v3 capture");
		ret = wlan_cfg80211_stop_enh_cfr_v3(vdev, 0);
		goto release_vdev;
	}

	/* Check if CFR capture is already active */
	if (pcfr->is_cfr_tx || pcfr->is_cfr_rx) {
		cfr_err("CFR capture already active: TX=%d, RX=%d",
			pcfr->is_cfr_tx, pcfr->is_cfr_rx);
		ret = -EBUSY;
		goto release_vdev;
	}

	is_sta_connected = hdd_is_any_sta_connected(adapter->hdd_ctx);
	cfr_debug("STA connected: %d", is_sta_connected);

	wlan_cfg80211_configure_cfr_v3(pcfr, &cfr_params, is_sta_connected);

	wlan_cfg80211_register_stop_cfr(pcfr, vdev->vdev_objmgr.vdev_id);

	ucfg_tdls_teardown_links_sync(adapter->hdd_ctx->psoc, vdev);

	if (cfr_params.tx_capture) {
		if (!is_sta_connected) {
			cfr_err("TX capture requires STA to be connected");
			ret = -ENOTCONN;
			goto release_vdev;
		}

		cfr_debug("Starting CFR TX capture");
		ret = wlan_enh_cfr_capture_v3_tx(adapter, tb, vdev, pdev, pcfr);
		goto release_vdev;
	}

	cfr_debug("Starting CFR RX capture");

	if (!is_sta_connected) {
		cfr_debug("Configuring unassociated capture mode");
		pcfr->unassoc_capture_config = 1;
		pcfr->unassoc_channel_mhz = cfr_params.freq;
	}

	if (!is_sta_connected &&
	    pcfr->bandwidth != CH_WIDTH_20MHZ) {
		cfr_err("Invalid bw for rx un associated");
			ret = -EINVAL;
			goto release_vdev;
	}

	ret = wlan_cfg80211_start_cfr_rx_capture(vdev, tb);
	if (ret) {
		cfr_err("Failed to start CFR RX capture, ret: %d", ret);
		goto release_vdev;
	}

release_vdev:
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
	if (ret)
		wlan_cfg80211_reset_cfr(pcfr, 0);
	return ret;
}

static int
wlan_cfg80211_peer_enh_cfr_capture(struct hdd_adapter *adapter,
				   struct nlattr **tb)
{
	struct cfr_wlanconfig_param params = { 0 };
	struct wlan_objmgr_vdev *vdev;
	bool is_start_capture = false;
	int ret = 0;

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE]) {
		is_start_capture = nla_get_flag(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE]);
	}

	if (is_start_capture &&
	    !tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE_GROUP_BITMAP]) {
		hdd_err("Invalid group bitmap");
		return -EINVAL;
	}

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_CFR_ID);
	if (!vdev) {
		hdd_err("can't get vdev");
		return -EINVAL;
	}

	if (is_start_capture) {
		ret = wlan_cfg80211_cfr_set_config(vdev, tb);
		if (ret) {
			hdd_err("set config failed");
			goto out;
		}
		params.en_cfg = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE_GROUP_BITMAP]);
		hdd_debug("params.en_cfg %d", params.en_cfg);
		ucfg_cfr_set_en_bitmap(vdev, &params);
		ucfg_cfr_resume(wlan_vdev_get_pdev(vdev));
		ucfg_cfr_subscribe_ppdu_desc(wlan_vdev_get_pdev(vdev),
					     true);
		ucfg_cfr_committed_rcc_config(vdev);
	} else {
		hdd_stop_enh_cfr(vdev);
	}
out:
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
	return ret;
}
#else
static int
wlan_cfg80211_peer_enh_cfr_capture(struct hdd_adapter *adapter,
				   struct nlattr **tb)
{
	return 0;
}

static int
wlan_cfg80211_enh_cfr_capture_v3(struct hdd_adapter *adapter,
				 struct nlattr **tb)
{
	return 0;
}
#endif

#ifdef WLAN_CFR_ADRASTEA
static QDF_STATUS
wlan_cfg80211_peer_cfr_capture_cfg_adrastea(struct hdd_adapter *adapter,
					    struct nlattr **tb)
{
	struct cfr_capture_params params = { 0 };
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;
	struct wlan_objmgr_peer *peer;
	struct wlan_objmgr_psoc *psoc;
	struct qdf_mac_addr peer_addr;
	bool is_start_capture = false;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!tb[QCA_WLAN_VENDOR_ATTR_CFR_PEER_MAC_ADDR]) {
		hdd_err("peer mac addr not given");
		return QDF_STATUS_E_INVAL;
	}

	nla_memcpy(peer_addr.bytes, tb[QCA_WLAN_VENDOR_ATTR_CFR_PEER_MAC_ADDR],
		   QDF_MAC_ADDR_SIZE);

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE]) {
		is_start_capture = nla_get_flag(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE]);
	}

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_CFR_ID);
	if (!vdev) {
		hdd_err("can't get vdev");
		return -EINVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		hdd_err("failed to get pdev");
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
		return QDF_STATUS_E_INVAL;
	}

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		hdd_err("Failed to get psoc");
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
		return QDF_STATUS_E_INVAL;
	}

	peer = wlan_objmgr_get_peer_by_mac(psoc, peer_addr.bytes, WLAN_CFR_ID);
	if (!peer) {
		hdd_err("No peer object found");
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
		return QDF_STATUS_E_INVAL;
	}

	if (is_start_capture) {
		if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_PERIODICITY]) {
			params.period = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_PEER_CFR_PERIODICITY]);
			hdd_debug("params.periodicity %d", params.period);
			/* Set the periodic CFR */
			if (params.period)
				ucfg_cfr_set_timer(pdev, params.period);
		}

		if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_METHOD]) {
			params.method = nla_get_u8(tb[
				QCA_WLAN_VENDOR_ATTR_PEER_CFR_METHOD]);
			/* Adrastea supports only QOS NULL METHOD */
			if (params.method !=
					QCA_WLAN_VENDOR_CFR_METHOD_QOS_NULL) {
				hdd_err_rl("invalid capture method %d",
					   params.method);
				status = QDF_STATUS_E_INVAL;
				goto exit;
			}
		}

		if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_BANDWIDTH]) {
			params.bandwidth = nla_get_u8(tb[
				QCA_WLAN_VENDOR_ATTR_PEER_CFR_BANDWIDTH]);
			/* Adrastea supports only 20Mhz bandwidth CFR capture */
			if (params.bandwidth != NL80211_CHAN_WIDTH_20_NOHT) {
				hdd_err_rl("invalid capture bandwidth %d",
					   params.bandwidth);
				status = QDF_STATUS_E_INVAL;
				goto exit;
			}
		}
		ucfg_cfr_start_capture(pdev, peer, &params);
	} else {
		/* Disable the periodic CFR if enabled */
		if (ucfg_cfr_get_timer(pdev))
			ucfg_cfr_set_timer(pdev, 0);

		/* Disable the peer CFR capture */
		ucfg_cfr_stop_capture(pdev, peer);
	}
exit:
	wlan_objmgr_peer_release_ref(peer, WLAN_CFR_ID);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);

	return status;
}
#elif defined(WLAN_CFR_DBR)
static enum
phy_ch_width convert_capture_bw(enum nl80211_chan_width capture_bw)
{
	switch (capture_bw) {
	case NL80211_CHAN_WIDTH_20_NOHT:
	case NL80211_CHAN_WIDTH_20:
		return CH_WIDTH_20MHZ;
	case NL80211_CHAN_WIDTH_40:
		return CH_WIDTH_40MHZ;
	case NL80211_CHAN_WIDTH_80:
		return CH_WIDTH_80MHZ;
	case NL80211_CHAN_WIDTH_80P80:
		return CH_WIDTH_80P80MHZ;
	case NL80211_CHAN_WIDTH_160:
		return CH_WIDTH_160MHZ;
	case NL80211_CHAN_WIDTH_5:
		return CH_WIDTH_5MHZ;
	case NL80211_CHAN_WIDTH_10:
		return CH_WIDTH_10MHZ;
	default:
		hdd_err("invalid capture bw");
		return CH_WIDTH_INVALID;
	}
}

static QDF_STATUS
wlan_cfg80211_peer_cfr_capture_cfg_adrastea(struct hdd_adapter *adapter,
					    struct nlattr **tb)
{
	struct cfr_capture_params params = { 0 };
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;
	struct wlan_objmgr_peer *peer;
	struct wlan_objmgr_psoc *psoc;
	struct qdf_mac_addr peer_addr;
	bool is_start_capture = false;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	int id;

	id = QCA_WLAN_VENDOR_ATTR_CFR_PEER_MAC_ADDR;
	if (!tb[id]) {
		hdd_err("peer mac addr not given");
		return QDF_STATUS_E_INVAL;
	}

	nla_memcpy(peer_addr.bytes, tb[id],
		   QDF_MAC_ADDR_SIZE);

	id = QCA_WLAN_VENDOR_ATTR_PEER_CFR_ENABLE;
	if (tb[id])
		is_start_capture = nla_get_flag(tb[id]);

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_CFR_ID);
	if (!vdev) {
		hdd_err("can't get vdev");
		return -EINVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		hdd_err("failed to get pdev");
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
		return QDF_STATUS_E_INVAL;
	}

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		hdd_err("Failed to get psoc");
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
		return QDF_STATUS_E_INVAL;
	}

	peer = wlan_objmgr_get_peer_by_mac(psoc, peer_addr.bytes, WLAN_CFR_ID);
	if (!peer) {
		hdd_err("No peer object found");
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);
		return QDF_STATUS_E_INVAL;
	}

	if (is_start_capture) {
		id = QCA_WLAN_VENDOR_ATTR_PEER_CFR_PERIODICITY;
		if (tb[id]) {
			params.period = nla_get_u32(tb[id]);
			hdd_debug("params.periodicity %d", params.period);
			/* Set the periodic CFR */
			if (params.period)
				ucfg_cfr_set_timer(pdev, params.period);
		}
		id = QCA_WLAN_VENDOR_ATTR_PEER_CFR_METHOD;
		if (tb[id]) {
			params.method = nla_get_u8(tb[id]);
			/* Adrastea supports only QOS NULL METHOD */
			if (params.method !=
					QCA_WLAN_VENDOR_CFR_METHOD_QOS_NULL) {
				hdd_err_rl("invalid capture method %d",
					   params.method);
				status = QDF_STATUS_E_INVAL;
				goto exit;
			}
		}
		id = QCA_WLAN_VENDOR_ATTR_PEER_CFR_BANDWIDTH;
		if (tb[id]) {
			params.bandwidth = nla_get_u8(tb[id]);
			params.bandwidth = convert_capture_bw(params.bandwidth);
			if (params.bandwidth > NL80211_CHAN_WIDTH_80) {
				hdd_err_rl("invalid capture bandwidth %d",
					   params.bandwidth);
				status = QDF_STATUS_E_INVAL;
				goto exit;
			}
		}
		ucfg_cfr_start_capture(pdev, peer, &params);
	} else {
		/* Disable the periodic CFR if enabled */
		if (ucfg_cfr_get_timer(pdev))
			ucfg_cfr_set_timer(pdev, 0);

		/* Disable the peer CFR capture */
		ucfg_cfr_stop_capture(pdev, peer);
		ucfg_cfr_stop_indication(vdev);
	}
exit:
	wlan_objmgr_peer_release_ref(peer, WLAN_CFR_ID);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_CFR_ID);

	return status;
}

#else
static QDF_STATUS
wlan_cfg80211_peer_cfr_capture_cfg_adrastea(struct hdd_adapter *adapter,
					    struct nlattr **tb)
{
	return QDF_STATUS_E_NOSUPPORT;
}
#endif

static int
wlan_cfg80211_peer_cfr_capture_cfg(struct wiphy *wiphy,
				   struct hdd_adapter *adapter,
				   const void *data,
				   int data_len)
{
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_MAX + 1];
	uint8_t version = 0;
	QDF_STATUS status;

	if (wlan_cfg80211_nla_parse(
			tb,
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_MAX,
			data,
			data_len,
			cfr_config_policy)) {
		hdd_err("Invalid ATTR");
		return -EINVAL;
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_PEER_CFR_VERSION]) {
		version = nla_get_u8(tb[
			QCA_WLAN_VENDOR_ATTR_PEER_CFR_VERSION]);
		hdd_debug("version %d", version);
		if (version == LEGACY_CFR_VERSION) {
			status = wlan_cfg80211_peer_cfr_capture_cfg_adrastea(
								adapter, tb);
			return qdf_status_to_os_return(status);
		} else if (version == ENHANCED_CFR_VERSION_V3) {
			hdd_debug("CFR V3 capture");
			return wlan_cfg80211_enh_cfr_capture_v3(adapter, tb);
		} else if (version != ENHANCED_CFR_VERSION) {
			hdd_err("unsupported version");
			return -EFAULT;
		}
	}

	return wlan_cfg80211_peer_enh_cfr_capture(adapter, tb);
}

static int __wlan_hdd_cfg80211_peer_cfr_capture_cfg(struct wiphy *wiphy,
						    struct wireless_dev *wdev,
						    const void *data,
						    int data_len)
{
	int ret;
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter;
	uint8_t ll_lt_sap_vdev_id;

	hdd_enter();

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		return ret;

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EPERM;
	}

	adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	if (wlan_hdd_validate_vdev_id(adapter->deflink->vdev_id))
		return -EINVAL;

	ll_lt_sap_vdev_id =
			wlan_policy_mgr_get_ll_lt_sap_vdev_id(hdd_ctx->psoc);
	if (ll_lt_sap_vdev_id != WLAN_INVALID_VDEV_ID) {
		hdd_info_rl("LL_LT_SAP vdev %d present, cfr cmd not allowed",
			     ll_lt_sap_vdev_id);
		return -EINVAL;
	}

	ret = wlan_cfg80211_peer_cfr_capture_cfg(wiphy, adapter,
						 data, data_len);

	hdd_exit();

	return ret;
}

int wlan_hdd_cfg80211_peer_cfr_capture_cfg(struct wiphy *wiphy,
					   struct wireless_dev *wdev,
					   const void *data,
					   int data_len)
{
	struct osif_psoc_sync *psoc_sync;
	int errno;

	errno = osif_psoc_sync_op_start(wiphy_dev(wiphy), &psoc_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_peer_cfr_capture_cfg(wiphy, wdev,
							 data, data_len);

	osif_psoc_sync_op_stop(psoc_sync);

	return errno;
}
