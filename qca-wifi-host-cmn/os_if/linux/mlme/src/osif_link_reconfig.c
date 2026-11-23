/*
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
 * DOC: osif_link_reconfig.c
 *
 * This file maintains definitaions of link reconfig request/response
 * common apis.
 */
#include <include/wlan_mlme_cmn.h>
#include "osif_cm_util.h"
#include "wlan_osif_priv.h"
#include "wlan_cfg80211.h"
#include "osif_cm_rsp.h"
#include "wlan_cfg80211_scan.h"
#include "wlan_mlo_mgr_sta.h"
#include "wlan_mlo_mgr_public_structs.h"
#include "wlan_mlo_link_recfg.h"
#include "qdf_status.h"
#include "osif_cm_util.h"
#include <wlan_cfg80211.h>
#ifdef WLAN_FEATURE_MLO_SAP_LINK_REMOVAL
#include "osif_link_reconfig.h"
#endif

enum links_reconfig_op {
	LINKS_RECONFIG_OP_ADD,
	LINKS_RECONFIG_OP_REMOVE,
	LINKS_RECONFIG_MAX,
};

#if defined(WLAN_FEATURE_11BE_MLO) && \
defined(CFG80211_SETUP_LINK_RECONFIG_SUPPORT)
/**
 * osif_get_net_dev_from_vdev() - Get netdev object from vdev
 * @vdev: Pointer to vdev manager
 * @out_net_dev: Pointer to output netdev
 *
 * Return: 0 on success, error code on failure
 */
int osif_get_net_dev_from_vdev(struct wlan_objmgr_vdev *vdev,
			       struct net_device **out_net_dev)
{
	struct vdev_osif_priv *priv;

	if (!vdev)
		return -EINVAL;
	priv = wlan_vdev_get_ospriv(vdev);
	if (!priv || !priv->wdev || !priv->wdev->netdev)
		return -EINVAL;

	*out_net_dev = priv->wdev->netdev;
	return 0;
}

/**
 * osif_get_link_reconfig_rsp_frame() - Get link reconfig resp
 * @link_reconfig_res: link reconfig response
 * @frame_len: frame len
 * @frame_ptr: frame data
 *
 * Return: NA
 */
static void osif_get_link_reconfig_rsp_frame(
				struct element_info *link_reconfig_res,
				size_t *frame_len,
				const uint8_t **frame_ptr)
{
	/* Validate IE and length */
	if (!link_reconfig_res->len || !link_reconfig_res->ptr)
		return;
	*frame_ptr = qdf_mem_malloc(link_reconfig_res->len);
	if (!*frame_ptr)
		return;

	*frame_len = link_reconfig_res->len;
	qdf_mem_copy((void *)*frame_ptr, link_reconfig_res->ptr,
		     link_reconfig_res->len);
}

/**
 * osif_fill_link_reconfig_deleted_links_params() - Update cfg response params
 * @recfg_ctx: reconfig context
 * @delete_valid_links: delete links bitmap
 *
 * Return : bool
 */
static bool
osif_fill_link_reconfig_deleted_links_params(
				 struct mlo_link_recfg_context *recfg_ctx,
				 uint16_t *delete_valid_links)
{
	uint8_t i = 0;
	uint8_t num_del_links;
	struct wlan_mlo_link_recfg_info del_link_info;

	if (!recfg_ctx) {
		osif_err("Recfg ctx is NULL");
		return false;
	}
	num_del_links = recfg_ctx->curr_recfg_req.del_link_info.num_links;
	if (!num_del_links)
		return false;

	del_link_info = recfg_ctx->curr_recfg_req.del_link_info;
	for (i = 0;
	     i < num_del_links &&
	     i < IEEE80211_MLD_MAX_NUM_LINKS &&
	     i < WLAN_MAX_ML_BSS_LINKS; i++) {
		if (del_link_info.link[i].link_id != WLAN_INVALID_LINK_ID)
			*delete_valid_links |=
				1 << del_link_info.link[i].link_id;
	}
	osif_debug("links deleted bit map %d", *delete_valid_links);

	return *delete_valid_links ? true : false;
}

/**
 * osif_fill_link_reconfig_added_links_params() - Update cfg response params
 * @vdev: vdev
 * @cfg_rsp: link reconfig response
 *
 * Return : bool
 */
static bool
osif_fill_link_reconfig_added_links_params(
				 struct wlan_objmgr_vdev *vdev,
				 struct cfg80211_mlo_reconf_done_data *cfg_rsp)
{
	struct wiphy *wiphy;
	uint8_t ssid[WLAN_SSID_MAX_LEN] = {0};
	struct mlo_link_recfg_user_req_params *req_param;
	uint8_t ssid_len;
	struct mlo_link_recfg_context *recfg_context;
	struct ieee80211_channel *channel;
	struct wlan_mlo_link_recfg_info add_link_info;
	enum wlan_status_code status_code;
	uint8_t i;
	uint8_t num_add_links;
	uint8_t link_id;
	QDF_STATUS status;

	wiphy = osif_get_wiphy_from_vdev(vdev);
	if (!wiphy) {
		osif_err("Invalid wiphy");
		return false;
	}

	recfg_context = vdev->mlo_dev_ctx->link_recfg_ctx;
	req_param = &vdev->mlo_dev_ctx->link_rcfg_req;
	num_add_links = recfg_context->curr_recfg_req.add_link_info.num_links;

	if (!recfg_context->curr_recfg_req.is_user_req && !num_add_links) {
		osif_debug("no link added");
		return false;
	}

	cfg_rsp->driver_initiated = !recfg_context->curr_recfg_req.is_user_req;
	add_link_info = recfg_context->curr_recfg_req.add_link_info;
	osif_get_link_reconfig_rsp_frame(
					&recfg_context->rsp_rx_frame,
					&cfg_rsp->len,
					&cfg_rsp->buf);

	/*
	 * Don't get BSS again for user requested link reconfig
	 * because get BSS incerements bss pointer reference
	 * and cfg80211 already does get BSS.
	 */
	for (i = 0; i < QDF_MIN(req_param->num_link_add_param,
				IEEE80211_MLD_MAX_NUM_LINKS) &&
	     i < WLAN_MAX_ML_BSS_LINKS && !cfg_rsp->driver_initiated; i++) {
		link_id = req_param->add_link[i].link_id;
		cfg_rsp->links[link_id].bss = req_param->add_link[i].bss;
	}

	for (i = 0; i < QDF_MIN(num_add_links, IEEE80211_MLD_MAX_NUM_LINKS) &&
	     i < WLAN_MAX_ML_BSS_LINKS; i++) {
		if (add_link_info.link[i].link_id == WLAN_INVALID_LINK_ID) {
			osif_err_rl("link id is invalid %d",
				    WLAN_INVALID_LINK_ID);
			status_code = STATUS_INVALID_PARAMETERS;
			continue;
		}
		link_id = add_link_info.link[i].link_id;
		cfg_rsp->links[link_id].addr =
			qdf_mem_malloc(sizeof(struct qdf_mac_addr));
		if (!cfg_rsp->links[link_id].addr) {
			osif_err_rl("failed to get STA link address");
			status_code = STATUS_INVALID_PARAMETERS;
			goto end;
		}
		qdf_mem_copy(cfg_rsp->links[link_id].addr,
			     add_link_info.link[i].self_link_addr.bytes,
			     sizeof(struct qdf_mac_addr));
		status_code = add_link_info.link[i].status_code;
		if (!cfg_rsp->driver_initiated)
			goto end;

		/* fill bss for driver initiated add link */
		channel = ieee80211_get_channel(wiphy,
						add_link_info.link[i].freq);
		if (!channel) {
			osif_debug("failed to get ieee chan");
			status_code = STATUS_INVALID_PARAMETERS;
			goto end;
		}

		status = wlan_vdev_mlme_get_ssid(vdev, ssid, &ssid_len);
		if (QDF_IS_STATUS_ERROR(status)) {
			osif_debug_rl("failed to get ssid");
			status_code = STATUS_INVALID_PARAMETERS;
			goto end;
		}

		cfg_rsp->links[link_id].bss =
			wlan_cfg80211_get_bss(
				wiphy, channel,
				add_link_info.link[i].ap_link_addr.bytes,
				ssid, ssid_len);
end:
		if (!cfg_rsp->links[link_id].bss) {
			osif_err_rl("failed to get BSS");
			status_code = STATUS_INVALID_PARAMETERS;
		}

		/* Set "added_links" only for successfully added links */
		if (status_code == STATUS_SUCCESS)
			cfg_rsp->added_links |= 1 << link_id;
		osif_debug("add link_id: %d with status: %d freq: %d ssid:" QDF_SSID_FMT " and MAC: " QDF_MAC_ADDR_FMT,
			   link_id, status_code, add_link_info.link[i].freq,
			   QDF_SSID_REF(ssid_len, ssid),
			   QDF_MAC_ADDR_REF(add_link_info.link[i].ap_link_addr.bytes));
	}
	osif_debug("added_link 0x%x driver_initiated %d num_link_add_param %d",
		   cfg_rsp->added_links, cfg_rsp->driver_initiated,
		   req_param->num_link_add_param);

	return (cfg_rsp->added_links ||
		(!cfg_rsp->driver_initiated &&
		 req_param->num_link_add_param));
}

/**
 * struct recfg_done_data - link recfg done data
 * @hdr: recfg done data header
 * @psoc: psoc object
 * @vdev_id: vdev id
 * @add_valid: add_link_rsp is valid
 * @del_valid: del_link_map is valid
 * @del_link_map: delete link bitmap
 * @add_link_rsp: add link information
 */
struct recfg_done_data {
	struct recfg_done_data_hdr hdr;
	struct wlan_objmgr_psoc *psoc;
	uint8_t vdev_id;
	bool add_valid;
	bool del_valid;
	uint16_t del_link_map;
	struct cfg80211_mlo_reconf_done_data add_link_rsp;
};

void osif_free_link_reconfig_done_data(void *ctx)
{
	struct recfg_done_data *recfg_indication_ptr = ctx;
	uint8_t i;

	for (i = 0; i < IEEE80211_MLD_MAX_NUM_LINKS; i++)
		qdf_mem_free(recfg_indication_ptr->add_link_rsp.links[i].addr);

	qdf_mem_free((void *)recfg_indication_ptr->add_link_rsp.buf);
	qdf_mem_free(recfg_indication_ptr);
}

void *
osif_populate_link_recfg_done_data(struct wlan_objmgr_vdev *vdev)
{
	struct mlo_link_recfg_context *recfg_ctx;
	struct recfg_done_data *recfg_indication_ptr;

	recfg_ctx = vdev->mlo_dev_ctx->link_recfg_ctx;
	if (!recfg_ctx) {
		osif_err("link reconfig context not valid");
		return NULL;
	}

	osif_debug("add num links %d, del num links %d",
		   recfg_ctx->curr_recfg_req.add_link_info.num_links,
		   recfg_ctx->curr_recfg_req.del_link_info.num_links);

	recfg_indication_ptr = qdf_mem_malloc(sizeof(struct recfg_done_data));
	if (!recfg_indication_ptr)
		return NULL;
	recfg_indication_ptr->add_valid =
		osif_fill_link_reconfig_added_links_params(
					vdev,
					&recfg_indication_ptr->add_link_rsp);

	recfg_indication_ptr->del_valid =
		osif_fill_link_reconfig_deleted_links_params(
					recfg_ctx,
					&recfg_indication_ptr->del_link_map);
	if (!recfg_indication_ptr->add_valid &&
	    !recfg_indication_ptr->del_valid) {
		osif_free_link_reconfig_done_data(recfg_indication_ptr);
		return NULL;
	}

	recfg_indication_ptr->psoc = wlan_vdev_get_psoc(vdev);
	recfg_indication_ptr->vdev_id = wlan_vdev_get_id(vdev);

	return recfg_indication_ptr;
}

QDF_STATUS osif_link_reconfig_status_cb(void *ctx)
{
	struct recfg_done_data *recfg_indication_ptr = ctx;
	struct wiphy *wiphy;
	struct net_device *dev = NULL;
	int errno;
	struct wlan_objmgr_vdev *vdev = NULL;
	struct wlan_objmgr_psoc *psoc;
	QDF_STATUS status = QDF_STATUS_E_INVAL;

	if (!recfg_indication_ptr) {
		osif_err("recfg_indication_ptr not valid");
		return QDF_STATUS_E_INVAL;
	}

	psoc = recfg_indication_ptr->psoc;
	if (!psoc) {
		mlo_err("psoc null");
		goto end;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(
				psoc, recfg_indication_ptr->vdev_id,
				WLAN_LINK_RECFG_ID);
	if (!vdev) {
		mlo_err("Invalid link recfg VDEV %d",
			recfg_indication_ptr->vdev_id);
		goto end;
	}

	wiphy = osif_get_wiphy_from_vdev(vdev);
	if (!wiphy) {
		osif_err("Failed to get wiphy");
		goto end;
	}

	errno = osif_get_net_dev_from_vdev(vdev, &dev);
	if (errno) {
		osif_err("failed to get netdev");
		goto end;
	}

	osif_enter_dev(dev);

	osif_wiphy_lock(wiphy, NULL);
	osif_debug("add_valid %d del_valid %d",
		   recfg_indication_ptr->add_valid,
		   recfg_indication_ptr->del_valid);
	if (recfg_indication_ptr->add_valid) {
		osif_debug("added_links 0x%x driver_initiated %d buf len %zu",
			   recfg_indication_ptr->add_link_rsp.added_links,
			   recfg_indication_ptr->add_link_rsp.driver_initiated,
			   recfg_indication_ptr->add_link_rsp.len);
		cfg80211_mlo_reconf_add_done(
				dev, &recfg_indication_ptr->add_link_rsp);
	}

	if (recfg_indication_ptr->del_valid) {
		osif_debug("del link bitmap 0x%x",
			   recfg_indication_ptr->del_link_map);
		cfg80211_links_removed(
				dev, recfg_indication_ptr->del_link_map);
	}
	osif_wiphy_unlock(wiphy, NULL);
	status = QDF_STATUS_SUCCESS;
end:
	osif_free_link_reconfig_done_data(recfg_indication_ptr);

	if (vdev)
		wlan_objmgr_vdev_release_ref(vdev, WLAN_LINK_RECFG_ID);

	return status;
}
#endif

#ifdef WLAN_FEATURE_MLO_SAP_LINK_REMOVAL
QDF_STATUS osif_mlo_sap_link_removal_evt_handler(struct wlan_objmgr_vdev *vdev,
						 uint32_t tbtt_count,
						 uint64_t tsf,
						 uint16_t link_id)
{
	int ret;
	struct vdev_osif_priv *osif_priv;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!vdev) {
		osif_err("Invalid vdev");
		return QDF_STATUS_E_INVAL;
	}

	osif_priv = wlan_vdev_get_ospriv(vdev);
	if (!osif_priv) {
		osif_err("Invalid vdev osif priv");
		return QDF_STATUS_E_INVAL;
	}
	osif_debug("update tbtt event to userspace: tbtt:%d", tbtt_count);

	if (tbtt_count)
		ret = cfg80211_update_link_reconfig_remove_update(osif_priv->wdev->netdev,
								  link_id,
								  tbtt_count,
								  tsf,
								  NL80211_CMD_LINK_REMOVAL_STARTED);
	else
		ret = cfg80211_update_link_reconfig_remove_update(osif_priv->wdev->netdev,
								  link_id,
								  tbtt_count,
								  tsf,
								  NL80211_CMD_LINK_REMOVAL_COMPLETED);

	status =  qdf_status_from_os_return(ret);
	if (QDF_IS_STATUS_ERROR(status))
		osif_err("Failed to update link removal event to userspace:%d",
			 ret);

	return status;
}
#endif

