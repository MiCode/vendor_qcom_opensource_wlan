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

/*
 * DOC: contains MLO manager Link Switch related functionality
 */
#include <wlan_mlo_mgr_link_switch.h>
#include <wlan_mlo_mgr_main.h>
#include <wlan_mlo_mgr_sta.h>
#include <wlan_serialization_api.h>
#include <wlan_cm_api.h>
#include <wlan_crypto_def_i.h>
#ifdef WLAN_FEATURE_11BE_MLO_ADV_FEATURE
#include "wlan_cm_roam_api.h"
#include <wlan_mlo_mgr_roam.h>
#include "wlan_dlm_api.h"
#include "wlan_dp_ucfg_api.h"
#include <wlan_mlo_link_recfg.h>
#endif
#include "host_diag_core_event.h"
#include <wlan_t2lm_api.h>

static QDF_STATUS
mlo_mgr_update_link_rej_mac_addr_resp(struct wlan_objmgr_vdev *vdev,
				      struct wlan_mlo_link_reject_req *link_rej_info)
{
	struct mlo_mgr_context *g_mlo_ctx = wlan_objmgr_get_mlo_ctx();
	QDF_STATUS status = QDF_STATUS_E_INVAL;

	if (!g_mlo_ctx) {
		mlo_err("global mlo ctx NULL");
		return status;
	}

	status = g_mlo_ctx->osif_ops->mlo_mgr_osif_link_rej_update_mac_addr(
							link_rej_info->rej_ieee_link_id,
							link_rej_info->acc_ieee_link_id,
							link_rej_info->vdev_id);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_debug("VDEV %d OSIF MAC addr update failed %d",
			  link_rej_info->vdev_id, status);
		return status;
	}

	return QDF_STATUS_SUCCESS;
}

void mlo_mgr_update_link_status_code(struct wlan_objmgr_vdev *vdev,
				     uint8_t link_id,
				     enum wlan_status_code status_code)
{
	struct mlo_link_info *link_info;

	if (!vdev || !vdev->mlo_dev_ctx)
		return;

	link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx, link_id);
	if (!link_info) {
		mlo_err("Link info not found for link id %d", link_id);
		return;
	}

	link_info->link_status_code = status_code;
	mlo_debug("Update status code info for link_id: %d, vdev_id:%d, link_status_code: %d",
		  link_info->link_id, link_info->vdev_id,
		  link_info->link_status_code);
}

void mlo_mgr_update_link_info_mac_addr(struct wlan_objmgr_vdev *vdev,
				       struct wlan_mlo_link_mac_update *ml_mac_update)
{
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;
	struct mlo_vdev_link_mac_info *link_mac_info;

	if (!vdev || !vdev->mlo_dev_ctx || !ml_mac_update)
		return;

	link_mac_info = &ml_mac_update->link_mac_info[0];
	link_info = &vdev->mlo_dev_ctx->link_ctx->links_info[0];

	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		qdf_mem_copy(&link_info->link_addr,
			     &link_mac_info->link_mac_addr,
			     QDF_MAC_ADDR_SIZE);

		link_info->vdev_id = link_mac_info->vdev_id;
		mlo_debug("Update STA Link info for vdev_id %d, link_addr:" QDF_MAC_ADDR_FMT,
			  link_info->vdev_id,
			  QDF_MAC_ADDR_REF(link_info->link_addr.bytes));
		link_mac_info++;
		link_info++;
	}
}

void mlo_mgr_update_ap_link_info(struct wlan_objmgr_vdev *vdev, uint8_t link_id,
				 uint8_t *ap_link_addr,
				 struct wlan_channel channel)
{
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;
	bool link_exist = false;

	if (!vdev || !vdev->mlo_dev_ctx || !ap_link_addr)
		return;

	/* Check if link already exists */
	link_info = &vdev->mlo_dev_ctx->link_ctx->links_info[0];
	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		if (qdf_is_macaddr_equal(&link_info->ap_link_addr,
					 (struct qdf_mac_addr *)ap_link_addr)) {
			link_exist = true;
			break;
		}
		link_info++;
	}

	/* Find first free link index if link does not exists */
	if (!link_exist) {
		link_info = &vdev->mlo_dev_ctx->link_ctx->links_info[0];
		for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
		     link_info_iter++) {
			if (qdf_is_macaddr_zero(&link_info->ap_link_addr))
				break;

			link_info++;
		}
	}

	if (link_info_iter == WLAN_MAX_ML_BSS_LINKS)
		return;

	qdf_mem_copy(&link_info->ap_link_addr, ap_link_addr, QDF_MAC_ADDR_SIZE);

	qdf_mem_copy(link_info->link_chan_info, &channel, sizeof(channel));
	link_info->chan_freq = channel.ch_freq;
	link_info->link_status_flags = 0;
	link_info->link_id = link_id;

	mlo_debug("Update AP Link info for link_id: %d, freq: %d vdev_id:%d, link_addr:" QDF_MAC_ADDR_FMT,
		  link_info->link_id, link_info->link_chan_info->ch_freq,
		  link_info->vdev_id,
		  QDF_MAC_ADDR_REF(link_info->ap_link_addr.bytes));
}

struct mlo_link_info *
mlo_mgr_get_ap_link_info(struct wlan_objmgr_vdev *vdev,
			 struct qdf_mac_addr *ap_link_addr)
{
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;

	if (!vdev || !vdev->mlo_dev_ctx || !ap_link_addr ||
	    qdf_is_macaddr_zero(ap_link_addr))
		return NULL;

	link_info = &vdev->mlo_dev_ctx->link_ctx->links_info[0];
	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		if (qdf_is_macaddr_equal(&link_info->ap_link_addr,
					 ap_link_addr))
			return link_info;
		link_info++;
	}

	return NULL;
}

void mlo_mgr_clear_ap_link_info(struct wlan_objmgr_vdev *vdev,
				struct qdf_mac_addr *ap_link_addr)
{
	struct mlo_link_info *link_info;

	link_info = mlo_mgr_get_ap_link_info(vdev, ap_link_addr);
	if (!link_info)
		return;

	mlo_debug("Clear AP link info for link_id: %d, vdev_id:%d, link_addr:" QDF_MAC_ADDR_FMT,
		  link_info->link_id, link_info->vdev_id,
		  QDF_MAC_ADDR_REF(link_info->ap_link_addr.bytes));

	mlo_free_cache_link_assoc_rsp(vdev, link_info->link_id);

	qdf_zero_macaddr(&link_info->ap_link_addr);
	qdf_mem_zero(link_info->link_chan_info,
		     sizeof(*link_info->link_chan_info));
	link_info->chan_freq = 0;
	link_info->link_id = WLAN_INVALID_LINK_ID;
	link_info->link_status_flags = 0;
}

void mlo_mgr_update_ap_channel_info(struct wlan_objmgr_vdev *vdev, uint8_t link_id,
				    uint8_t *ap_link_addr,
				    struct wlan_channel channel)
{
	struct mlo_link_info *link_info;

	if (!vdev || !vdev->mlo_dev_ctx || !ap_link_addr)
		return;

	link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx, link_id);
	if (!link_info)
		return;

	qdf_mem_copy(link_info->link_chan_info, &channel,
		     sizeof(*link_info->link_chan_info));

	mlo_debug("update AP channel info link_id: %d, vdev_id:%d, link_addr:" QDF_MAC_ADDR_FMT,
		  link_info->link_id, link_info->vdev_id,
		  QDF_MAC_ADDR_REF(link_info->ap_link_addr.bytes));
	mlo_debug("ch_freq: %d, freq1: %d, freq2: %d, phy_mode: %d, c_width:%d",
		  link_info->link_chan_info->ch_freq,
		  link_info->link_chan_info->ch_cfreq1,
		  link_info->link_chan_info->ch_cfreq2,
		  link_info->link_chan_info->ch_phymode,
		  link_info->link_chan_info->ch_width);
}

void mlo_mgr_update_link_info_reset(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlo_dev_context *ml_dev)
{
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;

	if (!ml_dev)
		return;

	link_info = &ml_dev->link_ctx->links_info[0];

	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		if (!qdf_is_macaddr_zero(&link_info->ap_link_addr) &&
		    !qdf_is_macaddr_zero(&link_info->link_addr))
			wlan_crypto_free_key_by_link_id(
						psoc,
						&link_info->link_addr,
						link_info->link_id);
		qdf_mem_zero(&link_info->link_addr, QDF_MAC_ADDR_SIZE);
		qdf_mem_zero(&link_info->ap_link_addr, QDF_MAC_ADDR_SIZE);
		qdf_mem_zero(link_info->link_chan_info,
			     sizeof(*link_info->link_chan_info));
		link_info->vdev_id = WLAN_INVALID_VDEV_ID;
		link_info->link_id = WLAN_INVALID_LINK_ID;
		link_info->link_status_flags = 0;
		link_info++;
	}
}

void mlo_mgr_reset_ap_link_info(struct wlan_objmgr_vdev *vdev)
{
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;
	struct wlan_objmgr_psoc *psoc;

	if (!vdev || !vdev->mlo_dev_ctx || !vdev->mlo_dev_ctx->link_ctx)
		return;

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		mlo_err("psoc NULL");
		return;
	}

	link_info = &vdev->mlo_dev_ctx->link_ctx->links_info[0];

	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		if (!qdf_is_macaddr_zero(&link_info->ap_link_addr) &&
		    !qdf_is_macaddr_zero(&link_info->link_addr))
			wlan_crypto_free_key_by_link_id(
						psoc,
						&link_info->link_addr,
						link_info->link_id);
		qdf_mem_zero(&link_info->ap_link_addr, QDF_MAC_ADDR_SIZE);
		qdf_mem_zero(link_info->link_chan_info,
			     sizeof(*link_info->link_chan_info));
		link_info->link_id = WLAN_INVALID_LINK_ID;
		link_info->bpcc = 0;
		link_info->link_status_flags = 0;
		link_info->is_link_active = false;
		link_info++;
	}

	mlo_reset_cache_link_assoc_rsp(vdev->mlo_dev_ctx);
}

struct mlo_link_info
*mlo_mgr_get_ap_link(struct wlan_objmgr_vdev *vdev)
{
	if (!vdev || !vdev->mlo_dev_ctx)
		return NULL;

	return &vdev->mlo_dev_ctx->link_ctx->links_info[0];
}

static
void mlo_mgr_alloc_link_info_wmi_chan(struct wlan_mlo_dev_context *ml_dev)
{
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;

	if (!ml_dev)
		return;

	link_info = &ml_dev->link_ctx->links_info[0];
	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		link_info->link_chan_info =
			qdf_mem_malloc(sizeof(*link_info->link_chan_info));
		if (!link_info->link_chan_info)
			return;
		link_info++;
	}
}

static
void mlo_mgr_free_link_info_wmi_chan(struct wlan_mlo_dev_context *ml_dev)
{
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;

	if (!ml_dev)
		return;

	link_info = &ml_dev->link_ctx->links_info[0];
	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		if (link_info->link_chan_info)
			qdf_mem_free(link_info->link_chan_info);
		link_info++;
	}
}

#ifdef WLAN_FEATURE_11BE_MLO_ADV_FEATURE
bool
mlo_mgr_update_link_state_delete_flag(
			struct wlan_mlo_dev_context *mlo_dev_ctx,
			uint8_t link_id,
			bool set)
{
	struct mlo_link_info *link_info;

	link_info = mlo_mgr_get_ap_link_by_link_id(mlo_dev_ctx,
						   link_id);
	if (!link_info) {
		mlo_debug("no found link info for id %d for %s",
			  link_id, set ? "delete" : "clear");
		return false;
	}

	if (set) {
		qdf_atomic_set_bit(LS_F_AP_REMOVAL_BIT,
				   &link_info->link_status_flags);
	} else {
		qdf_atomic_clear_bit(LS_F_AP_REMOVAL_BIT,
				     &link_info->link_status_flags);
	}
	mlo_debug("link %d updated link state 0x%x for %s",
		  link_id, (uint32_t)link_info->link_status_flags,
		  set ? "delete" : "clear");

	return true;
}

bool mlo_mgr_is_link_add_link_switch(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_mlo_dev_context *mlo_dev_ctx = vdev->mlo_dev_ctx;
	struct wlan_mlo_link_switch_req *req;

	if (!mlo_dev_ctx || !mlo_dev_ctx->link_ctx ||
	    !wlan_vdev_mlme_is_mlo_link_switch_in_progress(vdev))
		return false;

	req = &mlo_dev_ctx->link_ctx->last_req;

	return req->reason == MLO_LINK_SWITCH_REASON_HOST_ADD_LINK;
}

static void
mlo_mgr_update_link_vdev_id(struct wlan_objmgr_vdev *vdev, uint8_t accepted_link_id,
			    uint8_t rejected_link_id)
{
	struct mlo_link_info *accepted_link_info;
	struct mlo_link_info *rejected_link_info;
	uint8_t vdev_id;

	if (!vdev || !vdev->mlo_dev_ctx)
		return;

	accepted_link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx,
							    accepted_link_id);
	if (!accepted_link_info)
		return;

	rejected_link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx,
							    rejected_link_id);
	if (!rejected_link_info)
		return;

	mlo_debug("Accepted vdev id %d rejected vdev id %d ",
		  accepted_link_info->vdev_id, rejected_link_info->vdev_id);

	if (accepted_link_info->vdev_id == WLAN_INVALID_VDEV_ID &&
	    rejected_link_info->vdev_id != WLAN_INVALID_VDEV_ID) {
		vdev_id = accepted_link_info->vdev_id;
		accepted_link_info->vdev_id = rejected_link_info->vdev_id;
		rejected_link_info->vdev_id = vdev_id;
		rejected_link_info->link_id = WLAN_INVALID_LINK_ID;
	}

	mlo_debug("Updated accepted vdev id %d rejected vdev id %d ",
		  accepted_link_info->vdev_id, rejected_link_info->vdev_id);
}

/**
 * mlo_mgr_clear_rejected_partner_info- Clear rejected partner information
 *
 * @vdev: vdev pointer
 * @ml_partner_info: ML partner info.
 * @rejected_ap_link_addr: Rejected AP link address
 *
 * Return: none
 */
static void
mlo_mgr_clear_rejected_partner_info(struct wlan_objmgr_vdev *vdev,
				    struct mlo_partner_info *ml_partner_info,
				    uint8_t *rejected_ap_link_addr)
{
	struct mlo_link_info *link_info;
	struct mlo_partner_info *partner_info;
	uint8_t i, rejected_link_count = 0;

	if (!vdev || !vdev->mlo_dev_ctx || !vdev->mlo_dev_ctx->sta_ctx || !rejected_ap_link_addr)
		return;

	partner_info = &vdev->mlo_dev_ctx->sta_ctx->ml_partner_info;
	for (i = 0; i < partner_info->num_partner_links; i++) {
		link_info = &partner_info->partner_link_info[i];
		if (!link_info) {
			mlo_err("link_info null");
			continue;
		}

		if (qdf_is_macaddr_equal((struct qdf_mac_addr *)rejected_ap_link_addr,
					 &link_info->link_addr)) {
			mlo_debug("Clear AP partner for link_id: %d, link_addr:" QDF_MAC_ADDR_FMT,
				  link_info->link_id,
				  QDF_MAC_ADDR_REF(link_info->link_addr.bytes));

			mlo_mgr_clear_ap_link_info(vdev,
						   &link_info->link_addr);
			qdf_zero_macaddr(&link_info->link_addr);
			link_info->link_id = WLAN_INVALID_LINK_ID;
			link_info->link_status_flags = 0;
			rejected_link_count++;
		}
	}

	ml_partner_info->num_partner_links -= rejected_link_count;
	mlo_debug("Updated ml partner links %d", ml_partner_info->num_partner_links);
}

/**
 * mlo_mgr_get_rejected_links_info- Get rejected links information
 *
 * @vdev: vdev pointer
 * @ml_partner_info: ML partner link information.
 * @rej_links: Rejected links info
 *
 * Return: none
 */
static void
mlo_mgr_get_rejected_links_info(struct wlan_objmgr_vdev *vdev,
				struct mlo_partner_info *ml_partner_info,
				struct wlan_rejected_links_info *rej_links)
{
	uint8_t i, link_cnt;
	struct mlo_link_info *link_info;
	struct wlan_mlo_dev_context *mlo_dev_ctx;

	if (!vdev || !vdev->mlo_dev_ctx || !ml_partner_info || !rej_links) {
		mlo_err("vdev is null");
		return;
	}

	if (!ml_partner_info->num_partner_links)
		return;

	mlo_dev_ctx = vdev->mlo_dev_ctx;
	for (i = 0, link_cnt = 0; i < ml_partner_info->num_partner_links &&
	     link_cnt < ml_partner_info->num_partner_links;
	     i++) {
		link_info = mlo_mgr_get_ap_link_by_link_id(mlo_dev_ctx,
							   ml_partner_info->partner_link_info[i].link_id);
		if (!link_info || !link_info->link_status_code)
			continue;

		rej_links->num_rej_link_cnt++;
		rej_links->rejected_link_ids[link_cnt] = link_info->link_id;
		link_cnt++;
	}
}

void
mlo_mgr_check_if_all_partner_links_rejected(struct wlan_objmgr_vdev *vdev,
					    struct wlan_cm_connect_resp *resp)
{
	uint8_t link_idx, rejected_link_cnt = 0;
	struct mlo_partner_info *ml_parnter_info;
	struct mlo_link_info *link_info;

	if (!vdev || !resp)
		return;

	if (QDF_IS_STATUS_ERROR(resp->connect_status))
		return;

	ml_parnter_info = &resp->ml_parnter_info;
	for (link_idx = 0; link_idx < ml_parnter_info->num_partner_links; link_idx++) {
		link_info = &ml_parnter_info->partner_link_info[link_idx];

		if (link_info->link_status_code)
			rejected_link_cnt++;
	}

	if (rejected_link_cnt == ml_parnter_info->num_partner_links)
		mlo_mgr_find_and_clear_rejected_links(vdev, MAX_MLO_LINK_ID, ml_parnter_info);
}

void
mlo_mgr_find_and_clear_rejected_links(struct wlan_objmgr_vdev *vdev,
				      uint8_t partner_link_id,
				      struct mlo_partner_info *ml_partner_info)
{
	struct wlan_rejected_links_info rej_links = {0};
	struct wlan_mlo_dev_context *mlo_dev_ctx;
	uint8_t i;
	struct mlo_link_info *link_info;

	if (!vdev) {
		mlo_err("Vdev is null");
		return;
	}

	mlo_dev_ctx = vdev->mlo_dev_ctx;
	if (!mlo_dev_ctx) {
		mlo_err("ml dev ctx is null");
		return;
	}

	mlo_mgr_get_rejected_links_info(vdev,
					ml_partner_info,
					&rej_links);

	if (!rej_links.num_rej_link_cnt)
		return;

	mlo_debug("Rejected link cnt %d", rej_links.num_rej_link_cnt);
	for (i = 0; i < rej_links.num_rej_link_cnt; i++) {
		link_info = mlo_mgr_get_ap_link_by_link_id(mlo_dev_ctx,
							   rej_links.rejected_link_ids[i]);
		if (!link_info)
			continue;

		mlo_mgr_link_rejection_handler(vdev, link_info,
					       NULL, false);
	}
	ml_partner_info->num_partner_links -= rej_links.num_rej_link_cnt;
	mlo_debug("Updated Partner link num %d",
		  ml_partner_info->num_partner_links);
}

void
mlo_mgr_link_rejection_handler(struct wlan_objmgr_vdev *vdev,
			       struct mlo_link_info *rejected_link_info,
			       struct mlo_link_info *accepted_link_info,
			       bool is_non_standby_link)
{
	struct wlan_mlo_dev_context *mlo_dev_ctx;
	struct reject_ap_info ap_info;
	struct wlan_objmgr_pdev *pdev;
	struct wlan_mlo_link_reject_req *link_rej_req;
	QDF_STATUS status;
	struct mlo_partner_info *ml_partner_info;

	if (!vdev || !rejected_link_info)
		return;

	mlo_dev_ctx = vdev->mlo_dev_ctx;
	if (!mlo_dev_ctx || !mlo_dev_ctx->sta_ctx)
		return;

	if (is_non_standby_link && accepted_link_info) {
		link_rej_req = &mlo_dev_ctx->link_ctx->link_rej_req;
		link_rej_req->rej_ieee_link_id = rejected_link_info->link_id;
		link_rej_req->rej_ap_link_addr = rejected_link_info->ap_link_addr;
		link_rej_req->acc_ieee_link_id = accepted_link_info->link_id;
		link_rej_req->acc_ap_link_addr = accepted_link_info->ap_link_addr;
		link_rej_req->link_reject_update_in_progress = true;
		link_rej_req->vdev_id = wlan_vdev_get_id(vdev);
		wlan_vdev_mlme_set_mlo_link_rejection_in_progress(vdev);
		wlan_vdev_mlme_send_set_mac_addr(accepted_link_info->link_addr,
						 mlo_dev_ctx->mld_addr, vdev);
		if (accepted_link_info->vdev_id == WLAN_INVALID_VDEV_ID &&
		    rejected_link_info->vdev_id != WLAN_INVALID_VDEV_ID)
			mlo_mgr_update_link_vdev_id(vdev,
						    accepted_link_info->link_id,
						    rejected_link_info->link_id);

		wlan_vdev_mlme_set_macaddr(vdev, accepted_link_info->link_addr.bytes);
		wlan_vdev_mlme_set_linkaddr(vdev, accepted_link_info->link_addr.bytes);
		status = ucfg_dp_update_link_mac_addr(vdev,
						      &accepted_link_info->link_addr,
						      true);
		if (QDF_IS_STATUS_ERROR(status)) {
			mlo_err("DP link MAC update failed");
			return;
		}
	} else {
		pdev = wlan_vdev_get_pdev(vdev);
		ml_partner_info = &vdev->mlo_dev_ctx->sta_ctx->ml_partner_info;
		qdf_mem_zero(&ap_info, sizeof(struct reject_ap_info));
		ap_info.bssid = rejected_link_info->ap_link_addr;
		ap_info.reject_ap_type = DRIVER_AVOID_TYPE;
		ap_info.reject_reason = REASON_LINK_REJECTED;
		ap_info.source = ADDED_BY_DRIVER;
		wlan_update_mlo_reject_ap_info(pdev,
					       wlan_vdev_get_id(vdev),
					       &ap_info);
		wlan_dlm_add_bssid_to_reject_list(pdev,
						  &ap_info);
		mlo_mgr_clear_rejected_partner_info(vdev,
						    ml_partner_info,
						    rejected_link_info->ap_link_addr.bytes);
	}
}

struct mlo_link_info
*mlo_mgr_get_ap_link_by_link_id(struct wlan_mlo_dev_context *mlo_dev_ctx,
				int link_id)
{
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;

	if (!mlo_dev_ctx || link_id < 0 || link_id >= MAX_MLO_LINK_ID)
		return NULL;

	link_info = &mlo_dev_ctx->link_ctx->links_info[0];
	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		if (link_info->link_id == link_id)
			return link_info;
		link_info++;
	}

	return NULL;
}

bool mlo_mgr_if_freq_n_inactive_links_freq_same(struct wlan_objmgr_vdev *vdev,
						uint32_t freq)
{
	struct wlan_mlo_dev_context *mlo_dev_ctx;
	struct mlo_link_info *link_info;
	uint8_t link_info_iter;
	struct wlan_t2lm_info t2lm[WLAN_T2LM_MAX_DIRECTION] = {0};
	uint16_t tid_mapped_link_id = 0, tid_mapped = 0;
	QDF_STATUS status;

	if (!wlan_vdev_mlme_is_mlo_vdev(vdev))
		return false;

	mlo_dev_ctx = vdev->mlo_dev_ctx;
	if (!mlo_dev_ctx)
		return false;

	status = wlan_get_t2lm_mapping_status(vdev, t2lm);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_info("Unable to get t2lm_mapping");
		return false;
	}

	status = t2lm_find_tid_mapped_link_id(t2lm, &tid_mapped);
	if (QDF_IS_STATUS_ERROR(status))
		return false;

	tid_mapped_link_id = t2lm_get_tids_mapped_link_id(tid_mapped);

	link_info = &mlo_dev_ctx->link_ctx->links_info[0];
	for (link_info_iter = 0; link_info_iter < WLAN_MAX_ML_BSS_LINKS;
	     link_info_iter++) {
		if (link_info->is_link_active ||
		    qdf_is_macaddr_zero(&link_info->ap_link_addr)) {
			link_info++;
			continue;
		}

		/* Don't add freq in PCL if link is disable via TID mapping.
		 * default_link_mapping means all TID maps to all link id
		 * tid_mapped_link_id means this particular link id is active
		 * due to tid mapping
		 */
		if (!t2lm[0].default_link_mapping &&
		    link_info->link_id != tid_mapped_link_id) {
			if (link_info->link_chan_info->ch_freq == freq)
				mlo_debug("Skip link_id %d chan_freq %d as tid is mapped to %d",
					  link_info->link_id,
					  link_info->link_chan_info->ch_freq,
					  tid_mapped_link_id);

			link_info++;
			continue;
		}

		if (link_info->link_chan_info->ch_freq &&
		    (link_info->link_chan_info->ch_freq == freq))
			return true;

		link_info++;
	}

	return false;
}

bool mlo_mgr_update_csa_link_info(struct wlan_objmgr_pdev *pdev,
				  struct wlan_mlo_dev_context *mlo_dev_ctx,
				  struct csa_offload_params *csa_param,
				  uint8_t link_id)
{
	struct mlo_link_info *link_info;
	uint16_t bw_val;
	struct ch_params ch_params = {0};

	if (!mlo_dev_ctx) {
		mlo_err("invalid mlo dev ctx");
		goto done;
	}

	bw_val = wlan_reg_get_bw_value(csa_param->new_ch_width);

	link_info = mlo_mgr_get_ap_link_by_link_id(mlo_dev_ctx, link_id);
	if (!link_info) {
		mlo_err("invalid link_info");
		goto done;
	}

	link_info->link_chan_info->ch_freq = csa_param->csa_chan_freq;

	ch_params.ch_width = csa_param->new_ch_width;
	wlan_reg_set_channel_params_for_pwrmode(pdev,
						csa_param->csa_chan_freq,
						0, &ch_params,
						REG_CURRENT_PWR_MODE);

	link_info->link_chan_info->ch_cfreq1 = ch_params.mhz_freq_seg0;
	link_info->link_chan_info->ch_cfreq2 = ch_params.mhz_freq_seg1;

	link_info->link_chan_info->ch_phymode = wlan_eht_chan_phy_mode(
					csa_param->csa_chan_freq,
					bw_val, csa_param->new_ch_width);
	link_info->link_chan_info->ch_width = csa_param->new_ch_width;

	mlo_debug("CSA: freq: %d, cfreq1: %d, cfreq2: %d, bw: %d, phymode:%d",
		  link_info->link_chan_info->ch_freq,
		  link_info->link_chan_info->ch_cfreq1,
		  link_info->link_chan_info->ch_cfreq2,
		  link_info->link_chan_info->ch_width,
		  link_info->link_chan_info->ch_phymode);

	return true;
done:
	return false;
}

struct wlan_objmgr_vdev *
mlo_mgr_link_switch_get_assoc_vdev(struct wlan_objmgr_vdev *vdev)
{
	uint8_t vdev_id;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_objmgr_vdev *assoc_vdev;

	if (!vdev)
		return NULL;

	if (!mlo_mgr_is_link_switch_on_assoc_vdev(vdev))
		return NULL;

	vdev_id = vdev->mlo_dev_ctx->link_ctx->last_req.vdev_id;
	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		mlo_err("PSOC NULL");
		return NULL;
	}

	assoc_vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
							  WLAN_MLO_MGR_ID);

	return assoc_vdev;
}

uint8_t mlo_mgr_get_link_switch_last_link_id(struct wlan_objmgr_vdev *vdev)
{
	if (vdev && wlan_vdev_mlme_is_mlo_link_switch_in_progress(vdev))
		return vdev->mlo_dev_ctx->link_ctx->last_req.curr_ieee_link_id;

	return WLAN_INVALID_LINK_ID;
}

bool mlo_mgr_is_link_switch_in_progress(struct wlan_objmgr_vdev *vdev)
{
	enum mlo_link_switch_req_state state;

	if (!vdev || !vdev->mlo_dev_ctx)
		return false;

	state = mlo_mgr_link_switch_get_curr_state(vdev->mlo_dev_ctx);
	return (state > MLO_LINK_SWITCH_STATE_INIT);
}

static void
mlo_mgr_vdev_iterate_handler(struct wlan_objmgr_psoc *psoc,
			     void *obj, void *args)
{
	struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)obj;
	uint32_t *context = (uint32_t *)args;

	if (*context)
		return;

	if (wlan_vdev_mlme_get_opmode(vdev) != QDF_STA_MODE)
		return;

	if (!wlan_vdev_mlme_is_mlo_vdev(vdev))
		return;

	if (mlo_mgr_is_link_switch_in_progress(vdev))
		*context = true;
}

bool
mlo_mgr_is_link_switch_in_progress_by_psoc(struct wlan_objmgr_psoc *psoc)
{
	uint32_t context = 0;

	wlan_objmgr_iterate_obj_list(psoc, WLAN_VDEV_OP,
				     mlo_mgr_vdev_iterate_handler,
				     &context, true, WLAN_MLO_MGR_ID);

	return !!context;
}

bool mlo_mgr_is_link_switch_on_assoc_vdev(struct wlan_objmgr_vdev *vdev)
{
	if (!mlo_mgr_is_link_switch_in_progress(vdev))
		return false;

	return vdev->mlo_dev_ctx->link_ctx->last_req.restore_vdev_flag;
}

void mlo_mgr_link_switch_init_state(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
	mlo_dev_lock_acquire(mlo_dev_ctx);
	mlo_dev_ctx->link_ctx->last_req.state = MLO_LINK_SWITCH_STATE_IDLE;
	mlo_dev_lock_release(mlo_dev_ctx);
}

QDF_STATUS
mlo_mgr_link_switch_trans_next_state(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	enum mlo_link_switch_req_state cur_state, next_state;

	mlo_dev_lock_acquire(mlo_dev_ctx);
	cur_state = mlo_dev_ctx->link_ctx->last_req.state;
	switch (cur_state) {
	case MLO_LINK_SWITCH_STATE_IDLE:
		next_state = MLO_LINK_SWITCH_STATE_INIT;
		break;
	case MLO_LINK_SWITCH_STATE_INIT:
		next_state = MLO_LINK_SWITCH_STATE_DISCONNECT_CURR_LINK;
		break;
	case MLO_LINK_SWITCH_STATE_DISCONNECT_CURR_LINK:
		next_state = MLO_LINK_SWITCH_STATE_SET_MAC_ADDR;
		break;
	case MLO_LINK_SWITCH_STATE_SET_MAC_ADDR:
		next_state = MLO_LINK_SWITCH_STATE_CONNECT_NEW_LINK;
		break;
	case MLO_LINK_SWITCH_STATE_CONNECT_NEW_LINK:
		next_state = MLO_LINK_SWITCH_STATE_COMPLETE_SUCCESS;
		break;
	case MLO_LINK_SWITCH_STATE_COMPLETE_SUCCESS:
		next_state = MLO_LINK_SWITCH_STATE_IDLE;
		break;
	case MLO_LINK_SWITCH_STATE_ABORT_TRANS:
		next_state = cur_state;
		status = QDF_STATUS_E_PERM;
		mlo_debug("State transition not allowed");
		break;
	default:
		next_state = cur_state;
		QDF_ASSERT(0);
		break;
	}
	mlo_dev_ctx->link_ctx->last_req.state = next_state;
	mlo_dev_lock_release(mlo_dev_ctx);

	return status;
}

void
mlo_mgr_link_switch_trans_abort_state(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
	enum mlo_link_switch_req_state next_state =
					MLO_LINK_SWITCH_STATE_ABORT_TRANS;

	mlo_dev_lock_acquire(mlo_dev_ctx);
	mlo_dev_ctx->link_ctx->last_req.state = next_state;
	mlo_dev_lock_release(mlo_dev_ctx);
}

enum mlo_link_switch_req_state
mlo_mgr_link_switch_get_curr_state(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
	enum mlo_link_switch_req_state state;

	mlo_dev_lock_acquire(mlo_dev_ctx);
	state = mlo_dev_ctx->link_ctx->last_req.state;
	mlo_dev_lock_release(mlo_dev_ctx);

	return state;
}

#ifdef WLAN_FEATURE_11BE_MLO_ADV_FEATURE
static void
mlo_mgr_reset_roam_state_for_link_vdev(struct wlan_objmgr_vdev *vdev,
				       struct wlan_objmgr_vdev *assoc_vdev)
{
	QDF_STATUS status;

	status = wlan_cm_roam_state_change(wlan_vdev_get_pdev(vdev),
					   wlan_vdev_get_id(assoc_vdev),
					   WLAN_ROAM_DEINIT,
					   REASON_ROAM_LINK_SWITCH_ASSOC_VDEV_CHANGE);
	if (QDF_IS_STATUS_ERROR(status))
		mlo_err("vdev:%d failed to change RSO state to deinit",
			wlan_vdev_get_id(assoc_vdev));
}

static void
mlo_mgr_restore_rso_upon_link_switch_failure(struct wlan_objmgr_vdev *vdev)
{
	wlan_cm_roam_state_change(wlan_vdev_get_pdev(vdev),
				  wlan_vdev_get_id(vdev),
				  WLAN_ROAM_RSO_ENABLED,
				  REASON_CONNECT);
}
#else
static inline void
mlo_mgr_reset_roam_state_for_link_vdev(struct wlan_objmgr_vdev *vdev,
				       struct wlan_objmgr_vdev *assoc_vdev)
{}

static inline void
mlo_mgr_restore_rso_upon_link_switch_failure(struct wlan_objmgr_vdev *vdev)
{}
#endif

static QDF_STATUS
mlo_mgr_link_switch_osif_notification(struct wlan_objmgr_vdev *vdev,
				      struct wlan_mlo_link_switch_req *lswitch_req,
				      enum wlan_mlo_link_switch_notify_reason notify_reason)
{
	uint8_t idx;
	uint16_t vdev_count;
	struct wlan_objmgr_vdev *assoc_vdev;
	struct wlan_mlo_sta *sta_ctx;
	struct wlan_objmgr_vdev *vdev_list[WLAN_UMAC_MLO_MAX_VDEVS];
	QDF_STATUS status = QDF_STATUS_E_INVAL;
	struct mlo_mgr_context *g_mlo_ctx = wlan_objmgr_get_mlo_ctx();
	QDF_STATUS(*cb)(struct wlan_objmgr_vdev *vdev,
			uint8_t non_trans_vdev_id, bool is_switch_start_notify);
	bool is_start_notify;

	if (!vdev->mlo_dev_ctx)
		return status;

	sta_ctx = vdev->mlo_dev_ctx->sta_ctx;
	if (!sta_ctx)
		return status;

	assoc_vdev = wlan_mlo_get_assoc_link_vdev(vdev);
	if (!assoc_vdev)
		return status;

	if (notify_reason <= MLO_LINK_SWITCH_NOTIFY_REASON_PRE_START_POST_SER)
		is_start_notify = true;
	else
		is_start_notify = false;

	cb = g_mlo_ctx->osif_ops->mlo_mgr_osif_link_switch_notification;

	if (lswitch_req->restore_vdev_flag) {
		status = cb(assoc_vdev, wlan_vdev_get_id(vdev),
			    is_start_notify);
		if (QDF_IS_STATUS_SUCCESS(status)) {
			wlan_vdev_mlme_clear_mlo_link_vdev(vdev);
			wlan_vdev_mlme_set_mlo_link_vdev(assoc_vdev);
			lswitch_req->restore_vdev_flag = false;
		} else {
			mlo_debug("OSIF deflink restore failed");
		}

		mlo_mgr_reset_roam_state_for_link_vdev(vdev, assoc_vdev);
		return status;
	}

	if (!is_start_notify ||
	    wlan_vdev_get_id(assoc_vdev) != lswitch_req->vdev_id) {
		status = cb(assoc_vdev, WLAN_INVALID_VDEV_ID, is_start_notify);
		return status;
	}

	mlo_sta_get_vdev_list(vdev, &vdev_count, vdev_list);
	for (idx = 0; idx < vdev_count; idx++) {
		if (wlan_vdev_get_id(vdev_list[idx]) != lswitch_req->vdev_id &&
		    qdf_test_bit(idx, sta_ctx->wlan_connected_links)) {
			status = cb(assoc_vdev,
				    wlan_vdev_get_id(vdev_list[idx]),
				    is_start_notify);
			if (QDF_IS_STATUS_SUCCESS(status)) {
				wlan_vdev_mlme_clear_mlo_link_vdev(vdev_list[idx]);
				wlan_vdev_mlme_set_mlo_link_vdev(assoc_vdev);
				lswitch_req->restore_vdev_flag = true;
			}
			break;
		}

		mlo_release_vdev_ref(vdev_list[idx]);
	}

	for (; idx < vdev_count; idx++)
		mlo_release_vdev_ref(vdev_list[idx]);

	return status;
}

QDF_STATUS
mlo_mgr_link_switch_notification(struct wlan_objmgr_vdev *vdev,
				 struct wlan_mlo_link_switch_req *lswitch_req,
				 enum wlan_mlo_link_switch_notify_reason notify_reason)
{
	QDF_STATUS status;

	switch (notify_reason) {
	case MLO_LINK_SWITCH_NOTIFY_REASON_PRE_START_PRE_SER:
	case MLO_LINK_SWITCH_NOTIFY_REASON_PRE_START_POST_SER:
		if (!mlo_check_if_all_vdev_up(vdev)) {
			mlo_debug("Not all VDEVs up");
			return QDF_STATUS_E_AGAIN;
		}

		if (mlo_is_chan_switch_in_progress(vdev)) {
			mlo_debug("CSA is in progress on one of ML vdevs, abort link switch");
			return QDF_STATUS_E_AGAIN;
		}

		if (notify_reason ==
		    MLO_LINK_SWITCH_NOTIFY_REASON_PRE_START_PRE_SER) {
			return QDF_STATUS_SUCCESS;
		}

		break;
	default:
		break;
	}

	status = mlo_mgr_link_switch_osif_notification(vdev, lswitch_req,
						       notify_reason);

	return status;
}

QDF_STATUS mlo_mgr_link_switch_init(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlo_dev_context *ml_dev)
{
	ml_dev->link_ctx =
		qdf_mem_malloc(sizeof(struct mlo_link_switch_context));

	if (!ml_dev->link_ctx)
		return QDF_STATUS_E_NOMEM;

	mlo_mgr_link_switch_init_state(ml_dev);
	mlo_mgr_alloc_link_info_wmi_chan(ml_dev);
	mlo_mgr_update_link_info_reset(psoc, ml_dev);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlo_mgr_link_switch_deinit(struct wlan_mlo_dev_context *ml_dev)
{
	mlo_mgr_free_link_info_wmi_chan(ml_dev);
	qdf_mem_free(ml_dev->link_ctx);
	ml_dev->link_ctx = NULL;
	return QDF_STATUS_SUCCESS;
}

void
mlo_mgr_osif_update_connect_info(struct wlan_objmgr_vdev *vdev, int32_t link_id)
{
	struct mlo_mgr_context *g_mlo_ctx = wlan_objmgr_get_mlo_ctx();
	struct mlo_link_info *link_info;
	QDF_STATUS(*osif_bss_update_cb)(struct qdf_mac_addr *self_mac,
					struct qdf_mac_addr *bssid,
					int32_t link_id);

	if (!g_mlo_ctx || !vdev->mlo_dev_ctx || !g_mlo_ctx->osif_ops ||
	    !g_mlo_ctx->osif_ops->mlo_mgr_osif_update_bss_info)
		return;

	link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx, link_id);
	if (!link_info)
		return;

	mlo_debug("Vdev %d: link id %d freq %d self MAC " QDF_MAC_ADDR_FMT " BSSID " QDF_MAC_ADDR_FMT,
		  link_info->vdev_id, link_id, link_info->chan_freq,
		  QDF_MAC_ADDR_REF(link_info->link_addr.bytes),
		  QDF_MAC_ADDR_REF(link_info->ap_link_addr.bytes));
	osif_bss_update_cb = g_mlo_ctx->osif_ops->mlo_mgr_osif_update_bss_info;

	osif_bss_update_cb(&link_info->link_addr, &link_info->ap_link_addr,
			   link_id);
}

static QDF_STATUS
mlo_mgr_link_switch_decide_mac_addr_change(
			struct wlan_objmgr_vdev *vdev,
			struct wlan_mlo_link_switch_req *req,
			struct mlo_link_info *new_link_info)
{
	struct wlan_mlo_dev_context *mlo_dev_ctx = vdev->mlo_dev_ctx;
	uint8_t *vdev_mac_addr;
	uint8_t *vdev_link_addr;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct qdf_mac_addr mac_addr, mld_addr;

	if (req->reason == MLO_LINK_SWITCH_REASON_HOST_ADD_LINK) {
		vdev_mac_addr = wlan_vdev_mlme_get_macaddr(vdev);
		if (!qdf_is_macaddr_equal(&new_link_info->link_addr,
					  (struct qdf_mac_addr *)vdev_mac_addr)) {
			mlo_err("vdev MAC address " QDF_MAC_ADDR_FMT " not equal link info self " QDF_MAC_ADDR_FMT "",
				QDF_MAC_ADDR_REF(vdev_mac_addr),
				QDF_MAC_ADDR_REF(new_link_info->link_addr.bytes));
			status = QDF_STATUS_E_INVAL;
		}
		vdev_link_addr = wlan_vdev_mlme_get_linkaddr(vdev);
		if (!qdf_is_macaddr_equal(&new_link_info->link_addr,
					  (struct qdf_mac_addr *)vdev_link_addr)) {
			mlo_err("vdev link address " QDF_MAC_ADDR_FMT " not equal link info self " QDF_MAC_ADDR_FMT "",
				QDF_MAC_ADDR_REF(vdev_mac_addr),
				QDF_MAC_ADDR_REF(new_link_info->link_addr.bytes));
			status = QDF_STATUS_E_INVAL;
		}
		if (QDF_IS_STATUS_ERROR(status)) {
			mlo_err("validate vdev mac addr failed status %d", status);
			goto err;
		}
		/* new self link address is same as vdev self mac,
		 * skip set mac address step.
		 */
		status = mlo_mgr_link_switch_trans_next_state(mlo_dev_ctx);
		if (QDF_IS_STATUS_ERROR(status)) {
			mlo_err("trans_next_state failed status %d", status);
			goto err;
		}

		status = mlo_mgr_link_switch_start_connect(vdev);
		if (QDF_IS_STATUS_SUCCESS(status))
			return status;
		goto err;
	}

	qdf_copy_macaddr(&mld_addr, &mlo_dev_ctx->mld_addr);
	qdf_copy_macaddr(&mac_addr, &new_link_info->link_addr);
	status = wlan_vdev_mlme_send_set_mac_addr(mac_addr, mld_addr, vdev);
	if (QDF_IS_STATUS_SUCCESS(status))
		return status;
err:
	mlo_mgr_remove_link_switch_cmd(vdev);

	return status;
}

QDF_STATUS mlo_mgr_link_switch_disconnect_done(struct wlan_objmgr_vdev *vdev,
					       QDF_STATUS discon_status,
					       bool is_link_switch_resp)
{
	QDF_STATUS status;
	enum mlo_link_switch_req_state cur_state;
	struct mlo_link_info *new_link_info;
	struct wlan_mlo_dev_context *mlo_dev_ctx = vdev->mlo_dev_ctx;
	struct wlan_mlo_link_switch_req *req = &mlo_dev_ctx->link_ctx->last_req;

	if (!is_link_switch_resp) {
		mlo_mgr_link_switch_trans_abort_state(mlo_dev_ctx);
		return QDF_STATUS_SUCCESS;
	}

	cur_state = mlo_mgr_link_switch_get_curr_state(mlo_dev_ctx);
	if (QDF_IS_STATUS_ERROR(discon_status) ||
	    cur_state != MLO_LINK_SWITCH_STATE_DISCONNECT_CURR_LINK) {
		mlo_err("VDEV %d link switch disconnect req failed",
			req->vdev_id);
		mlo_mgr_remove_link_switch_cmd(vdev);
		return QDF_STATUS_SUCCESS;
	}

	mlo_debug("VDEV %d link switch disconnect complete",
		  wlan_vdev_get_id(vdev));

	new_link_info =
		mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx,
					       req->new_ieee_link_id);
	if (!new_link_info) {
		mlo_err("New link not found in mlo dev ctx");
		mlo_mgr_remove_link_switch_cmd(vdev);
		return QDF_STATUS_E_INVAL;
	}

	status = mlo_mgr_link_switch_trans_next_state(mlo_dev_ctx);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_mgr_remove_link_switch_cmd(vdev);
		return status;
	}

	return mlo_mgr_link_switch_decide_mac_addr_change(vdev, req,
							  new_link_info);
}

void
mlo_mgr_link_switch_connect_done_notify(struct wlan_objmgr_vdev *vdev,
					struct wlan_cm_connect_resp *resp)
{
	if (wlan_cm_is_link_switch_connect_resp(resp)) {
		wlan_cm_reset_active_cm_id(vdev, resp->cm_id);
		mlo_mgr_link_switch_connect_done(vdev,
						 resp->connect_status);
	} else if (wlan_cm_is_link_add_connect_resp(resp)) {
		wlan_cm_reset_active_cm_id(vdev, resp->cm_id);
		mlo_link_recfg_add_connect_done_indication(
				vdev,
				resp->connect_status);
	}
}

QDF_STATUS mlo_mgr_link_reject_set_mac_addr_resp(struct wlan_objmgr_vdev *vdev,
						 uint8_t resp_status)
{
	QDF_STATUS status = QDF_STATUS_E_INVAL;
	struct wlan_mlo_link_reject_req *link_rej_req;
	struct mlo_mgr_context *g_mlo_ctx = wlan_objmgr_get_mlo_ctx();

	if (resp_status) {
		mlo_err("VDEV %d set MAC address response %d",
			wlan_vdev_get_id(vdev), resp_status);
		goto out;
	}

	if (!g_mlo_ctx) {
		mlo_err("global mlo ctx NULL");
		goto out;
	}

	mlo_debug("Dynamic vdev resp received");
	link_rej_req = &vdev->mlo_dev_ctx->link_ctx->link_rej_req;
	if (link_rej_req->link_reject_update_in_progress) {
		mlo_debug("Dynamic vdev update done for link reject");
		status = mlo_mgr_update_link_rej_mac_addr_resp(vdev,
							       link_rej_req);
		link_rej_req->link_reject_update_in_progress = false;
	}
out:
	wlan_vdev_mlme_clear_mlo_link_rejection_in_progress(vdev);
	return status;
}

QDF_STATUS mlo_mgr_link_switch_set_mac_addr_resp(struct wlan_objmgr_vdev *vdev,
						 uint8_t resp_status)
{
	QDF_STATUS status = QDF_STATUS_E_INVAL;
	enum mlo_link_switch_req_state cur_state;
	struct mlo_mgr_context *g_mlo_ctx = wlan_objmgr_get_mlo_ctx();
	struct wlan_mlo_link_switch_req *req;
	struct mlo_link_info *new_link_info;

	if (resp_status) {
		mlo_err("VDEV %d set MAC address response %d",
			wlan_vdev_get_id(vdev), resp_status);
		mlo_mgr_remove_link_switch_cmd(vdev);
		return status;
	}

	if (!g_mlo_ctx) {
		mlo_err("global mlo ctx NULL");
		mlo_mgr_remove_link_switch_cmd(vdev);
		return status;
	}

	req = &vdev->mlo_dev_ctx->link_ctx->last_req;
	cur_state = mlo_mgr_link_switch_get_curr_state(vdev->mlo_dev_ctx);
	if (cur_state != MLO_LINK_SWITCH_STATE_SET_MAC_ADDR) {
		mlo_err("Link switch cmd flushed, there can be MAC addr mismatch with FW");
		mlo_mgr_remove_link_switch_cmd(vdev);
		return status;
	}

	new_link_info =
		mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx,
					       req->new_ieee_link_id);
	if (!new_link_info) {
		mlo_mgr_remove_link_switch_cmd(vdev);
		return status;
	}

	wlan_vdev_mlme_set_macaddr(vdev, new_link_info->link_addr.bytes);
	wlan_vdev_mlme_set_linkaddr(vdev, new_link_info->link_addr.bytes);

	status = g_mlo_ctx->osif_ops->mlo_mgr_osif_update_mac_addr(
							req->curr_ieee_link_id,
							req->new_ieee_link_id,
							req->vdev_id);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_debug("VDEV %d OSIF MAC addr update failed %d",
			  req->vdev_id, status);
		mlo_mgr_remove_link_switch_cmd(vdev);
		return status;
	}

	status = mlo_mgr_link_switch_trans_next_state(vdev->mlo_dev_ctx);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_mgr_remove_link_switch_cmd(vdev);
		return status;
	}

	status = mlo_mgr_link_switch_start_connect(vdev);

	return status;
}

QDF_STATUS mlo_mgr_link_switch_start_connect(struct wlan_objmgr_vdev *vdev)
{
	QDF_STATUS status = QDF_STATUS_E_INVAL;
	struct wlan_cm_connect_req conn_req = {0};
	struct mlo_link_info *mlo_link_info;
	uint8_t *vdev_mac;
	struct wlan_mlo_sta *sta_ctx;
	struct wlan_mlo_dev_context *mlo_dev_ctx = vdev->mlo_dev_ctx;
	struct wlan_mlo_link_switch_req *req = &mlo_dev_ctx->link_ctx->last_req;
	struct wlan_objmgr_vdev *assoc_vdev = wlan_mlo_get_assoc_link_vdev(vdev);

	if (!assoc_vdev) {
		mlo_err("Assoc VDEV not found");
		goto out;
	}

	mlo_link_info = mlo_mgr_get_ap_link_by_link_id(mlo_dev_ctx,
						       req->new_ieee_link_id);

	if (!mlo_link_info) {
		mlo_err("New link ID not found");
		goto out;
	}

	vdev_mac = wlan_vdev_mlme_get_linkaddr(vdev);
	if (!qdf_is_macaddr_equal(&mlo_link_info->link_addr,
				  (struct qdf_mac_addr *)vdev_mac)) {
		mlo_err("MAC address not equal for the new Link ID VDEV: " QDF_MAC_ADDR_FMT ", MLO_LINK: " QDF_MAC_ADDR_FMT,
			QDF_MAC_ADDR_REF(vdev_mac),
			QDF_MAC_ADDR_REF(mlo_link_info->link_addr.bytes));
		goto out;
	}

	sta_ctx = mlo_dev_ctx->sta_ctx;
	copied_conn_req_lock_acquire(sta_ctx);
	if (sta_ctx->copied_conn_req) {
		qdf_mem_copy(&conn_req, sta_ctx->copied_conn_req,
			     sizeof(struct wlan_cm_connect_req));
	} else {
		copied_conn_req_lock_release(sta_ctx);
		goto out;
	}
	copied_conn_req_lock_release(sta_ctx);

	conn_req.vdev_id = wlan_vdev_get_id(vdev);
	conn_req.source = CM_MLO_LINK_SWITCH_CONNECT;
	wlan_vdev_set_link_id(vdev, req->new_ieee_link_id);

	conn_req.chan_freq = req->new_primary_freq;
	conn_req.link_id = req->new_ieee_link_id;
	qdf_copy_macaddr(&conn_req.bssid, &mlo_link_info->ap_link_addr);
	qdf_copy_macaddr(&conn_req.bssid_hint, &mlo_link_info->ap_link_addr);
	wlan_vdev_mlme_get_ssid(assoc_vdev, conn_req.ssid.ssid,
				&conn_req.ssid.length);
	status = wlan_vdev_get_bss_peer_mld_mac(assoc_vdev, &conn_req.mld_addr);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_debug("Get MLD addr failed");
		goto out;
	}

	conn_req.crypto.auth_type = 0;
	conn_req.ml_parnter_info = sta_ctx->ml_partner_info;
	mlo_allocate_and_copy_ies(&conn_req, sta_ctx->copied_conn_req);

	status = wlan_cm_start_connect(vdev, &conn_req);
	if (QDF_IS_STATUS_SUCCESS(status))
		mlo_update_connected_links(vdev, 1);

	wlan_cm_free_connect_req_param(&conn_req);

out:
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_err("VDEV %d link switch connect request failed",
			wlan_vdev_get_id(vdev));
		mlo_mgr_remove_link_switch_cmd(vdev);
	}

	return status;
}

static void
mlo_mgr_link_switch_connect_success_trans_state(struct wlan_objmgr_vdev *vdev)
{
	enum mlo_link_switch_req_state curr_state;

	/*
	 * If connection is success, then sending link switch failure to FW
	 * might result in not updating VDEV to link mapping in FW and FW may
	 * immediately send next link switch with params corresponding to
	 * pre-link switch which may vary post-link switch in host and might
	 * not be valid and results in Host-FW out-of-sync.
	 *
	 * Force the result of link switch in align with link switch connect
	 * so that Host and FW are not out of sync.
	 */
	mlo_dev_lock_acquire(vdev->mlo_dev_ctx);
	curr_state = vdev->mlo_dev_ctx->link_ctx->last_req.state;
	vdev->mlo_dev_ctx->link_ctx->last_req.state =
					MLO_LINK_SWITCH_STATE_COMPLETE_SUCCESS;
	mlo_dev_lock_release(vdev->mlo_dev_ctx);

	if (curr_state != MLO_LINK_SWITCH_STATE_CONNECT_NEW_LINK)
		mlo_debug("Current link switch state %d changed", curr_state);
}

void mlo_mgr_link_switch_connect_done(struct wlan_objmgr_vdev *vdev,
				      QDF_STATUS status)
{
	struct wlan_mlo_link_switch_req *req;
	struct wlan_objmgr_vdev *assoc_vdev;
	bool is_link_recfg_in_progress = mlo_is_link_recfg_in_progress(vdev);

	req = &vdev->mlo_dev_ctx->link_ctx->last_req;
	if (QDF_IS_STATUS_SUCCESS(status)) {
		mlo_mgr_link_switch_connect_success_trans_state(vdev);
	} else {
		mlo_update_connected_links(vdev, 0);
		mlo_err("VDEV %d link switch connect failed", req->vdev_id);
	}

	mlo_mgr_remove_link_switch_cmd(vdev);

	/* Roam is not disabled for link recfg, no need restore roam */
	if (!is_link_recfg_in_progress &&
	    QDF_IS_STATUS_ERROR(status)) {
		assoc_vdev = wlan_mlo_get_assoc_link_vdev(vdev);
		if (!assoc_vdev) {
			mlo_err("VDEV(%d) assoc vdev not found", req->vdev_id);
			return;
		}

		mlo_mgr_restore_rso_upon_link_switch_failure(assoc_vdev);
	}
}

static enum wlan_mlo_link_switch_notify_reason
mlo_mgr_link_switch_get_notify_reason(struct wlan_objmgr_vdev *vdev)
{
	enum mlo_link_switch_req_state curr_state;
	enum wlan_mlo_link_switch_notify_reason notify_reason;

	curr_state = mlo_mgr_link_switch_get_curr_state(vdev->mlo_dev_ctx);
	switch (curr_state) {
	case MLO_LINK_SWITCH_STATE_IDLE:
		notify_reason = MLO_LINK_SWITCH_NOTIFY_REASON_PRE_START_PRE_SER;
		break;
	case MLO_LINK_SWITCH_STATE_INIT:
		notify_reason =
			MLO_LINK_SWITCH_NOTIFY_REASON_PRE_START_POST_SER;
		break;
	case MLO_LINK_SWITCH_STATE_COMPLETE_SUCCESS:
		notify_reason = MLO_LINK_SWITCH_NOTIFY_REASON_STOP_SUCCESS;
		break;
	default:
		notify_reason = MLO_LINK_SWITCH_NOTIFY_REASON_STOP_FAILURE;
		break;
	}

	return notify_reason;
}

static QDF_STATUS
mlo_mgr_start_link_switch(struct wlan_objmgr_vdev *vdev,
			  struct wlan_serialization_command *cmd)
{
	QDF_STATUS status = QDF_STATUS_E_INVAL;
	uint8_t vdev_id, old_link_id, new_link_id;
	struct wlan_mlo_dev_context *mlo_dev_ctx = vdev->mlo_dev_ctx;
	struct wlan_mlo_link_switch_req *req = &mlo_dev_ctx->link_ctx->last_req;
	struct qdf_mac_addr bssid;

	vdev_id = wlan_vdev_get_id(vdev);
	old_link_id = req->curr_ieee_link_id;
	new_link_id = req->new_ieee_link_id;

	mlo_debug("VDEV %d start link switch", vdev_id);
	mlo_mgr_link_switch_trans_next_state(mlo_dev_ctx);

	if (!wlan_cm_is_vdev_connected(vdev)) {
		mlo_err("VDEV %d not in connected state", vdev_id);
		return status;
	}

	status = wlan_vdev_get_bss_peer_mac(vdev, &bssid);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	status = wlan_vdev_get_bss_peer_mld_mac(vdev, &req->peer_mld_addr);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	status = mlo_mgr_link_switch_notify(vdev, req);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	wlan_vdev_mlme_set_mlo_link_switch_in_progress(vdev);
	status = mlo_mgr_link_switch_trans_next_state(mlo_dev_ctx);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	status = wlan_cm_disconnect(vdev, CM_MLO_LINK_SWITCH_DISCONNECT,
				    REASON_FW_TRIGGERED_LINK_SWITCH, &bssid);

	if (QDF_IS_STATUS_ERROR(status))
		mlo_err("VDEV %d disconnect request not handled", req->vdev_id);

	return status;
}

void mlo_link_recfg_link_switch_timeout(
		struct wlan_objmgr_psoc *psoc,
		struct wlan_mlo_dev_context *mlo_dev_ctx)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_mlo_link_switch_req *req;
	enum qdf_hang_reason reason = QDF_VDEV_ACTIVE_SER_LINK_SWITCH_TIMEOUT;

	req = &mlo_dev_ctx->link_ctx->last_req;
	mlo_err("Link switch active cmd timeout");
	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, req->vdev_id,
						    WLAN_MLO_MGR_ID);
	if (!vdev) {
		mlo_err("Invalid link switch VDEV %d", req->vdev_id);
		return;
	}

	wlan_cm_trigger_panic_on_cmd_timeout(vdev, reason);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLO_MGR_ID);
}

static QDF_STATUS
mlo_mgr_ser_link_switch_cb(struct wlan_serialization_command *cmd,
			   enum wlan_serialization_cb_reason cb_reason)
{
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct wlan_mlo_link_switch_req *req;
	enum qdf_hang_reason reason = QDF_VDEV_ACTIVE_SER_LINK_SWITCH_TIMEOUT;

	if (!cmd) {
		mlo_err("cmd is NULL, reason: %d", cb_reason);
		QDF_ASSERT(0);
		return QDF_STATUS_E_NULL_VALUE;
	}

	vdev = cmd->vdev;
	req = &vdev->mlo_dev_ctx->link_ctx->last_req;

	switch (cb_reason) {
	case WLAN_SER_CB_ACTIVATE_CMD:
		status = mlo_mgr_start_link_switch(vdev, cmd);
		if (QDF_IS_STATUS_ERROR(status)) {
			mlo_mgr_link_switch_trans_abort_state(vdev->mlo_dev_ctx);
			mlo_mgr_link_switch_notify(vdev, req);
			mlo_mgr_link_switch_complete(vdev);
		}
		break;
	case WLAN_SER_CB_RELEASE_MEM_CMD:
		break;
	case WLAN_SER_CB_CANCEL_CMD:
		mlo_err("Link switch cmd cancelled");
		break;
	case WLAN_SER_CB_ACTIVE_CMD_TIMEOUT:
		mlo_err("Link switch active cmd timeout");
		wlan_cm_trigger_panic_on_cmd_timeout(vdev, reason);
		break;
	default:
		QDF_ASSERT(0);
		mlo_mgr_link_switch_complete(vdev);
		break;
	}

	return status;
}

void mlo_mgr_remove_link_switch_cmd(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_serialization_queued_cmd_info cmd_info = {0};
	enum mlo_link_switch_req_state cur_state;
	uint8_t vdev_id = wlan_vdev_get_id(vdev);
	struct wlan_mlo_link_switch_req *req;
	bool is_link_recfg_in_prog = mlo_is_link_recfg_in_progress(vdev);

	cur_state = mlo_mgr_link_switch_get_curr_state(vdev->mlo_dev_ctx);
	if (cur_state == MLO_LINK_SWITCH_STATE_IDLE)
		return;

	req = &vdev->mlo_dev_ctx->link_ctx->last_req;
	mlo_mgr_link_switch_notify(vdev, req);

	/* Force queue disconnect on failure */
	if (cur_state != MLO_LINK_SWITCH_STATE_COMPLETE_SUCCESS &&
	    cur_state >= MLO_LINK_SWITCH_STATE_DISCONNECT_CURR_LINK &&
	    !wlan_cm_is_vdev_connected(vdev)) {
		mlo_mgr_link_switch_defer_disconnect_req(vdev,
							 CM_MLME_DISCONNECT,
							 REASON_HOST_TRIGGERED_LINK_DELETE);
	}

	/* Handle any pending disconnect */
	mlo_handle_pending_disconnect(vdev);

	mlo_mgr_link_switch_complete(vdev);

	if (req->reason == MLO_LINK_SWITCH_REASON_HOST_FORCE ||
	    is_link_recfg_in_prog) {
		mlo_debug("Link switch not serialized reason %d link_recfg_in_prog %d",
			  req->reason, is_link_recfg_in_prog);
		return;
	}

	cmd_info.cmd_id = (vdev_id << 16) + (req->new_ieee_link_id << 8) +
			  (req->curr_ieee_link_id);
	cmd_info.req_type = WLAN_SER_CANCEL_NON_SCAN_CMD;
	cmd_info.cmd_type = WLAN_SER_CMD_MLO_VDEV_LINK_SWITCH;
	cmd_info.vdev = vdev;
	cmd_info.queue_type = WLAN_SERIALIZATION_ACTIVE_QUEUE;
	cmd_info.requestor = WLAN_UMAC_COMP_MLO_MGR;

	wlan_serialization_remove_cmd(&cmd_info);
}

#define MLO_MGR_MAX_LSWITCH_TIMEOUT	35000

QDF_STATUS mlo_mgr_ser_link_switch_cmd(struct wlan_objmgr_vdev *vdev,
				       struct wlan_mlo_link_switch_req *req)
{
	QDF_STATUS status;
	enum wlan_serialization_status ser_cmd_status;
	struct wlan_serialization_command cmd = {0};
	uint8_t vdev_id = wlan_vdev_get_id(vdev);
	struct mlo_link_switch_context *link_ctx;
	bool is_link_recfg_in_prog;

	if (!vdev->mlo_dev_ctx) {
		mlo_err("ML dev ctx NULL, reject link switch");
		return QDF_STATUS_E_INVAL;
	}

	link_ctx = vdev->mlo_dev_ctx->link_ctx;
	link_ctx->last_req = *req;

	cmd.cmd_type = WLAN_SER_CMD_MLO_VDEV_LINK_SWITCH;
	cmd.cmd_id = (vdev_id << 16) + (req->new_ieee_link_id << 8) +
		     (req->curr_ieee_link_id);
	cmd.cmd_cb = mlo_mgr_ser_link_switch_cb;
	cmd.source = WLAN_UMAC_COMP_MLO_MGR;
	cmd.is_high_priority = false;
	cmd.cmd_timeout_duration = MLO_MGR_MAX_LSWITCH_TIMEOUT;
	cmd.vdev = vdev;
	cmd.is_blocking = true;

	is_link_recfg_in_prog = mlo_is_link_recfg_in_progress(vdev);
	if (req->reason == MLO_LINK_SWITCH_REASON_HOST_FORCE ||
	    is_link_recfg_in_prog) {
		mlo_debug("Do not serialize link switch for reason %d link_recfg_in_prog %d",
			  req->reason, is_link_recfg_in_prog);
		status = mlo_mgr_start_link_switch(vdev, &cmd);
		if (QDF_IS_STATUS_ERROR(status)) {
			mlo_mgr_link_switch_trans_abort_state(vdev->mlo_dev_ctx);
			mlo_mgr_link_switch_notify(vdev, &link_ctx->last_req);
		}
		return status;
	}

	ser_cmd_status = wlan_serialization_request(&cmd);
	switch (ser_cmd_status) {
	case WLAN_SER_CMD_PENDING:
		mlo_debug("Link switch cmd in pending queue");
		break;
	case WLAN_SER_CMD_ACTIVE:
		mlo_debug("Link switch cmd in active queue");
		break;
	default:
		return QDF_STATUS_E_INVAL;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlo_mgr_link_switch_notify(struct wlan_objmgr_vdev *vdev,
				      struct wlan_mlo_link_switch_req *req)
{
	int8_t i;
	QDF_STATUS status, ret_status = QDF_STATUS_SUCCESS;
	enum wlan_mlo_link_switch_notify_reason notify_reason;
	struct mlo_mgr_context *mlo_mgr_ctx = wlan_objmgr_get_mlo_ctx();

	if (!mlo_mgr_ctx) {
		mlo_err("Global mlo mgr NULL");
		return QDF_STATUS_E_NULL_VALUE;
	}

	notify_reason = mlo_mgr_link_switch_get_notify_reason(vdev);
	for (i = 0; i < WLAN_UMAC_COMP_ID_MAX; i++) {
		if (!mlo_mgr_ctx->lswitch_notifier[i].in_use)
			continue;

		status = mlo_mgr_ctx->lswitch_notifier[i].cb(vdev, req,
							     notify_reason);
		if (QDF_IS_STATUS_SUCCESS(status))
			continue;

		mlo_debug("Link switch notify %d failed in %d",
			  notify_reason, i);
		ret_status = status;
		if (notify_reason == MLO_LINK_SWITCH_NOTIFY_REASON_PRE_START_PRE_SER)
			break;
	}

	return ret_status;
}

static QDF_STATUS
mlo_mgr_host_link_switch_validate_request(struct wlan_objmgr_vdev *vdev,
					  struct wlan_mlo_link_switch_req *req)
{
	uint8_t vdev_id = wlan_vdev_get_id(vdev);
	struct mlo_link_info *new_link_info;

	if (req->curr_ieee_link_id >= WLAN_INVALID_LINK_ID ||
	    req->new_ieee_link_id >= WLAN_INVALID_LINK_ID) {
		mlo_err("Invalid link params, curr link id %d, new link id %d",
			req->curr_ieee_link_id, req->new_ieee_link_id);
		return QDF_STATUS_E_INVAL;
	}

	if (wlan_vdev_get_id(vdev) != req->vdev_id) {
		mlo_err("Invalid vdev params, curr id %d, req id %d",
			wlan_vdev_get_id(vdev), req->vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	new_link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx,
						       req->new_ieee_link_id);
	if (!new_link_info) {
		mlo_err("New link id %d not part of association",
			req->new_ieee_link_id);
		return QDF_STATUS_E_INVAL;
	}

	if (new_link_info->vdev_id != WLAN_INVALID_VDEV_ID &&
	    new_link_info->vdev_id != req->vdev_id) {
		mlo_err("requested link already active on other vdev:%d",
			new_link_info->vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	if (!mlo_is_mld_sta(vdev)) {
		mlo_err("Link switch req not valid for VDEV %d", vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	if (!wlan_cm_is_vdev_connected(vdev)) {
		mlo_err("VDEV %d not in connected state", vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	if (mlo_mgr_is_link_switch_in_progress(vdev)) {
		mlo_err("Link switch already in progress");
		return QDF_STATUS_E_INVAL;
	}

	if (new_link_info->link_chan_info->ch_freq != req->new_primary_freq) {
		mlo_err("Host freq(%d) FW req freq(%d)",
			new_link_info->link_chan_info->ch_freq,
			req->new_primary_freq);
		return QDF_STATUS_E_INVAL;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
mlo_mgr_link_switch_validate_request(struct wlan_objmgr_vdev *vdev,
				     struct wlan_mlo_link_switch_req *req)
{
	QDF_STATUS status = QDF_STATUS_E_INVAL;
	uint8_t vdev_id = wlan_vdev_get_id(vdev);
	struct mlo_link_info *new_link_info;
	bool notify_link_recfg = false;

	if (req->reason == MLO_LINK_SWITCH_REASON_HOST_ADD_LINK) {
		status = mlo_mgr_host_link_switch_validate_request(vdev, req);
		if (QDF_IS_STATUS_ERROR(status)) {
			mlo_err("link switch status %d for add link", status);
			return status;
		}
		goto validated;
	}

	if (req->curr_ieee_link_id >= WLAN_INVALID_LINK_ID ||
	    req->new_ieee_link_id >= WLAN_INVALID_LINK_ID) {
		mlo_err("Invalid link params, curr link id %d, new link id %d",
			req->curr_ieee_link_id, req->new_ieee_link_id);
		return status;
	}

	new_link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx,
						       req->new_ieee_link_id);
	if (!new_link_info) {
		mlo_err("New link id %d not part of association",
			req->new_ieee_link_id);
		return status;
	}

	if (new_link_info->vdev_id != WLAN_INVALID_VDEV_ID) {
		mlo_err("requested link already active on other vdev:%d",
			new_link_info->vdev_id);
		return status;
	}

	if (!mlo_is_mld_sta(vdev)) {
		mlo_err("Link switch req not valid for VDEV %d", vdev_id);
		return status;
	}

	if (!wlan_cm_is_vdev_connected(vdev)) {
		mlo_err("VDEV %d not in connected state", vdev_id);
		return status;
	}

	if (mlo_mgr_is_link_switch_in_progress(vdev)) {
		mlo_err("Link switch already in progress");
		return status;
	}

	if (wlan_vdev_get_link_id(vdev) != req->curr_ieee_link_id) {
		mlo_err("VDEV %d link id wrong, curr link id %d",
			vdev_id, wlan_vdev_get_link_id(vdev));
		return status;
	}

	if (new_link_info->link_chan_info->ch_freq != req->new_primary_freq) {
		mlo_err("Host freq(%d) FW req freq(%d)",
			new_link_info->link_chan_info->ch_freq,
			req->new_primary_freq);
		return status;
	}
validated:
	/* If link recfg in progress, link switch is only allowed for host
	 * force reason code.
	 */
	if (mlo_is_link_recfg_in_progress(vdev)) {
		if (req->reason == MLO_LINK_SWITCH_REASON_HOST_FORCE ||
		    req->reason ==
		    MLO_LINK_SWITCH_REASON_HOST_FORCE_FOLLOWUP ||
		    req->reason == MLO_LINK_SWITCH_REASON_HOST_ADD_LINK) {
			/* notify link recfg link switch start */
			notify_link_recfg = true;
		} else {
			mlo_debug("unexpected link switch fw reason %d in link recfg prog",
				  req->reason);
			return QDF_STATUS_E_INVAL;
		}
	}

	/* Notify callers on the new link switch request before serializing */
	status = mlo_mgr_link_switch_notify(vdev, req);
	if (QDF_IS_STATUS_ERROR(status))
		mlo_err("Link switch rejected in pre-serialize notify");

	if (notify_link_recfg)
		mlo_link_recfg_linksw_start_indication(vdev, status);

	return status;
}

QDF_STATUS mlo_mgr_link_switch_request_params(struct wlan_objmgr_psoc *psoc,
					      void *evt_params)
{
	QDF_STATUS status;
	struct wlan_mlo_link_switch_cnf cnf_params = {0};
	struct wlan_mlo_link_switch_req *req;
	struct wlan_objmgr_vdev *vdev;

	if (!evt_params) {
		mlo_err("Invalid params");
		return QDF_STATUS_E_INVAL;
	}

	req = (struct wlan_mlo_link_switch_req *)evt_params;

	/* The reference is released on Link Switch status confirm to FW */
	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, req->vdev_id,
						    WLAN_MLO_MGR_ID);
	if (!vdev) {
		mlo_err("Invalid link switch VDEV %d", req->vdev_id);

		/* Fill reject params here and send to FW as VDEV is invalid */
		cnf_params.vdev_id = req->vdev_id;
		cnf_params.status = MLO_LINK_SWITCH_CNF_STATUS_REJECT;
		mlo_mgr_link_switch_send_cnf_cmd(psoc, &cnf_params);
		return QDF_STATUS_E_INVAL;
	}

	mlo_debug("VDEV %d, curr_link_id %d, new_link_id %d, new_freq %d, new_phymode: %d, reason %d",
		  req->vdev_id, req->curr_ieee_link_id, req->new_ieee_link_id,
		  req->new_primary_freq, req->new_phymode, req->reason);

	status = mlo_mgr_link_switch_validate_request(vdev, req);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_debug("Link switch params/request invalid");
		mlo_mgr_link_switch_complete(vdev);
		return QDF_STATUS_E_INVAL;
	}

	status = mlo_mgr_ser_link_switch_cmd(vdev, req);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlo_err("Failed to serialize link switch command");
		mlo_mgr_link_switch_complete(vdev);
	}

	return status;
}

#ifdef WLAN_FEATURE_11BE_MLO_ADV_FEATURE
/**
 * mlo_mgr_update_policy_mgr_disabled_links_info() - Update the policy manager
 * with the info on inactive links and move the inactive links to disabled table
 * @psoc: Pointer to PSOC object
 * @vdev_id: Vdev id
 * @link_id: link id
 * @is_link_active: If link is active or inactive
 *
 * Return: None
 */
static void
mlo_mgr_update_policy_mgr_disabled_links_info(struct wlan_objmgr_psoc *psoc,
					      uint8_t vdev_id, uint8_t link_id,
					      bool is_link_active)
{
	if (policy_mgr_is_hw_dbs_capable(psoc))
		return;

	/* Dont update the policy manager for standby link */
	if (link_id == WLAN_INVALID_LINK_ID)
		return;

	if (is_link_active) {
		policy_mgr_move_vdev_from_disabled_to_connection_tbl(psoc,
								     vdev_id);
		return;
	}

	policy_mgr_move_vdev_from_connection_to_disabled_tbl(psoc, vdev_id);
}
#else
static inline void
mlo_mgr_update_policy_mgr_disabled_links_info(struct wlan_objmgr_psoc *psoc,
					      uint8_t vdev_id, uint8_t link_id,
					      bool is_link_active)
{}
#endif

#define IS_LINK_SET(link_bitmap, link_id) ((link_bitmap) & (BIT(link_id)))

#define WLAN_MLO_SINGLE_LINK 1
static void mlo_mgr_update_link_state(struct wlan_objmgr_psoc *psoc,
				      struct wlan_mlo_dev_context *mld_ctx,
				      uint32_t active_link_bitmap)
{
	uint8_t i, vdev_id, num_links = 0;
	struct mlo_link_info *link_info;
	struct wlan_objmgr_vdev *vdev;
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();
	bool is_cb_register = false;

	if (mlo_ctx && mlo_ctx->osif_ops &&
	    mlo_ctx->osif_ops->mlo_mgr_osif_update_link_state)
		is_cb_register = true;

	num_links = mlo_get_sta_num_links(mld_ctx);
	for (i = 0; i < WLAN_MAX_ML_BSS_LINKS; i++) {
		link_info = &mld_ctx->link_ctx->links_info[i];

		if (qdf_is_macaddr_zero(&link_info->ap_link_addr) ||
		    qdf_is_macaddr_zero(&link_info->link_addr))
			continue;

		if (IS_LINK_SET(active_link_bitmap, link_info->link_id))
			link_info->is_link_active = true;
		else
			link_info->is_link_active = false;

		vdev_id = link_info->vdev_id;
		mlo_debug("vdev:%d is_link_active:%d num_links:%d", vdev_id,
			  link_info->is_link_active, num_links);
		/*
		 * Teardown TDLS for non-DBS target when number of
		 * connected links is > 1, so that it can be formed again on
		 * active link.
		 */
		if (num_links > WLAN_MLO_SINGLE_LINK &&
		    !link_info->is_link_active &&
		    mlo_ctx && mlo_ctx->mlme_ops &&
		    mlo_ctx->mlme_ops->mlo_mlme_ext_teardown_tdls)
			mlo_ctx->mlme_ops->mlo_mlme_ext_teardown_tdls(psoc,
								      vdev_id);

		if (is_cb_register)
			mlo_ctx->osif_ops->mlo_mgr_osif_update_link_state(
						link_info->vdev_id,
						link_info->is_link_active);

		vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
							    WLAN_MLO_MGR_ID);
		if (!vdev)
			continue;

		/*
		 * If VDEV is not in connected state don't update the policy
		 * manager table, this can happen if disconnect is ongoing when
		 * host receives event from FW.
		 */
		if (wlan_cm_is_vdev_connected(vdev))
			mlo_mgr_update_policy_mgr_disabled_links_info(psoc,
								      vdev_id,
								      link_info->link_id,
								      link_info->is_link_active);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLO_MGR_ID);
	}
}

QDF_STATUS
mlo_mgr_link_state_switch_info_handler(struct wlan_objmgr_psoc *psoc,
				       struct mlo_link_switch_state_info *info)
{
	uint8_t i;
	struct wlan_mlo_dev_context *mld_ctx = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	wlan_mlo_get_mlpeer_by_peer_mladdr(
			&info->link_switch_param[0].mld_addr, &mld_ctx);

	if (!mld_ctx) {
		mlo_err("mlo dev ctx for mld_mac: " QDF_MAC_ADDR_FMT " not found",
			QDF_MAC_ADDR_REF(info->link_switch_param[0].mld_addr.bytes));
		return QDF_STATUS_E_INVAL;
	}

	for (i = 0; i < info->num_params; i++) {
		wlan_connectivity_mld_link_status_event(
				psoc,
				&info->link_switch_param[i]);
		mlo_mgr_update_link_state(
				psoc, mld_ctx,
				info->link_switch_param[i].active_link_bitmap);
	}

	return status;
}

QDF_STATUS mlo_mgr_link_switch_complete(struct wlan_objmgr_vdev *vdev)
{
	enum mlo_link_switch_req_state state;
	struct wlan_mlo_link_switch_cnf params = {0};
	struct mlo_link_switch_context *link_ctx;
	struct wlan_mlo_link_switch_req *req;
	struct wlan_objmgr_psoc *psoc;
	QDF_STATUS comp_status = QDF_STATUS_SUCCESS;
	bool link_recfg_in_prog = mlo_is_link_recfg_in_progress(vdev);
	struct wlan_objmgr_peer *peer;
	struct wlan_mlo_peer_context *ml_peer;

	/* Not checking NULL value as reference is already taken for vdev */
	psoc = wlan_vdev_get_psoc(vdev);

	if (!vdev->mlo_dev_ctx) {
		mlo_err("mlo_dev_ctx for vdev is null vedv_id %d",
			wlan_vdev_get_id(vdev));
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLO_MGR_ID);
		return QDF_STATUS_E_INVAL;
	}

	link_ctx = vdev->mlo_dev_ctx->link_ctx;
	req = &link_ctx->last_req;

	state = mlo_mgr_link_switch_get_curr_state(vdev->mlo_dev_ctx);
	if (state != MLO_LINK_SWITCH_STATE_COMPLETE_SUCCESS)
		params.status = MLO_LINK_SWITCH_CNF_STATUS_REJECT;
	else
		params.status = MLO_LINK_SWITCH_CNF_STATUS_ACCEPT;

	params.vdev_id = wlan_vdev_get_id(vdev);
	params.reason = MLO_LINK_SWITCH_CNF_REASON_BSS_PARAMS_CHANGED;

	if (req->reason != MLO_LINK_SWITCH_REASON_HOST_ADD_LINK)
		mlo_mgr_link_switch_send_cnf_cmd(psoc, &params);

	mlo_mgr_link_switch_init_state(vdev->mlo_dev_ctx);
	wlan_vdev_mlme_clear_mlo_link_switch_in_progress(vdev);

	/* notify link recfg the link switch completed */
	if (link_recfg_in_prog) {
		if (params.status != MLO_LINK_SWITCH_CNF_STATUS_ACCEPT)
			comp_status = QDF_STATUS_E_FAILURE;

		mlo_link_recfg_linksw_completion_indication(vdev, comp_status);
	}

	peer = wlan_objmgr_vdev_try_get_bsspeer(vdev, WLAN_MLO_MGR_ID);
	if (!peer) {
		mlo_err("peer is null");
		comp_status = QDF_STATUS_E_NULL_VALUE;
		goto end;
	}

	ml_peer = peer->mlo_peer_ctx;
	if (!ml_peer) {
		mlo_err("ml peer is null");
		comp_status = QDF_STATUS_E_NULL_VALUE;
		goto end;
	}

	if (ml_peer->t2lm_policy.is_standby_link_enabled) {
		mlme_cm_osif_roam_abort_ind(vdev);
		ml_peer->t2lm_policy.is_standby_link_enabled = false;
		t2lm_debug("Enable all queues");
	}

	wlan_objmgr_peer_release_ref(peer, WLAN_MLO_MGR_ID);
end:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLO_MGR_ID);

	return comp_status;
}

QDF_STATUS
mlo_mgr_link_switch_send_cnf_cmd(struct wlan_objmgr_psoc *psoc,
				 struct wlan_mlo_link_switch_cnf *cnf_params)
{
	QDF_STATUS status;
	struct wlan_lmac_if_mlo_tx_ops *mlo_tx_ops;

	mlo_debug("VDEV %d link switch completed, %s", cnf_params->vdev_id,
		  (cnf_params->status == MLO_LINK_SWITCH_CNF_STATUS_ACCEPT) ?
		  "success" : "fail");

	mlo_tx_ops = &psoc->soc_cb.tx_ops->mlo_ops;
	if (!mlo_tx_ops || !mlo_tx_ops->send_mlo_link_switch_cnf_cmd) {
		mlo_err("handler is not registered");
		return QDF_STATUS_E_INVAL;
	}

	status = mlo_tx_ops->send_mlo_link_switch_cnf_cmd(psoc, cnf_params);
	if (QDF_IS_STATUS_ERROR(status))
		mlo_err("Link switch status update to FW failed");

	return status;
}

QDF_STATUS
mlo_mgr_link_switch_defer_disconnect_req(struct wlan_objmgr_vdev *vdev,
					 enum wlan_cm_source source,
					 enum wlan_reason_code reason)
{
	struct wlan_mlo_dev_context *mlo_dev_ctx;
	struct wlan_mlo_sta *sta_ctx;

	if (!mlo_mgr_is_link_switch_in_progress(vdev)) {
		mlo_info("Link switch not in progress");
		return QDF_STATUS_E_INVAL;
	}

	mlo_dev_ctx = vdev->mlo_dev_ctx;
	sta_ctx = mlo_dev_ctx->sta_ctx;

	if (!sta_ctx) {
		mlo_err("sta ctx null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	/* Move current link switch to abort state */
	mlo_mgr_link_switch_trans_abort_state(mlo_dev_ctx);

	mlo_link_recfg_abort_if_in_progress(vdev, false);

	if (sta_ctx->disconn_req) {
		mlo_debug("Pending disconnect from source %d, reason %d",
			  sta_ctx->disconn_req->source,
			  sta_ctx->disconn_req->reason_code);
		return QDF_STATUS_E_ALREADY;
	}

	sta_ctx->disconn_req =
			qdf_mem_malloc(sizeof(struct wlan_cm_disconnect_req));
	if (!sta_ctx->disconn_req)
		return QDF_STATUS_E_NOMEM;

	sta_ctx->disconn_req->vdev_id = wlan_vdev_get_id(vdev);
	sta_ctx->disconn_req->source = source;
	sta_ctx->disconn_req->reason_code = reason;

	mlo_debug("Deferred disconnect source: %d, reason: %d", source, reason);
	return QDF_STATUS_SUCCESS;
}

bool mlo_mgr_is_mlo_vdev_active(struct wlan_objmgr_vdev *vdev)
{
	struct mlo_link_info *link_info;
	uint8_t link_id = WLAN_INVALID_LINK_ID;

	if (!wlan_vdev_mlme_is_mlo_vdev(vdev) || !vdev->mlo_dev_ctx)
		return false;

	link_id = wlan_vdev_get_link_id(vdev);
	link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx, link_id);
	if (!link_info) {
		mlo_debug("Link info not found for link_id %d vdev %d",
			  link_id, wlan_vdev_get_id(vdev));
		return false;
	}

	return link_info->is_link_active;
}
#endif
