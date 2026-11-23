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
 * DOC: contains definitions for DFS NO WAIT (DNW) functions
 */

#include "wlan_dfs_no_wait.h"
#include "wlan_pre_cac_main.h"
#include <wlan_reg_services_api.h>
#include <wlan_utility.h>

static inline struct wlan_dnw_vdev_info *
wlan_get_dnw_vdev_info(struct wlan_objmgr_vdev *vdev)
{
	struct pre_cac_vdev_priv *vdev_priv;

	if (!vdev) {
		pre_cac_err("NULL vdev");
		return NULL;
	}

	vdev_priv = pre_cac_vdev_get_priv(vdev);
	if (!vdev_priv) {
		pre_cac_err("NULL pre cac vdev priv");
		return NULL;
	}

	return &vdev_priv->dnw_vdev_info;
}

static inline struct wlan_dnw_pdev_info *
wlan_get_dnw_pdev_info(struct wlan_objmgr_pdev *pdev)
{
	struct pre_cac_pdev_priv *pdev_priv;

	if (!pdev) {
		pre_cac_err("NULL pdev");
		return NULL;
	}

	pdev_priv = wlan_objmgr_pdev_get_comp_private_obj(
				pdev, WLAN_UMAC_COMP_PRE_CAC);
	if (!pdev_priv) {
		pre_cac_err("NULL pre cac pdev priv");
		return NULL;
	}

	return &pdev_priv->dnw_pdev_info;
}

static inline struct wlan_dnw_pdev_info *
wlan_get_dnw_pdev_info_by_vdev(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_objmgr_pdev *pdev;
	struct pre_cac_pdev_priv *pdev_priv;

	if (!vdev) {
		pre_cac_err("NULL vdev");
		return NULL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		pre_cac_err("NULL pdev");
		return NULL;
	}

	pdev_priv = wlan_objmgr_pdev_get_comp_private_obj(
				pdev, WLAN_UMAC_COMP_PRE_CAC);
	if (!pdev_priv) {
		pre_cac_err("NULL pre cac pdev priv");
		return NULL;
	}

	return &pdev_priv->dnw_pdev_info;
}

static void wlan_dnw_reset(struct wlan_objmgr_vdev *vdev,
			   struct wlan_dnw_pdev_info *dnw_pdev_info,
			   struct wlan_dnw_vdev_info *dnw_vdev_info)
{
	/* Reset DNW vdev information */
	dnw_vdev_info->dnw_in_progress = false;
	dnw_vdev_info->ctx = NULL;

	/* Reset DNW pdev information */
	if (dnw_pdev_info->dnw_count) {
		dnw_pdev_info->dnw_count--;
		if (!dnw_pdev_info->dnw_count) {
			dnw_pdev_info->dnw_in_progress = false;
			stop_dnw_timer(dnw_pdev_info);
		}
	}
	pre_cac_debug("dnw count %d, vdev %d", dnw_pdev_info->dnw_count,
		      wlan_vdev_get_id(vdev));
}

static const uint8_t *dnw_get_state_string(enum wlan_dfs_no_wait_state state)
{
	switch (state) {
		CASE_RETURN_STRING(DNW_STATE_INIT);
		CASE_RETURN_STRING(DNW_STATE_CAC);
		CASE_RETURN_STRING(DNW_STATE_RADAR_FOUND);
		CASE_RETURN_STRING(DNW_STATE_END);
	}
	return (const uint8_t *)"UNKNOWN";
}

static QDF_STATUS
wlan_dnw_set_state(struct wlan_dnw_pdev_info *dnw_pdev_info,
		   enum wlan_dfs_no_wait_state state)
{
	pre_cac_debug("old %d new %d, %s->%s", dnw_pdev_info->state, state,
		      dnw_get_state_string(dnw_pdev_info->state),
		      dnw_get_state_string(state));
	dnw_pdev_info->state = state;

	return QDF_STATUS_SUCCESS;
}

static bool
wlan_dnw_find_downgrade_bw(struct wlan_objmgr_pdev *pdev, uint32_t ch_freq,
			   uint8_t ch_width, enum phy_ch_width *dg_ch_width)
{
	struct ch_params ch_params = {0};
	bool is_dfs = true;

	if (!dg_ch_width || !pdev) {
		pre_cac_debug("NULL dg_ch_width or pdev");
		return false;
	}

	pre_cac_debug("freq %d bw %d", ch_freq, ch_width);
	wlan_reg_set_create_punc_bitmap(&ch_params, true);
	ch_params.ch_width = ch_width;

	do {
		ch_params.ch_width--;
		if (ch_params.ch_width <= CH_WIDTH_20MHZ)
			return false;

		is_dfs = wlan_reg_get_5g_bonded_channel_state_for_pwrmode(
			pdev, ch_freq, &ch_params, REG_CURRENT_PWR_MODE) ==
			CHANNEL_STATE_DFS;
	} while (is_dfs);

	*dg_ch_width = ch_params.ch_width;

	return true;
}

static void dnw_find_vdev_handler(struct wlan_objmgr_pdev *pdev,
				  void *obj, void *arg)
{
	struct wlan_objmgr_vdev *vdev = obj;
	struct wlan_dnw_pdev_info *dnw_pdev_info = arg;
	struct wlan_dnw_vdev_info *dnw_vdev_info;
	enum wlan_dnw_request dnw_request = DNW_REQ_UPGRADE_BW;

	if (!vdev) {
		pre_cac_err("invalid vdev");
		return;
	}

	if (wlan_vdev_mlme_get_opmode(vdev) != QDF_SAP_MODE &&
	    wlan_vdev_mlme_get_opmode(vdev) != QDF_P2P_GO_MODE)
		return;

	dnw_vdev_info = wlan_get_dnw_vdev_info(vdev);
	if (!dnw_vdev_info || !dnw_pdev_info) {
		pre_cac_err("NULL dnw vdev or pdev info");
		return;
	}

	if (!dnw_vdev_info->dnw_in_progress)
		return;

	if (dnw_pdev_info->state == DNW_STATE_RADAR_FOUND)
		dnw_request = DNW_REQ_DOWNGRADE_BW;

	if (dnw_pdev_info->request_handler)
		dnw_pdev_info->request_handler(dnw_vdev_info->ctx,
					       dnw_pdev_info->ori_ch_width,
					       dnw_pdev_info->dg_ch_width,
					       dnw_request);
	wlan_dnw_reset(vdev, dnw_pdev_info, dnw_vdev_info);

}

static void wlan_dnw_timer_callback(void *data)
{
	struct wlan_dnw_pdev_info *dnw_pdev_info = data;
	QDF_STATUS status;

	if (!dnw_pdev_info || !dnw_pdev_info->pdev) {
		pre_cac_err("NULL pdev or info");
		return;
	}

	status = wlan_objmgr_pdev_try_get_ref(dnw_pdev_info->pdev,
					      WLAN_PRE_CAC_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		pre_cac_err("pdev ref fail");
		return;
	}

	if (dnw_pdev_info->is_dnw_cac_timer_running) {
		qdf_mc_timer_destroy(&dnw_pdev_info->dnw_cac_timer);
		dnw_pdev_info->is_dnw_cac_timer_running = false;
	}

	pre_cac_debug("Update bw to %d", dnw_pdev_info->ori_ch_width);
	wlan_dnw_set_state(dnw_pdev_info, DNW_STATE_END);

	/* Save DFS No Wait history */
	dnw_pdev_info->pre_dnw_info.ch_freq = dnw_pdev_info->ch_freq;
	dnw_pdev_info->pre_dnw_info.ori_ch_width = dnw_pdev_info->ori_ch_width;
	dnw_pdev_info->pre_dnw_info.dg_ch_width = dnw_pdev_info->dg_ch_width;
	dnw_pdev_info->pre_dnw_info.complete_time =
					qdf_get_time_of_the_day_ms();

	/* Update all SAPs which are DFS in progress */
	wlan_objmgr_pdev_iterate_obj_list(dnw_pdev_info->pdev, WLAN_VDEV_OP,
					  dnw_find_vdev_handler,
					  dnw_pdev_info, 0, WLAN_PRE_CAC_ID);
	wlan_objmgr_pdev_release_ref(dnw_pdev_info->pdev, WLAN_PRE_CAC_ID);
}

QDF_STATUS start_dnw_timer(struct wlan_dnw_pdev_info *dnw_pdev_info)
{
	QDF_STATUS status;

	if (!dnw_pdev_info) {
		pre_cac_err("null dnw_pdev_info");
		return QDF_STATUS_E_INVAL;
	}

	if (dnw_pdev_info->is_dnw_cac_timer_running) {
		pre_cac_debug("dnw timer started");
		return QDF_STATUS_E_FAILURE;
	}
	pre_cac_debug("DFS no wait timer start on freq %d, duration %d sec",
		      dnw_pdev_info->ch_freq,
		      dnw_pdev_info->cac_duration_ms / 1000);

	qdf_mc_timer_init(&dnw_pdev_info->dnw_cac_timer,
			  QDF_TIMER_TYPE_SW,
			  wlan_dnw_timer_callback, dnw_pdev_info);

	status = qdf_mc_timer_start(
			&dnw_pdev_info->dnw_cac_timer,
			dnw_pdev_info->cac_duration_ms);
	if (QDF_IS_STATUS_ERROR(status)) {
		pre_cac_err("failed to start cac timer");
		goto destroy_timer;
	}

	dnw_pdev_info->is_dnw_cac_timer_running = true;

	return QDF_STATUS_SUCCESS;

destroy_timer:
	dnw_pdev_info->is_dnw_cac_timer_running = false;
	qdf_mc_timer_destroy(&dnw_pdev_info->dnw_cac_timer);

	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS stop_dnw_timer(struct wlan_dnw_pdev_info *dnw_pdev_info)
{
	if (!dnw_pdev_info) {
		pre_cac_err("NULL dnw_pdev_info");
		return QDF_STATUS_E_INVAL;
	}
	if (!dnw_pdev_info->is_dnw_cac_timer_running ||
	    (QDF_TIMER_STATE_RUNNING !=
	     qdf_mc_timer_get_current_state(&dnw_pdev_info->dnw_cac_timer))) {
		pre_cac_debug("timer isn't running");
		return QDF_STATUS_E_FAILURE;
	}

	qdf_mc_timer_stop(&dnw_pdev_info->dnw_cac_timer);
	dnw_pdev_info->is_dnw_cac_timer_running = false;
	qdf_mc_timer_destroy(&dnw_pdev_info->dnw_cac_timer);
	pre_cac_debug("dnw timer stopped");

	return QDF_STATUS_SUCCESS;
}

bool is_dnw_in_progress(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_dnw_vdev_info *dnw_vdev_info;
	bool ret;

	if (!pdev) {
		pre_cac_err("null pdev");
		return false;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_PRE_CAC_ID);
	if (!vdev) {
		pre_cac_err("null vdev");
		return QDF_STATUS_E_INVAL;
	}

	dnw_vdev_info = wlan_get_dnw_vdev_info(vdev);
	if (!dnw_vdev_info) {
		pre_cac_err("NULL dnw vdev info");
		ret = false;
		goto release_vdev_ref;
	}

	ret = dnw_vdev_info->dnw_in_progress;

release_vdev_ref:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_PRE_CAC_ID);

	return ret;
}

bool is_valid_dnw(struct wlan_objmgr_pdev *pdev, uint32_t ch_freq,
		  enum phy_ch_width old_ch_width,
		  enum phy_ch_width new_ch_width)
{
	struct wlan_dnw_pdev_info *dnw_pdev_info;
	QDF_STATUS status;
	bool ret = false;

	status = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_PRE_CAC_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		pre_cac_err("vdev ref fail");
		return false;
	}

	dnw_pdev_info = wlan_get_dnw_pdev_info(pdev);
	if (!dnw_pdev_info) {
		pre_cac_err("NULL dnw vdev info");
		ret = false;
		goto release_vdev_ref;
	}

	if ((dnw_pdev_info->pre_dnw_info.ch_freq == ch_freq) &&
	    (dnw_pdev_info->pre_dnw_info.ori_ch_width == new_ch_width) &&
	    (dnw_pdev_info->pre_dnw_info.dg_ch_width == old_ch_width))
		ret = true;

release_vdev_ref:
	wlan_objmgr_pdev_release_ref(pdev, WLAN_PRE_CAC_ID);

	return ret;
}

QDF_STATUS
dnw_set_info(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id, uint32_t ch_freq,
	     uint8_t ch_width, uint32_t cac_duration_ms, bool ignore_cac,
	     dnw_request_handler request_handler, void *ctx)
{
	struct wlan_dnw_pdev_info *dnw_pdev_info;
	struct wlan_dnw_vdev_info *dnw_vdev_info;
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!pdev) {
		pre_cac_err("null pdev");
		return QDF_STATUS_E_INVAL;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_PRE_CAC_ID);
	if (!vdev) {
		pre_cac_err("null vdev");
		return QDF_STATUS_E_FAILURE;
	}

	dnw_pdev_info = wlan_get_dnw_pdev_info(pdev);
	if (!dnw_pdev_info) {
		pre_cac_err("NULL dnw pdev info");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	if (!dnw_pdev_info->enabled) {
		status = QDF_STATUS_E_FAILURE;
		goto release_vdev_ref;
	}

	dnw_vdev_info = wlan_get_dnw_vdev_info(vdev);
	if (!dnw_vdev_info) {
		pre_cac_err("NULL dnw vdev info");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	pre_cac_debug("vdev %d freq %d bw %d cac duration %d ignore cac %d",
		      vdev_id, ch_freq, ch_width, cac_duration_ms, ignore_cac);

	/*
	 * Supports only one DFS in progress, include multiple SAP/GO
	 * on same channel and band.
	 */
	if (dnw_pdev_info->dnw_in_progress) {
		if ((dnw_pdev_info->ori_ch_width == ch_width) &&
		    (dnw_pdev_info->ch_freq == ch_freq)) {
			dnw_vdev_info->dnw_in_progress = true;
			dnw_vdev_info->ctx = ctx;
			dnw_pdev_info->dnw_count++;
			pre_cac_debug("same to in progress dnw, count %d",
				      dnw_pdev_info->dnw_count);
			status = QDF_STATUS_SUCCESS;
			goto release_vdev_ref;
		} else {
			pre_cac_debug("different to in progress dnw freq %d bw %d",
				      dnw_pdev_info->ori_ch_width,
				      dnw_pdev_info->ch_freq);
			status = QDF_STATUS_E_NOSUPPORT;
			goto release_vdev_ref;
		}
	}

	/*
	 * a. Don't support bandwidth 80P80MHz.
	 * b. cac_duration_ms is 0 if start again after SAP/GO on DFS
	 *    channel and found radar.
	 * c. Don't enable DFS no wait if user required to ignore CAC.
	 */
	if (ch_width == CH_WIDTH_80P80MHZ ||
	    !cac_duration_ms || ignore_cac) {
		status = QDF_STATUS_E_NOSUPPORT;
		goto release_vdev_ref;
	}

	/* Don't support DFS channel */
	if (wlan_reg_is_dfs_for_freq(pdev, ch_freq)) {
		pre_cac_debug("dfs ch freq %d", ch_freq);
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	if (!wlan_dnw_find_downgrade_bw(pdev, ch_freq, ch_width,
					&dnw_pdev_info->dg_ch_width)) {
		pre_cac_debug("Failed to find downgrade bw");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	dnw_pdev_info->ori_ch_width = ch_width;
	dnw_pdev_info->ch_freq = ch_freq;
	dnw_pdev_info->cac_duration_ms = cac_duration_ms;
	dnw_pdev_info->dnw_in_progress = true;
	dnw_pdev_info->dnw_count = 1;
	dnw_pdev_info->pdev = pdev;
	dnw_pdev_info->request_handler = request_handler;
	wlan_dnw_set_state(dnw_pdev_info, DNW_STATE_INIT);

	dnw_vdev_info->dnw_in_progress = true;
	dnw_vdev_info->ctx = ctx;

	pre_cac_debug("Enable DNW for vdev %d freq %d ori bw %d dg bw %d",
		      vdev_id, dnw_pdev_info->ch_freq,
		      dnw_pdev_info->ori_ch_width,
		      dnw_pdev_info->dg_ch_width);

release_vdev_ref:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_PRE_CAC_ID);

	return status;
}

QDF_STATUS dnw_handle_bss_start(struct wlan_objmgr_pdev *pdev,
				uint8_t vdev_id, bool is_success)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_dnw_pdev_info *dnw_pdev_info;
	struct wlan_dnw_vdev_info *dnw_vdev_info;
	struct wlan_channel *chan;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!pdev) {
		pre_cac_err("null pdev");
		return QDF_STATUS_E_INVAL;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_PRE_CAC_ID);
	if (!vdev) {
		pre_cac_err("null vdev");
		return QDF_STATUS_E_FAILURE;
	}

	dnw_vdev_info = wlan_get_dnw_vdev_info(vdev);
	if (!dnw_vdev_info) {
		pre_cac_err("NULL dnw vdev info");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	if (!dnw_vdev_info->dnw_in_progress) {
		status = QDF_STATUS_E_FAILURE;
		goto release_vdev_ref;
	}

	dnw_pdev_info = wlan_get_dnw_pdev_info(pdev);
	if (!dnw_pdev_info) {
		pre_cac_err("NULL dnw pdev info");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	pre_cac_debug("start bss %s, dnw in progress, vdev %d",
		      is_success ? "success" : "fail", vdev_id);
	chan = wlan_vdev_get_active_channel(vdev);
	if (!chan) {
		pre_cac_debug("Couldn't get vdev active channel");
		status = QDF_STATUS_E_FAILURE;
		goto release_vdev_ref;
	}
	/*
	 * If ch width updated during starting BSS, stop DFS No Wait
	 */
	if (dnw_pdev_info->ori_ch_width != chan->ch_width) {
		pre_cac_debug("Updated BW %d -> %d",
			      dnw_pdev_info->ori_ch_width,
			      chan->ch_width);
		is_success = false;
	}
	if (is_success) {
		if (dnw_pdev_info->state == DNW_STATE_INIT) {
			start_dnw_timer(dnw_pdev_info);
			wlan_dnw_set_state(dnw_pdev_info, DNW_STATE_CAC);
		} else
			pre_cac_debug("dnw state %d vdev %d",
				      dnw_pdev_info->state, vdev_id);
	} else {
		wlan_dnw_reset(vdev, dnw_pdev_info, dnw_vdev_info);
		wlan_dnw_set_state(dnw_pdev_info, DNW_STATE_END);
	}

release_vdev_ref:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_PRE_CAC_ID);

	return status;
}

QDF_STATUS dnw_handle_radar_found(struct wlan_objmgr_pdev *pdev,
				  uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_dnw_pdev_info *dnw_pdev_info;
	struct wlan_dnw_vdev_info *dnw_vdev_info;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!pdev) {
		pre_cac_err("null pdev");
		return QDF_STATUS_E_INVAL;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_PRE_CAC_ID);
	if (!vdev) {
		pre_cac_err("null vdev");
		return QDF_STATUS_E_INVAL;
	}

	dnw_vdev_info = wlan_get_dnw_vdev_info(vdev);
	if (!dnw_vdev_info) {
		pre_cac_err("NULL dnw vdev info");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	if (!dnw_vdev_info->dnw_in_progress) {
		status = QDF_STATUS_E_FAILURE;
		goto release_vdev_ref;
	}

	dnw_pdev_info = wlan_get_dnw_pdev_info(pdev);
	if (!dnw_pdev_info) {
		pre_cac_err("NULL dnw pdev info");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	wlan_dnw_set_state(dnw_pdev_info, DNW_STATE_RADAR_FOUND);
	wlan_objmgr_pdev_iterate_obj_list(dnw_pdev_info->pdev, WLAN_VDEV_OP,
					  dnw_find_vdev_handler,
					  dnw_pdev_info, 0, WLAN_PRE_CAC_ID);

release_vdev_ref:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_PRE_CAC_ID);

	return status;
}

QDF_STATUS dnw_handle_bss_stop(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_dnw_pdev_info *dnw_pdev_info;
	struct wlan_dnw_vdev_info *dnw_vdev_info;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!pdev) {
		pre_cac_err("null pdev");
		return QDF_STATUS_E_INVAL;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_PRE_CAC_ID);
	if (!vdev) {
		pre_cac_err("null vdev");
		return QDF_STATUS_E_INVAL;
	}

	dnw_vdev_info = wlan_get_dnw_vdev_info(vdev);
	if (!dnw_vdev_info) {
		pre_cac_err("NULL dnw vdev info");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	if (!dnw_vdev_info->dnw_in_progress) {
		status = QDF_STATUS_E_FAILURE;
		goto release_vdev_ref;
	}
	dnw_pdev_info = wlan_get_dnw_pdev_info(pdev);
	if (!dnw_pdev_info) {
		pre_cac_err("NULL dnw pdev info");
		status = QDF_STATUS_E_INVAL;
		goto release_vdev_ref;
	}

	wlan_dnw_reset(vdev, dnw_pdev_info, dnw_vdev_info);
	wlan_dnw_set_state(dnw_pdev_info, DNW_STATE_END);
	pre_cac_debug("reset dnw since dnw in progress, vdev %d",
		      wlan_vdev_get_id(vdev));
release_vdev_ref:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_PRE_CAC_ID);

	return status;
}

enum phy_ch_width
dnw_update_bandwidth(struct wlan_objmgr_vdev *vdev,
		     enum phy_ch_width ch_width)
{
	struct wlan_dnw_pdev_info *dnw_pdev_info;
	struct wlan_dnw_vdev_info *dnw_vdev_info;
	enum phy_ch_width new_ch_width = ch_width;
	QDF_STATUS status;

	if (!vdev)
		return ch_width;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_PRE_CAC_ID);
	if (QDF_IS_STATUS_ERROR(status))
		return ch_width;

	dnw_vdev_info = wlan_get_dnw_vdev_info(vdev);
	if (!dnw_vdev_info)
		goto release_vdev_ref;

	dnw_pdev_info = wlan_get_dnw_pdev_info_by_vdev(vdev);
	if (!dnw_pdev_info)
		goto release_vdev_ref;

	if (!dnw_pdev_info->dnw_in_progress)
		goto release_vdev_ref;

	if (!dnw_vdev_info->dnw_in_progress)
		goto release_vdev_ref;

	if (dnw_pdev_info->ori_ch_width != ch_width)
		goto release_vdev_ref;

	if (dnw_pdev_info->state == DNW_STATE_CAC ||
	    dnw_pdev_info->state == DNW_STATE_RADAR_FOUND)
		new_ch_width = dnw_pdev_info->dg_ch_width;

release_vdev_ref:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_PRE_CAC_ID);

	return new_ch_width;
}

QDF_STATUS set_dfs_no_wait_support(struct wlan_objmgr_pdev *pdev, bool enable)
{
	struct pre_cac_pdev_priv *pdev_priv;
	QDF_STATUS status;

	if (!pdev) {
		pre_cac_err("NULL pdev");
		return QDF_STATUS_E_INVAL;
	}

	status = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_PRE_CAC_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		pre_cac_err("pdev get ref fail");
		return QDF_STATUS_E_FAILURE;
	}
	pdev_priv = wlan_objmgr_pdev_get_comp_private_obj(
				pdev, WLAN_UMAC_COMP_PRE_CAC);
	if (!pdev_priv) {
		pre_cac_err("NULL pre cac pdev priv");
		wlan_objmgr_pdev_release_ref(pdev, WLAN_PRE_CAC_ID);
		return QDF_STATUS_E_INVAL;
	}

	pre_cac_debug("dnw enabled %d->%d", pdev_priv->dnw_pdev_info.enabled,
		      enable);
	pdev_priv->dnw_pdev_info.enabled = enable;
	wlan_objmgr_pdev_release_ref(pdev, WLAN_PRE_CAC_ID);

	return QDF_STATUS_SUCCESS;
}
