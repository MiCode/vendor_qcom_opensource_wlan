/* Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: contains MLO manager ap related functionality
 */
#include "wlan_mlo_mgr_cmn.h"
#include "wlan_mlo_mgr_main.h"
#ifdef WLAN_MLO_MULTI_CHIP
#include "wlan_lmac_if_def.h"
#include <cdp_txrx_mlo.h>
#endif

#ifdef WLAN_MLO_MULTI_CHIP
void mlo_setup_update_total_socs(uint8_t tot_socs)
{
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();

	if (!mlo_ctx)
		return;

	mlo_ctx->setup_info.tot_socs = tot_socs;
}

qdf_export_symbol(mlo_setup_update_total_socs);

void mlo_setup_update_num_links(struct wlan_objmgr_psoc *psoc,
				uint8_t num_links)
{
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();

	if (!mlo_ctx)
		return;

	mlo_ctx->setup_info.tot_links += num_links;
}

qdf_export_symbol(mlo_setup_update_num_links);

void mlo_setup_update_soc_ready(struct wlan_objmgr_psoc *psoc)
{
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();
	uint8_t chip_idx;

	if (!mlo_ctx || !mlo_ctx->setup_info.tot_socs)
		return;

	chip_idx = mlo_ctx->setup_info.num_soc;
	qdf_assert_always(chip_idx < MAX_MLO_CHIPS);
	mlo_ctx->setup_info.soc_list[chip_idx] = psoc;
	mlo_ctx->setup_info.num_soc++;

	if (mlo_ctx->setup_info.num_soc != mlo_ctx->setup_info.tot_socs)
		return;

	for (chip_idx = 0; chip_idx < mlo_ctx->setup_info.num_soc;
			chip_idx++) {
		struct wlan_objmgr_psoc *tmp_soc =
			mlo_ctx->setup_info.soc_list[chip_idx];

		cdp_soc_mlo_soc_setup(wlan_psoc_get_dp_handle(tmp_soc),
				      mlo_ctx->dp_handle);
	}

	cdp_mlo_setup_complete(wlan_psoc_get_dp_handle(psoc),
			       mlo_ctx->dp_handle);
}

qdf_export_symbol(mlo_setup_update_soc_ready);

void mlo_setup_link_ready(struct wlan_objmgr_pdev *pdev)
{
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();
	uint8_t link_idx;

	if (!mlo_ctx || !mlo_ctx->setup_info.tot_links)
		return;

	link_idx = mlo_ctx->setup_info.num_links;
	/* TODO: Get reference to PDEV */
	qdf_assert_always(link_idx < MAX_MLO_LINKS);
	mlo_ctx->setup_info.pdev_list[link_idx] = pdev;
	mlo_ctx->setup_info.state[link_idx] = MLO_LINK_SETUP_INIT;
	mlo_ctx->setup_info.num_links++;

	if (mlo_ctx->setup_info.num_links == mlo_ctx->setup_info.tot_links &&
	    mlo_ctx->setup_info.num_soc == mlo_ctx->setup_info.tot_socs) {
		struct wlan_objmgr_psoc *psoc;
		struct wlan_lmac_if_tx_ops *tx_ops;

		psoc = wlan_pdev_get_psoc(pdev);
		tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
		/* Trigger MLO setup */
		if (tx_ops && tx_ops->mops.target_if_mlo_setup_req) {
			tx_ops->mops.target_if_mlo_setup_req(
					mlo_ctx->setup_info.pdev_list,
					mlo_ctx->setup_info.num_links,
					mlo_ctx->setup_info.ml_grp_id);
		}
	}
}

qdf_export_symbol(mlo_setup_link_ready);

void mlo_link_setup_complete(struct wlan_objmgr_pdev *pdev)
{
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();
	uint8_t link_idx;

	if (!mlo_ctx)
		return;

	for (link_idx = 0; link_idx < mlo_ctx->setup_info.tot_links; link_idx++)
		if (mlo_ctx->setup_info.pdev_list[link_idx] == pdev) {
			mlo_ctx->setup_info.state[link_idx] =
							MLO_LINK_SETUP_DONE;
			break;
		}

	for (link_idx = 0; link_idx < mlo_ctx->setup_info.tot_links; link_idx++)
		if (mlo_ctx->setup_info.state[link_idx] == MLO_LINK_SETUP_DONE)
			continue;
		else
			break;

	if (link_idx == mlo_ctx->setup_info.tot_links) {
		struct wlan_objmgr_psoc *psoc;
		struct wlan_lmac_if_tx_ops *tx_ops;

		psoc = wlan_pdev_get_psoc(pdev);
		tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
		/* Trigger MLO ready */
		if (tx_ops && tx_ops->mops.target_if_mlo_ready) {
			tx_ops->mops.target_if_mlo_ready(
					mlo_ctx->setup_info.pdev_list,
					mlo_ctx->setup_info.num_links);
		}
	}
}

qdf_export_symbol(mlo_link_setup_complete);

static QDF_STATUS mlo_find_pdev_idx(struct wlan_objmgr_pdev *pdev,
				    uint8_t *link_idx)
{
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();
	uint8_t idx;

	if (!mlo_ctx)
		return QDF_STATUS_E_FAILURE;

	if (!link_idx)
		return QDF_STATUS_E_FAILURE;

	for (idx = 0; idx < mlo_ctx->setup_info.tot_links; idx++) {
		if (mlo_ctx->setup_info.pdev_list[idx] == pdev) {
			*link_idx = idx;
			return QDF_STATUS_SUCCESS;
		}
	}

	return QDF_STATUS_E_FAILURE;
}

void mlo_link_teardown_complete(struct wlan_objmgr_pdev *pdev)
{
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();
	uint8_t link_idx;

	if (!mlo_ctx)
		return;

	if (!mlo_ctx->setup_info.num_links) {
		qdf_err("Delayed response ignore");
		return;
	}

	if (mlo_find_pdev_idx(pdev, &link_idx) != QDF_STATUS_SUCCESS) {
		qdf_info("Failed to find pdev");
		return;
	}

	qdf_debug("link idx = %d", link_idx);
	mlo_ctx->setup_info.pdev_list[link_idx] = NULL;
	mlo_ctx->setup_info.state[link_idx] = MLO_LINK_TEARDOWN;
	mlo_ctx->setup_info.num_links--;

	if (!mlo_ctx->setup_info.num_links) {
		qdf_info("Teardown complete");
		qdf_event_set(&mlo_ctx->setup_info.event);
	}
}

qdf_export_symbol(mlo_link_teardown_complete);

#define MLO_MGR_TEARDOWN_TIMEOUT 3000
QDF_STATUS mlo_link_teardown_link(struct wlan_objmgr_psoc *psoc,
				  uint32_t reason)
{
	struct wlan_lmac_if_tx_ops *tx_ops;
	QDF_STATUS status;
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();

	qdf_debug(" %d %d ",
		  mlo_ctx->setup_info.num_soc,
		  mlo_ctx->setup_info.num_links);

	if (!mlo_ctx)
		return QDF_STATUS_E_FAILURE;

	if (!mlo_ctx->setup_info.num_soc)
		return QDF_STATUS_SUCCESS;

	if (!mlo_ctx->setup_info.num_links) {
		mlo_ctx->setup_info.num_soc--;
		return QDF_STATUS_SUCCESS;
	}

	if (qdf_event_create(&mlo_ctx->setup_info.event) != QDF_STATUS_SUCCESS)
		return QDF_STATUS_E_FAULT;

	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	/* Trigger MLO teardown */
	if (tx_ops && tx_ops->mops.target_if_mlo_teardown_req) {
		tx_ops->mops.target_if_mlo_teardown_req(
				mlo_ctx->setup_info.pdev_list,
				mlo_ctx->setup_info.num_links,
				reason);
	}

	status = qdf_wait_for_event_completion(&mlo_ctx->setup_info.event,
					       MLO_MGR_TEARDOWN_TIMEOUT);
	if (status != QDF_STATUS_SUCCESS) {
		qdf_info("Teardown timeout");
		mlo_ctx->setup_info.num_links = 0;
	}

	qdf_event_destroy(&mlo_ctx->setup_info.event);

	mlo_ctx->setup_info.num_soc--;

	return status;
}

qdf_export_symbol(mlo_link_teardown_link);
#endif /*WLAN_MLO_MULTI_CHIP*/
