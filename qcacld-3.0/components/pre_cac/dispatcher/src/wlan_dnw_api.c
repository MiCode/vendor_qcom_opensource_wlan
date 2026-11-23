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
 * DOC: Public API implementation of DFS No Wait
 */

#include "wlan_dfs_no_wait.h"
#include "wlan_dnw_api.h"

bool wlan_is_dnw_in_progress(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	return is_dnw_in_progress(pdev, vdev_id);
}

bool wlan_is_valid_dnw(struct wlan_objmgr_pdev *pdev, uint32_t ch_freq,
		       enum phy_ch_width old_ch_width,
		       enum phy_ch_width new_ch_width)
{
	return is_valid_dnw(pdev, ch_freq, old_ch_width, new_ch_width);
}

QDF_STATUS
wlan_dnw_set_info(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id,
		  uint32_t chan_freq, uint8_t ch_width,
		  uint32_t cac_duration, bool ignore_cac,
		  dnw_request_handler request_handler, void *ctx)
{
	return dnw_set_info(pdev, vdev_id, chan_freq, ch_width, cac_duration,
			    ignore_cac, request_handler, ctx);
}

QDF_STATUS wlan_dnw_handle_bss_start(struct wlan_objmgr_pdev *pdev,
				     uint8_t vdev_id, bool is_success)
{
	return dnw_handle_bss_start(pdev, vdev_id, is_success);
}

QDF_STATUS wlan_dnw_handle_radar_found(struct wlan_objmgr_pdev *pdev,
				       uint8_t vdev_id)
{
	return dnw_handle_radar_found(pdev, vdev_id);
}

QDF_STATUS wlan_dnw_handle_bss_stop(struct wlan_objmgr_pdev *pdev,
				    uint8_t vdev_id)
{
	return dnw_handle_bss_stop(pdev, vdev_id);
}

enum phy_ch_width
wlan_dnw_update_bandwidth(struct wlan_objmgr_vdev *vdev,
			  enum phy_ch_width ch_width)
{
	return dnw_update_bandwidth(vdev, ch_width);
}
