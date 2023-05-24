/*
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC : contains interface prototypes for OS_IF layer
 */

#include <qdf_trace.h>
#include <spatial_reuse_ucfg_api.h>
#include <spatial_reuse_api.h>

void ucfg_spatial_reuse_get_sr_config(struct wlan_objmgr_vdev *vdev,
				      uint8_t *sr_ctrl,
				      uint8_t *non_srg_max_pd_offset,
				      bool *he_spr_enabled)
{
	*sr_ctrl = wlan_vdev_mlme_get_sr_ctrl(vdev);
	*non_srg_max_pd_offset = wlan_vdev_mlme_get_pd_offset(vdev);
	*he_spr_enabled = wlan_vdev_mlme_get_he_spr_enabled(vdev);
}

void ucfg_spatial_reuse_set_sr_config(struct wlan_objmgr_vdev *vdev,
				      uint8_t sr_ctrl,
				      uint8_t non_srg_max_pd_offset)
{
	wlan_vdev_mlme_set_sr_ctrl(vdev, sr_ctrl);
	wlan_vdev_mlme_set_pd_offset(vdev, non_srg_max_pd_offset);
}

void ucfg_spatial_reuse_send_sr_config(struct wlan_objmgr_vdev *vdev,
				       bool enable)
{
	uint8_t sr_ctrl = 0;
	uint8_t non_srg_max_pd_offset = 0;

	if (enable && (!wlan_vdev_mlme_get_he_spr_enabled(vdev))) {
		sr_ctrl = wlan_vdev_mlme_get_sr_ctrl(vdev);
		non_srg_max_pd_offset = wlan_vdev_mlme_get_pd_offset(vdev);
		if (sr_ctrl && non_srg_max_pd_offset) {
			wlan_spatial_reuse_config_set(vdev, sr_ctrl,
						      non_srg_max_pd_offset);
			wlan_vdev_mlme_set_he_spr_enabled(vdev, true);
		}
	} else if (!enable && wlan_vdev_mlme_get_he_spr_enabled(vdev)) {
		wlan_spatial_reuse_config_set(vdev, sr_ctrl,
					      non_srg_max_pd_offset);
		wlan_vdev_mlme_set_he_spr_enabled(vdev, false);
	}
}
