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
 * DOC : contains interface prototypes for spatial_reuse api
 */

#include <spatial_reuse_api.h>

QDF_STATUS wlan_spatial_reuse_config_set(struct wlan_objmgr_vdev *vdev,
					 uint8_t sr_ctrl,
					 uint8_t non_srg_max_pd_offset)
{
	struct wlan_lmac_if_tx_ops *tx_ops;
	struct wlan_objmgr_psoc *psoc = wlan_vdev_get_psoc(vdev);

	if (!psoc)
		return QDF_STATUS_E_NULL_VALUE;

	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	if (!tx_ops)
		return QDF_STATUS_E_NULL_VALUE;

	if (tx_ops->spatial_reuse_tx_ops.send_cfg)
		return tx_ops->spatial_reuse_tx_ops.send_cfg(vdev, sr_ctrl,
							non_srg_max_pd_offset);

	return QDF_STATUS_E_NULL_VALUE;
}
