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

#ifndef _SPATIAL_REUSE_API_H_
#define _SPATIAL_REUSE_API_H_

#include <qdf_types.h>
#include <qdf_trace.h>
#include <wlan_objmgr_vdev_obj.h>

/**
 * wlan_spatial_reuse_config_set() - Set spatial reuse config
 * @vdev: objmgr manager vdev
 * @sr_ctrl: spatial reuse control
 * @non_srg_max_pd_offset: non-srg max pd offset
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wlan_spatial_reuse_config_set(struct wlan_objmgr_vdev *vdev,
					 uint8_t sr_ctrl,
					 uint8_t non_srg_max_pd_offset);

#endif
