/*
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: contains MLO manager operation functionality
 */
#include <wlan_cmn.h>
#include <wlan_cm_public_struct.h>
#include "wlan_mlo_mgr_cmn.h"
#include "wlan_mlo_mgr_main.h"
#include "wlan_mlo_mgr_public_structs.h"
#include "wlan_mlo_mgr_op.h"
#include "wlan_mlo_mgr_sta.h"

#ifdef WLAN_FEATURE_11BE_MLO
QDF_STATUS wlan_mlo_set_cu_bpcc(struct wlan_objmgr_vdev *vdev,
				uint8_t link_id, uint8_t bpcc)
{
	if (!vdev) {
		mlo_debug("vdev is NULL");
		return QDF_STATUS_E_INVAL;
	}

	return mlo_set_cu_bpcc(vdev, link_id, bpcc);
}

QDF_STATUS wlan_mlo_get_cu_bpcc(struct wlan_objmgr_vdev *vdev,
				uint8_t link_id, uint8_t *bpcc)
{
	if (!vdev || !bpcc) {
		mlo_debug("vdev or bpcc is NULL");
		return QDF_STATUS_E_INVAL;
	}

	return mlo_get_cu_bpcc(vdev, link_id, bpcc);
}
#endif
