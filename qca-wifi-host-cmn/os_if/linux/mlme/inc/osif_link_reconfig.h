/*
 * Copyright (c) 2025 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: osif_link_reconfig.h
 *
 * This header file maintains declarations of link reconfig request/response
 * common apis.
 */

#ifndef __OSIF_LINK_RECONFIG_UTIL_H
#define __OSIF_LINK_RECONFIG_UTIL_H

#include <qca_vendor.h>
#include "wlan_cm_ucfg_api.h"
#include "wlan_cm_public_struct.h"

#if defined(WLAN_FEATURE_11BE_MLO) && \
defined(CFG80211_SETUP_LINK_RECONFIG_SUPPORT)
/**
 * osif_get_net_dev_from_vdev() - Get netdev object from vdev
 * @vdev: Pointer to vdev manager
 * @out_net_dev: Pointer to output netdev
 *
 * This API gets net dev from vdev
 *
 * Return: 0 on success, error code on failure
 */
int osif_get_net_dev_from_vdev(struct wlan_objmgr_vdev *vdev,
			       struct net_device **out_net_dev);

/**
 * osif_free_link_reconfig_done_data() - free link recfg done ctx struct
 * @ctx: link recfg done ctx
 *
 * Return : void
 */
void osif_free_link_reconfig_done_data(void *ctx);

/**
 * osif_populate_link_recfg_done_data() - create recfg done ctx struct
 * @vdev: vdev object
 *
 * Return : link recfg done ctx data
 */
void *
osif_populate_link_recfg_done_data(struct wlan_objmgr_vdev *vdev);

/**
 * osif_link_reconfig_status_cb() - Callback to set add link or delete link info
 * @ctx: link recfg done ctx struct
 *
 * This API sends response of link reconfig request to kernel
 *
 * Return: qdf_status
 */
QDF_STATUS
osif_link_reconfig_status_cb(void *ctx);
#else
static inline void osif_free_link_reconfig_done_data(void *ctx)
{
}

static inline void *
osif_populate_link_recfg_done_data(struct wlan_objmgr_vdev *vdev)
{
	return NULL;
}

static inline QDF_STATUS
osif_link_reconfig_status_cb(void *ctx)
{
	return QDF_STATUS_SUCCESS;
}
#endif

#ifdef WLAN_FEATURE_MLO_SAP_LINK_REMOVAL
/**
 * osif_mlo_sap_link_removal_evt_handler() - Handler for MLO link removal event
 *
 * @vdev: Object manager vdev
 * @tbtt_count: tbtt count report from target
 * @tsf: TSF of the reported beacon
 * @link_id: link id of the link going for removal
 *
 * Return: QDF_STATUS of operation
 */
QDF_STATUS osif_mlo_sap_link_removal_evt_handler(struct wlan_objmgr_vdev *vdev,
						 uint32_t tbtt_count,
						 uint64_t tsf,
						 uint16_t link_id);
#else
static inline
QDF_STATUS osif_mlo_sap_link_removal_evt_handler(struct wlan_objmgr_vdev *vdev,
						 uint32_t tbtt_count,
						 uint64_t tsf,
						 uint16_t link_id)
{
	return QDF_STATUS_E_NOSUPPORT;
}

#endif
#endif

