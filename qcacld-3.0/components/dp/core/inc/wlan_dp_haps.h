/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef _WLAN_DP_HAPS_H_
#define _WLAN_DP_HAPS_H_

#include "wlan_dp_priv.h"

#ifdef WLAN_HAPS_ENABLE

#define HAPS_TRY_AGAIN_TIME_NS 200000
#define HAPS_MAX_PAUSE_TIME_MS 200
#define QTIME_SYNC_PERIOD      3000
#define US_TO_MS(_var)         ((_var) / 1000)

#define HAPS_ENABLE_M	       0x1
#define IS_HAPS_ENABLE(_var)   ((_var) & HAPS_ENABLE_M)

#define HAPS_START_SYNC_M      0x00000002
#define HAPS_START_SYNC_S      1
#define IS_TIME_SYNC_REQUIRED(_var) (((_var) & HAPS_START_SYNC_M) >> \
					HAPS_START_SYNC_S)

void dp_vdev_haps_attach(struct cdp_soc *psoc, struct wlan_dp_intf *dp_intf,
			 uint8_t vdev_id);

void dp_vdev_haps_detach(struct wlan_dp_intf *dp_intf);

void dp_haps_init(struct wlan_objmgr_psoc *psoc);

QDF_STATUS dp_print_haps_stats(struct wlan_objmgr_psoc *psoc);

void dp_clear_haps_stats(struct wlan_objmgr_psoc *psoc);

static inline void dp_haps_kill_timer(qdf_hrtimer_data_t *timer)
{
	if (qdf_hrtimer_is_queued(timer) &&
	    !qdf_hrtimer_callback_running(timer))
		qdf_hrtimer_kill(timer);
}

static inline void dp_haps_start_timer(qdf_hrtimer_data_t *timer,
				       qdf_ktime_t ktime)
{
	qdf_hrtimer_start(timer, ktime, QDF_HRTIMER_MODE_REL);
}

static inline
struct dp_haps *dp_get_haps_ctx_from_vdev(ol_osif_vdev_handle osif_vdev)
{
	struct wlan_dp_link *dp_link = (struct wlan_dp_link *)osif_vdev;
	struct wlan_dp_intf *dp_intf = NULL;

	if (dp_link) {
		dp_intf = dp_link->dp_intf;
		return &dp_intf->haps_ctx;
	} else {
		return NULL;
	}
}

/**
 * dp_is_haps_enabled() - Check if haps is enabled from INI
 * @osif_vdev: Handle to the OS shim SW's virtual device
 *
 * Returns: True/False
 */
static inline bool dp_is_haps_enabled(ol_osif_vdev_handle osif_vdev)
{
	struct dp_haps *haps_ctx = dp_get_haps_ctx_from_vdev(osif_vdev);

	if (haps_ctx)
		return haps_ctx->is_enable;
	else
		return false;
}

/**
 * dp_is_haps_paused() - Check if vdev is in pause state
 * @soc: Datapath global soc handle
 * @osif_vdev: Handle to the OS shim SW's virtual device
 *
 * Returns: True/False
 */
static inline
bool dp_is_haps_paused(struct dp_soc *soc, ol_osif_vdev_handle osif_vdev)
{
	struct dp_haps *haps_ctx = dp_get_haps_ctx_from_vdev(osif_vdev);

	if (!haps_ctx || !haps_ctx->is_enable)
		return false;

	if (haps_ctx->state == STATE_PAUSE)
		return true;
	else
		return false;
}
#else
static inline
void dp_vdev_haps_attach(struct cdp_soc *psoc, struct wlan_dp_intf *dp_intf,
			 uint8_t vdev_id)
{
}

static inline void dp_vdev_haps_detach(struct wlan_dp_intf *dp_intf)
{
}

static inline void dp_haps_init(struct wlan_objmgr_psoc *psoc)
{
}

static inline QDF_STATUS dp_print_haps_stats(struct wlan_objmgr_psoc *psoc)
{
	return QDF_STATUS_SUCCESS;
}

static inline void dp_clear_haps_stats(struct wlan_objmgr_psoc *psoc)
{
}
#endif
#endif
