/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <dp_types.h>
#include <wlan_cfg.h>
#include <qdf_time.h>
#include <qdf_util.h>
#include <qdf_status.h>
#include <qdf_hrtimer.h>
#include <wlan_dp_main.h>
#include "dp_tx.h"
#include "wlan_dp_haps.h"

static void dp_haps_stats_update(struct dp_haps *haps_ctx,
				 enum cdp_haps_state curr_state,
				 enum cdp_haps_state new_state)
{
	struct dp_haps_stats *stats = &haps_ctx->stats;
	qdf_time_t delta = 0;
	qdf_time_t curr_time_ms = US_TO_MS(qdf_get_log_timestamp_usecs());

	if (curr_state == STATE_UNPAUSE && new_state == STATE_PAUSE) {
		stats->last_time = curr_time_ms;
	} else if (curr_state == STATE_PAUSE && new_state == STATE_UNPAUSE) {
		delta = curr_time_ms - stats->last_time;
		stats->total_pause_time += delta;

		if (delta < 20)
			stats->haps_pause_bucket[HAPS_BUCKET_20_MS]++;
		else if (delta < 40)
			stats->haps_pause_bucket[HAPS_BUCKET_40_MS]++;
		else if (delta < 60)
			stats->haps_pause_bucket[HAPS_BUCKET_60_MS]++;
		else if (delta < 80)
			stats->haps_pause_bucket[HAPS_BUCKET_80_MS]++;
		else if (delta < 100)
			stats->haps_pause_bucket[HAPS_BUCKET_100_MS]++;
		else if (delta < 120)
			stats->haps_pause_bucket[HAPS_BUCKET_120_MS]++;
		else if (delta < 140)
			stats->haps_pause_bucket[HAPS_BUCKET_140_MS]++;
		else
			stats->haps_pause_bucket[HAPS_BUCKET_BEYOND]++;
	}
}

/**
 * dp_haps_update_state() - Update haps state
 * @haps_ctx: haps_ctx pointer
 * @new_state: New haps state
 * @timeout: Timer timeout value
 * @is_one_shot: If one shot operation is required
 * @is_direct_reg_write: To decide whether delayed reg write or direct reg
 *			 is required
 *
 * Returns: none
 */
static inline
void dp_haps_update_state(struct dp_haps *haps_ctx,
			  enum cdp_haps_state new_state, qdf_ktime_t timeout,
			  bool is_one_shot, bool is_direct_reg_write)
{
	QDF_STATUS ret;
	qdf_ktime_t retry_timeout;
	enum cdp_haps_state curr_state = haps_ctx->state;

	dp_debug("HAPS: vdev_id:(%u) curr state:(%u) -> new state:(%u),"
		 "is one shot:(%u) timeout:(%lld ns) is_direct_reg_write:(%u)",
		  haps_ctx->vdev_id, curr_state, new_state, is_one_shot,
		  timeout, is_direct_reg_write);

	switch (new_state) {
	case STATE_PAUSE:
		haps_ctx->state = STATE_PAUSE;

		if (timeout) {
			dp_haps_start_timer(&haps_ctx->haps_timer, timeout);
			haps_ctx->is_one_shot = is_one_shot;
		} else {
			haps_ctx->is_one_shot = false;
		}

		if (!qdf_hrtimer_is_queued(&haps_ctx->haps_fail_safe_timer) &&
		    !qdf_hrtimer_callback_running(&haps_ctx->haps_fail_safe_timer))
			dp_haps_start_timer(&haps_ctx->haps_fail_safe_timer,
				qdf_time_ms_to_ktime(HAPS_MAX_PAUSE_TIME_MS));

		dp_haps_stats_update(haps_ctx, curr_state, new_state);
		break;

	case STATE_UNPAUSE:
		dp_haps_kill_timer(&haps_ctx->haps_timer);
		dp_haps_kill_timer(&haps_ctx->haps_fail_safe_timer);

		ret = dp_try_hp_update(haps_ctx, is_direct_reg_write);
		if (ret == QDF_STATUS_E_TIMEOUT) {
			retry_timeout = qdf_time_ns_to_ktime(HAPS_TRY_AGAIN_TIME_NS);
			qdf_hrtimer_start(&haps_ctx->haps_timer,
					  qdf_ktime_get(), retry_timeout);
			break;
		}

		dp_haps_stats_update(haps_ctx, curr_state, new_state);

		if (is_one_shot && (curr_state == STATE_PAUSE)) {
			haps_ctx->is_one_shot = false;
			dp_haps_start_timer(&haps_ctx->haps_fail_safe_timer,
				qdf_time_ms_to_ktime(HAPS_MAX_PAUSE_TIME_MS));
			/* In the event of a one-shot upause record the
			 * last_time since the state change will not take place,
			 * and only a single unpause will occur from the host.
			 */
			dp_haps_stats_update(haps_ctx, STATE_UNPAUSE,
					     STATE_PAUSE);
		} else {
			haps_ctx->is_one_shot = false;
			haps_ctx->state = STATE_UNPAUSE;
		}

		break;

	default:
		dp_err("HAPS: Unknown state received for vdev:%u",
		       haps_ctx->vdev_id);
		break;
	}
}

/**
 * dp_haps_handle_ind() - Handle haps message indication
 * @osif_vdev: Handle to the OS shim SW's virtual device
 * @new_state: New haps state
 * @time_rcvd: Timeout value
 * @is_one_shot: If one shot operation is required
 * @is_direct_reg_write: To decide whether delayed reg write or direct reg
 *			 is required
 *
 * Returns: none
 */
static void
dp_haps_handle_ind(ol_osif_vdev_handle osif_vdev, enum cdp_haps_state new_state,
		   qdf_ktime_t time_rcvd, bool is_one_shot,
		   bool is_direct_reg_write)
{
	struct dp_haps *haps_ctx = dp_get_haps_ctx_from_vdev(osif_vdev);
	uint64_t curr_time_us = qdf_get_log_timestamp_usecs();
	uint64_t delta_us = 0;
	qdf_time_t timeout;

	if (!haps_ctx) {
		dp_err("HAPS: Null haps_ctx rcvd");
		return;
	}

	if (!dp_is_haps_enabled(osif_vdev)) {
		dp_err("HAPS: Not enabled");
		return;
	}

	haps_ctx->stats.event_received++;

	if (new_state == STATE_UNPAUSE) {
		haps_ctx->stats.unpause_ind++;
	} else {
		if (is_one_shot)
			haps_ctx->stats.oneshot_pause_ind++;
		else
			haps_ctx->stats.pause_ind++;
	}

	if ((time_rcvd != 0) && (time_rcvd < curr_time_us)) {
		dp_err("HAPS: Host time:(%llu us) is less than device time:"
		       "(%lld us) for vdev:%u", curr_time_us, time_rcvd,
			haps_ctx->vdev_id);
		return;
	}

	if (time_rcvd) {
		delta_us = time_rcvd - curr_time_us;
		timeout = qdf_time_ns_to_ktime(delta_us * 1000);

		if (timeout >= qdf_time_ms_to_ktime(HAPS_MAX_PAUSE_TIME_MS)) {
			dp_err("HAPS: invalid timeout (%lu ns) received for vdev:%u",
				timeout, haps_ctx->vdev_id);
			return;
		}
	} else {
		timeout = 0;
	}

	dp_haps_update_state(haps_ctx, new_state, timeout, is_one_shot,
			     is_direct_reg_write);
}

/**
 * dp_haps_timer_handler() - HAPS timer interrupt handler
 * @arg: Private data of the timer
 *
 * Returns: Timer restart status
 */
static enum qdf_hrtimer_restart_status
dp_haps_timer_handler(qdf_hrtimer_data_t *arg)
{
	struct dp_haps *haps_ctx;

	haps_ctx = qdf_container_of(arg, struct dp_haps,
				    haps_timer);

	dp_haps_update_state(haps_ctx, STATE_UNPAUSE, 0,
			     haps_ctx->is_one_shot, true);

	haps_ctx->stats.haps_timer_expired++;

	return QDF_HRTIMER_NORESTART;
}

/**
 * dp_haps_fail_safe_timer_handler() - HAPS fail safe timer interrupt handler
 * @arg: Private data of the timer
 *
 * Returns: Timer restart status
 */
static enum qdf_hrtimer_restart_status
dp_haps_fail_safe_timer_handler(qdf_hrtimer_data_t *arg)
{
	struct dp_haps *haps_ctx;

	haps_ctx = qdf_container_of(arg, struct dp_haps,
				    haps_fail_safe_timer);

	dp_haps_update_state(haps_ctx, STATE_UNPAUSE, 0, false, false);

	haps_ctx->stats.fail_safe_timer_expired++;

	dp_debug("HAPS: Fail safe timer expired for vdev:%u",
		 haps_ctx->vdev_id);

	return QDF_HRTIMER_NORESTART;
}

/**
 * dp_print_haps_stats() - Display HAPS stats
 * @psoc: pointer to psoc object
 *
 * Returns: QDF_STATUS
 */
QDF_STATUS dp_print_haps_stats(struct wlan_objmgr_psoc *psoc)
{
	struct dp_haps *haps_ctx;
	struct dp_haps_stats *stats;
	uint32_t *hist;
	qdf_time_t curr_time_ms, total_time;
	struct wlan_dp_intf *dp_intf = NULL, *dp_intf_next = NULL;
	struct wlan_dp_psoc_context *dp_ctx = dp_psoc_get_priv(psoc);

	dp_for_each_intf_held_safe(dp_ctx, dp_intf, dp_intf_next) {
		if (!dp_intf)
			continue;

		haps_ctx = &dp_intf->haps_ctx;
		stats = &haps_ctx->stats;

		if (!haps_ctx->is_enable || !stats->event_received)
			continue;

		hist = haps_ctx->stats.haps_pause_bucket;
		curr_time_ms = US_TO_MS(qdf_get_log_timestamp_usecs());
		total_time = curr_time_ms - stats->start_time;

		if (haps_ctx->state == STATE_PAUSE)
			stats->total_pause_time += curr_time_ms -
							stats->last_time;

		dp_info("*** HAPS vdev:%u stats ***", haps_ctx->vdev_id);
		dp_info("Total HAPS events received: %u",
			stats->event_received);
		dp_info("Pause ind: %u", stats->pause_ind);
		dp_info("One Shot ind: %u", stats->oneshot_pause_ind);
		dp_info("Unpause ind: %u", stats->unpause_ind);
		dp_info("HAPS timer expired: %u", stats->haps_timer_expired);
		dp_info("Fail safe timer expired: %u",
			stats->fail_safe_timer_expired);
		dp_info("Total time/Pause time: %zu/%zu", total_time,
			stats->total_pause_time);
		dp_info("Pause bucket: 0-20[%u] 20-40[%u] 40-60[%u] 60-80[%u] "
			"80-100[%u] 100-120[%u] 120-140[%u] 140+[%u]",
			hist[HAPS_BUCKET_20_MS], hist[HAPS_BUCKET_40_MS],
			hist[HAPS_BUCKET_60_MS], hist[HAPS_BUCKET_80_MS],
			hist[HAPS_BUCKET_100_MS], hist[HAPS_BUCKET_120_MS],
			hist[HAPS_BUCKET_140_MS], hist[HAPS_BUCKET_BEYOND]);
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * dp_clear_haps_stats() - Clear HAPS stats
 * @psoc: pointer to psoc object
 *
 * Returns: None
 */
void dp_clear_haps_stats(struct wlan_objmgr_psoc *psoc)
{
	struct dp_haps *haps_ctx;
	struct wlan_dp_intf *dp_intf = NULL, *dp_intf_next = NULL;
	struct wlan_dp_psoc_context *dp_ctx = dp_psoc_get_priv(psoc);

	dp_for_each_intf_held_safe(dp_ctx, dp_intf, dp_intf_next) {
		if (!dp_intf)
			continue;

		haps_ctx = &dp_intf->haps_ctx;

		qdf_mem_set(&haps_ctx->stats, 0, sizeof(struct dp_haps_stats));
		haps_ctx->stats.start_time =
				US_TO_MS(qdf_get_log_timestamp_usecs());
	}
}

static struct cdp_haps_ops dp_ops_haps = {
	.haps_handle_ind = dp_haps_handle_ind,
};

/**
 * dp_vdev_haps_attach() - Attach the HAPS
 * @psoc: Datapath global soc handle
 * @dp_intf: wlan dp interface
 * @vdev_id: DP vdev id
 *
 * Returns: None
 */
void dp_vdev_haps_attach(struct cdp_soc *psoc, struct wlan_dp_intf *dp_intf,
			 uint8_t vdev_id)
{
	struct dp_haps *haps_ctx = &dp_intf->haps_ctx;
	struct dp_soc *soc = (struct dp_soc *)psoc;
	struct wlan_dp_psoc_context *dp_ctx = dp_intf->dp_ctx;
	uint32_t haps_config = dp_ctx->dp_cfg.haps_config;

	haps_ctx->is_enable = IS_HAPS_ENABLE(haps_config);

	if (!haps_ctx->is_enable)
		return;

	haps_ctx->is_one_shot = false;
	haps_ctx->state = STATE_UNPAUSE;
	haps_ctx->soc = soc;
	haps_ctx->vdev_id = vdev_id;

	qdf_mem_set(&haps_ctx->stats, 0, sizeof(struct dp_haps_stats));
	haps_ctx->stats.start_time = US_TO_MS(qdf_get_log_timestamp_usecs());

	qdf_hrtimer_init(&haps_ctx->haps_timer,
			 dp_haps_timer_handler,
			 QDF_CLOCK_MONOTONIC,
			 QDF_HRTIMER_MODE_REL,
			 QDF_CONTEXT_TASKLET);

	qdf_hrtimer_init(&haps_ctx->haps_fail_safe_timer,
			 dp_haps_fail_safe_timer_handler,
			 QDF_CLOCK_MONOTONIC,
			 QDF_HRTIMER_MODE_REL,
			 QDF_CONTEXT_TASKLET);

	soc->cdp_soc.ops->haps_ops = &dp_ops_haps;
	dp_info("HAPS is successfully attached for vdev:%u\n", vdev_id);
}

/**
 * dp_haps_init() - Initialize the HAPS config and update the tsf sync period
 * @psoc: Datapath global soc handle
 *
 * Returns: None
 */
void dp_haps_init(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_psoc_get_priv(psoc);
	hdd_cb_handle ctx = dp_ctx->dp_ops.callback_ctx;
	uint32_t config = dp_ctx->dp_cfg.haps_config;

	if (IS_TIME_SYNC_REQUIRED(config)) {
		if (!dp_ctx->dp_ops.wlan_dp_haps_update_qtime_sync_period)
			return;

		dp_ctx->dp_ops.wlan_dp_haps_update_qtime_sync_period(ctx,
							QTIME_SYNC_PERIOD);
		dp_info("HAPS: Qtime time sync period set to %u",
			QTIME_SYNC_PERIOD);
	}
}

/**
 * dp_vdev_haps_detach() - Detach the HAPS
 * @dp_intf: Wlan dp interface
 *
 * Returns: None
 */
void dp_vdev_haps_detach(struct wlan_dp_intf *dp_intf)
{
	struct dp_haps *haps_ctx = &dp_intf->haps_ctx;

	if (!haps_ctx->is_enable)
		return;

	qdf_hrtimer_cancel(&haps_ctx->haps_timer);
	qdf_hrtimer_cancel(&haps_ctx->haps_fail_safe_timer);

	haps_ctx->is_enable = false;
	haps_ctx->is_one_shot = false;
	haps_ctx->state = STATE_UNPAUSE;
	haps_ctx->soc = NULL;

	dp_info("HAPS is successfully detached\n");
}
