/*
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: contains policy manager ll_sap definitions specific to the ll_sap module
 */
#ifndef WLAN_POLICY_MGR_LL_SAP_H
#define WLAN_POLICY_MGR_LL_SAP_H

#include "wlan_objmgr_psoc_obj.h"
#include "wlan_policy_mgr_public_struct.h"

/**
 * enum ll_lt_sap_event - event of LL SAP
 * @LL_LT_SAP_EVENT_STARTING: LL_LT_SAP is starting
 * @LL_LT_SAP_EVENT_STARTED: LL_LT_SAP has started.
 * @LL_LT_SAP_EVENT_STOPPED: LL_LT_SAP has stopped.
 * @LL_LT_SAP_EVENT_MAX: LL_LT_SAP max event
 */
enum ll_lt_sap_event {
	LL_LT_SAP_EVENT_STARTING = 1,
	LL_LT_SAP_EVENT_STARTED,
	LL_LT_SAP_EVENT_STOPPED,
	LL_LT_SAP_EVENT_MAX,
};

#ifdef WLAN_FEATURE_LL_LT_SAP
/**
 * wlan_policy_mgr_get_ll_lt_sap_vdev_id() - Get ll_lt_sap vdev id
 * @psoc: PSOC object
 *
 * API to find ll_lt_sap vdev id
 *
 * Return: vdev id
 */
uint8_t wlan_policy_mgr_get_ll_lt_sap_vdev_id(struct wlan_objmgr_psoc *psoc);

/**
 * __policy_mgr_is_ll_lt_sap_restart_required() - Check in ll_lt_sap restart is
 * required
 * @psoc: PSOC object
 * @ll_lt_sap_start_freq: starting LL LT SAP freq.
 * @func: Function pointer of the caller function.
 *
 * This API checks if ll_lt_sap restart is required or not
 *
 * Return: true/false
 */
bool __policy_mgr_is_ll_lt_sap_restart_required(struct wlan_objmgr_psoc *psoc,
						qdf_freq_t ll_lt_sap_start_freq,
						const char *func);

#define policy_mgr_is_ll_lt_sap_restart_required(psoc, ll_sap_freq) \
	__policy_mgr_is_ll_lt_sap_restart_required(psoc, ll_sap_freq, __func__)

/**
 * __policy_mgr_is_ll_lt_freq_allowed() - Check if ll_lt_sap given freq
 * can be allowed
 * @psoc: PSOC object
 * @ll_lt_sap_freq: LL LT SAP freq to check
 * @ll_lt_sap_vdev_id: LL LT SAP vdev id
 * @func: Function pointer of the caller function.
 *
 * This API checks if ll_lt_sap restart is required or not
 *
 * Return: true if frequency is allowed, false otherwise
 */
bool __policy_mgr_is_ll_lt_freq_allowed(struct wlan_objmgr_psoc *psoc,
					qdf_freq_t ll_lt_sap_freq,
					uint8_t ll_lt_sap_vdev_id,
					const char *func);

#define policy_mgr_is_ll_lt_freq_allowed(psoc, ll_sap_freq, ll_lt_sap_vdev_id) \
	__policy_mgr_is_ll_lt_freq_allowed(psoc, ll_sap_freq, \
					ll_lt_sap_vdev_id, __func__)

/**
 * policy_mgr_ll_lt_sap_restart_concurrent_sap() - Check and restart
 * concurrent SAP or ll_lt_sap
 * @psoc: PSOC object
 * @event: Indicates if ll_lt_sap is getting enabled or getting disabled
 *
 * This API checks and restarts concurrent SAP or ll_lt_sap when ll_lt_sap comes
 * up or goes down.
 * Concurrent SAP and ll_lt_sap should always be on different MAC.
 * restart the concurrent SAP in below scenario:
 * If ll_lt_sap is coming up and HW is not sbs capable and concurrent SAP is
 * operating on 5 GHz, then move concurrent SAP to 2.4 Ghz MAC to allow
 * ll_lt_sap on 5 GHz
 * If ll_lt_sap is going down and if concurrent SAP is on 2.4 GHz then try to
 * restart concurrent SAP on its original user configured frequency
 * If ll_lt_sap interface has come up and in parallel if some other interface
 * comes up on the ll_lt_sap frequency, then ll_lt_sap needs to be restarted.
 *
 * Return: None
 */
void policy_mgr_ll_lt_sap_restart_concurrent_sap(struct wlan_objmgr_psoc *psoc,
						 enum ll_lt_sap_event event);

/**
 * policy_mgr_ll_lt_sap_allow_csa() - Check if CSA can be allowed for the given
 * vdev for the given freq.
 * @psoc: PSOC object
 * @vdev_id: vdev id whic initiated CSA
 * @target_freq: target freq for CSA
 * @pm_con_mode: con mode for vdev
 *
 * Return: true if allowed else false
 */
bool policy_mgr_ll_lt_sap_allow_csa(struct wlan_objmgr_psoc *psoc,
				    uint8_t vdev_id, qdf_freq_t target_freq,
				    enum policy_mgr_con_mode pm_con_mode);

#else

static inline bool
policy_mgr_is_ll_lt_sap_restart_required(struct wlan_objmgr_psoc *psoc,
					 qdf_freq_t ll_lt_sap_start_freq)
{
	return false;
}

static inline bool
policy_mgr_is_ll_lt_freq_allowed(struct wlan_objmgr_psoc *psoc,
				 qdf_freq_t ll_lt_sap_freq,
				 uint8_t ll_lt_sap_vdev_id)
{
	return false;
}

static inline
uint8_t wlan_policy_mgr_get_ll_lt_sap_vdev_id(struct wlan_objmgr_psoc *psoc)
{
	return WLAN_INVALID_VDEV_ID;
}

static inline void
policy_mgr_ll_lt_sap_restart_concurrent_sap(struct wlan_objmgr_psoc *psoc,
					    enum ll_lt_sap_event event)
{
}

static inline bool
policy_mgr_ll_lt_sap_allow_csa(struct wlan_objmgr_psoc *psoc,
			       uint8_t vdev_id, qdf_freq_t target_freq,
			       enum policy_mgr_con_mode pm_con_mode)
{
	return true;
}

#endif
#endif /* WLAN_POLICY_MGR_LL_SAP_H */
