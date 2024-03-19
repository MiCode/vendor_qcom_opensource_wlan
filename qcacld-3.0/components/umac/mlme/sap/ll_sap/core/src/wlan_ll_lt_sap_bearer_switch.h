/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: contains ll_lt_sap declarations specific to the bearer
 * switch functionalities
 */

#ifndef _WLAN_LL_LT_SAP_BEARER_SWITCH_H_
#define _WLAN_LL_LT_SAP_BEARER_SWITCH_H_

#include "wlan_ll_sap_public_structs.h"
#include <qdf_atomic.h>
#include "wlan_cmn.h"
#include "wlan_ll_sap_main.h"

/**
 * enum bearer_switch_status: Bearer switch request status
 * @XPAN_BLE_SWITCH_INIT: Init status
 * @XPAN_BLE_SWITCH_SUCCESS: Bearer switch success
 * @XPAN_BLE_SWITCH_REJECTED: Bearer switch is rejected
 * @XPAN_BLE_SWITCH_TIMEOUT: Bearer switch request timed out
 */
enum bearer_switch_status {
	XPAN_BLE_SWITCH_INIT,
	XPAN_BLE_SWITCH_SUCCESS,
	XPAN_BLE_SWITCH_REJECTED,
	XPAN_BLE_SWITCH_TIMEOUT,
};

/**
 * enum wlan_bearer_switch_sm_state - Bearer switch states
 * @BEARER_NON_WLAN: Default state, Bearer non wlan state
 * @BEARER_NON_WLAN_REQUESTED: State when bearer switch requested to non-wlan
 * @BEARER_WLAN_REQUESTED: State when bearer switch requested to wlan
 * @BEARER_WLAN: Bearer non wlan state
 * @BEARER_SWITCH_MAX: Max state
 */
enum wlan_bearer_switch_sm_state {
	BEARER_NON_WLAN = 0,
	BEARER_NON_WLAN_REQUESTED = 1,
	BEARER_WLAN_REQUESTED = 2,
	BEARER_WLAN = 3,
	BEARER_SWITCH_MAX = 4,
};

/**
 * enum wlan_bearer_switch_sm_evt - Bearer switch related events, if any new
 * enum is added to this enum, then please update bs_sm_event_names
 * @WLAN_BS_SM_EV_SWITCH_TO_WLAN: Bearer switch request to WLAN
 * @WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN: Bearer switch request to NON WLAN
 * @WLAN_BS_SM_EV_SWITCH_TO_WLAN_TIMEOUT: Bearer switch request to WLA
 * timeout
 * @WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_TIMEOUT: Bearer switch request to NON-WLAN
 * timeout
 * @WLAN_BS_SM_EV_SWITCH_TO_WLAN_COMPLETED: Bearer switch request to WLAN
 * completed
 * @WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_COMPLETED: Bearer switch request to
 * NON-WLAN completed
 * @WLAN_BS_SM_EV_SWITCH_TO_WLAN_FAILURE: Bearer switch request to WLAN
 * failure
 * @WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_FAILURE: Bearer switch request to NON-WLAN
 * failure
 */
enum wlan_bearer_switch_sm_evt {
	WLAN_BS_SM_EV_SWITCH_TO_WLAN = 0,
	WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN = 1,
	WLAN_BS_SM_EV_SWITCH_TO_WLAN_TIMEOUT = 2,
	WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_TIMEOUT = 3,
	WLAN_BS_SM_EV_SWITCH_TO_WLAN_COMPLETED = 4,
	WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_COMPLETED = 5,
	WLAN_BS_SM_EV_SWITCH_TO_WLAN_FAILURE = 6,
	WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_FAILURE = 7,
};

/**
 * struct bs_state_sm - Bearer switch state machine
 * @bs_sm_lock: sm lock
 * @sm_hdl: sm handlers
 * @bs_state: bearer switch state
 */
struct bs_state_sm {
	qdf_mutex_t bs_sm_lock;
	struct wlan_sm *sm_hdl;
	enum wlan_bearer_switch_sm_state bs_state;
};

/**
 * struct bearer_switch_request - Data structure to store the bearer switch
 * request
 * @requester_cb: Callback which needs to be invoked to indicate the status of
 * the request to the requester, this callback will be passed by the requester
 * when requester will send the request.
 * @arg: Argument passed by requester, this will be returned back in the
 * callback
 * @request_id: Unique value to identify the request
 */

struct bearer_switch_request {
	requester_callback requester_cb;
	void *arg;
	uint32_t request_id;
};

/**
 * struct bearer_switch_info - Data structure to store the bearer switch
 * requests and related information
 * @vdev: Pointer to the ll lt sap vdev
 * @request_id: Last allocated request id
 * @sm: state machine context
 * @ref_count: Reference count corresponding to each vdev and requester
 * @last_status: last status of the bearer switch request
 * @requests: Array of bearer_switch_requests to cache the request information
 */
struct bearer_switch_info {
	struct wlan_objmgr_vdev *vdev;
	qdf_atomic_t request_id;
	struct bs_state_sm sm;
	uint8_t ref_count[WLAN_UMAC_PSOC_MAX_VDEVS][XPAN_BLE_SWITCH_REQUESTER_MAX];
	enum bearer_switch_status last_status;
	struct bearer_switch_request requests[MAX_BEARER_SWITCH_REQUESTERS];
};

/**
 * ll_lt_sap_bearer_switch_get_id() - Get the request id for bearer switch
 * request
 * @vdev: Pointer to vdev
 * Return: Bearer switch request id
 */
uint32_t ll_lt_sap_bearer_switch_get_id(struct wlan_objmgr_vdev *vdev);

/**
 * bs_sm_create() - Invoke SM creation for bearer switch
 * @bs_ctx:  Bearer switch context
 *
 * Return: SUCCESS on successful creation
 *         FAILURE, if creation fails
 */
QDF_STATUS bs_sm_create(struct bearer_switch_info *bs_ctx);

/**
 * bs_sm_destroy() - Invoke SM deletion for bearer switch
 * @bs_ctx:  Bearer switch context
 *
 * Return: SUCCESS on successful deletion
 *         FAILURE, if deletion fails
 */
QDF_STATUS bs_sm_destroy(struct bearer_switch_info *bs_ctx);

/**
 * bs_lock_create() - Create BS SM mutex
 * @bs_ctx:  Bearer switch ctx
 *
 * Creates Bearer switch state machine mutex
 *
 * Return: void
 */
static inline void bs_lock_create(struct bearer_switch_info *bs_ctx)
{
	qdf_mutex_create(&bs_ctx->sm.bs_sm_lock);
}

/**
 * bs_lock_destroy() - Create BS SM mutex
 * @bs_ctx:  Bearer switch ctx
 *
 * Deatroys Bearer switch state machine mutex
 *
 * Return: void
 */
static inline void bs_lock_destroy(struct bearer_switch_info *bs_ctx)
{
	qdf_mutex_destroy(&bs_ctx->sm.bs_sm_lock);
}

/**
 * bs_lock_acquire() - Acquires BS SM mutex
 * @bs_ctx:  Bearer switch ctx
 *
 * Acquire Bearer switch state machine mutex
 *
 * Return: void
 */
static inline void bs_lock_acquire(struct bearer_switch_info *bs_ctx)
{
	qdf_mutex_acquire(&bs_ctx->sm.bs_sm_lock);
}

/**
 * bs_lock_release() - Release BS SM mutex
 * @bs_ctx:  Bearer switch ctx
 *
 * Releases Bearer switch state machine mutex
 *
 * Return: void
 */
static inline void bs_lock_release(struct bearer_switch_info *bs_ctx)
{
	qdf_mutex_release(&bs_ctx->sm.bs_sm_lock);
}
#endif /* _WLAN_LL_LT_SAP_BEARER_SWITCH_H_ */
