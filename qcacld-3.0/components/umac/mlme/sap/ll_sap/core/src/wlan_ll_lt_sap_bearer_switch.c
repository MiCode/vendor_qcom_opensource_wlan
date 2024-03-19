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

#include "wlan_ll_sap_main.h"
#include "wlan_ll_lt_sap_bearer_switch.h"
#include "wlan_sm_engine.h"

uint32_t ll_lt_sap_bearer_switch_get_id(struct wlan_objmgr_vdev *vdev)
{
	uint32_t request_id;
	struct ll_sap_vdev_priv_obj *ll_sap_obj;

	ll_sap_obj = ll_sap_get_vdev_priv_obj(vdev);

	if (!ll_sap_obj) {
		ll_sap_err("vdev %d ll_sap obj null",
			   wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_INVAL;
	}

	request_id = qdf_atomic_inc_return(
				&ll_sap_obj->bearer_switch_ctx->request_id);

	ll_sap_debug("bearer_switch request_id %d", request_id);
	return request_id;
}

/**
 * bs_state_non_wlan_entry() - Entry API for non wlan state for bearer switch
 * state machine
 * @ctx: Bearer switch context
 *
 * API to perform operations on moving to non-wlan state
 *
 * Return: void
 */
static void bs_state_non_wlan_entry(void *ctx)
{
}

/**
 * bs_state_non_wlan_exit() - Exit API for non wlan state for bearer switch
 * state machine
 * @ctx: Bearer switch context
 *
 * API to perform operations on exiting from non-wlan state
 *
 * Return: void
 */
static void bs_state_non_wlan_exit(void *ctx)
{
}

/**
 * bs_state_non_wlan_event() - Non-wlan State event handler for bearer switch
 * state machine
 * @ctx: Bearer switch context
 * @event: event
 * @data_len: length of @data
 * @data: event data
 *
 * API to handle events in Non-wlan state
 *
 * Return: bool
 */
static bool bs_state_non_wlan_event(void *ctx, uint16_t event,
				    uint16_t data_len, void *data)
{
	bool event_handled = false;

	switch (event) {
	case WLAN_BS_SM_EV_SWITCH_TO_WLAN:
	case WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN:
		event_handled = true;
		break;
	default:
		break;
	}

	return event_handled;
}

/**
 * bs_state_non_wlan_req_entry() - Entry API for non wlan requested state for
 *bearer switch state machine
 * @ctx: Bearer switch context
 *
 * API to perform operations on moving to non-wlan requested state
 *
 * Return: void
 */
static void bs_state_non_wlan_req_entry(void *ctx)
{
}

/**
 * bs_state_non_wlan_req_exit() - Exit API for non wlan requested state for
 * bearer switch state machine
 * @ctx: Bearer switch context
 *
 * API to perform operations on exiting from non-wlan requested state
 *
 * Return: void
 */
static void bs_state_non_wlan_req_exit(void *ctx)
{
}

/**
 * bs_state_non_wlan_req_event() - Non-wlan requested State event handler for
 * bearer switch state machine
 * @ctx: Bearer switch context
 * @event: event
 * @data_len: length of @data
 * @data: event data
 *
 * API to handle events in Non-wlan state
 *
 * Return: bool
 */
static bool bs_state_non_wlan_req_event(void *ctx, uint16_t event,
					uint16_t data_len, void *data)
{
	bool event_handled = false;

	switch (event) {
	case WLAN_BS_SM_EV_SWITCH_TO_WLAN:
	case WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN:
	case WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_TIMEOUT:
	case WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_COMPLETED:
	case WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_FAILURE:
		event_handled = true;
		break;
	default:
		break;
	}

	return event_handled;
}

/**
 * bs_state_wlan_entry() - Entry API for wlan state for bearer switch
 * state machine
 * @ctx: Bearer switch context
 *
 * API to perform operations on moving to wlan state
 *
 * Return: void
 */
static void bs_state_wlan_entry(void *ctx)
{
}

/**
 * bs_state_wlan_exit() - Exit API for wlan state for bearer switch
 * state machine
 * @ctx: Bearer switch context
 *
 * API to perform operations on exiting from wlan state
 *
 * Return: void
 */
static void bs_state_wlan_exit(void *ctx)
{
}

/**
 * bs_state_wlan_event() - Wlan State event handler for bearer switch
 * state machine
 * @ctx: Bearer switch context
 * @event: event
 * @data_len: length of @data
 * @data: event data
 *
 * API to handle events in Wlan state
 *
 * Return: bool
 */
static bool bs_state_wlan_event(void *ctx, uint16_t event,
				uint16_t data_len, void *data)
{
	bool event_handled = false;

	switch (event) {
	case WLAN_BS_SM_EV_SWITCH_TO_WLAN:
	case WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN:
		event_handled = true;
		break;
	default:
		break;
	}

	return event_handled;
}

/**
 * bs_state_wlan_req_entry() - Entry API for Wlan requested state for
 *bearer switch state machine
 * @ctx: Bearer switch context
 *
 * API to perform operations on moving to Wlan requested state
 *
 * Return: void
 */
static void bs_state_wlan_req_entry(void *ctx)
{
}

/**
 * bs_state_wlan_req_exit() - Exit API for Wlan requested state for
 * bearer switch state machine
 * @ctx: Bearer switch context
 *
 * API to perform operations on exiting from Wlan requested state
 *
 * Return: void
 */
static void bs_state_wlan_req_exit(void *ctx)
{
}

/**
 * bs_state_wlan_req_event() - Wlan requested State event handler for
 * bearer switch state machine
 * @ctx: Bearer switch context
 * @event: event
 * @data_len: length of @data
 * @data: event data
 *
 * API to handle events in Wlan state
 *
 * Return: bool
 */
static bool bs_state_wlan_req_event(void *ctx, uint16_t event,
				    uint16_t data_len, void *data)
{
	bool event_handled = false;

	switch (event) {
	case WLAN_BS_SM_EV_SWITCH_TO_WLAN:
	case WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN:
	case WLAN_BS_SM_EV_SWITCH_TO_WLAN_TIMEOUT:
	case WLAN_BS_SM_EV_SWITCH_TO_WLAN_FAILURE:
	case WLAN_BS_SM_EV_SWITCH_TO_NON_WLAN_FAILURE:
		event_handled = true;
		break;
	default:
		break;
	}

	return event_handled;
}

struct wlan_sm_state_info bs_sm_info[] = {
	{
		(uint8_t)BEARER_NON_WLAN,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		false,
		"NON_WLAN",
		bs_state_non_wlan_entry,
		bs_state_non_wlan_exit,
		bs_state_non_wlan_event
	},
	{
		(uint8_t)BEARER_NON_WLAN_REQUESTED,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		false,
		"NON_WLAN_REQUESTED",
		bs_state_non_wlan_req_entry,
		bs_state_non_wlan_req_exit,
		bs_state_non_wlan_req_event
	},
	{
		(uint8_t)BEARER_WLAN_REQUESTED,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		false,
		"WLAN_REQUESTED",
		bs_state_wlan_req_entry,
		bs_state_wlan_req_exit,
		bs_state_wlan_req_event
	},
	{
		(uint8_t)BEARER_WLAN,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		false,
		"WLAN",
		bs_state_wlan_entry,
		bs_state_wlan_exit,
		bs_state_wlan_event
	},
	{
		(uint8_t)BEARER_SWITCH_MAX,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		(uint8_t)WLAN_SM_ENGINE_STATE_NONE,
		false,
		"INVALID",
		NULL,
		NULL,
		NULL
	},
};

static const char *bs_sm_event_names[] = {
	"EV_SW_TO_WLAN",
	"EV_SW_TO_NON_WLAN",
	"EV_SW_TO_WLAN_TIMEOUT",
	"EV_SW_TO_NON_WLAN_TIMEOUT",
	"EV_SW_TO_WLAN_COMPLETED",
	"EV_SW_TO_NON_WLAN_COMPLETED",
	"EV_SW_TO_WLAN_FAILURE",
	"EV_SW_TO_NON_WLAN_FAILURE",
};

QDF_STATUS bs_sm_create(struct bearer_switch_info *bs_ctx)
{
	struct wlan_sm *sm;
	uint8_t name[WLAN_SM_ENGINE_MAX_NAME];

	qdf_scnprintf(name, sizeof(name), "BS_%d",
		      wlan_vdev_get_id(bs_ctx->vdev));
	sm = wlan_sm_create(name, bs_ctx,
			    BEARER_NON_WLAN,
			    bs_sm_info,
			    QDF_ARRAY_SIZE(bs_sm_info),
			    bs_sm_event_names,
			    QDF_ARRAY_SIZE(bs_sm_event_names));
	if (!sm) {
		ll_sap_err("Bearer switch State Machine creation failed");
		return QDF_STATUS_E_NOMEM;
	}
	bs_ctx->sm.sm_hdl = sm;

	bs_lock_create(bs_ctx);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS bs_sm_destroy(struct bearer_switch_info *bs_ctx)
{
	bs_lock_destroy(bs_ctx);
	wlan_sm_delete(bs_ctx->sm.sm_hdl);

	return QDF_STATUS_SUCCESS;
}

