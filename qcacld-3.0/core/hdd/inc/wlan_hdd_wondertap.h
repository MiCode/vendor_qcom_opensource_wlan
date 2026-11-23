/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

/**
 * DOC: wlan_hdd_wondertap.h
 *
 * WLAN Host Device Driver file for wondertap functionality.
 *
 */
#if !defined(WLAN_HDD_WONDERTAP_H)
#define WLAN_HDD_WONDERTAP_H

#include <qdf_event.h>

#ifdef DRIVER_PASSTHRU_MODE
#include <qdf_wondertap.h>

#define WLAN_WONDERTAP_VDEV_OP_TIMEOUT_MS 10000

/**
 * struct hdd_wondertap_context - hdd wondertap context
 * @hdd_ctx: global hdd context
 * @wt_adapter: pointer to wondertap adapter
 * @wondertap_vdev_event: wondertap vdev event
 * @wondertap_wakelock: wondertap wakelock
 * @wondertap_rtpm_lock: wondertap rtpm lock
 * @is_frame_filter_set: is frame filter configured
 * @frame_filter: frame filter value
 * @magic: handle for external entity
 */
struct hdd_wondertap_context {
	struct hdd_context *hdd_ctx;
	struct hdd_adapter *wt_adapter;
	qdf_event_t wondertap_vdev_event;
	qdf_wake_lock_t wondertap_wakelock;
	qdf_runtime_lock_t wondertap_rtpm_lock;
	bool is_frame_filter_set;
	uint8_t frame_filter;
	uint64_t magic;
};

/**
 * wlan_hdd_wondertap_register_ops() - Register wondertap operations
 * @dev: device handle
 *
 * This function registers the WLAN driver's wondertap operations with the
 * wondertap framework. It should be called during driver initialization
 * to enable wondertap functionality.
 *
 * Return: 0 on success, negative error code on failure
 */
int wlan_hdd_wondertap_register_ops(struct device *dev);

/**
 * wlan_hdd_wondertap_unregister_ops() - Unregister wondertap operations
 * @dev: device handle
 * @force_cleanup: force cleanup wondertap resources
 *
 * This function unregisters the WLAN driver's wondertap operations from the
 * wondertap framework. It should be called during driver cleanup to
 * properly release wondertap resources.
 *
 * Return: void
 */
void wlan_hdd_wondertap_unregister_ops(struct device *dev, bool force_cleanup);

/**
 * hdd_sme_passthrough_mode_callback() - Callback triggered by SME layer on
 *  successful channel change operation.
 * @vdev_id: vdev id
 * @is_up: is vdev up
 *
 * Return: None
 */
void hdd_sme_passthrough_mode_callback(uint8_t vdev_id, bool is_up);
#else
static inline int wlan_hdd_wondertap_register_ops(struct device *dev)
{
	return 0;
}

static inline
void wlan_hdd_wondertap_unregister_ops(struct device *dev, bool force_cleanup)
{
}

static inline
void hdd_sme_passthrough_mode_callback(uint8_t vdev_id, bool is_up)
{
}
#endif /*DRIVER_PASSTHRU_MODE */
#endif /* WLAN_HDD_WONDERTAP_H */
