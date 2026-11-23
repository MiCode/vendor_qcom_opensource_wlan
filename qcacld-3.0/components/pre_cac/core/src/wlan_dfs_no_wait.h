/*
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

/*
 * DOC: contains declarations for DFS NO WAIT (DNW) functions
 */

#ifndef _WLAN_DFS_NO_WAIT_H_
#define _WLAN_DFS_NO_WAIT_H_

#ifdef WLAN_FEATURE_DNW
#include <qdf_types.h>
#include <wlan_cmn.h>
#include <qdf_mc_timer.h>
#include "wlan_dnw_public_structs.h"

/**
 * enum wlan_dfs_no_wait_state - State of DFS no wait feature
 * @DNW_STATE_INIT: Init state
 * @DNW_STATE_CAC:  CAC in progress state
 * @DNW_STATE_RADAR_FOUND: Radar found state
 * @DNW_STATE_END:  End state
 */
enum wlan_dfs_no_wait_state {
	DNW_STATE_INIT,
	DNW_STATE_CAC,
	DNW_STATE_RADAR_FOUND,
	DNW_STATE_END,
};

/**
 * struct pre_dnw_info - Previous DFS No Wait information
 * @ch_freq: channel frequency
 * @ori_ch_width: Original channel width
 * @dg_ch_width: Downgrade channel width
 * @complete_time: DFS No Wait complete timestamp
 */
struct pre_dnw_info {
	uint32_t ch_freq;
	enum phy_ch_width ori_ch_width;
	enum phy_ch_width dg_ch_width;
	qdf_time_t complete_time;
};

/**
 * struct wlan_dnw_pdev_info - DNW information in pdev private structure
 * @pdev: Pointer to pdev object
 * @enabled: DNW feature is enabled
 * @dnw_in_progress: DFS no wait feature is in progress
 * @is_dnw_cac_timer_running: dnw_cac_timer is running
 * @dnw_count: DNW count for multiple SAP
 * @ch_freq: channel frequency
 * @ori_ch_width: Original channel width
 * @dg_ch_width: Downgrade channel width
 * @cac_duration_ms: CAC duration
 * @state: State of DFS no wait feature
 * @dnw_map: Policy DFS no wait feature
 * @dnw_cac_timer: CAC timer for DFS no wait feature
 * @pre_dnw_info: Previous DFS no wait information
 * @request_handler: Handle DFS No Wait request
 */
struct wlan_dnw_pdev_info {
	struct wlan_objmgr_pdev *pdev;
	bool enabled;
	bool dnw_in_progress;
	bool is_dnw_cac_timer_running;
	uint8_t dnw_count;
	uint32_t ch_freq;
	enum phy_ch_width ori_ch_width;
	enum phy_ch_width dg_ch_width;
	uint32_t cac_duration_ms;
	enum wlan_dfs_no_wait_state state;
	qdf_mc_timer_t dnw_cac_timer;
	struct pre_dnw_info pre_dnw_info;
	dnw_request_handler request_handler;
};

/**
 * struct wlan_dnw_vdev_info - DNW information in vdev private structure
 * @vdev: Pointer to vdev object
 * @ctx: Pointer to sap context
 * @dnw_in_progress: DFS no wait feature is in progress
 */
struct wlan_dnw_vdev_info {
	struct wlan_objmgr_vdev *vdev;
	void *ctx;
	bool dnw_in_progress;
};

/**
 * start_dnw_timer() - Start timer to lisen radar in DFS No Wait
 * @dnw_pdev_info: Pointer to DFS No Wait pdev object
 *
 * This function gets called when handle start BSS success events.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS start_dnw_timer(struct wlan_dnw_pdev_info *dnw_pdev_info);

/**
 * stop_dnw_timer() - Stop timer to lisen radar in DFS No Wait
 * @dnw_pdev_info: Pointer to DFS No Wait pdev object
 *
 * This function gets called when handle start bss fail or stop BSS events.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS stop_dnw_timer(struct wlan_dnw_pdev_info *dnw_pdev_info);

/**
 * is_dnw_in_progress() - Check DFS No Wait is in progress or not
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 *
 * This function gets called when handle BSS events in sap component.
 *
 * Return: true - in case of DNW in progress
 */
bool is_dnw_in_progress(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id);

/**
 * is_valid_dnw() - Check it's valid DFS No Wait or not
 * @pdev: Pointer to pdev object
 * @ch_freq: Channel frequency
 * @old_ch_width: Old channel width
 * @new_ch_width: New channel width
 *
 * This function gets called when upgrade bandwidth from old to new.
 *
 * Return: true - in case of it's valid DNW case
 */
bool is_valid_dnw(struct wlan_objmgr_pdev *pdev, uint32_t ch_freq,
		  enum phy_ch_width old_ch_width,
		  enum phy_ch_width new_ch_width);
/**
 * dnw_set_info() - Set information for DFS No Wait
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 * @chan_freq: Channel frequency
 * @ch_width: Channel width
 * @cac_duration: CAC duration
 * @ignore_cac: Ignore CAC
 * @request_handler: Handler for DFS No Wait request
 * @ctx: Pointer to sap context
 *
 * This function gets called when trying to start bss in sap component.
 *
 * Return: QDF_STATUS_SUCCESS - in case of valid DNW case
 */
QDF_STATUS
dnw_set_info(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id, uint32_t chan_freq,
	     uint8_t ch_width, uint32_t cac_duration, bool ignore_cac,
	     dnw_request_handler request_handler, void *ctx);

/**
 * dnw_handle_bss_start() - Handle BSS start event in DFS No Wait
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 * @is_success: Start BSS successful
 *
 * This function gets called when handle BSS start event in sap component.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS dnw_handle_bss_start(struct wlan_objmgr_pdev *pdev,
				uint8_t vdev_id, bool is_success);

/**
 * dnw_handle_radar_found() - Handle radar found event in DFS No Wait
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 *
 * This function gets called when handle radar found event in sap component.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS dnw_handle_radar_found(struct wlan_objmgr_pdev *pdev,
				  uint8_t vdev_id);

/**
 * dnw_handle_bss_stop() - Handle bss stop or start fail event in DFS No Wait
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 *
 * This function gets called when handle bss stop or start fail event in
 * sap component.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS dnw_handle_bss_stop(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id);

/**
 * dnw_update_bandwidth() - Update channel width base on DFS No Wait state
 * @vdev: Pointer to vdev object
 * @ch_width: Original Channel width
 *
 * This function gets called when fill VHT/HT/EHT operation IE.
 *
 * Return: Downgrade channel width if DFS No Wait is CAC or radar found state,
 *         otherwise return Original Channel width
 */
enum phy_ch_width
dnw_update_bandwidth(struct wlan_objmgr_vdev *vdev,
		     enum phy_ch_width ch_width);

/**
 * set_dfs_no_wait_support() - Configure DFS No Wait support
 * @pdev: Pointer to pdev object
 * @enable: Enable DFS No Wait support
 *
 * This function gets called When enable or disable DFS No Wait support
 * by userspace.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS set_dfs_no_wait_support(struct wlan_objmgr_pdev *pdev,
				   bool enable);
#endif /* WLAN_FEATURE_DNW */
#endif /* _WLAN_DFS_NO_WAIT_H_ */
