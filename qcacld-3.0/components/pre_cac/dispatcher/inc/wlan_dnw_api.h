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

/**
 * DOC: Public API declarations of DFS No Wait
 */

#ifndef _WLAN_DNW_API_H_
#define _WLAN_DNW_API_H_

#include "wlan_dnw_public_structs.h"

#ifdef WLAN_FEATURE_DNW

/**
 * wlan_is_dnw_in_progress() - Check DFS No Wait is in progress or not
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 *
 * This function gets called when handle BSS events in sap component.
 *
 * Return: true - in case of DNW in progress
 */
bool wlan_is_dnw_in_progress(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id);

/**
 * wlan_is_valid_dnw() - Check it's valid DFS No Wait or not
 * @pdev: Pointer to pdev object
 * @ch_freq: Channel frequency
 * @old_ch_width: Old channel width
 * @new_ch_width: New channel width
 *
 * This function gets called when upgrade bandwidth from old to new.
 *
 * Return: true - in case of it's valid DNW case
 */
bool wlan_is_valid_dnw(struct wlan_objmgr_pdev *pdev, uint32_t ch_freq,
		       enum phy_ch_width old_ch_width,
		       enum phy_ch_width new_ch_width);
/**
 * wlan_dnw_set_info() - Set information for DFS No Wait
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
wlan_dnw_set_info(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id,
		  uint32_t chan_freq, uint8_t ch_width,
		  uint32_t cac_duration, bool ignore_cac,
		  dnw_request_handler request_handler, void *ctx);

/**
 * wlan_dnw_handle_bss_start() - Handle BSS start event in DFS No Wait
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 * @is_success: Start BSS successful
 *
 * This function gets called when handle BSS start event in sap component.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS wlan_dnw_handle_bss_start(struct wlan_objmgr_pdev *pdev,
				     uint8_t vdev_id, bool is_success);

/**
 * wlan_dnw_handle_radar_found() - Handle radar found event in DFS No Wait
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 *
 * This function gets called when handle radar found event in sap component.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS wlan_dnw_handle_radar_found(struct wlan_objmgr_pdev *pdev,
				       uint8_t vdev_id);

/**
 * wlan_dnw_handle_bss_stop() - Handle bss stop or start fail event in
 * DFS No Wait
 * @pdev: Pointer to pdev object
 * @vdev_id: Vdev id
 *
 * This function gets called when handle bss stop or start fail event in
 * sap component.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS wlan_dnw_handle_bss_stop(struct wlan_objmgr_pdev *pdev,
				    uint8_t vdev_id);

/**
 * wlan_dnw_update_bandwidth() - Update channel width base on state of
 * DFS No Wait
 * @vdev: Pointer to vdev object
 * @ch_width: Original Channel width
 *
 * This function gets called when fill VHT/HT/EHT operation IE.
 *
 * Return: Downgrade channel width if DFS No Wait is CAC or radar found state,
 *         otherwise return Original Channel width.
 */
enum phy_ch_width
wlan_dnw_update_bandwidth(struct wlan_objmgr_vdev *vdev,
			  enum phy_ch_width ch_width);
#else
static inline bool
wlan_is_dnw_in_progress(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	return false;
}

static inline bool
wlan_is_valid_dnw(struct wlan_objmgr_pdev *pdev, uint32_t ch_freq,
		  enum phy_ch_width old_ch_width,
		  enum phy_ch_width new_ch_width)
{
	return false;
}

static inline QDF_STATUS
wlan_dnw_set_info(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id,
		  uint32_t chan_freq, uint8_t ch_width,
		  uint32_t cac_duration, bool ignore_cac,
		  dnw_request_handler request_handler, void *ctx)
{
	return QDF_STATUS_E_FAILURE;
}

static inline QDF_STATUS
wlan_dnw_handle_bss_start(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id,
			  bool is_success)
{
	return QDF_STATUS_E_FAILURE;
}

static inline QDF_STATUS
wlan_dnw_handle_radar_found(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	return QDF_STATUS_E_FAILURE;
}

static inline QDF_STATUS
wlan_dnw_handle_bss_stop(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	return QDF_STATUS_E_FAILURE;
}

static inline enum phy_ch_width
wlan_dnw_update_bandwidth(struct wlan_objmgr_vdev *vdev,
			  enum phy_ch_width ch_width)
{
	return ch_width;
}
#endif /* WLAN_FEATURE_DNW */
#endif /* _WLAN_DNW_API_H_ */
