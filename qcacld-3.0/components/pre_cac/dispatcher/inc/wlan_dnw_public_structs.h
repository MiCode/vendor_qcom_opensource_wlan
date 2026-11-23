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
 * DOC: Public structures declarations of DFS No Wait
 */

#ifndef _WLAN_DNW_PUBLIC_STRUCTS_H_
#define _WLAN_DNW_PUBLIC_STRUCTS_H_

#include <wlan_cmn.h>
struct wlan_objmgr_vdev;

/**
 * enum wlan_dnw_request - DFS No Wait request type
 * @DNW_REQ_UPGRADE_BW: Upgrade bandwidth request
 * @DNW_REQ_DOWNGRADE_BW:  Downgrade bandwidth request
 */
enum wlan_dnw_request {
	DNW_REQ_UPGRADE_BW,
	DNW_REQ_DOWNGRADE_BW,
};

/**
 * typedef dnw_request_handler() - Handler for DFS No Wait request
 * @ctx: Pointer to SAP context
 * @ori_ch_width: Original channel width
 * @dg_ch_width: Downgrade channel width
 * @dnw_request: Request type from DFS No Wait
 *
 * DFS No Wait calls this handler to process requests - upgrade or downgrade
 * bandwidth, which only be handled in mac layer.
 *
 * Return: QDF_STATUS_SUCCESS on success, or an appropriate QDF_STATUS
 * error code
 */
typedef QDF_STATUS
(*dnw_request_handler)(void *ctx,
		       enum phy_ch_width ori_ch_width,
		       enum phy_ch_width dg_ch_width,
		       enum wlan_dnw_request dnw_request);

#endif /* _WLAN_DNW_PUBLIC_STRUCTS_H_ */
