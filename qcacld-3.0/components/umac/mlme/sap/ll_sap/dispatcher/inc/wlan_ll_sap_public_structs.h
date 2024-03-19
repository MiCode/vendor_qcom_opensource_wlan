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
 * DOC: contains ll_lt_sap structure definitions specific to the bearer
 * switch functionalities
 */

#ifndef _WLAN_LL_LT_SAP_BEARER_SWITCH_PUBLIC_STRUCTS_H_
#define _WLAN_LL_LT_SAP_BEARER_SWITCH_PUBLIC_STRUCTS_H_

#include "wlan_objmgr_psoc_obj.h"
#include <qdf_status.h>

/* Indicates MAX bearer switch requesters at a time */
#define MAX_BEARER_SWITCH_REQUESTERS 5

/**
 * enum bearer_switch_requester_source: Bearer switch requester source
 * @XPAN_BLE_SWITCH_REQUESTER_CONNECT: Bearer switch requester is connect
 * @XPAN_BLE_SWITCH_REQUESTER_CSA: Bearer switch requester is CSA
 * @XPAN_BLE_SWITCH_REQUESTER_FW: Bearer switch requester is FW
 * @XPAN_BLE_SWITCH_REQUESTER_MAX: Indicates MAX bearer switch requester
 */
enum bearer_switch_requester_source {
	XPAN_BLE_SWITCH_REQUESTER_CONNECT,
	XPAN_BLE_SWITCH_REQUESTER_CSA,
	XPAN_BLE_SWITCH_REQUESTER_FW,
	XPAN_BLE_SWITCH_REQUESTER_MAX,
};

 /**
  * typedef requester_callback() - Callback function, which will be invoked with
  * the bearer switch request status.
  * @psoc: Psoc pointer
  * @request_id: Request ID
  * @status: Status of the bearer switch request
  * @request_params: Request params for the bearer switch request
  *
  * Return: None
  */

typedef void (*requester_callback)(struct wlan_objmgr_psoc *psoc,
				    uint8_t vdev_id, uint32_t request_id,
				    QDF_STATUS status,
				    void *request_params);

#endif /* _WLAN_LL_LT_SAP_BEARER_SWITCH_PUBLIC_STRUCTS_H_ */
