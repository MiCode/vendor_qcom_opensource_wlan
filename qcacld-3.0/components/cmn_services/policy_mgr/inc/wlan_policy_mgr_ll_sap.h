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
 * DOC: contains policy manager ll_sap definitions specific to the ll_sap module
 */

#include "wlan_objmgr_psoc_obj.h"

/**
 * wlan_policy_mgr_get_ll_lt_sap_vdev() - Get ll_lt_sap vdev
 * @psoc: PSOC object
 *
 * API to find ll_lt_sap vdev pointer
 *
 * This API increments the ref count of the vdev object internally, the
 * caller has to invoke the wlan_objmgr_vdev_release_ref() to decrement
 * ref count
 *
 * Return: vdev pointer
 *         NULL on FAILURE
 */
struct wlan_objmgr_vdev *
wlan_policy_mgr_get_ll_lt_sap_vdev(struct wlan_objmgr_psoc *psoc);
