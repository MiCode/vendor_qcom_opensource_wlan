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
 * DOC: UCFG API declarations of DFS No Wait
 */
#ifndef _WLAN_DNW_UCFG_API_H_
#define _WLAN_DNW_UCFG_API_H_
#include <qdf_types.h>
struct wlan_objmgr_pdev;

#ifdef WLAN_FEATURE_DNW
/**
 * ucfg_set_dfs_no_wait_support() - Configure DFS No Wait support
 * @pdev: Pointer to pdev object
 * @enable: Enable DFS No Wait support
 *
 * This function gets called When enable or disable DFS No Wait support
 * by userspace.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success
 */
QDF_STATUS ucfg_set_dfs_no_wait_support(struct wlan_objmgr_pdev *pdev,
					bool enable);
#else
static inline QDF_STATUS
ucfg_set_dfs_no_wait_support(struct wlan_objmgr_pdev *pdev, bool enable)
{
	return QDF_STATUS_SUCCESS;
}
#endif /* WLAN_FEATURE_DNW */
#endif /* _WLAN_DNW_UCFG_API_H_ */
