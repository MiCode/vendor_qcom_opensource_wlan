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
 * DOC: Configuration declarations of PRE CAC
 */

#ifndef _WLAN_PRE_CAC_CFG_H_
#define _WLAN_PRE_CAC_CFG_H_

#ifdef WLAN_FEATURE_DNW
/*
 * <ini>
 * g_enable_dfs_no_wait - Enable/disable DFS No Wait feature
 * @Min: 0
 * @Max: 1
 * @Default: 0
 *
 * This ini is used to Enable/disable DFS No Wait feature
 *
 * Supported Feature: DFS No Wait
 *
 * Usage: Internal
 *
 * </ini>
 */
#define CFG_ENABLE_DFS_NO_WAIT \
	CFG_INI_BOOL("g_enable_dfs_no_wait", false, \
		     "Enable/disable DFS No Wait feature")
#define CFG_PRE_CAC_ALL \
	CFG(CFG_ENABLE_DFS_NO_WAIT)
#else
#define CFG_PRE_CAC_ALL
#endif /* WLAN_FEATURE_DNW */
#endif /* _WLAN_DNW_CFG_H_ */
