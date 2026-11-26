/*
 * Copyright (c) 2012-2015, 2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: This file contains connection manager related CFG/INI Items.
 */

#ifndef __CFG_MLME_CM_H
#define __CFG_MLME_CM_H

#ifdef WLAN_FEATURE_11BE_MLO
/*
 * <ini>
 * num_nontx_to_scan_from_top - Value of scan entries to check for nonTx scan
 * @Min: 0
 * @Max: 5
 * @Default: 3
 *
 * This ini is used to increase/decrease the count of entries to check in the
 * filtered candidate list which are non-Tx MBSSID and don't have scan entry
 * of atleast of the partner links which are valid. If the value is set to X,
 * then X scan entries from the start of the filtered scan list are checked
 * to see if any non-Tx MBSSID needs scanning for partner links.
 *
 * Related: None
 *
 * Supported Feature: STA Candidate selection
 *
 * Usage: External
 *
 * </ini>
 */
#define MIN_NONTX_TO_SCAN 0
#define MAX_NONTX_TO_SCAN 3
#define DEF_NONTX_TO_SCAN 2

#define CFG_NUM_NONTX_TO_SCAN_FROM_TOP CFG_UINT( \
	"num_nontx_to_scan_from_top", \
	MIN_NONTX_TO_SCAN, \
	MAX_NONTX_TO_SCAN, \
	DEF_NONTX_TO_SCAN, \
	CFG_VALUE_OR_DEFAULT, \
	"Num of scan entries of candidate list to check for nonTx scan")

#define CFG_MLO_MLME_CM_CONFIG \
	CFG(CFG_NUM_NONTX_TO_SCAN_FROM_TOP)
#else /* WLAN_FEATURE_11BE_MLO */
#define CFG_MLO_MLME_CM_CONFIG
#endif /* WLAN_FEATURE_11BE_MLO */
#endif /* __CFG_MLME_CM_H */
