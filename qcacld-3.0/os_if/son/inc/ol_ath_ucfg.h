/*
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

#ifndef OL_ATH_UCFG_H_
#define OL_ATH_UCFG_H_

enum {
	HE_SR_PSR_ENABLE                        = 1,
	HE_SR_NON_SRG_OBSSPD_ENABLE             = 2,
	HE_SR_SR15_ENABLE                       = 3,
	HE_SR_SRG_OBSSPD_ENABLE                 = 4,
	HE_SR_ENABLE_PER_AC                     = 5,
};

enum {
	HE_SRP_IE_SRG_BSS_COLOR_BITMAP                 = 1,
	HE_SRP_IE_SRG_PARTIAL_BSSID_BITMAP             = 2,
};

#endif /* OL_ATH_UCFG_H_ */
