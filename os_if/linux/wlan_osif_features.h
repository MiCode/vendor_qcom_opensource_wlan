/*
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: wlan_osif_features.h
 *
 * Define feature flags to cleanly describe when features
 * are present in a given version of the kernel
 */

#ifndef _WLAN_OSIF_FEATURES_H_
#define _WLAN_OSIF_FEATURES_H_

#include <linux/version.h>

/*
 * CFG80211_11BE_BASIC
 * Used to indicate the Linux Kernel contains support for basic 802.11be
 * definitions.
 *
 * These definitions were introduced in Linux Kernel 5.18 via:
 * cbc1ca0a9d0a ieee80211: Add EHT (802.11be) definitions
 * 2a2c86f15e17 ieee80211: add EHT 1K aggregation definitions
 * 5cd5a8a3e2fb cfg80211: Add data structures to capture EHT capabilities
 * 3743bec6120a cfg80211: Add support for EHT 320 MHz channel width
 * cfb14110acf8 nl80211: add EHT MCS support
 * c2b3d7699fb0 nl80211: add support for 320MHz channel limitation
 * 31846b657857 cfg80211: add NO-EHT flag to regulatory
 * ea05fd3581d3 cfg80211: Support configuration of station EHT capabilities
 *
 * These definitions were backported to Android Common Kernel 5.15 via:
 * https://android-review.googlesource.com/c/kernel/common/+/1996261
 * https://android-review.googlesource.com/c/kernel/common/+/1996262
 * https://android-review.googlesource.com/c/kernel/common/+/1996263
 * https://android-review.googlesource.com/c/kernel/common/+/1996264
 * https://android-review.googlesource.com/c/kernel/common/+/1996265
 * https://android-review.googlesource.com/c/kernel/common/+/1996266
 * https://android-review.googlesource.com/c/kernel/common/+/1996267
 * https://android-review.googlesource.com/c/kernel/common/+/1996268
 */

#if (defined(__ANDROID_COMMON_KERNEL__) && \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)) && \
	(LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0))) || \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0))
#define CFG80211_11BE_BASIC 1
#endif

#endif
