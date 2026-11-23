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

/**
 * DOC: wlan_hdd_sysfs_dp_stc.h
 *
 * implementation for creating sysfs files:
 *
 * stc_logmask
 */

#ifndef _WLAN_HDD_SYSFS_DP_STC_H
#define _WLAN_HDD_SYSFS_DP_STC_H

#if defined(WLAN_SYSFS) && defined(WLAN_DP_FEATURE_STC)
/**
 * hdd_sysfs_dp_stc_create() - API to create STC related sysfs entries
 * @driver_kobject: sysfs driver kobject
 *
 * file path:
 *	/sys/kernel/wifi/stc_logmask
 *	/sys/kernel/wifi/stc_tx_aft
 *	/sys/kernel/wifi/stc_c_table
 *	/sys/kernel/wifi/stc_s_table
 *	/sys/kernel/wifi/stc_active_traffic_map
 *
 * usage:
 *      echo [0/1] > stc_logging
 *      cat stc_tx_aft
 *      cat stc_c_table
 *      cat stc_s_table
 *      cat stc_active_traffic_map
 *
 * Return: 0 on success and errno on failure
 */
int hdd_sysfs_dp_stc_create(struct kobject *driver_kobject);

/**
 * hdd_sysfs_dp_stc_destroy() - API to destroy STC related sysfs entries
 * @driver_kobject: sysfs driver kobject
 *
 * Return: None
 */
void hdd_sysfs_dp_stc_destroy(struct kobject *driver_kobject);
#else
static inline void hdd_sysfs_dp_stc_create(struct kobject *driver_kobject)
{
}

static inline void hdd_sysfs_dp_stc_destroy(struct kobject *driver_kobject)
{
}
#endif
#endif /* #ifndef _WLAN_HDD_SYSFS_DP_STC_H */
