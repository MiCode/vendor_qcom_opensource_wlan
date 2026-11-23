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

/*
 * Ioctl-related definitions for the Atheros Wireless LAN controller driver.
 */
#ifndef _DEV_ATH_ATHIOCTL_H
#define _DEV_ATH_ATHIOCTL_H

#define CTL_5G_SIZE 1536
#define CTL_2G_SIZE 684
#define MAX_CTL_SIZE (CTL_5G_SIZE > CTL_2G_SIZE ? CTL_5G_SIZE : CTL_2G_SIZE)

typedef struct ath_ctl_table {
	u_int32_t   len;
	u_int8_t   band;
	u_int8_t    ctl_tbl[MAX_CTL_SIZE];
} ath_ctl_table_t;

#define ATH_MAC_ADDR        6
/* Maximum number of associated STAs for which power limit can be sent */
#define WMI_STA_MAX_SIZE   40

struct ath_sta_pwr_table_list {
	u_int8_t peer_mac_addr[ATH_MAC_ADDR]; /* peer MAC Address */
	int32_t peer_pwr_limit;   /* Peer tx power limit */
};

typedef struct ath_sta_pwr_table {
	u_int32_t   num_peers;
	struct ath_sta_pwr_table_list sta_pwr_table_list[WMI_STA_MAX_SIZE];
} ath_sta_pwr_table_t;

#define MAX_PWTAB_SIZE 3392

typedef struct ath_power_table {
	u_int32_t   len;
	u_int32_t   freq_band;
	u_int32_t   sub_band;
	u_int32_t   is_ext;
	u_int32_t   target_type;
	u_int32_t   end_of_update;
	int8_t      pwr_tbl[MAX_PWTAB_SIZE];
} ath_power_table_t;

struct ath_diag {
	char    ad_name[IFNAMSIZ];    /* if name, e.g. "ath0" */
	u_int16_t ad_id;
#define    ATH_DIAG_DYN    0x8000        /* allocate buffer in caller */
#define    ATH_DIAG_IN    0x4000        /* copy in parameters */
#define    ATH_DIAG_OUT    0x0000        /* copy out results (always) */
#define    ATH_DIAG_ID    0x0fff
	u_int16_t ad_in_size;        /* pack to fit, yech */
	caddr_t    ad_in_data;
	caddr_t    ad_out_data;
	u_int    ad_out_size;
};

#endif /* _DEV_ATH_ATHIOCTL_H */
