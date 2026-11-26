/*
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2008 Atheros Communications Inc.
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

#ifndef __IEEE80211_H_
#define __IEEE80211_H_

#include "ieee80211_rrm.h"
#include "ieee80211_wnm_proto.h"
#include "ieee80211_external_config.h"

#ifdef CONFIG_BAND_6GHZ
#define IEEE80211_CHAN_MAX      2047
#else
#define IEEE80211_CHAN_MAX      1023
#endif

/**
 * enum wlan_band_id - Operational wlan band id
 * @WLAN_BAND_UNSPECIFIED: Band id not specified. Default to 2GHz/5GHz band
 * @WLAN_BAND_2GHZ: Band 2.4 GHz
 * @WLAN_BAND_5GHZ: Band 5 GHz
 * @WLAN_BAND_6GHZ: Band 6 GHz
 * @WLAN_BAND_MAX:  Max supported band
 */
enum wlan_band_id {
	WLAN_BAND_UNSPECIFIED = 0,
	WLAN_BAND_2GHZ = 1,
	WLAN_BAND_5GHZ = 2,
	WLAN_BAND_6GHZ = 3,
	/* Add new band definitions here */
	WLAN_BAND_MAX,
};

/* XXX not really a mode; there are really multiple PHY's */
enum ieee80211_phymode {
	IEEE80211_MODE_AUTO             = 0,    /* autoselect */
	IEEE80211_MODE_11A              = 1,    /* 5GHz, OFDM */
	IEEE80211_MODE_11B              = 2,    /* 2GHz, CCK */
	IEEE80211_MODE_11G              = 3,    /* 2GHz, OFDM */
	IEEE80211_MODE_FH               = 4,    /* 2GHz, GFSK */
	/* 5GHz, OFDM, 2x clock dynamic turbo */
	IEEE80211_MODE_TURBO_A          = 5,
	/* 2GHz, OFDM, 2x clock dynamic turbo */
	IEEE80211_MODE_TURBO_G          = 6,
	IEEE80211_MODE_11NA_HT20        = 7,    /* 5Ghz, HT20 */
	IEEE80211_MODE_11NG_HT20        = 8,    /* 2Ghz, HT20 */
	IEEE80211_MODE_11NA_HT40PLUS    = 9,    /* 5Ghz, HT40 (ext ch +1) */
	IEEE80211_MODE_11NA_HT40MINUS   = 10,   /* 5Ghz, HT40 (ext ch -1) */
	IEEE80211_MODE_11NG_HT40PLUS    = 11,   /* 2Ghz, HT40 (ext ch +1) */
	IEEE80211_MODE_11NG_HT40MINUS   = 12,   /* 2Ghz, HT40 (ext ch -1) */
	IEEE80211_MODE_11NG_HT40        = 13,   /* 2Ghz, Auto HT40 */
	IEEE80211_MODE_11NA_HT40        = 14,   /* 5Ghz, Auto HT40 */
	IEEE80211_MODE_11AC_VHT20       = 15,   /* 5Ghz, VHT20 */
	IEEE80211_MODE_11AC_VHT40PLUS   = 16,   /* 5Ghz, VHT40 (Ext ch +1) */
	IEEE80211_MODE_11AC_VHT40MINUS  = 17,   /* 5Ghz  VHT40 (Ext ch -1) */
	IEEE80211_MODE_11AC_VHT40       = 18,   /* 5Ghz, VHT40 */
	IEEE80211_MODE_11AC_VHT80       = 19,   /* 5Ghz, VHT80 */
	IEEE80211_MODE_11AC_VHT160      = 20,   /* 5Ghz, VHT160 */
	IEEE80211_MODE_11AC_VHT80_80    = 21,   /* 5Ghz, VHT80_80 */
	IEEE80211_MODE_11AXA_HE20       = 22,   /* 5GHz, HE20 */
	IEEE80211_MODE_11AXG_HE20       = 23,   /* 2GHz, HE20 */
	IEEE80211_MODE_11AXA_HE40PLUS   = 24,   /* 5GHz, HE40 (ext ch +1) */
	IEEE80211_MODE_11AXA_HE40MINUS  = 25,   /* 5GHz, HE40 (ext ch -1) */
	IEEE80211_MODE_11AXG_HE40PLUS   = 26,   /* 2GHz, HE40 (ext ch +1) */
	IEEE80211_MODE_11AXG_HE40MINUS  = 27,   /* 2GHz, HE40 (ext ch -1) */
	IEEE80211_MODE_11AXA_HE40       = 28,   /* 5GHz, HE40 */
	IEEE80211_MODE_11AXG_HE40       = 29,   /* 2GHz, HE40 */
	IEEE80211_MODE_11AXA_HE80       = 30,   /* 5GHz, HE80 */
	IEEE80211_MODE_11AXA_HE160      = 31,   /* 5GHz, HE160 */
	IEEE80211_MODE_11AXA_HE80_80    = 32,   /* 5GHz, HE80_80 */
#ifdef WLAN_FEATURE_11BE
	IEEE80211_MODE_11BEA_EHT20       = 33,   /* 5GHz, EHT20 */
	IEEE80211_MODE_11BEG_EHT20       = 34,   /* 2GHz, EHT20 */
	IEEE80211_MODE_11BEA_EHT40PLUS   = 35,   /* 5GHz, EHT40 (ext ch +1) */
	IEEE80211_MODE_11BEA_EHT40MINUS  = 36,   /* 5GHz, EHT40 (ext ch -1) */
	IEEE80211_MODE_11BEG_EHT40PLUS   = 37,   /* 2GHz, EHT40 (ext ch +1) */
	IEEE80211_MODE_11BEG_EHT40MINUS  = 38,   /* 2GHz, EHT40 (ext ch -1) */
	IEEE80211_MODE_11BEA_EHT40       = 39,   /* 5GHz, EHT40 */
	IEEE80211_MODE_11BEG_EHT40       = 40,   /* 2GHz, EHT40 */
	IEEE80211_MODE_11BEA_EHT80       = 41,   /* 5GHz, EHT80 */
	IEEE80211_MODE_11BEA_EHT160      = 42,   /* 5GHz, EHT160 */
	IEEE80211_MODE_11BEA_EHT320      = 43,   /* 5GHz, EHT320 */
#endif /* WLAN_FEATURE_11BE */
};

enum ieee80211_cwm_width {
	IEEE80211_CWM_WIDTH20,
	IEEE80211_CWM_WIDTH40,
	IEEE80211_CWM_WIDTH80,
	IEEE80211_CWM_WIDTH160,
	IEEE80211_CWM_WIDTH80_80,
#ifdef WLAN_FEATURE_11BE
	IEEE80211_CWM_WIDTH320,
#endif /* WLAN_FEATURE_11BE */

	IEEE80211_CWM_WIDTH_MAX,
	IEEE80211_CWM_WIDTHINVALID = 0xff    /* user invalid value */
};

/**
 * struct ieee80211_ath_channel - Channels are specified by frequency
 *                                and attributes.
 * @ic_flags: see below
 * @ic_maxregpower: maximum regulatory tx power in dBm
 * @ic_maxpower: maximum tx power in dBm
 * @ic_minpower: minimum tx power in dBm
 * @ic_freq: setting in Mhz
 * @ic_flagext: see below
 * @ic_vhtop_freq_seg1: seg1 Center Channel frequency
 * @ic_vhtop_freq_seg2: Seg2 center Channel frequency index for 80+80MHz mode
 *                      or center Channel frequency of operating span for
 *                      160Mhz mode
 * @reg_punc_pattern: Regulatory puncturing bitmap
 * @op_puncture_bitmap: Operating puncture bitmap obtained after applying
 *                      the user configured puncturing and other puncturing
 *                      restrictions
 * @ic_ieee: IEEE channel number
 * @ic_regClassId: regClassId of this channel
 * @ic_antennamax: antenna gain max from regulatory
 *  11AX TODO (Phase II) - Rename ic_vhtop_ch_freq_seg1/seg2 to make them
 *  agnostic of VHT. This would have to take regulatory convergence into
 *  consideration, which may touch the channel structure to an extent.
 * @ic_vhtop_ch_num_seg1: Seg1 center Channel index
 * @ic_vhtop_ch_num_seg2: Seg2 center Channel index for 80+80MHz mode or
 *  center Channel index of operating span for 160Mhz mode
 */
struct ieee80211_ath_channel {
	u_int64_t       ic_flags;
	int8_t          ic_maxregpower;
	int8_t          ic_maxpower;
	int8_t          ic_minpower;
	u_int16_t       ic_freq;
	u_int16_t       ic_flagext;
	uint16_t        ic_vhtop_freq_seg1;
	uint16_t        ic_vhtop_freq_seg2;
#ifdef WLAN_FEATURE_11BE
	uint16_t        reg_punc_pattern;
	uint16_t        op_puncture_bitmap;
#endif
	u_int8_t        ic_ieee;
	u_int8_t        ic_regClassId;
	u_int8_t        ic_antennamax;
	u_int8_t        ic_vhtop_ch_num_seg1;
	u_int8_t        ic_vhtop_ch_num_seg2;
};

#define IEEE80211_ADDR_LEN  6       /* size of 802.11 address */

/*
 * 802.11 rate set.
 */
#define IEEE80211_RATE_MAXSIZE  44              /* max rates we'll handle */
#define MAX_NUM_OPCLASS_SUPPORTED       64

#ifdef WLAN_FEATURE_11BE
#define IEEE80211_MODE_MAX      (IEEE80211_MODE_11BEA_EHT320 + 1)
#else
#define IEEE80211_MODE_MAX      (IEEE80211_MODE_11AXA_HE80_80 + 1)
#endif /* WLAN_FEATURE_11BE */

/* bits 0-3 are for private use by drivers */
/* channel attributes */
#define IEEE80211_CHAN_20MHZ            0x0000000000000100
#define IEEE80211_CHAN_40PLUS           0x0000000000000200
#define IEEE80211_CHAN_40MINUS          0x0000000000000300

#define IEEE80211_CHAN_HTCAP            0x0000000000001000
#define IEEE80211_CHAN_VHTCAP           0x0000000000002000
#define IEEE80211_CHAN_HECAP            0x0000000000003000
#ifdef WLAN_FEATURE_11BE
#define IEEE80211_CHAN_EHTCAP           0x0000000000004000
#endif /* WLAN_FEATURE_11BE */

#define IEEE80211_CHAN_2GHZ     0x0000000000000010 /* 2 GHz spectrum channel */
#define IEEE80211_CHAN_5GHZ     0x0000000000000020 /* 5 GHz spectrum channel */
#define IEEE80211_CHAN_6GHZ     0x0000000000000030 /* 6 GHz spectrum channel */

/* HT 20 channel */
#define IEEE80211_CHAN_HT20      (IEEE80211_CHAN_HTCAP | IEEE80211_CHAN_20MHZ)
/* HT 40 with extension channel above */
#define IEEE80211_CHAN_HT40PLUS	 (IEEE80211_CHAN_HTCAP | IEEE80211_CHAN_40PLUS)
/* HT 40 with extension channel below */
#define IEEE80211_CHAN_HT40MINUS (IEEE80211_CHAN_HTCAP | IEEE80211_CHAN_40MINUS)

#define IEEE80211_CHAN_CCK  0x0000000000200000 /* CCK channel */
#define IEEE80211_CHAN_OFDM 0x0000000000400000 /* OFDM channel */
#define IEEE80211_CHAN_DYN  0x0000000000800000 /* Dynamic CCK-OFDM channel */

#define IEEE80211_CHAN_TURBO            0x0000000020000000 /* Turbo channel */

#define IEEE80211_CHAN_CAP_MASK         0x000000000000F000

#define IEEE80211_CHAN_BAND_MASK  0x00000000000000F0 /* Mask only band */
#define IEEE80211_CHAN_BW_MASK    0x000000000000FF00 /* Mask only bandwidths */

#define IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)

#define IEEE80211_CHAN_108A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)
#define IEEE80211_CHAN_108G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)

#define IEEE80211_IS_FLAG_2GHZ(_flag) \
	(((_flag) & IEEE80211_CHAN_BAND_MASK) == IEEE80211_CHAN_2GHZ)
#define IEEE80211_IS_FLAG_5GHZ(_flag) \
	(((_flag) & IEEE80211_CHAN_BAND_MASK) == IEEE80211_CHAN_5GHZ)
#define IEEE80211_IS_FLAG_6GHZ(_flag) \
	(((_flag) & IEEE80211_CHAN_BAND_MASK) == IEEE80211_CHAN_6GHZ)

#define IEEE80211_IS_FLAG_HT20(_flag) \
	(((_flag) & IEEE80211_CHAN_BW_MASK) == IEEE80211_CHAN_HT20)
#define IEEE80211_IS_FLAG_HT40PLUS(_flag) \
	(((_flag) & IEEE80211_CHAN_BW_MASK) == IEEE80211_CHAN_HT40PLUS)
#define IEEE80211_IS_FLAG_HT40MINUS(_flag) \
	(((_flag) & IEEE80211_CHAN_BW_MASK) == IEEE80211_CHAN_HT40MINUS)

#define IEEE80211_IS_FLAG_VHT(_flag) \
	(((_flag) & IEEE80211_CHAN_CAP_MASK) == IEEE80211_CHAN_VHTCAP)
#define IEEE80211_IS_FLAG_HE(_flag) \
	(((_flag) & IEEE80211_CHAN_CAP_MASK) == IEEE80211_CHAN_HECAP)
#define IEEE80211_IS_FLAG_EHT(_flag) \
	    (((_flag) & IEEE80211_CHAN_CAP_MASK) == IEEE80211_CHAN_EHTCAP)

#define IEEE80211_IS_FLAG_TURBO(_flag) \
	((_flag) & IEEE80211_CHAN_TURBO)

#define IEEE80211_IS_CHAN_2GHZ(_c) \
	IEEE80211_IS_FLAG_2GHZ((_c)->ic_flags)
#define IEEE80211_IS_CHAN_5GHZ(_c) \
	IEEE80211_IS_FLAG_5GHZ((_c)->ic_flags)
#define IEEE80211_IS_CHAN_6GHZ(_c) \
	IEEE80211_IS_FLAG_6GHZ((_c)->ic_flags)
#define IEEE80211_IS_CHAN_BW_HT20(_c) \
	IEEE80211_IS_FLAG_HT20((_c)->ic_flags)

#define IEEE80211_IS_CHAN_BW_HT40PLUS(_c) \
	IEEE80211_IS_FLAG_HT40PLUS((_c)->ic_flags)
#define IEEE80211_IS_CHAN_BW_HT40MINUS(_c) \
	IEEE80211_IS_FLAG_HT40MINUS((_c)->ic_flags)

#define IEEE80211_IS_CHAN_BW_VHT(_c) \
	IEEE80211_IS_FLAG_VHT((_c)->ic_flags)
#define IEEE80211_IS_CHAN_BW_HE(_c) \
	IEEE80211_IS_FLAG_HE((_c)->ic_flags)

#define IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) \
	(IEEE80211_IS_CHAN_5GHZ(_c) || IEEE80211_IS_CHAN_6GHZ(_c))

#define IEEE80211_IS_CHAN_BW_EHT(_c)   IEEE80211_IS_FLAG_EHT((_c)->ic_flags)

#define IEEE80211_IS_CHAN_EHT(_c)  IEEE80211_IS_CHAN_BW_EHT(_c)

#define IEEE80211_IS_CHAN_108A(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_108A) == IEEE80211_CHAN_108A)
#define IEEE80211_IS_CHAN_108G(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_108G) == IEEE80211_CHAN_108G)

#define IEEE80211_IS_CHAN_TURBO(_c) \
	IEEE80211_IS_FLAG_TURBO((_c)->ic_flags)
#define IEEE80211_IS_CHAN_ANYG(_c) \
	(IEEE80211_IS_CHAN_PUREG(_c) || IEEE80211_IS_CHAN_G(_c))
#define IEEE80211_IS_CHAN_A(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define IEEE80211_IS_CHAN_B(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define IEEE80211_IS_CHAN_PUREG(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define IEEE80211_IS_CHAN_G(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define IEEE80211_IS_CHAN_11N(_c) \
	(IEEE80211_IS_CHAN_BW_HT20(_c) || \
	 IEEE80211_IS_CHAN_BW_HT40MINUS(_c) || \
	 IEEE80211_IS_CHAN_BW_HT40PLUS(_c))
#define IEEE80211_IS_CHAN_11NG(_c) \
	(IEEE80211_IS_CHAN_2GHZ(_c) && IEEE80211_IS_CHAN_11N(_c))
#define IEEE80211_IS_CHAN_11NA(_c) \
	(IEEE80211_IS_CHAN_5GHZ(_c) && IEEE80211_IS_CHAN_11N(_c))

#define IEEE80211_IS_CHAN_VHT(_c) IEEE80211_IS_CHAN_BW_VHT(_c)

#define IEEE80211_IS_CHAN_11AC(_c) \
	(IEEE80211_IS_CHAN_5GHZ(_c) && IEEE80211_IS_CHAN_VHT(_c))

#define IEEE80211_IS_CHAN_HE(_c)  IEEE80211_IS_CHAN_BW_HE(_c)

#define IEEE80211_IS_CHAN_11AX(_c) \
	((IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) || IEEE80211_IS_CHAN_2GHZ(_c)) && \
	 IEEE80211_IS_CHAN_HE(_c))

#define IEEE80211_IS_CHAN_11BE(_c) \
	((IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) || IEEE80211_IS_CHAN_2GHZ(_c)) && \
	 IEEE80211_IS_CHAN_EHT(_c))

struct ieee80211_rateset {
	u_int8_t                rs_nrates;
	u_int8_t                rs_rates[IEEE80211_RATE_MAXSIZE];
};

/**
 * enum wlan_channel_dfs_state - DFS  channel states.
 * @WLAN_CH_DFS_S_INVALID: The DFS state for invalid channel numbers
 *                         that are not part of the radio's channel list.
 * @WLAN_CH_DFS_S_CAC_REQ: Indicates that the CAC/Off-channel CAC has
 *                         to performed before Tx on the DFS channel.
 * @WLAN_CH_DFS_S_CAC_STARTED: Indicates that the CAC has been started
 *                         for the DFS channel.
 * @WLAN_CH_DFS_S_CAC_COMPLETED: Indicates that the CAC has been completed
 *                               for the DFS channel.
 * @WLAN_CH_DFS_S_NOL: Indicates that the DFS channel is in NOL.
 * @WLAN_CH_DFS_S_PRECAC_STARTED: Indicates that the PreCAC has been
 *                                started for the DFS channel.
 * @WLAN_CH_DFS_S_PRECAC_COMPLETED: Indicates that the PreCAC has been
 *                                  completed for the DFS channel.
 * @WLAN_CH_DFS_S_NON_DFS: Indicates that it is a non-DFS channel.
 */
enum wlan_channel_dfs_state {
	WLAN_CH_DFS_S_INVALID,
	WLAN_CH_DFS_S_CAC_REQ,
	WLAN_CH_DFS_S_CAC_STARTED,
	WLAN_CH_DFS_S_CAC_COMPLETED,
	WLAN_CH_DFS_S_NOL,
	WLAN_CH_DFS_S_PRECAC_STARTED,
	WLAN_CH_DFS_S_PRECAC_COMPLETED,
	WLAN_CH_DFS_S_NON_DFS,
};

#define NUM_5GHZ_CHANS 40

enum wlan_afc_power_type {
	AFC_POWER_TYPE_LP,
	AFC_POWER_TYPE_SP,
	AFC_POWER_TYPE_VLP,
	AFC_POWER_TYPE_MAX,
};

struct wlan_chan_6g {
	uint8_t chan_idx;
	uint8_t cfreq2;
	uint16_t puncture_bitmap;
	int16_t psd_pwr;
	int32_t eirp_pwr;
};

/* Rounded value */
#define NUM_6GHZ_CHANS 60

struct wlan_chan_list_6g {
	uint16_t num_valid_chan[IEEE80211_CWM_WIDTH_MAX];
	struct wlan_chan_6g chan[IEEE80211_CWM_WIDTH_MAX][NUM_6GHZ_CHANS];
};

#endif //__IEEE80211_H_
