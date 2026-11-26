/*
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include <queue.h>
#include "ieee80211_external_config.h"

#ifndef _IEEE80211_WNM_PROTO_H_
#define _IEEE80211_WNM_PROTO_H_

#define IEEE80211_IPV4_LEN 4
#define IEEE80211_IPV6_LEN 16

#define MAC_ADDR_LEN 6

/* categories */
#define IEEE80211_ACTION_CAT_WNM    10   /* Wireless Network Management */

struct tclas_type3 {
	u_int16_t filter_offset;
	u_int8_t  *filter_value;
	u_int8_t  *filter_mask;
	u_int8_t  filter_len;
} __packed;

struct tclas_type10 {
	u_int8_t prot_instance;
	u_int8_t protocol;
	u_int8_t filter_len;
	u_int8_t *filter_value;
	u_int8_t *filter_mask;
} __packed;

struct tclas_type14_v4 {
	u_int8_t  version;
	u_int8_t  src_ip[IEEE80211_IPV4_LEN];
	u_int8_t  dst_ip[IEEE80211_IPV4_LEN];
	u_int16_t src_port;
	u_int16_t dst_port;
	u_int8_t  dscp;
	u_int8_t  protocol;
	u_int8_t  reserved;
} __packed;

struct tclas_type14_v6 {
	u_int8_t version;
	u_int8_t  src_ip[IEEE80211_IPV6_LEN];
	u_int8_t  dst_ip[IEEE80211_IPV6_LEN];
	u_int16_t src_port;
	u_int16_t dst_port;
	u_int8_t  type4_dscp;
	u_int8_t  type4_next_header;
	u_int8_t  flow_label[3];
} __packed;

typedef struct tclas_element {
	u_int8_t  elemid;
	u_int8_t  len;
	u_int8_t  up;
	u_int8_t  type;
	u_int8_t  mask;
	union {
		union {
			struct tclas_type14_v4  type14_v4;
			struct tclas_type14_v6  type14_v6;
		} type14;
		struct tclas_type3  type3;
		struct tclas_type10 type10;
	} tclas;
	TAILQ_ENTRY(tclas_element) tclas_next;
} ieee80211_tclas_element;

#define ieee80211_bstm_req_max_optie 10
struct ieee80211_bstm_reqinfo {
	u_int8_t dialogtoken;
	u_int8_t candidate_list;
	u_int8_t disassoc;
	u_int16_t disassoc_timer;
	u_int8_t validity_itvl;
	u_int8_t bssterm_inc;
	u_int64_t bssterm_tsf;
	u_int16_t bssterm_duration;
	u_int8_t abridged;
	u_int8_t optie_len;
	u_int8_t optie_buf[ieee80211_bstm_req_max_optie];
} __packed;

#define IEEE80211_WNM_WLAN_MAX_MLO_VDEVS 3

/* candidate BSSID for BSS Transition Management Request */
struct ieee80211_bstm_candidate {
	/* candidate BSSID */
	u_int8_t bssid[MAC_ADDR_LEN];
	/* channel number for the candidate BSSID */
	u_int8_t channel_number;
	/* preference from 1-255 (higher number = higher preference) */
	u_int8_t preference;
	/* operating class */
	u_int8_t op_class;
	/* PHY type */
	u_int8_t phy_type;
#ifdef WLAN_FEATURE_11BE_MLO
	/* MLD candidate */
	u_int8_t mld;
	/* MLD MAC */
	u_int8_t mld_addr[MAC_ADDR_LEN];
	u_int8_t recommend_link;
	u_int8_t linkid[IEEE80211_WNM_WLAN_MAX_MLO_VDEVS];
#endif
} __packed;

/*
 * maximum number of candidates in the list.  Value 3 was selected based on a
 * 2 AP network, so may be increased if needed
 */
#define ieee80211_bstm_req_max_candidates 3
/*
 * BSS Transition Management Request information that can be specified via
 * ioctl
 */
struct ieee80211_bstm_reqinfo_target {
	u_int8_t dialogtoken;
	u_int8_t num_candidates;
#if defined(QCN_IE) && (QCN_IE != 0)
	/*If we use trans reason code in QCN IE */
	u_int8_t qcn_trans_reason;
#endif
	/*abrdiged*/
	u_int8_t abridged;
	struct ieee80211_bstm_candidate
		candidates[ieee80211_bstm_req_max_candidates];
	u_int8_t trans_reason;
	u_int8_t disassoc;
	u_int16_t disassoc_timer;
} __packed;

/*
 * When user, via "wifitool athX setbssidpref mac_addr pref_val"
 * command enters a bssid with preference value needed to
 * be assigned to that bssid, it is stored in a structure
 * as given below
 */
struct ieee80211_user_bssid_pref {
	u_int8_t bssid[MAC_ADDR_LEN];
	u_int8_t pref_val;
	u_int8_t regclass;
	u_int8_t chan;
} __packed;

struct ieee80211_bstmresp_ev_data {
	u_int8_t type;
	u_int8_t token;
	u_int8_t status;
	u_int8_t termination_delay;
	u_int8_t peer_mac[6];
	u_int8_t target_mac[6];
	u_int8_t reject_code;
	u_int16_t num_candidate;
	u_int8_t candidates[1];
} __packed;

struct ieee80211_bstmquery_ev_data {
	u_int8_t type;
	u_int8_t token;
	u_int16_t reason;
	u_int16_t num_candidate;
	u_int8_t peer_mac[6];
	u_int8_t candidates[1];
} __packed;

enum {
	BSTM_QUERY_DATA = 1,
	BSTM_RESP_DATA,
	BSTM_INVALID,
};

/* BSTM MBO/QCN Transition Request Reason Code */
enum IEEE80211_BSTM_REQ_REASON_CODE {
	IEEE80211_BSTM_REQ_REASON_UNSPECIFIED,
	IEEE80211_BSTM_REQ_REASON_FRAME_LOSS_RATE,
	IEEE80211_BSTM_REQ_REASON_DELAY_FOR_TRAFFIC,
	IEEE80211_BSTM_REQ_REASON_INSUFFICIENT_BANDWIDTH,
	IEEE80211_BSTM_REQ_REASON_LOAD_BALANCING,
	IEEE80211_BSTM_REQ_REASON_LOW_RSSI,
	IEEE80211_BSTM_REQ_REASON_EXCESSIVE_RETRANSMISSION,
	IEEE80211_BSTM_REQ_REASON_HIGH_INTERFERENCE,
	IEEE80211_BSTM_REQ_REASON_GRAY_ZONE,
	IEEE80211_BSTM_REQ_REASON_PREMIUM_AP,

	IEEE80211_BSTM_REQ_REASON_INVALID
};

/*
 * BSS Transition Management response status codes
 * Taken from 802.11v standard
 */
enum IEEE80211_WNM_BSTM_RESP_STATUS {
	IEEE80211_WNM_BSTM_RESP_SUCCESS,
};

/**
 * enum IEEE80211_BSTM_REJECT_REASON_CODE - BSTM MBO/QCN Transition
 *                                          Rejection Reason Code
 * @IEEE80211_BSTM_REJECT_REASON_UNSPECIFIED:
 * @IEEE80211_BSTM_REJECT_REASON_FRAME_LOSS_RATE: Excessive frame loss rate
 *                                                is expected by STA
 * @IEEE80211_BSTM_REJECT_REASON_DELAY_FOR_TRAFFIC: Excessive traffic delay
 *                                              will be incurred this time
 * @IEEE80211_BSTM_REJECT_REASON_INSUFFICIENT_CAPACITY: Insufficient QoS
 *                   capacity for current traffic stream expected by STA
 * @IEEE80211_BSTM_REJECT_REASON_LOW_RSSI: STA receiving low RSSI in frames
 *                                         from suggested channel(s)
 * @IEEE80211_BSTM_REJECT_REASON_HIGH_INTERFERENCE: High Interference is
 *                                  expected at the candidate channel(s)
 * @IEEE80211_BSTM_REJECT_REASON_SERVICE_UNAVAILABLE: Required services by
 *                              STA are not available on requested channel
 * @IEEE80211_BSTM_REJECT_REASON_INVALID: value 7 - 255 is reserved and
 *                                        considered invalid
 */
enum IEEE80211_BSTM_REJECT_REASON_CODE {
	IEEE80211_BSTM_REJECT_REASON_UNSPECIFIED,
	IEEE80211_BSTM_REJECT_REASON_FRAME_LOSS_RATE,
	IEEE80211_BSTM_REJECT_REASON_DELAY_FOR_TRAFFIC,
	IEEE80211_BSTM_REJECT_REASON_INSUFFICIENT_CAPACITY,
	IEEE80211_BSTM_REJECT_REASON_LOW_RSSI,
	IEEE80211_BSTM_REJECT_REASON_HIGH_INTERFERENCE,
	IEEE80211_BSTM_REJECT_REASON_SERVICE_UNAVAILABLE,
	IEEE80211_BSTM_REJECT_REASON_INVALID
};

typedef struct ieee80211_tclas_processing {
	u_int8_t elem_id;
	u_int8_t length;
	u_int8_t tclas_process;
} __packed ieee80211_tclas_processing;

enum ieee80211_bstm_cmd {
	IEEE80211_SET_BSTMRPT_ENABLE = 1,
	IEEE80211_GET_BSTMRPT_ENABLE = 2,
	IEEE80211_GET_BSTMRPT_IMPLEMENTED = 3,
};

typedef struct ieee80211_bstm_cmd_s {
	enum ieee80211_bstm_cmd cmdid;
	u_int8_t val;
} ieee80211_bstm_cmd_t;

#endif //_IEEE80211_WNM_PROTO_H_
