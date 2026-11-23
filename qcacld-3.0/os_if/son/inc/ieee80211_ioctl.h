/*
 * Copyright (c) 2023-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2010, Atheros Communications Inc.
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

#ifndef _IEEE80211_IOCTL_H_
#define _IEEE80211_IOCTL_H_

#if defined(QCA_AIRTIME_FAIRNESS) && (QCA_AIRTIME_FAIRNESS != 0)
#include <wlan_atf_utils_defs.h>
#endif
#include <_ieee80211.h>
#include "ieee80211.h"
#include "ieee80211_defines.h"
#include <ext_ioctl_drv_if.h>
#include <wlan_son_ioctl.h>

#include <cfg80211_ven_cmd.h>

#define VENDOR_CHAN_FLAG2(_flag)  \
	    ((uint64_t)(_flag) << 32)

#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_6GHZ (1 << 4)
#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_A (1 << 5)
#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_B (1 << 6)
#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_EXT_PSC (1 << 10)

#define TR69_MAX_BUF_LEN    800

#define MAP_DEFAULT_PPDU_DURATION 100
#define MAP_PPDU_DURATION_UNITS 50

#define DEFAULT_IDENTIFIER 0
#define COEX_CFG_MAX_ARGS 6

/*
 * BA Window Size Subfield Encoding
 */
typedef enum wlan_ba_window_size {
	ba_window_not_used = 0,
	ba_window_size_2 = 2,
	ba_window_size_4 = 4,
	ba_window_size_6 = 6,
	ba_window_size_8 = 8,
	ba_window_size_16 = 16,
	ba_window_size_32 = 32,
	ba_window_size_64 = 64,
} wlan_ba_window_size;

/*
 * Data Format Subfield Encoding
 */
typedef enum wlan_data_format {
	data_no_aggregation_enabled,
	data_amsdu_aggregation_enabled,
	data_ampdu_aggregation_enabled,
	data_amsdu_ampdu_aggregation_enabled,
	data_aggregation_max,  // always last
} wlan_data_format;

typedef struct beacon_rssi_info {
	struct beacon_rssi_stats {
		u_int32_t   ni_last_bcn_snr;
		u_int32_t   ni_last_bcn_age;
		u_int32_t   ni_last_bcn_cnt;
		u_int64_t   ni_last_bcn_jiffies;
	} stats;
	u_int8_t macaddr[IEEE80211_ADDR_LEN];
} beacon_rssi_info;

typedef struct ack_rssi_info {
	struct ack_rssi_stats {
		u_int32_t   ni_last_ack_rssi;
		u_int32_t   ni_last_ack_age;
		u_int32_t   ni_last_ack_cnt;
		u_int64_t   ni_last_ack_jiffies;
	} stats;
	u_int8_t macaddr[IEEE80211_ADDR_LEN];
} ack_rssi_info;

struct ieee80211_channel_info {
	uint8_t ieee;
	uint16_t freq;
	uint64_t flags;
	uint32_t flags_ext;
	uint8_t vhtop_ch_num_seg1;
	uint8_t vhtop_ch_num_seg2;
};

typedef struct ieee80211req_acs_r {
	u_int32_t index;
	u_int32_t data_size;
	void *data_addr;
} ieee80211req_acs_t;

#define ACS_MAX_CHANNEL_COUNT 255
typedef struct ieee80211_user_chanlist_r {
	u_int16_t n_chan;
	struct ieee80211_chan_def chans[ACS_MAX_CHANNEL_COUNT];
} ieee80211_user_chanlist_t;

typedef struct ieee80211_user_ctrl_tbl_r {
	u_int16_t ctrl_len;
	u_int8_t *ctrl_table_buff;
} ieee80211_user_ctrl_tbl_t;

/*
 * Wlan Latency Parameters
 */
typedef struct wlan_latency_info {
	uint32_t tid;
	uint32_t dl_ul_enable;
	uint32_t service_interval;
	uint32_t burst_size;
	uint32_t burst_size_add_or_sub;
	uint8_t  peer_mac[IEEE80211_ADDR_LEN];
} wlan_latency_info_t;

#define MAX_CUSTOM_CHANS	 101

typedef struct {
	/* Number of channels to scan, 0 for all channels */
	u_int8_t     scan_numchan_associated;
	u_int8_t     scan_numchan_nonassociated;
	struct ieee80211_chan_def
		scan_channel_list_associated[MAX_CUSTOM_CHANS];
	struct ieee80211_chan_def
		scan_channel_list_nonassociated[MAX_CUSTOM_CHANS];
} ieee80211req_custom_chan_t;

typedef struct ieee80211_wide_band_scan {
	u_int8_t bw_mode;
	u_int8_t sec_chan_offset;
} ieee80211_wide_band_scan_t;

/**
 * struct ieee80211_offchan_tx_test: off channel tx parameters
 * @band: band in which off chan tx has to happen
 * @ieee_chan: primary 20 offchan tx chan
 * @dwell_time: Dwell time
 * @wide_scan: indicated wide bandwidth scan
 * @ieee_cfreq2: center frequency of continuous bandwidth channel of center freq
 *	           of secondary 80 of 80+80 channel
 */
typedef struct ieee80211_offchan_tx_test {
	u_int8_t band;
	u_int8_t ieee_chan;
	u_int16_t dwell_time;
	ieee80211_wide_band_scan_t wide_scan;
	u_int8_t ieee_cfreq2;
} ieee80211_offchan_tx_test_t;

typedef struct ieee80211_node_info {
	u_int16_t count;
	u_int16_t bin_number;
	u_int32_t traf_rate;
} ieee80211_node_info_t;

struct ieee80211req_fake_mgmt {
	u_int32_t buflen;  /*application supplied buffer length */
	u_int8_t  *buf;
};

/*
 * command id's for use in tr069 request
 */
typedef enum _ieee80211_tr069_cmd_ {
	TR069_CHANHIST           = 1,
	TR069_TXPOWER            = 2,
	TR069_GETTXPOWER         = 3,
	TR069_GUARDINTV          = 4,
	TR069_GET_GUARDINTV      = 5,
	TR069_GETASSOCSTA_CNT    = 6,
	TR069_GETTIMESTAMP       = 7,
	TR069_GETDIAGNOSTICSTATE = 8,
	TR069_GETNUMBEROFENTRIES = 9,
	TR069_GET11HSUPPORTED    = 10,
	TR069_GETPOWERRANGE      = 11,
	TR069_SET_OPER_RATE      = 12,
	TR069_GET_OPER_RATE      = 13,
	TR069_GET_POSIBLRATE     = 14,
	TR069_SET_BSRATE         = 15,
	TR069_GET_BSRATE         = 16,
	TR069_GETSUPPORTEDFREQUENCY  = 17,
	TR069_GET_PLCP_ERR_CNT   = 18,
	TR069_GET_FCS_ERR_CNT    = 19,
	TR069_GET_PKTS_OTHER_RCVD = 20,
	TR069_GET_FAIL_RETRANS_CNT = 21,
	TR069_GET_RETRY_CNT      = 22,
	TR069_GET_MUL_RETRY_CNT  = 23,
	TR069_GET_ACK_FAIL_CNT   = 24,
	TR069_GET_AGGR_PKT_CNT   = 25,
	TR069_GET_STA_BYTES_SENT = 26,
	TR069_GET_STA_BYTES_RCVD = 27,
	TR069_GET_DATA_SENT_ACK  = 28,
	TR069_GET_DATA_SENT_NOACK = 29,
	TR069_GET_CHAN_UTIL      = 30,
	TR069_GET_RETRANS_CNT    = 31,
	TR069_GET_RRM_UTIL       = 32,
	TR069_GET_CSA_DEAUTH     = 33,
	TR069_SET_CSA_DEAUTH     = 34,
} ieee80211_tr069_cmd;

/*
 * common structure to handle tr069 commands;
 * the cmdid and data pointer has to be appropriately
 * filled in
 */
typedef struct{
	u_int32_t data_size;
	ieee80211_tr069_cmd cmdid;
	u_int8_t data_buff[TR69_MAX_BUF_LEN];
} ieee80211req_tr069_t;

typedef struct ieee80211req_fips {
	u_int32_t data_size;
	void *data_addr;
} ieee80211req_fips_t;

#define MAX_FW_UNIT_TEST_NUM_ARGS 100
/**
 * struct ieee80211_fw_unit_test_cmd - unit test command parameters
 * @module_id: module id
 * @num_args: number of arguments
 * @diag_token: Token representing the transaction ID (between host and fw)
 * @args: arguments
 */
struct ieee80211_fw_unit_test_cmd {
		u_int32_t module_id;
		u_int32_t num_args;
		u_int32_t diag_token;
		u_int32_t args[MAX_FW_UNIT_TEST_NUM_ARGS];
} __attribute__((packed));

/*
 * Parameters that can be configured by userspace on a per client
 * basis
 */
typedef struct ieee80211_acl_cli_param_t {
	u_int8_t  probe_rssi_hwm;
	u_int8_t  probe_rssi_lwm;
	u_int8_t  inact_snr_xing;
	u_int8_t  low_snr_xing;
	u_int8_t  low_rate_snr_xing;
	u_int8_t  high_rate_snr_xing;
	u_int8_t  auth_block;
	u_int8_t  auth_rssi_hwm;
	u_int8_t  auth_rssi_lwm;
	u_int8_t  auth_reject_reason;
} ieee80211_acl_cli_param_t;

typedef struct __ieee80211req_dbptrace {
	u_int32_t dp_trace_subcmd;
	u_int32_t val1;
	u_int32_t val2;
} ieee80211req_dptrace;

/**
 * struct coex_cfg_t - coex configuration command parameters
 * @type: config type (wmi_coex_config_type enum)
 * @arg: arguments based on config type
 */
typedef struct {
	u_int32_t type;
	u_int32_t arg[COEX_CFG_MAX_ARGS];
} coex_cfg_t;

struct ieee80211_twt_add_dialog {
	uint32_t dialog_id;
	uint32_t wake_intvl_us;
	uint32_t wake_intvl_mantis;
	uint32_t wake_dura_us;
	uint32_t sp_offset_us;
	uint32_t twt_cmd;
	uint32_t flags;
};

#ifdef WLAN_SUPPORT_TWT
struct ieee80211_twt_del_pause_dialog {
	uint32_t dialog_id;
#ifdef WLAN_SUPPORT_BCAST_TWT
	uint32_t b_twt_persistence;
#endif
};

struct ieee80211_twt_resume_dialog {
	uint32_t dialog_id;
	uint32_t sp_offset_us;
	uint32_t next_twt_size;
};

#ifdef WLAN_SUPPORT_BCAST_TWT
struct ieee80211_twt_btwt_sta_inv_remove {
	uint32_t dialog_id;
};
#endif
#endif

#if UMAC_SUPPORT_VI_DBG
/**
 * struct ieee80211_vow_dbg_stream_param
 * @stream_num: the stream number whose markers are being set
 * @marker_num: the marker number whose parameters (offset, size & match)
 *              are being set
 * @marker_offset: byte offset from skb start (upper 16 bits) & size in
 *                 bytes(lower 16 bits)
 * @marker_match:  marker pattern match used in filtering
 */
typedef struct ieee80211_vow_dbg_stream_param {
	u_int8_t  stream_num;
	u_int8_t  marker_num;
	u_int32_t marker_offset;
	u_int32_t marker_match;
} ieee80211_vow_dbg_stream_param_t;

/**
 * struct ieee80211_vow_dbg_param
 * @num_stream: Number of streams
 * @num_marker: total number of markers used to filter pkts
 * @rxq_offset: Rx Seq num offset skb start (upper 16 bits) & size
 *              in bytes(lower 16 bits)
 * @rxq_shift:  right-shift value in case field is not word aligned
 * @rxq_max: Max Rx seq number
 * @time_offset:  Time offset for the packet
 */
typedef struct ieee80211_vow_dbg_param {
	u_int8_t  num_stream;
	u_int8_t  num_marker;
	u_int32_t rxq_offset;
	u_int32_t rxq_shift;
	u_int32_t rxq_max;
	u_int32_t time_offset;
} ieee80211_vow_dbg_param_t;
#endif

#define MAX_SCAN_CHANS       32

#if QCA_LTEU_SUPPORT
/**
 * enum mu_algo_t
 * @MU_ALGO_1: Basic binning algo
 * @MU_ALGO_2: Enhanced binning algo
 * @MU_ALGO_3: Enhanced binning including accounting for hidden nodes
 * @MU_ALGO_4: TA based MU calculation
 */
typedef enum {
	MU_ALGO_1 = 0x1,
	MU_ALGO_2 = 0x2,
	MU_ALGO_3 = 0x4,
	MU_ALGO_4 = 0x8,
} mu_algo_t;

/**
 * struct ieee80211req_mu_scan_t
 * @mu_req_id: MU request id
 * @mu_channel: IEEE channel number on which to do MU scan
 * @mu_type: Rx which MU algo to use
 * @mu_duration: Duration of the scan in ms
 * @lteu_tx_power: LTEu Tx power
 * @mu_rssi_thr_bssid: RSSI threshold to account for active APs
 * @mu_rssi_thr_sta: RSSI threshold to account for active STAs
 * @mu_rssi_thr_sc: RSSI threshold to account for active small cells
 * @home_plmnid: To be compared with PLMN ID to distinguish same and
 *               different operator WCUBS
 * @alpha_num_bssid: Alpha for num active bssid calculation,kept for
 *                   backward compatibility
 */
typedef struct {
	u_int8_t     mu_req_id;
	u_int8_t     mu_channel;
	mu_algo_t    mu_type;
	u_int32_t    mu_duration;
	u_int32_t    lteu_tx_power;
	u_int32_t    mu_rssi_thr_bssid;
	u_int32_t    mu_rssi_thr_sta;
	u_int32_t    mu_rssi_thr_sc;
	u_int32_t    home_plmnid;
	u_int32_t    alpha_num_bssid;
} ieee80211req_mu_scan_t;

#define LTEU_MAX_BINS        10

/**
 * struct ieee80211req_lteu_cfg_t
 * @lteu_gpio_start: Start MU/AP scan after GPIO toggle
 * @lteu_num_bins: No. of elements in the following arrays
 * @use_actual_nf: Whether to use the actual NF obtained or a hardcoded one
 * @lteu_weight: Weights for MU algo
 * @lteu_thresh: Thresholds for MU algo
 * @lteu_gamma:  Gamma's for MU algo
 * @lteu_scan_timeout:  Timeout in ms to gpio toggle
 * @alpha_num_bssid: Alpha for num active bssid calculation
 * @lteu_cfg_reserved_1: Used to indicate to fw whether or not packets with
 *                    phy error are to be included in MU calculation or not
 */
typedef struct {
	u_int8_t     lteu_gpio_start;
	u_int8_t     lteu_num_bins;
	u_int8_t     use_actual_nf;
	u_int32_t    lteu_weight[LTEU_MAX_BINS];
	u_int32_t    lteu_thresh[LTEU_MAX_BINS];
	u_int32_t    lteu_gamma[LTEU_MAX_BINS];
	u_int32_t    lteu_scan_timeout;
	u_int32_t    alpha_num_bssid;
	u_int32_t    lteu_cfg_reserved_1;
} ieee80211req_lteu_cfg_t;

typedef enum {
	SCAN_PASSIVE,
	SCAN_ACTIVE,
} scan_type_t;

/**
 * struct ieee80211req_ap_scan_t
 * @scan_req_id: AP scan request id
 * @scan_num_chan: Number of channels to scan, 0 for all channels
 * @scan_channel_list: IEEE channel number of channels to scan
 * @scan_type: Scan type - active or passive
 * @scan_duration: Duration in ms for which a channel is scanned, 0 for default
 * @scan_repeat_probe_time: Time before sending second probe request,
 *                          (u32)(-1) for default
 * @scan_rest_time: Time in ms on the BSS channel, (u32)(-1) for default
 * @scan_idle_time: Time in msec on BSS channel before switching channel,
 *                  (u32)(-1) for default
 * @scan_probe_delay: Delay in msec before sending probe request,
 *                    (u32)(-1) for default
 */
typedef struct {
	u_int8_t     scan_req_id;
	u_int8_t     scan_num_chan;
	u_int8_t     scan_channel_list[MAX_SCAN_CHANS];
	scan_type_t  scan_type;
	u_int32_t    scan_duration;
	u_int32_t    scan_repeat_probe_time;
	u_int32_t    scan_rest_time;
	u_int32_t    scan_idle_time;
	u_int32_t    scan_probe_delay;
} ieee80211req_ap_scan_t;
#endif /* QCA_LTEU_SUPPORT */

/*
 * Opcodes to add or delete or print stats for a flow tag
 */
typedef enum {
	RX_FLOW_TAG_OPCODE_ADD,
	RX_FLOW_TAG_OPCODE_DEL,
	RX_FLOW_TAG_OPCODE_DUMP_STATS,
} RX_FLOW_TAG_OPCODE_TYPE;

/*
 * IP protocol version type
 */
typedef enum {
	IP_VER_4,
	IP_VER_6
} IP_VER_TYPE;

/*
 * Layer 4 Protocol types supported for flow tagging
 */
typedef enum {
	L4_PROTOCOL_TYPE_TCP,
	L4_PROTOCOL_TYPE_UDP,
} L4_PROTOCOL_TYPE;

/**
 * struct ieee80211_rx_flow_tuple - 5-tuple for RX flow
 * @source_ip: L3 Source IP address (v4 and v6)
 * @dest_ip: L3 Destination IP address (v4 and v6)
 * @source_port: L4 Source port
 * @dest_port: L4 Destination port
 * @protocol: L4 Protocol type (TCP or UDP)
 */
struct ieee80211_rx_flow_tuple {
	uint32_t                source_ip[4];
	uint32_t                dest_ip[4];
	uint16_t                source_port;
	uint16_t                dest_port;
	L4_PROTOCOL_TYPE        protocol;
};

struct ieee80211_rx_flow_info {
	uint32_t svc_id;
	uint8_t tid;
	uint8_t drop_flow;
	uint8_t ring_id;
	u_int8_t dstmac[IEEE80211_ADDR_LEN];
};

/**
 * struct ieee80211_rx_flow_tag - Parameters for configuring RX flow tag
 * @op_code: operation to be performed
 * @ip_ver: IPv4 or IPv6 version
 * @flow_tuple: 5-tuple info per flow
 * @flow_info: flow information
 * @flow_metadata: flow meta data for above 5 tuple
 */
typedef struct ieee80211_rx_flow_tag {
	RX_FLOW_TAG_OPCODE_TYPE         op_code;
	IP_VER_TYPE                     ip_ver;
	struct ieee80211_rx_flow_tuple  flow_tuple;
	struct ieee80211_rx_flow_info   flow_info;
	uint16_t                        flow_metadata;
} ieee80211_wlanconfig_rx_flow_tag;

#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
typedef struct ieee80211_primary_allowed_chanlist {
	u_int8_t n_chan;
	struct ieee80211_chan_def chans[ACS_MAX_CHANNEL_COUNT];
} ieee80211_primary_allowed_chanlist_t;
#endif

#ifdef QCA_SUPPORT_SCAN_SPCL_VAP_STATS
/**
 * struct ieee80211_scan_spcl_vap_stats
 * @tx_ok_pkts: Raw frame home chan tx success cnt
 * @tx_ok_bytes: Raw frame home chan tx success bytes
 * @tx_retry_pkts: Raw frame home chan tx retry cnt
 * @tx_retry_bytes: Raw frame home chan tx retry bytes
 * @tx_err_pkts: Raw frame home chan tx err cnt
 * @tx_err_bytes:  Raw frame home chan tx err bytes
 * @rx_ok_pkts: RX fcs err cnt
 * @rx_ok_bytes: RX fcs ok bytes
 * @rx_err_pkts: RX fcs err cnt
 * @rx_err_bytes: RX fcs err bytes
 * @rx_mgmt_pkts: RX mgmt cnt
 * @rx_ctrl_pkts:  RX ctrl cnt
 * @rx_data_pkts:  RX data cnt
 */
typedef struct ieee80211_scan_spcl_vap_stats {
	uint64_t tx_ok_pkts;
	uint64_t tx_ok_bytes;
	uint64_t tx_retry_pkts;
	uint64_t tx_retry_bytes;
	uint64_t tx_err_pkts;
	uint64_t tx_err_bytes;
	uint64_t rx_ok_pkts;
	uint64_t rx_ok_bytes;
	uint64_t rx_err_pkts;
	uint64_t rx_err_bytes;
	uint64_t rx_mgmt_pkts;
	uint64_t rx_ctrl_pkts;
	uint64_t rx_data_pkts;
} ieee80211_scan_spcl_vap_stats_t;
#endif

struct acs_chan_weightage {
	uint8_t  band;
	uint16_t chnum;
	uint8_t  weightage;
};

struct acs_chan_weightage_list {
	uint8_t  get;
	uint8_t  append;
	uint16_t last_idx;
	struct acs_chan_weightage chan[IEEE80211_CHAN_MAX];
};

typedef struct ieee80211_opclass_chan_list {
	uint8_t is_disable;
	uint8_t n_chan;
	uint8_t opclass;
	uint8_t chans[MAX_CHANNELS_PER_OP_CLASS];
} ieee80211_opclass_chan_list_t;

struct ieee80211_wfa_test_cmd {
	uint8_t module_id;
	uint8_t cmd_id;
	uint8_t num_args;
	uint32_t args[100];
} __attribute__((packed));

struct ieee80211req_athdbg {
	u_int8_t cmd;
	u_int8_t needs_reply;
	u_int8_t dstmac[IEEE80211_ADDR_LEN];
	union {
		u_long param[5];
		ieee80211_rrm_beaconreq_info_t bcnrpt;
		ieee80211_rrm_tsmreq_info_t    tsmrpt;
		ieee80211_rrm_nrreq_info_t     neigrpt;
		struct ieee80211_bstm_reqinfo   bstmreq;
		struct ieee80211_bstm_reqinfo_target   bstmreq_target;
		struct ieee80211_mscs_resp      mscsresp;
		struct ieee80211_mscs_disallow_db disallow_mscs_list;
		struct ieee80211_qos_mgmt_ie    qos_data;
		struct ieee80211_qos_req        dscp_req;
#ifdef WLAN_SUPPORT_SCS
		struct ieee80211_scs_resp       scsresp;
#endif
		struct ieee80211_user_bssid_pref bssidpref;
		ieee80211_tspec_info     tsinfo;
		ieee80211_rrm_cca_info_t   cca;
		ieee80211_rrm_rpihist_info_t   rpihist;
		ieee80211_rrm_chloadreq_info_t chloadrpt;
		ieee80211_rrm_stastats_info_t  stastats;
		ieee80211_rrm_nhist_info_t     nhist;
		ieee80211_rrm_frame_req_info_t frm_req;
		ieee80211_rrm_lcireq_info_t    lci_req;
		ieee80211req_rrmstats_t        rrmstats_req;
		ieee80211req_acs_t             acs_rep;
		ieee80211req_tr069_t           tr069_req;
		timespec_t t_spec;
		ieee80211req_fips_t fips_req;
		//ieee80211req_fips_mode_t fips_mode_req;
		struct ieee80211_qos_map       qos_map;
		ieee80211_acl_cli_param_t      acl_cli_param;
		ieee80211_offchan_tx_test_t offchan_req;
#if defined(UMAC_SUPPORT_VI_DBG) && (UMAC_SUPPORT_VI_DBG != 0)
		ieee80211_vow_dbg_stream_param_t   vow_dbg_stream_param;
		ieee80211_vow_dbg_param_t	   vow_dbg_param;
#endif

#if defined(QCA_LTEU_SUPPORT) && (QCA_LTEU_SUPPORT != 0)
		ieee80211req_mu_scan_t         mu_scan_req;
		ieee80211req_lteu_cfg_t        lteu_cfg;
		ieee80211req_ap_scan_t         ap_scan_req;
#endif
		ieee80211req_custom_chan_t     custom_chan_req;
#if defined(QCA_AIRTIME_FAIRNESS) && (QCA_AIRTIME_FAIRNESS != 0)
		//atf_debug_req_t                atf_dbg_req;
#endif
		struct ieee80211_fw_unit_test_cmd	fw_unit_test_cmd;
		ieee80211_user_ctrl_tbl_t      *user_ctrl_tbl;
		ieee80211_user_chanlist_t      user_chanlist;
		ieee80211req_dptrace           dptrace;
		coex_cfg_t                     coex_cfg_req;
#if defined(ATH_ACL_SOFTBLOCKING) && (ATH_ACL_SOFTBLOCKING != 0)
		u_int8_t                       acl_softblocking;
#endif
		u_int8_t twt_enable;
#ifdef WLAN_SUPPORT_TWT
		struct ieee80211_twt_add_dialog twt_add;
		struct ieee80211_twt_del_pause_dialog twt_del_pause;
		struct ieee80211_twt_resume_dialog twt_resume;
#ifdef WLAN_SUPPORT_BCAST_TWT
		struct ieee80211_twt_btwt_sta_inv_remove
				twt_btwt_sta_inv_remove;
#endif
#endif
		ieee80211_node_info_t          node_info;
		beacon_rssi_info               beacon_rssi_info;
		ack_rssi_info                  ack_rssi_info;
#ifdef WLAN_SUPPORT_RX_FLOW_TAG
		ieee80211_wlanconfig_rx_flow_tag rx_flow_tag_info;
#endif /* WLAN_SUPPORT_RX_FLOW_TAG */
		ieee80211_user_nrresp_info_t   *neighrpt_custom;
#ifdef WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
		ieee80211_primary_allowed_chanlist_t primary_allowed_chanlist;
#endif
		struct ieee80211req_fake_mgmt mgmt_frm;
		struct ieee80211_tpe_ie_config tpe_conf;
		wlan_latency_info_t wlan_latency_info;
#ifdef QCA_SUPPORT_SCAN_SPCL_VAP_STATS
		ieee80211_scan_spcl_vap_stats_t scan_spcl_vap_stats;
#endif
		struct ieee80211_wfa_test_cmd wfa_test_cmd;
		struct acs_chan_weightage_list acs_chanweightage_chlist;
		ieee80211_rrm_cmd_t rm_cmd;
		ieee80211_bstm_cmd_t bstm_cmd;
		ieee80211_opclass_chan_list_t opclass_disabled_chans;
#ifdef QCA_STANDALONE_SOUNDING_TRIGGER
		txbf_sounding_trig_info_t txbf_sounding_trig_info;
		peer_trig_fb_type_info_t peer_trig_fb_type_info;
#endif
#ifdef QCA_MANUAL_TRIGGERED_ULOFDMA
		struct ul_ofdma_trig_info trig_ul_ofdma;
#endif
	} data;
};

struct ieee80211_smps_update_data {
	uint8_t is_static;
	uint8_t macaddr[IEEE80211_ADDR_LEN];
};

struct ieee80211_opmode_update_data {
	uint8_t max_chwidth;
	uint8_t num_streams;
	uint8_t macaddr[IEEE80211_ADDR_LEN];
};

/*
 * Get the active channel list info.
 */
struct ieee80211req_chaninfo {
	uint32_t ic_nchans;
	struct ieee80211_ath_channel ic_chans[IEEE80211_CHAN_MAX];
};

struct ieee80211req_channel_list {
	uint32_t nchans;
	struct ieee80211_channel_info chans[IEEE80211_CHAN_MAX];
};

/*
 * Retrieve per-node statistics.
 */
struct ieee80211req_sta_stats {
	union {
		/* NB: explicitly force 64-bit alignment */
		u_int8_t	macaddr[IEEE80211_ADDR_LEN];
		u_int64_t	pad;
	} is_u;
	struct ieee80211_nodestats is_stats;
};

/**
 * enum wlan_son_dbg_req - wlan son debug request
 * @IEEE80211_DBGREQ_SENDBCNRPT:
 * @IEEE80211_DBGREQ_SENDBCNRPT: beacon report request
 * @IEEE80211_DBGREQ_GETACSREPORT: GET the ACS report
 * @IEEE80211_DBGREQ_SETACSUSERCHANLIST: SET ch list for acs reporting
 * @IEEE80211_DBGREQ_BLOCK_ACS_CHANNEL: Block ACS for these channels
 * @IEEE80211_DBGREQ_SENDBSTMREQ_TARGET: bss transition management request,
 *                                       targeted to a particular
 *                                       AP (or set of APs)
 * @IEEE80211_DBGREQ_BSTEERING_SETINNETWORK_2G: set 2.4G innetwork information
 *                                              in SON module
 * @IEEE80211_DBGREQ_BSTEERING_GETINNETWORK_2G: get 2.4G innetwork information
 *                                              from SON module
 * @IEEE80211_DBGREQ_BSSCOLOR_DOT11_COLOR_COLLISION_AP_PERIOD: override BSS
 *                                                Color Collision AP period
 * @IEEE80211_DBGREQ_HMWDS_AST_ADD_STATUS: HMWDS ast add stats
 * @IEEE80211_DBGREQ_MESH_SET_GET_CONFIG: Mesh config set and get
 * @IEEE80211_DBGREQ_ADD_DSCPACTION_POLICY: Add DSCP Action policy
 * @IEEE80211_DBGREQ_SEND_DSCPACTION_POLICY: Send DSCP Action request
 * @IEEE80211_DBGREQ_UNBLOCK_ACS_CHANNEL: Unblock ACS channel from block list
 * @IEEE80211_DBGREQ_DISALLOW_MSCS:Disallow MSCS feature for selected STA/s
 */
enum wlan_son_dbg_req {
	IEEE80211_DBGREQ_SENDBCNRPT    =	4,
	IEEE80211_DBGREQ_GETACSREPORT  =	20,
	IEEE80211_DBGREQ_SETACSUSERCHANLIST  =    21,
	IEEE80211_DBGREQ_BLOCK_ACS_CHANNEL            = 23,
	IEEE80211_DBGREQ_SENDBSTMREQ_TARGET           = 44,
	IEEE80211_DBGREQ_BSTEERING_SETINNETWORK_2G    = 90,
	IEEE80211_DBGREQ_BSTEERING_GETINNETWORK_2G    = 91,
	IEEE80211_DBGREQ_BSSCOLOR_DOT11_COLOR_COLLISION_AP_PERIOD = 92,
	IEEE80211_DBGREQ_HMWDS_AST_ADD_STATUS         = 115,
	IEEE80211_DBGREQ_MESH_SET_GET_CONFIG          = 117,
	IEEE80211_DBGREQ_ADD_DSCPACTION_POLICY        = 124,
	IEEE80211_DBGREQ_SEND_DSCPACTION_POLICY       = 126,
	IEEE80211_DBGREQ_UNBLOCK_ACS_CHANNEL          = 130,
	IEEE80211_DBGREQ_DISALLOW_MSCS                = 139,
};

struct ieee80211_wlanconfig_hmwds {
	u_int8_t  wds_ni_macaddr[IEEE80211_ADDR_LEN];
	u_int16_t wds_macaddr_cnt;
	u_int8_t  wds_macaddr[0];
};

/* All array size allocation is based on higher range i.e.lithium */
#define NAC_MAX_CLIENT		48

struct ieee80211_wlanconfig_nac {
	u_int8_t    mac_type;
	/* client has max limit */
	u_int8_t    mac_list[NAC_MAX_CLIENT][IEEE80211_ADDR_LEN];
	u_int8_t    rssi[NAC_MAX_CLIENT];
	timespec_t      ageSecs[NAC_MAX_CLIENT];
};

/**
 * struct ieee80211_wlanconfig_ipa_wds - For deleting wds type ast entry
 * @wds_ni_macaddr  : wds ni macaddress
 * @wds_macaddr_cnt : wds node mac address cnt
 * @wds_macaddr : wds node mac address
 * @peer_macaddr : direct associated peer mac address
 */
struct ieee80211_wlanconfig_ipa_wds {
	u_int8_t  wds_ni_macaddr[IEEE80211_ADDR_LEN];
	u_int16_t wds_macaddr_cnt;
	u_int8_t  wds_macaddr[IEEE80211_ADDR_LEN];
	u_int8_t  peer_macaddr[IEEE80211_ADDR_LEN];
};

/* generic structure to support sub-ioctl due to limited ioctl */
typedef enum {
	IEEE80211_WLANCONFIG_NOP                           = 0,
	IEEE80211_WLANCONFIG_HMWDS_ADD_ADDR                = 18,
	IEEE80211_WLANCONFIG_HMWDS_RESET_TABLE             = 20,
	IEEE80211_WLANCONFIG_GETCHANINFO_160               = 29,
	IEEE80211_WLANCONFIG_NAC_ADDR_ADD                  = 34,
	IEEE80211_WLANCONFIG_NAC_ADDR_DEL                  = 35,
	IEEE80211_WLANCONFIG_NAC_ADDR_LIST                 = 36,
	IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR             = 38,
	IEEE80211_WLANCONFIG_SVC_CLASS_CREATE              = 89,
	IEEE80211_WLANCONFIG_SVC_CLASS_DISABLE             = 90,
	IEEE80211_WLANCONFIG_T2LM_REQUEST                  = 95,
	IEEE80211_WLANCONFIG_T2LM_RESPONSE                 = 96,
	IEEE80211_WLANCONFIG_T2LM_TEARDOWN                 = 97,
	IEEE80211_WLANCONFIG_T2LM_LINK_MAP_CONFIG          = 98,
	IEEE80211_WLANCONFIG_IPA_WDS_REMOVE_ADDR           = 101,
	IEEE80211_WLANCONFIG_SVC_CREATE                    = 106,
	IEEE80211_WLANCONFIG_SVC_DELETE                    = 107,
	IEEE80211_WLANCONFIG_SVC_UPDATE                    = 108,
} IEEE80211_WLANCONFIG_CMDTYPE;

typedef enum {
	IEEE80211_WLANCONFIG_OK	  = 0,
	IEEE80211_WLANCONFIG_FAIL = 1,
} IEEE80211_WLANCONFIG_STATUS;

struct ieee80211_wlanconfig_setmaxrate {
	u_int8_t mac[IEEE80211_ADDR_LEN];
	u_int8_t maxrate;
};

enum {
	WLAN_SVC_TYPE_SAWF,
	WLAN_SVC_TYPE_SCS,
	WLAN_SVC_TYPE_MAX,
};

enum {
	WLAN_SVC_DIR_UL,
	WLAN_SVC_DIR_DL,
	WLAN_SVC_DIR_UL_DL,
	WLAN_SVC_DIR_MAX,
};

enum {
	WLAN_SVC_PARAM_MIN_TPUT,
	WLAN_SVC_PARAM_MAX_TPUT,
	WLAN_SVC_PARAM_BURST_SIZE,
	WLAN_SVC_PARAM_SERVICE_INTERVAL,
	WLAN_SVC_PARAM_DELAY_BOUND,
	WLAN_SVC_PARAM_MSDU_TTL,
	WLAN_SVC_PARAM_PRIORITY,
	WLAN_SVC_PARAM_TID,
	WLAN_SVC_PARAM_MSDU_RATE_LOSS,
	WLAN_SVC_PARAM_UL_BURST_SIZE,
	WLAN_SVC_PARAM_UL_SERVICE_INTERVAL,
	WLAN_SVC_PARAM_DL_SCHED_DISABLE_MODES,
	WLAN_SVC_PARAM_UL_SCHED_DISABLE_MODES,
	WLAN_SVC_PARAM_UL_MIN_TPUT,
	WLAN_SVC_PARAM_UL_MAX_LATENCY,
};

struct sawf_wlanconfig_create_param {
	uint32_t svc_id;
	char app_name[64];
	uint32_t param_set_mask;

	uint32_t min_thruput_rate;
	uint32_t max_thruput_rate;
	uint32_t burst_size;
	uint32_t service_interval;
	uint32_t delay_bound;
	uint32_t msdu_ttl;
	uint32_t priority;
	uint32_t tid;
	uint32_t msdu_rate_loss;
	uint32_t ul_burst_size;
	uint32_t ul_service_interval;
	char dl_disabled_modes[128];
	char ul_disabled_modes[128];
	uint32_t ul_min_tput;
	uint32_t ul_max_latency;
};

struct sawf_wlanconfig_svc_create {
	char app_name[64];
	uint32_t min_thruput_rate;
	uint32_t max_thruput_rate;
	uint32_t burst_size;
	uint32_t service_interval;
	uint32_t delay_bound;
	uint32_t msdu_ttl;
	uint32_t priority;
	uint32_t tid;
	uint32_t msdu_rate_loss;
	uint32_t ul_burst_size;
	uint32_t ul_service_interval;
	char dl_disabled_modes[128];
	char ul_disabled_modes[128];
	uint32_t ul_min_tput;
	uint32_t ul_max_latency;

	uint8_t type;
	uint8_t direction;
	uint32_t mask;
	uint8_t peer_mac_addr[IEEE80211_ADDR_LEN];
};

struct sawf_wlanconfig_svc_delete {
	uint32_t svc_id;
	uint8_t type;
	uint8_t peer_mac_addr[IEEE80211_ADDR_LEN];
};

struct sawf_wlanconfig_svc_update {
	uint32_t svc_id;
	char app_name[64];
	uint32_t min_thruput_rate;
	uint32_t max_thruput_rate;
	uint32_t burst_size;
	uint32_t service_interval;
	uint32_t delay_bound;
	uint32_t msdu_ttl;
	uint32_t priority;
	uint32_t tid;
	uint32_t msdu_rate_loss;
	uint32_t ul_burst_size;
	uint32_t ul_service_interval;
	char dl_disabled_modes[128];
	char ul_disabled_modes[128];
	uint32_t ul_min_tput;
	uint32_t ul_max_latency;

	uint8_t type;
	uint8_t direction;
	uint32_t mask;
	uint8_t peer_mac_addr[IEEE80211_ADDR_LEN];
};

struct sawf_wlanconfig_svc_rsp {
	uint32_t svc_id;
};

struct sawf_wlanconfig_disable_param {
	uint8_t svc_id;
};

/* Max supported TIDs */
#define NUM_MAX_TIDS 8

/**
 * enum t2lm_dir - TID-to-link mapping direction
 * @T2LM_DIRECTION_DL: Downlink
 * @T2LM_DIRECTION_UL: Uplink
 * @T2LM_DIRECTION_BIDI: Bidirectional
 * @T2LM_DIRECTION_MAX: Max direction
 * @T2LM_DIRECTION_INVALID: Invalid direction
 */
enum t2lm_dir {
	T2LM_DIRECTION_DL,
	T2LM_DIRECTION_UL,
	T2LM_DIRECTION_BIDI,
	T2LM_DIRECTION_MAX,
	T2LM_DIRECTION_INVALID
};

/**
 * struct tid_to_link_map - TID-to-link mapping params
 * @tid_num: TID number
 * @link_map: T2LM provisioned links for the given TID
 */
struct tid_to_link_map {
	uint8_t tid_num;
	uint16_t link_map;
};

/**
 * struct t2lm_of_direction - TID-to-link mapping for a given direction
 * @num_tids: Total number of TIDs for which mapping is given
 * @direction: direction, DL/UL/BIDI
 * @default_mapping: default tid-to-link mapping value
 * @map_tid_to_links: link mappings of the TIDs
 * @link_mapping_size: link map size for TIDn where value 0:2 bytes 1:1 byte
 */
struct t2lm_of_direction {
	uint8_t num_tids;
	uint8_t direction;
	uint8_t default_mapping;
	struct tid_to_link_map map_tid_to_links[NUM_MAX_TIDS];
	uint8_t link_mapping_size;
};

/**
 * struct ieee80211_wlanconfig_t2lm - User configured T2LM params
 * @assoc_frm: 1 - include the T2LM frame during assoc.
 *         0 - send T2LM action frame
 * @peer_mld_mac: MLO peer macaddress (STA macaddr)
 * @status: T2LM response status value
 * @unsolicited_t2lm_resp: Unsolicited T2LM response
 * @t2lm_direction: TID-to-link mapping params for DL/UL/BIDI
 */
struct ieee80211_wlanconfig_t2lm {
	uint8_t assoc_frm;
	uint8_t peer_mld_mac[IEEE80211_ADDR_LEN];
	uint8_t status;
	uint8_t unsolicited_t2lm_resp;
	struct t2lm_of_direction t2lm_direction[T2LM_DIRECTION_MAX];
};

struct ieee80211_t2lm_link_map_value {
	uint16_t link_map_value;
	u_int16_t map_switch_time;
	uint32_t expected_dur;
	uint8_t link_mapping_size;
};

#ifdef WLAN_FEATURE_11BE

/* Number of T2LM params expected per TID (params are listed in struct
 * tid_to_link_map).
 */
#define T2LM_MAP_PARAMS 2

/* T2LM Request rejected and preferred TID-to-link mapping is suggested */
#define T2LM_STATUS_PREFERRED_TID_TO_LINK_MAPPING 134

#endif /* WLAN_FEATURE_11BE */

struct ieee80211_wlanconfig {
	IEEE80211_WLANCONFIG_CMDTYPE cmdtype;  /* sub-command */
	IEEE80211_WLANCONFIG_STATUS status;	 /* status code */
	union {
		struct ieee80211_wlanconfig_hmwds hmwds;
		struct ieee80211_wlanconfig_nac nac;
		struct sawf_wlanconfig_create_param sawf_create_config;
		struct sawf_wlanconfig_disable_param sawf_disable_config;
		struct sawf_wlanconfig_svc_create sawf_svc_create;
		struct sawf_wlanconfig_svc_delete sawf_svc_delete;
		struct sawf_wlanconfig_svc_update sawf_svc_update;
		struct ieee80211_wlanconfig_t2lm t2lm;
		struct ieee80211_t2lm_link_map_value t2lm_link_map_config;
		struct ieee80211_wlanconfig_ipa_wds ipa_wds;
	} data;

	struct ieee80211_wlanconfig_setmaxrate smr;
};

/* Options for requesting nl reply */
enum {
	DBGREQ_REPLY_IS_NOT_REQUIRED =	0,
	DBGREQ_REPLY_IS_REQUIRED     =	1,
};

#define	IEEE80211_IOCTL_SETMODE		(SIOCIWFIRSTPRIV + 18)

#define IEEE80211_IOCTL_ATF_ADDSSID     0xFF01
#define IEEE80211_IOCTL_ATF_DELSSID     0xFF02
#define IEEE80211_IOCTL_ATF_ADDSTA      0xFF03
#define IEEE80211_IOCTL_ATF_DELSTA      0xFF04
#define IEEE80211_IOCTL_ATF_SHOWATFTBL  0xFF05

#define IEEE80211_IOCTL_ATF_ADDGROUP    0xFF08
#define IEEE80211_IOCTL_ATF_CONFIGGROUP 0xFF09
#define IEEE80211_IOCTL_ATF_DELGROUP    0xFF0a

typedef enum ieee80211_nac_mactype {
	IEEE80211_NAC_MACTYPE_BSSID  = 1,
	IEEE80211_NAC_MACTYPE_CLIENT = 2,
} IEEE80211_NAC_MACTYPE;

/**
 * struct ieee80211_hmwds_ast_add_status - hmwds ast add status
 * @cmd: dbg req cmd id
 * @peer_mac: peer mac address
 * @ast_mac: ast mac address
 * @status: ast add status
 * @args: arguments
 */
struct ieee80211_hmwds_ast_add_status {
	u_int8_t cmd;
	u_int8_t peer_mac[IEEE80211_ADDR_LEN];
	u_int8_t ast_mac[IEEE80211_ADDR_LEN];
	int      status;
} __attribute__((packed));

/* kev event_code value for Atheros IEEE80211 events */
enum {
	IEEE80211_EV_CHAN_CHANGE,
	IEEE80211_EV_RADAR_DETECTED,
	IEEE80211_EV_CAC_STARTED,
	IEEE80211_EV_CAC_COMPLETED,
	IEEE80211_EV_NOL_STARTED,
	IEEE80211_EV_NOL_FINISHED,
};

/**
 * struct ieee80211_fw_unit_test_event - unit test event structure
 * @module_id: module id (typically the same module-id as send in the command)
 * @diag_token: This token identifies the command token to
 *              which fw is responding
 * @flag: Informational flags to be used by the application (wifitool)
 * @payload_len: Length of meaningful bytes inside buffer[]
 * @buffer_len: Actual length of the buffer[]
 * @hdr:
 * @buffer: buffer containing event data
 */
struct ieee80211_fw_unit_test_event {
	struct {
		u_int32_t module_id;
		u_int32_t diag_token;
		u_int32_t flag;
		u_int32_t payload_len;
		u_int32_t buffer_len;
	} hdr;
	u_int8_t buffer[1];
} __attribute__((packed));

struct ieee80211req_athdbg_event {
	u_int8_t cmd;
	union {
		struct ieee80211_fw_unit_test_event fw_unit_test;
	};
} __attribute__((packed));

/*
 * Regulatory EIRP/PSD powers for valid 6GHz AP power types.
 */
struct reg_power_val {
	uint8_t psd_flag;
	uint16_t psd_eirp;
	uint32_t tx_power;
};

#define MAX_NUM_SEG2_CENTERS 3

#define INDEX_160_SEG2_CENTER 0
#define INVALID_SEG2_CENTER_INDEX 0xF

#define MAX_AP_PWR_TYPE 3

struct ieee80211_channel_params {
	uint8_t ieee;
	uint16_t freq;
	uint64_t flags;
	uint32_t flags_ext;
	uint8_t vhtop_ch_num_seg1;
	uint8_t vhtop_ch_num_seg2[MAX_NUM_SEG2_CENTERS];
	struct reg_power_val reg_powers[MAX_AP_PWR_TYPE];
	uint8_t supp_power_modes;
};

struct ieee80211_channel_list_info {
	uint32_t nchans;
	struct ieee80211_channel_params chans[IEEE80211_CHAN_MAX];
};

struct ieee80211_awgn_update_data {
	uint32_t primary_freq;
	uint32_t center_freq;
	uint32_t bandwidth;
	uint32_t bitmap;
};

typedef enum {
	IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE0 = 0,
	IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE1 = 1,
	IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE2 = 2,
	IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE3 = 3,
	IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE4 = 4,
	IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE10 = 10,
} IEEE80211_WNM_TCLAS_CLASSIFIER;

#define TFS_MAX_FILTER_LEN 50
#define TFS_MAX_TCLAS_ELEMENTS 2

#define FMS_MAX_TCLAS_ELEMENTS 2

typedef enum {
	IEEE80211_WNM_TCLAS_CLAS14_VERSION_4 = 4,
	IEEE80211_WNM_TCLAS_CLAS14_VERSION_6 = 6,
} IEEE80211_WNM_TCLAS_VERSION;

#ifndef IEEE80211_IPV4_LEN
#define IEEE80211_IPV4_LEN 4
#endif

#ifndef IEEE80211_IPV6_LEN
#define IEEE80211_IPV6_LEN 16
#endif

/*
 * TCLAS Classifier Type 1 and Type 4 are exactly the same for IPv4.
 * For IPv6, Type 4 has two more fields (dscp, next header) than
 * Type 1. So we use the same structure for both Type 1 and 4 here.
 */
struct clas14_v4 {
	u_int8_t     version;
	u_int8_t     source_ip[IEEE80211_IPV4_LEN];
	u_int8_t     reserved1[IEEE80211_IPV6_LEN - IEEE80211_IPV4_LEN];
	u_int8_t     dest_ip[IEEE80211_IPV4_LEN];
	u_int8_t     reserved2[IEEE80211_IPV6_LEN - IEEE80211_IPV4_LEN];
	u_int16_t    source_port;
	u_int16_t    dest_port;
	u_int8_t     dscp;
	u_int8_t     protocol;
	u_int8_t     reserved;
	u_int8_t     reserved3[2];
} __packed;

struct clas14_v6 {
	u_int8_t     version;
	u_int8_t     source_ip[IEEE80211_IPV6_LEN];
	u_int8_t     dest_ip[IEEE80211_IPV6_LEN];
	u_int16_t    source_port;
	u_int16_t    dest_port;
	u_int8_t     clas4_dscp;
	u_int8_t     clas4_next_header;
	u_int8_t     flow_label[3];
} __packed;

struct clas3 {
	u_int16_t filter_offset;
	u_int32_t filter_len;
	u_int8_t  filter_value[TFS_MAX_FILTER_LEN];
	u_int8_t  filter_mask[TFS_MAX_FILTER_LEN];
} __packed;

struct tfsreq_tclas_element {
	u_int8_t classifier_type;
	u_int8_t classifier_mask;
	u_int8_t priority;
	union {
		union {
			struct clas14_v4 clas14_v4;
			struct clas14_v6 clas14_v6;
		} clas14;
		 struct clas3 clas3;
	} clas;
} __packed;

struct fmsresp_tclas_subele_status {
	u_int8_t fmsid;
	u_int8_t ismcast;
	u_int32_t mcast_ipaddr;
	ieee80211_tclas_processing tclasprocess;
	u_int32_t num_tclas_elements;
	struct tfsreq_tclas_element tclas[TFS_MAX_TCLAS_ELEMENTS];
};

#endif //_IEEE80211_IOCTL_H_
