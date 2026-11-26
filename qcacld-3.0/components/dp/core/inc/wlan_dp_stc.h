/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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
  * DOC: wlan_dp_stc.h
  *
  *
  */
#ifndef __WLAN_DP_STC_H__
#define __WLAN_DP_STC_H__

#include "wlan_dp_main.h"
#include "wlan_dp_spm.h"

/* Macros used by STC logmask */
#define WLAN_DP_STC_LOGMASK_FLOW_STATS BIT(0)
#define WLAN_DP_STC_LOGMASK_CLASSIFIED_FLOW_STATS BIT(1)
/* L1 is the lowest verbosity level */
#define WLAN_DP_STC_LOGMASK_VERBOSE_L1 BIT(2)
#define WLAN_DP_STC_LOGMASK_VERBOSE_L2 BIT(3)
#define WLAN_DP_STC_LOGMASK_BURST BIT(4)
#define WLAN_DP_STC_LOGMASK_TXRX_PKT BIT(5)

#define dp_stc_info(debug_mask, params...)				\
	do {								\
		if (unlikely((debug_mask) &				\
		    WLAN_DP_STC_LOGMASK_VERBOSE_L1))			\
			__QDF_TRACE_FL(QDF_TRACE_LEVEL_INFO_HIGH,	\
				       QDF_MODULE_ID_DP, ## params);	\
	} while (0)

#define dp_stc_debug(debug_mask, params...)				\
	do {								\
		if (unlikely((debug_mask) &				\
		    WLAN_DP_STC_LOGMASK_VERBOSE_L2))			\
			__QDF_TRACE_FL(QDF_TRACE_LEVEL_INFO_HIGH,	\
				       QDF_MODULE_ID_DP, ## params);	\
	} while (0)

#define dp_stc_log(debug_mask, log_level, params...)			\
	do {								\
		if (unlikely((debug_mask) & (log_level)))		\
			__QDF_TRACE_FL(QDF_TRACE_LEVEL_INFO_HIGH,	\
				       QDF_MODULE_ID_DP, ## params);	\
	} while (0)

#define DP_STC_UPDATE_MIN_MAX_STATS(__field, __val)			\
	do {								\
		if (__field##_min == 0 || __field##_min > __val)	\
			__field##_min = __val;				\
		if (__field##_max < __val)				\
			__field##_max = __val;				\
	} while (0)

#define DP_STC_UPDATE_MIN_MAX_SUM_STATS(__field, __val)			\
	do {								\
		__field##_sum += __val;					\
		if (__field##_min == 0 || __field##_min > __val)	\
			__field##_min = __val;				\
		if (__field##_max < __val)				\
			__field##_max = __val;				\
	} while (0)

#define DP_STC_UPDATE_SUM_STATS(__field, __val)			\
	do {								\
		__field##_sum += __val;					\
	} while (0)

#define DP_STC_UPDATE_WIN_MIN_MAX_STATS(__field, __val)			\
	do {								\
		if (__field##_min == 0 || __field##_min > __val)	\
			__field##_min = __val;				\
		if (__field##_max < __val)				\
			__field##_max = __val;				\
	} while (0)

/* TODO - This macro needs to be same as the max peers in CMN DP */
#define DP_STC_MAX_PEERS 64

#define BURST_START_TIME_THRESHOLD_NS 10000000
#define BURST_START_BYTES_THRESHOLD 5000
#define BURST_END_TIME_THRESHOLD_NS 1500000000
#define FLOW_CLASSIFY_WAIT_TIME_NS 10000000000

#define WLAN_DP_STC_TX_FLOW_ID_INTF_ID_SHIFT 6
#define WLAN_DP_STC_TX_FLOW_ID_INTF_ID_MASK 0x3
#define WLAN_DP_STC_TX_FLOW_ID_MASK 0x3f

/* This macro is a copy of DP_INVALID_PEER_ID */
#define DP_STC_INVALID_PEER_ID 0xFFFF

/**
 * struct wlan_dp_stc_peer_ping_info - Active ping information table with
 *				       per peer records
 * @mac_addr: mac address of the peer
 * @last_ping_ts: timestamp when the last ping packet was traced
 */
struct wlan_dp_stc_peer_ping_info {
	struct qdf_mac_addr mac_addr;
	uint64_t last_ping_ts;
};

/**
 * enum wlan_dp_stc_periodic_work_state - Periodic work states
 * @WLAN_DP_STC_WORK_INIT: INIT state
 * @WLAN_DP_STC_WORK_STOPPED: Stopped state
 * @WLAN_DP_STC_WORK_STARTED: Started state
 * @WLAN_DP_STC_WORK_RUNNING: Running state
 */
enum wlan_dp_stc_periodic_work_state {
	WLAN_DP_STC_WORK_INIT,
	WLAN_DP_STC_WORK_STOPPED,
	WLAN_DP_STC_WORK_STARTED,
	WLAN_DP_STC_WORK_RUNNING,
};

/**
 * enum wlan_dp_stc_burst_state - Burst detection state
 * @BURST_DETECTION_INIT: Burst detection not started
 * @BURST_DETECTION_START: Burst detection has started
 * @BURST_DETECTION_BURST_START: Burst start is detected and burst has started
 */
enum wlan_dp_stc_burst_state {
	BURST_DETECTION_INIT,
	BURST_DETECTION_START,
	BURST_DETECTION_BURST_START,
};

/**
 * enum wlan_dp_stc_evict_code - Flow evicting success code
 * @DP_EVICT_DENIED: Abort evicting flow
 * @DP_EVICT_SUCCESS_CODE_1: Evicting flow with success code 1
 * @DP_EVICT_SUCCESS_CODE_2: Evicting flow with success code 2
 * @DP_EVICT_SUCCESS_CODE_3: Evicting flow with success code 3
 */
enum wlan_dp_stc_evict_code {
	DP_EVICT_DENIED,
	DP_EVICT_SUCCESS_CODE_1,
	DP_EVICT_SUCCESS_CODE_2,
	DP_EVICT_SUCCESS_CODE_3,
};

#define DP_STC_SAMPLE_FLOWS_MAX 128
#define DP_STC_SAMPLE_BIDI_FLOW_MAX 96
#define DP_STC_SAMPLE_RX_FLOW_MAX 32
#define DP_STC_SAMPLE_TX_FLOW_MAX 0

#define DP_STC_LONG_WINDOW_MS 30000
#define DP_STC_TIMER_THRESH_MS 600

#define DP_STC_BURST_STAGE_1_WINDOW_MS 10800
#define DP_STC_BURST_STAGE_2_WINDOW_MS DP_STC_LONG_WINDOW_MS

/* Burst stat for stage 1 needs to be collected at 10.8s. Each sample state
 * being 600ms. Collect burst stat at 18th sample (10.8s/0.6s).
 */
#define WLAN_DP_SAMPLING_BURST_STAT_STAGE_1_END 18
/* Burst stat for stage 2 needs to be collected at 30s. Each sample state
 * being 600ms. Collect burst stat at 50th sample (30s/0.6s).
 */
#define WLAN_DP_SAMPLING_BURST_STAT_STAGE_2_END 50

#define DP_STC_IS_CLASSIFIED_KNOWN(classified_state) \
			((classified_state) == DP_STC_CLASSIFIED_KNOWN)

enum dp_stc_classified_state {
	DP_STC_CLASSIFIED_INIT,
	DP_STC_CLASSIFIED_UNKNOWN,
	DP_STC_CLASSIFIED_KNOWN,

	/*
	 * Max value of classified state, based on the
	 * size of the variable holding this state.
	 */
	DP_STC_CLASSIFIED_MAX = 255,
};

/**
 * enum wlan_stc_sampling_state - Sampling state
 * @WLAN_DP_SAMPLING_STATE_INIT: init state
 * @WLAN_DP_SAMPLING_STATE_FLOW_ADDED: flow added for sampling
 * @WLAN_DP_SAMPLING_STATE_SAMPLING_START: sampling started
 * @WLAN_DP_SAMPLING_STATE_SAMPLING_BURST_STATS_1: Sampling burst stats stage 1
 * @WLAN_DP_SAMPLING_STATE_SAMPLING_BURST_STATS_2: sampling burst stats stage 2
 * @WLAN_DP_SAMPLING_STATE_SAMPLING_DONE: sampling completed
 * @WLAN_DP_SAMPLING_STATE_SAMPLING_FAIL: sampling failed
 * @WLAN_DP_SAMPLING_STATE_SAMPLES_SENT: samples sent
 * @WLAN_DP_SAMPLING_STATE_CLASSIFIED: flow classified
 */
enum wlan_stc_sampling_state {
	WLAN_DP_SAMPLING_STATE_INIT,
	WLAN_DP_SAMPLING_STATE_FLOW_ADDED,
	WLAN_DP_SAMPLING_STATE_SAMPLING_START,
	WLAN_DP_SAMPLING_STATE_SAMPLING_BURST_STATS_1,
	WLAN_DP_SAMPLING_STATE_SAMPLING_BURST_STATS_2,
	WLAN_DP_SAMPLING_STATE_SAMPLING_DONE,
	WLAN_DP_SAMPLING_STATE_SAMPLING_FAIL,
	WLAN_DP_SAMPLING_STATE_SAMPLES_SENT,
	WLAN_DP_SAMPLING_STATE_CLASSIFIED,
};

/* Bit-fields used for "flags" in struct wlan_dp_stc_sampling_candidate */
#define WLAN_DP_SAMPLING_CANDIDATE_VALID BIT(0)
#define WLAN_DP_SAMPLING_CANDIDATE_TX_FLOW_VALID BIT(1)
#define WLAN_DP_SAMPLING_CANDIDATE_RX_FLOW_VALID BIT(2)
#define WLAN_DP_SAMPLING_CANDIDATE_STAGE_1 BIT(3)
#define WLAN_DP_SAMPLING_CANDIDATE_STAGE_2 BIT(4)
#define WLAN_DP_SAMPLING_CANDIDATE_STAGE_3 BIT(5)

enum wlan_dp_flow_dir {
	WLAN_DP_FLOW_DIR_INVALID,
	WLAN_DP_FLOW_DIR_TX,
	WLAN_DP_FLOW_DIR_RX,
	WLAN_DP_FLOW_DIR_BIDI,
};

/**
 * struct wlan_dp_stc_sampling_candidate - Sampling candidate
 * @peer_id: Peer ID
 * @flags: flags
 * @tx_flow_id: TX flow ID
 * @rx_flow_id: RX flow ID
 * @tx_flow_metadata: TX flow metadata
 * @rx_flow_metadata: RX flow metadata
 * @dir: flow direction
 */
struct wlan_dp_stc_sampling_candidate {
	uint16_t peer_id;
	uint32_t flags;
	uint16_t tx_flow_id;
	uint16_t rx_flow_id;
	uint32_t tx_flow_metadata;
	uint32_t rx_flow_metadata;
	enum wlan_dp_flow_dir dir;
};

/* bit-fields used for "flags" in struct wlan_dp_stc_sampling_table_entry */
#define WLAN_DP_SAMPLING_FLAGS_TX_FLOW_VALID BIT(0)
#define WLAN_DP_SAMPLING_FLAGS_RX_FLOW_VALID BIT(1)
#define WLAN_DP_SAMPLING_FLAGS_TXRX_SAMPLES_READY BIT(2)
#define WLAN_DP_SAMPLING_FLAGS_BURST_SAMPLES_1_READY BIT(3)
#define WLAN_DP_SAMPLING_FLAGS_BURST_SAMPLES_2_READY BIT(4)
#define WLAN_DP_SAMPLING_FLAGS_STAGE_1 BIT(5)
#define WLAN_DP_SAMPLING_FLAGS_STAGE_2 BIT(6)
#define WLAN_DP_SAMPLING_FLAGS_STAGE_3 BIT(7)
#define WLAN_DP_SAMPLING_FLAGS_PEER_DEL BIT(8)

#define WLAN_DP_SAMPLING_FLAGS1_FLOW_REPORT_SENT BIT(0)
#define WLAN_DP_SAMPLING_FLAGS1_TXRX_SAMPLES_SENT BIT(1)
#define WLAN_DP_SAMPLING_FLAGS1_BURST_SAMPLES_1_SENT BIT(2)
#define WLAN_DP_SAMPLING_FLAGS1_BURST_SAMPLES_2_SENT BIT(3)

/*
 * struct wlan_dp_stc_sampling_table_entry - Sampling table entry
 * @state: State of sampling for this flow
 * @dir: direction of flow
 * @last_stats_report_ts: Timestamp of last stats reported for this flow
 * @flags: flags set by timer
 * @flags1: flags set by periodic work
 * @id: index of this sampling table entry in the sampling table
 * @next_sample_idx: next sample index to fill min/max stats in per-packet path
 * @next_win_idx: next window index to fill min/max stats in per-packet path
 * @curr_sample_attempt: Current sample number which is being checked or
 *                       collected
 * @traffic_type: traffic type classified
 * @ul_tid: Uplink TID id for the flow
 * @peer_id: Peer ID
 * @tx_flow_id: tx flow ID
 * @rx_flow_id: rx flow ID
 * @tx_flow_metadata: tx flow metadata
 * @rx_flow_metadata: rx flow metadata
 * @tuple_hash: Flow tuple hash
 * @tx_stats_ref: tx window stats reference
 * @rx_stats_ref: rx window stats reference
 * @flow_samples: flow samples
 */
struct wlan_dp_stc_sampling_table_entry {
	enum wlan_stc_sampling_state state;
	enum wlan_dp_flow_dir dir;
	uint64_t last_stats_report_ts;
	uint32_t flags;
	uint32_t flags1;
	uint8_t id;
	uint8_t next_sample_idx;
	uint8_t next_win_idx;
	uint8_t curr_sample_attempt;
	uint8_t traffic_type;
	uint8_t ul_tid;
	uint16_t peer_id;
	uint16_t tx_flow_id;
	uint16_t rx_flow_id;
	uint32_t tx_flow_metadata;
	uint32_t rx_flow_metadata;
	uint64_t tuple_hash;
	uint64_t sampling_start_ts;
	struct wlan_dp_stc_txrx_stats tx_stats_ref;
	struct wlan_dp_stc_txrx_stats rx_stats_ref;
	struct wlan_dp_stc_flow_samples flow_samples;
};

/*
 * struct wlan_dp_stc_sampling_table - Sampling table
 * @num_valid_entries: Number of valid flows added to sampling flow table
 * @num_bidi_flows: number of Bi-Di flows added to sampling flow table
 * @num_tx_only_flows: number of TX only flows added to sampling flow table
 * @num_rx_only_flows: number of RX only flows added to sampling flow table
 * @entries: records added to sampling table
 */
struct wlan_dp_stc_sampling_table {
	qdf_atomic_t num_valid_entries;
	qdf_atomic_t num_bidi_flows;
	qdf_atomic_t num_tx_only_flows;
	qdf_atomic_t num_rx_only_flows;
	struct wlan_dp_stc_sampling_table_entry entries[DP_STC_SAMPLE_FLOWS_MAX];
};

#define WLAN_DP_STC_TRANSITION_FLAG_SAMPLE 0
#define WLAN_DP_STC_TRANSITION_FLAG_WIN 1

/**
 * struct wlan_dp_stc_flow_table_entry - Flow table maintained in per pkt path
 * @prev_pkt_arrival_ts: previous packet arrival time
 * @metadata: flow metadata
 * @burst_state: burst state
 * @burst_start_time: burst start time
 * @burst_start_detect_bytes: current snapshot of total bytes during burst
 *			      start detection phase
 * @cur_burst_bytes: total bytes accumulated in current burst
 * @transition_flags: transition flags to indicate sample or a window change
 *		      for flow stats collection
 * @idx: union for storing sample & window index
 * @idx.sample_win_idx: sample and window index
 * @idx.s.win_idx: window index
 * @idx.s.sample_idx: sample index
 * @txrx_stats: txrx stats
 * @txrx_min_max_stats: placeholder for stats which needs per window
 *			min/max values
 * @burst_stats: burst stats
 */
struct wlan_dp_stc_flow_table_entry {
	uint64_t prev_pkt_arrival_ts;
	uint32_t metadata;
	enum wlan_dp_stc_burst_state burst_state;
	uint64_t burst_start_time;
	uint32_t burst_start_detect_bytes;
	uint32_t cur_burst_bytes;
	unsigned long transition_flags;
	/* Can be atomic.! Decide based on the accuracy during test */
	union {
		uint32_t sample_win_idx;
		struct {
			uint32_t win_idx:16,
				 sample_idx:16;
		} s;
	} idx;
	struct wlan_dp_stc_txrx_stats txrx_stats;
	struct wlan_dp_stc_txrx_min_max_stats txrx_min_max_stats[DP_STC_TXRX_SAMPLES_MAX][DP_TXRX_SAMPLES_WINDOW_MAX];
	struct wlan_dp_stc_burst_stats burst_stats;
};

#define DP_STC_FLOW_TABLE_ENTRIES_MAX 256
/**
 * struct wlan_dp_stc_rx_flow_table - RX flow table
 * @entries: RX flow table records
 */
struct wlan_dp_stc_rx_flow_table {
	struct wlan_dp_stc_flow_table_entry entries[DP_STC_FLOW_TABLE_ENTRIES_MAX];
};

/**
 * struct wlan_dp_stc_tx_flow_table - TX flow table
 * @entries: TX flow table records
 */
struct wlan_dp_stc_tx_flow_table {
	struct wlan_dp_stc_flow_table_entry entries[DP_STC_FLOW_TABLE_ENTRIES_MAX];
};

/**
 * enum wlan_dp_stc_timer_state - Sampling timer state
 * @WLAN_DP_STC_TIMER_INIT: Init state
 * @WLAN_DP_STC_TIMER_STOPPED: timer stopped state
 * @WLAN_DP_STC_TIMER_STARTED: timer started state
 * @WLAN_DP_STC_TIMER_RUNNING: timer running state
 */
enum wlan_dp_stc_timer_state {
	WLAN_DP_STC_TIMER_INIT,
	WLAN_DP_STC_TIMER_STOPPED,
	WLAN_DP_STC_TIMER_STARTED,
	WLAN_DP_STC_TIMER_RUNNING,
};

#define WLAN_DP_STC_TRAFFIC_BK BIT(0)
#define WLAN_DP_STC_TRAFFIC_PING BIT(1)

/**
 * struct wlan_dp_stc_peer_traffic_context - peer traffic context
 * @mac_addr: peer mac address
 * @valid: context valid flag
 * @is_mld: flag to indicate if the peer is MLD peer
 * @vdev_id: vdev_id for the peer
 * @peer_id: peer_id assigned to this peer
 * @last_ping_ts: Last seen ping pkt timestamp
 * @prev_tx_pkts: Previous cached TX packet count
 * @prev_rx_pkts: Previous cached RX packet count
 * @prev_pkt_count: Previous cached total packet count
 * @prev_tput_check_ts: Timestamp when last background throughput was checked
 * @num_streaming: Number of streaming flows on this peer
 * @num_gaming: Number of gaming flows on this peer
 * @num_voice_call: Number of voice call flows on this peer
 * @num_video_call: Number of video call flows on this peer
 * @num_browsing: Number of web browsing flows on this peer
 * @num_aperiodic_bursts: Number of aperiodic bursty traffic flows on this peer
 * @non_flow_traffic: BITMAP to indicate active non-TCP/UDP traffic on the peer
 * @send_fw_ind: Flag to mark if traffic_map indication is to be sent to FW
 */
struct wlan_dp_stc_peer_traffic_context {
	struct qdf_mac_addr mac_addr;
	uint8_t valid;
	uint8_t is_mld;
	uint8_t vdev_id;
	uint16_t peer_id;
	uint64_t last_ping_ts;
	uint64_t prev_tx_pkts;
	uint64_t prev_rx_pkts;
	uint64_t prev_pkt_count;
	uint64_t prev_tput_check_ts;
	qdf_atomic_t num_streaming;
	qdf_atomic_t num_gaming;
	qdf_atomic_t num_voice_call;
	qdf_atomic_t num_video_call;
	qdf_atomic_t num_browsing;
	qdf_atomic_t num_aperiodic_bursts;
	unsigned long non_flow_traffic;
	qdf_atomic_t send_fw_ind;
};

#define DP_STC_CLASSIFIED_TABLE_FLOW_MAX 256
/**
 * struct wlan_dp_stc_classified_flow_entry - Classified flow entry
 * @flow_active: flag to indicate if the flow is active
 * @vdev_id: vdev_id on which the flow is active
 * @tx_flow_id: TX flow table index
 * @rx_flow_id: RX flow table index
 * @peer_id: ID of the peer on which the flow is running
 * @id: index of this classified flow entry in the classified flow table
 * @prev_tx_pkts: Last snapshot for TX pkts count
 * @prev_rx_pkts: Last snapshot for RX pkts count
 * @flow_tuple: Flow tuple info
 * @flags: flags bitmap
 * @del_flags: delete flags bitmap
 * @traffic_type: Traffic type identified
 * @state: STATE
 * @inactivity_start_ts: start timestamp when flow was marked inactive
 * @num_inactive: number of times this flow became inactive
 * @inactive_time: Total time for which the flow was inactive
 * @add_ts: timestamp when the flow was added to classified flow table
 */
struct wlan_dp_stc_classified_flow_entry {
	uint8_t flow_active;
	uint8_t vdev_id;
	uint16_t tx_flow_id;
	uint16_t rx_flow_id;
	uint16_t peer_id;
	uint16_t id;
	uint32_t prev_tx_pkts;
	uint32_t prev_rx_pkts;
	struct flow_info flow_tuple;
	unsigned long flags;
	unsigned long del_flags;
	enum qca_traffic_type traffic_type;
	qdf_atomic_t state;
	uint64_t inactivity_start_ts;
	uint32_t num_inactive;
	uint64_t inactive_time;
	uint64_t add_ts;
};

/**
 * struct wlan_dp_stc_classified_flow_table - Classified flow table
 * @num_valid_entries: Number of valid entries
 * @entries: classified flow table entries
 */
struct wlan_dp_stc_classified_flow_table {
	qdf_atomic_t num_valid_entries;
	struct wlan_dp_stc_classified_flow_entry entries[DP_STC_CLASSIFIED_TABLE_FLOW_MAX];
};

/**
 * struct wlan_dp_stc - Smart traffic classifier context
 * @dp_ctx: DP component global context
 * @send_flow_stats: Flag to indicate whether flow stats are to be reported
 * @send_classified_flow_stats: Flag to indicate whether the classified
 *				flow stats are to be reported
 * @flow_monitor_work: periodic work to process all the misc work for STC
 * @flow_monitor_interval: periodic flow monitor work interval
 * @logmask: mask indicating which logs are enabled
 * @periodic_work_state: States of the periodic flow monitor work
 * @flow_sampling_timer: timer to sample all the short-listed flows
 * @sample_timer_state: sampling timer state
 * @rtpm_control_flow_cnt: Total flows of traffic types affecting RTPM
 * @rtpm_control: RTPM control enable check
 * @tcam_client_available: TCAM client available check
 * @peer_tc: per peer active traffic context
 * @peer_ping_info: Ping tracking per peer
 * @sampling_flow_table: Sampling flow table
 * @rx_flow_table: RX flow table
 * @tx_flow_table: TX flow table
 * @classified_flow_table: Flow table of all the classified flows
 * @candidates: Sampling candidate selection table
 */
struct wlan_dp_stc {
	struct wlan_dp_psoc_context *dp_ctx;
	uint8_t send_flow_stats;
	uint8_t send_classified_flow_stats;
	struct qdf_periodic_work flow_monitor_work;
	uint32_t flow_monitor_interval;
	uint32_t logmask;
	enum wlan_dp_stc_periodic_work_state periodic_work_state;
	qdf_hrtimer_data_t flow_sampling_timer;
	enum wlan_dp_stc_timer_state sample_timer_state;
	uint16_t rtpm_control_flow_cnt;
	bool rtpm_control;
	bool tcam_client_available;
	struct wlan_dp_stc_peer_traffic_context peer_tc[DP_STC_MAX_PEERS];
	struct wlan_dp_stc_sampling_table *sampling_flow_table;
	struct wlan_dp_stc_rx_flow_table *rx_flow_table;
	struct wlan_dp_stc_tx_flow_table *tx_flow_table;
	struct wlan_dp_stc_classified_flow_table *classified_flow_table;
	struct wlan_dp_stc_sampling_candidate candidates[DP_STC_SAMPLE_FLOWS_MAX];
};

/* Function Declaration - START */

#ifdef WLAN_DP_FEATURE_STC
#define BUF_LEN_MAX 256
static inline bool is_flow_tuple_ipv4(struct flow_info *flow_tuple)
{
	if (qdf_likely((flow_tuple->flags | DP_FLOW_TUPLE_FLAGS_IPV4)))
		return true;

	return false;
}

static inline bool is_flow_tuple_ipv6(struct flow_info *flow_tuple)
{
	if (qdf_likely((flow_tuple->flags | DP_FLOW_TUPLE_FLAGS_IPV6)))
		return true;

	return false;
}

/**
 * dp_print_tuple_to_str() - Print flow tuple to a string
 * @flow_tuple: Flow tuple
 * @buf: Buffer to which the tuple is to be printed
 * @buf_len: buffer length
 *
 * Return: buffer where flow tuple is printed as string
 */
static inline uint8_t *dp_print_tuple_to_str(struct flow_info *flow_tuple,
					     uint8_t *buf, uint16_t buf_len)
{
	uint16_t len = 0;

	if (is_flow_tuple_ipv4(flow_tuple)) {
		len += scnprintf(buf + len, buf_len - len,
				 "0x%x", flow_tuple->src_ip.ipv4_addr);
		len += scnprintf(buf + len, buf_len - len,
				 " 0x%x", flow_tuple->dst_ip.ipv4_addr);
	} else if (is_flow_tuple_ipv6(flow_tuple)) {
		len += scnprintf(buf + len, buf_len - len,
				 " 0x%x-0x%x-0x%x-0x%x",
				 flow_tuple->src_ip.ipv6_addr[0],
				 flow_tuple->src_ip.ipv6_addr[1],
				 flow_tuple->src_ip.ipv6_addr[2],
				 flow_tuple->src_ip.ipv6_addr[3]);
		len += scnprintf(buf + len, buf_len - len,
				 " 0x%x-0x%x-0x%x-0x%x",
				 flow_tuple->dst_ip.ipv6_addr[0],
				 flow_tuple->dst_ip.ipv6_addr[1],
				 flow_tuple->dst_ip.ipv6_addr[2],
				 flow_tuple->dst_ip.ipv6_addr[3]);
	}

	len += scnprintf(buf + len, buf_len - len,
			 " %u", flow_tuple->src_port);
	len += scnprintf(buf + len, buf_len - len,
			 " %u", flow_tuple->dst_port);
	len += scnprintf(buf + len, buf_len - len, " %u", flow_tuple->proto);

	return buf;
}

/**
 * dp_stc_get_timestamp() - Get current timestamp to be used in STC
 *			    critical per packet path and its related calculation
 *
 * Return: current timestamp in ns
 */
static inline uint64_t dp_stc_get_timestamp(void)
{
	return qdf_sched_clock();
}

static inline uint8_t wlan_dp_ip_proto_to_stc_proto(uint16_t ip_proto)
{
	switch (ip_proto) {
	case IPPROTO_TCP:
		return QCA_WLAN_VENDOR_FLOW_POLICY_PROTO_TCP;
	case IPPROTO_UDP:
		return QCA_WLAN_VENDOR_FLOW_POLICY_PROTO_UDP;
	default:
		break;
	}

	return -EINVAL;
}

/**
 * wlan_dp_stc_populate_flow_tuple() - Populate the STC flow tuple using the
 *				       flow tuple in active flow table
 * @flow_tuple: STC flow tuple
 * @flow_tuple_info: flow tuple info
 *
 * Return: None
 */
static inline void
wlan_dp_stc_populate_flow_tuple(struct flow_info *flow_tuple,
				struct cdp_rx_flow_tuple_info *flow_tuple_info)
{
	uint8_t is_ipv4_flow = 1;	//TODO - Get from fisa flow table entry
	uint8_t is_ipv6_flow = 0;
	uint8_t proto = flow_tuple_info->l4_protocol;

	if (is_ipv4_flow) {
		flow_tuple->src_ip.ipv4_addr = flow_tuple_info->src_ip_31_0;
		flow_tuple->dst_ip.ipv4_addr = flow_tuple_info->dest_ip_31_0;
	} else if (is_ipv6_flow) {
		flow_tuple->src_ip.ipv6_addr[0] = flow_tuple_info->src_ip_31_0;
		flow_tuple->src_ip.ipv6_addr[1] = flow_tuple_info->src_ip_63_32;
		flow_tuple->src_ip.ipv6_addr[2] = flow_tuple_info->src_ip_95_64;
		flow_tuple->src_ip.ipv6_addr[3] =
						flow_tuple_info->src_ip_127_96;

		flow_tuple->dst_ip.ipv6_addr[0] = flow_tuple_info->dest_ip_31_0;
		flow_tuple->dst_ip.ipv6_addr[1] =
						flow_tuple_info->dest_ip_63_32;
		flow_tuple->dst_ip.ipv6_addr[2] =
						flow_tuple_info->dest_ip_95_64;
		flow_tuple->dst_ip.ipv6_addr[3] =
						flow_tuple_info->dest_ip_127_96;
	}
	flow_tuple->src_port = flow_tuple_info->src_port;
	flow_tuple->dst_port = flow_tuple_info->dest_port;
	flow_tuple->proto = wlan_dp_ip_proto_to_stc_proto(proto);
	flow_tuple->flags = 0;
}

enum wlan_dp_stc_classfied_flow_state {
	WLAN_DP_STC_CLASSIFIED_FLOW_STATE_INIT,
	WLAN_DP_STC_CLASSIFIED_FLOW_STATE_ADDING,
	WLAN_DP_STC_CLASSIFIED_FLOW_STATE_ADDED,
};

#define WLAN_DP_CLASSIFIED_FLAGS_TX_FLOW_VALID 0
#define WLAN_DP_CLASSIFIED_FLAGS_RX_FLOW_VALID 1
#define WLAN_DP_CLASSIFIED_FLAGS_RT_FLOW_BIT 2

#define WLAN_DP_CLASSIFIED_DEL_FLAGS_TX_DEL 0
#define WLAN_DP_CLASSIFIED_DEL_FLAGS_RX_DEL 1
#define WLAN_DP_CLASSIFIED_DEL_FLAGS_PEER 2

static inline void
wlan_dp_stc_tx_flow_retire_ind(struct wlan_dp_psoc_context *dp_ctx,
			       uint8_t classified,
			       uint8_t c_flow_id,
			       uint8_t flow_evict_success_code)
{
	struct wlan_dp_stc *dp_stc = dp_ctx->dp_stc;
	struct wlan_dp_stc_classified_flow_table *c_table;
	struct wlan_dp_stc_classified_flow_entry *c_entry;
	struct flow_info *flow_tuple;
	uint8_t buf[BUF_LEN_MAX];

	if (!dp_stc)
		return;

	c_table = dp_stc->classified_flow_table;
	c_entry = &c_table->entries[c_flow_id];
	flow_tuple = &c_entry->flow_tuple;
	dp_stc_debug(dp_stc->logmask,
		     "STC: c_state: [%u], c_flags: [%lu], classified: [%u] Remove TX flow [%u] reason:[%u], tuple: %s",
		     qdf_atomic_read(&c_entry->state),
		     c_entry->flags, classified, c_flow_id,
		     flow_evict_success_code,
		     dp_print_tuple_to_str(flow_tuple, buf,
					   BUF_LEN_MAX));

	if (!DP_STC_IS_CLASSIFIED_KNOWN(classified))
		return;

	if (qdf_atomic_read(&c_entry->state) ==
					WLAN_DP_STC_CLASSIFIED_FLOW_STATE_INIT)
		return;

	if (qdf_atomic_test_bit(WLAN_DP_CLASSIFIED_FLAGS_TX_FLOW_VALID,
				&c_entry->flags))
		qdf_atomic_set_bit(WLAN_DP_CLASSIFIED_DEL_FLAGS_TX_DEL,
				   &c_entry->del_flags);
}

static inline void
wlan_dp_stc_rx_flow_retire_ind(struct wlan_dp_psoc_context *dp_ctx,
			       uint8_t classified,
			       uint8_t c_flow_id,
			       uint8_t flow_evict_success_code)
{
	struct wlan_dp_stc *dp_stc = dp_ctx->dp_stc;
	struct wlan_dp_stc_classified_flow_table *c_table;
	struct wlan_dp_stc_classified_flow_entry *c_entry;
	struct flow_info *flow_tuple;
	uint8_t buf[BUF_LEN_MAX];

	if (!dp_stc)
		return;

	c_table = dp_stc->classified_flow_table;
	c_entry = &c_table->entries[c_flow_id];
	flow_tuple = &c_entry->flow_tuple;
	dp_stc_debug(dp_stc->logmask,
		     "STC: c_state: [%u], c_flags: [%lu], classified: [%u] Remove RX flow [%u] reason:[%u], tuple: %s",
		     qdf_atomic_read(&c_entry->state),
		     c_entry->flags, classified, c_flow_id,
		     flow_evict_success_code,
		     dp_print_tuple_to_str(flow_tuple, buf,
					   BUF_LEN_MAX));

	if (!DP_STC_IS_CLASSIFIED_KNOWN(classified))
		return;

	if (qdf_atomic_read(&c_entry->state) ==
					WLAN_DP_STC_CLASSIFIED_FLOW_STATE_INIT)
		return;

	if (qdf_atomic_test_bit(WLAN_DP_CLASSIFIED_FLAGS_RX_FLOW_VALID,
				&c_entry->flags))
		qdf_atomic_set_bit(WLAN_DP_CLASSIFIED_DEL_FLAGS_RX_DEL,
				   &c_entry->del_flags);
}

/**
 * wlan_dp_stc_mark_ping_ts() - Mark the last ping timestamp in STC table
 * @dp_ctx: DP global psoc context
 * @peer_id: peer id
 *
 * Return: void
 */
static inline void
wlan_dp_stc_mark_ping_ts(struct wlan_dp_psoc_context *dp_ctx,
			 uint16_t peer_id)
{
	struct wlan_dp_stc *dp_stc = dp_ctx->dp_stc;
	struct wlan_dp_stc_peer_traffic_context *peer_tc;
	bool send_fw_indication = false;

	if (!dp_stc)
		return;

	if (peer_id == DP_STC_INVALID_PEER_ID)
		return;

	peer_tc = &dp_stc->peer_tc[peer_id];
	if (!peer_tc->valid)
		return;

	if (peer_tc->last_ping_ts == 0)
		send_fw_indication = true;

	peer_tc->last_ping_ts = dp_stc_get_timestamp();
	qdf_atomic_set_bit(WLAN_DP_STC_TRAFFIC_PING,
			   &peer_tc->non_flow_traffic);

	if (send_fw_indication)
		qdf_atomic_set(&peer_tc->send_fw_ind, 1);
}

static inline bool
dp_stc_is_remove_flow_allowed(uint8_t classified, uint8_t selected_to_sample,
			      uint64_t inactivity_timeout, uint64_t active_ts,
			      uint64_t cur_ts)
{
	/* Caller has to make sure cur_ts > active_ts */
	if ((DP_STC_IS_CLASSIFIED_KNOWN(classified) || selected_to_sample) &&
	    inactivity_timeout && (cur_ts - active_ts < inactivity_timeout))
		return false;

	return true;
}

/**
 * wlan_dp_get_tx_flow_hdl() - Retrieve TX flow handle from flow ID
 * @dp_ctx: Pointer to the DP (Data Path) context structure
 * @flow_id: Flow ID used to index into the flow records
 *
 * This API is only call if the tx_flow_id is valid. STC takes care
 * of checking gl_flow_recs when trying to find the tx flow.
 *
 * Return: Pointer to the corresponding struct wlan_dp_spm_flow_info
 */
static inline struct wlan_dp_spm_flow_info *
wlan_dp_get_tx_flow_hdl(struct wlan_dp_psoc_context *dp_ctx, uint8_t flow_id)
{
	return &dp_ctx->gl_flow_recs[flow_id];
}

static inline uint8_t *
dp_print_tx_flow_info_to_str(uint32_t flow_id, enum wlan_dp_flow_dir dir,
			     uint8_t *buf, uint16_t buf_len)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();
	struct wlan_dp_spm_flow_info *tx_flow;
	uint16_t len = 0;

	tx_flow = wlan_dp_get_tx_flow_hdl(dp_ctx, flow_id);
	len += scnprintf(buf + len, buf_len - len, "%u %u %llu",
			 tx_flow->selected_to_sample,
			 tx_flow->classified, tx_flow->flow_add_ts);

	return buf;
}

static inline uint8_t *
dp_print_rx_flow_info_to_str(uint32_t flow_id, enum wlan_dp_flow_dir dir,
			     uint8_t *buf, uint16_t buf_len)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();
	struct dp_fisa_rx_sw_ft *rx_flow;
	uint16_t len = 0;

	rx_flow = wlan_dp_get_rx_flow_hdl(dp_ctx, flow_id);
	len += scnprintf(buf + len, buf_len - len, "%u %u %llu",
			 rx_flow->selected_to_sample,
			 rx_flow->classified, rx_flow->flow_init_ts);

	return buf;
}

/**
 * wlan_dp_indicate_flow_add() - Indication to STC when flow is added
 * @dp_ctx: Global DP psoc context
 * @dir: direction of flow (RX/TX)
 * @flow_tuple: Tuple of the flow which got added
 * @flow_id: Flow id of flow
 *
 * Return: None
 */
static inline void
wlan_dp_indicate_flow_add(struct wlan_dp_psoc_context *dp_ctx,
			  enum wlan_dp_flow_dir dir,
			  struct flow_info *flow_tuple, uint32_t flow_id)
{
	struct wlan_dp_stc *dp_stc = dp_ctx->dp_stc;
	uint8_t buf[BUF_LEN_MAX];
	uint8_t flow_info_buf[BUF_LEN_MAX];

	if (!dp_stc)
		return;

	switch (dir) {
	case WLAN_DP_FLOW_DIR_TX:
		dp_stc_debug(dp_stc->logmask, "STC: Add TX flow [%u] %s [%s]",
			     flow_id, dp_print_tuple_to_str(flow_tuple, buf,
							    BUF_LEN_MAX),
			     dp_print_tx_flow_info_to_str(flow_id, dir,
							  flow_info_buf,
							  BUF_LEN_MAX));
		break;
	case WLAN_DP_FLOW_DIR_RX:
		dp_stc_debug(dp_stc->logmask, "STC: Add RX flow [%u] %s [%s]",
			     flow_id, dp_print_tuple_to_str(flow_tuple, buf,
							    BUF_LEN_MAX),
			     dp_print_rx_flow_info_to_str(flow_id, dir,
							  flow_info_buf,
							  BUF_LEN_MAX));
		break;
	default:
		break;
	}

	/* RCU or atomic variable?? */
	if (dp_stc->periodic_work_state < WLAN_DP_STC_WORK_STARTED) {
		qdf_periodic_work_start(&dp_stc->flow_monitor_work,
					dp_stc->flow_monitor_interval);
		dp_stc->periodic_work_state = WLAN_DP_STC_WORK_STARTED;
	}
}

/**
 * wlan_dp_stc_track_flow_features() - Track flow features
 * @dp_stc: STC context
 * @nbuf: packet handle
 * @flow_entry: flow entry (to which the current pkt belongs)
 * @vdev_id: ID of vdev to which the packet belongs
 * @peer_id: ID of peer to which the packet belongs
 * @pkt_len: length of the packet (excluding ethernet header)
 * @metadata: RX flow metadata
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
wlan_dp_stc_track_flow_features(struct wlan_dp_stc *dp_stc, qdf_nbuf_t nbuf,
				struct wlan_dp_stc_flow_table_entry *flow_entry,
				uint8_t vdev_id, uint16_t peer_id,
				uint16_t pkt_len, uint32_t metadata);

static inline
bool wlan_dp_stc_rx_nbuf_is_tcp_ack(qdf_nbuf_t nbuf)
{
	bool is_pure_ack;

	if (QDF_NBUF_CB_RX_TCP_PROTO(nbuf))
		return false;

	qdf_nbuf_push_head(nbuf, QDF_ETH_HDR_LEN);
	is_pure_ack = qdf_nbuf_is_ipv4_v6_pure_tcp_ack(nbuf);
	qdf_nbuf_pull_head(nbuf, QDF_ETH_HDR_LEN);

	return is_pure_ack;
}

static inline QDF_STATUS
wlan_dp_stc_check_n_track_rx_flow_features(struct wlan_dp_psoc_context *dp_ctx,
					   qdf_nbuf_t nbuf)
{
	struct wlan_dp_stc_flow_table_entry *flow_entry;
	struct wlan_dp_stc *dp_stc;
	uint8_t vdev_id;
	uint16_t peer_id;
	uint16_t flow_id;
	uint32_t metadata;
	uint16_t pkt_len;

	if (qdf_likely(!QDF_NBUF_CB_RX_TRACK_FLOW(nbuf)))
		return QDF_STATUS_SUCCESS;

	/* Do not update flow feature stats for TCP pure acks */
	if (qdf_unlikely(QDF_NBUF_CB_RX_TCP_PURE_ACK(nbuf) ||
			 wlan_dp_stc_rx_nbuf_is_tcp_ack(nbuf)))
		return QDF_STATUS_SUCCESS;

	dp_stc = dp_ctx->dp_stc;
	vdev_id = QDF_NBUF_CB_RX_VDEV_ID(nbuf);
	peer_id = QDF_NBUF_CB_RX_PEER_ID(nbuf);
	flow_id = QDF_NBUF_CB_EXT_RX_FLOW_ID(nbuf);
	metadata = QDF_NBUF_CB_RX_FLOW_METADATA(nbuf);
	pkt_len = qdf_nbuf_len(nbuf);

	flow_entry = &dp_stc->rx_flow_table->entries[flow_id];

	return wlan_dp_stc_track_flow_features(dp_stc, nbuf, flow_entry,
					       vdev_id, peer_id, pkt_len,
					       metadata);
}

/**
 * wlan_dp_stc_check_n_track_tx_flow_features() - Update the stats if flow is
 *						  tracking enabled
 * @dp_ctx: DP global psoc context
 * @nbuf: Packet nbuf
 * @flow_track_enabled: Flow tracking enabled
 * @flow_id: Flow id of flow
 * @vdev_id: Vdev of the flow
 * @peer_id: Peer_id of the flow
 * @metadata: Metadata of the flow
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
wlan_dp_stc_check_n_track_tx_flow_features(struct wlan_dp_psoc_context *dp_ctx,
					   qdf_nbuf_t nbuf,
					   uint32_t flow_track_enabled,
					   uint16_t flow_id, uint8_t vdev_id,
					   uint16_t peer_id, uint32_t metadata)
{
	struct wlan_dp_stc *dp_stc = dp_ctx->dp_stc;
	struct wlan_dp_stc_flow_table_entry *flow_entry;
	uint16_t pkt_len;

	if (qdf_likely(!flow_track_enabled))
		return QDF_STATUS_SUCCESS;

	/* Do not update flow feature stats for TCP pure acks */
	if (qdf_unlikely(QDF_NBUF_CB_GET_PACKET_TYPE(nbuf) ==
					QDF_NBUF_CB_PACKET_TYPE_TCP_ACK))
		return QDF_STATUS_SUCCESS;

	flow_entry = &dp_stc->tx_flow_table->entries[flow_id];
	pkt_len = qdf_nbuf_len(nbuf) - sizeof(qdf_ether_header_t);

	return wlan_dp_stc_track_flow_features(dp_stc, nbuf, flow_entry,
					       vdev_id, peer_id, pkt_len,
					       metadata);
}

QDF_STATUS
wlan_dp_stc_handle_flow_stats_policy(enum qca_async_stats_type type,
				     enum qca_async_stats_action);
/**
 * wlan_dp_stc_handle_flow_classify_result() - Handle flow classify result
 * @flow_classify_result:
 *
 * Return: none
 */
void
wlan_dp_stc_handle_flow_classify_result(struct wlan_dp_stc_flow_classify_result *flow_classify_result);

/**
 * wlan_dp_stc_peer_event_notify() - Handle the peer map/unmap events
 * @soc: CDP soc
 * @event: Peer event
 * @peer_id: Peer ID
 * @vdev_id: VDEV ID
 * @peer_mac_addr: mac address of the Peer
 */
QDF_STATUS wlan_dp_stc_peer_event_notify(ol_txrx_soc_handle soc,
					 enum cdp_peer_event event,
					 uint16_t peer_id, uint8_t vdev_id,
					 uint8_t *peer_mac_addr);

/**
 * wlan_dp_stc_cfg_init() - CFG init for STC
 * @config: SoC CFG config
 * @psoc: Objmgr PSoC handle
 *
 * Return: None
 */
void wlan_dp_stc_cfg_init(struct wlan_dp_psoc_cfg *config,
			  struct wlan_objmgr_psoc *psoc);

/**
 * wlan_dp_cfg_is_stc_enabled() - Helper function to check if STC is enabled
 * @dp_cfg: SoC CFG config
 *
 * Return: true if STC is enabled, false if STC is disabled.
 */
static inline bool wlan_dp_cfg_is_stc_enabled(struct wlan_dp_psoc_cfg *dp_cfg)
{
	return dp_cfg->stc_enable;
}

/**
 * wlan_dp_cfg_is_stc_rtpm_control_enabled() - Helper function to check if STC
 *                                             is enabled
 * @dp_cfg: SoC CFG config
 *
 * Return: true if STC is enabled, false if STC is disabled.
 */
static inline bool
wlan_dp_cfg_is_stc_rtpm_control_enabled(struct wlan_dp_psoc_cfg *dp_cfg)
{
	return dp_cfg->stc_rtpm_control;
}

/**
 * wlan_dp_stc_get_logmask() - Get STC log mask
 * @dp_ctx: DP global psoc context
 *
 * Return: logmask configured in STC
 */
uint32_t wlan_dp_stc_get_logmask(struct wlan_dp_psoc_context *dp_ctx);

/**
 * wlan_dp_stc_update_logmask() - Set STC log mask
 * @dp_ctx: DP global psoc context
 * @mask: new log mask to be set
 *
 * Return: None
 */
void wlan_dp_stc_update_logmask(struct wlan_dp_psoc_context *dp_ctx,
				uint32_t mask);

/**
 * wlan_dp_stc_dump_periodic_stats() - Function to print STC periodic stats
 * @dp_ctx: Datapath component context
 *
 * Return: None
 */
void wlan_dp_stc_dump_periodic_stats(struct wlan_dp_psoc_context *dp_ctx);

/**
 * wlan_dp_stc_print_sampling_table() - Dump the sampling table
 * @dp_ctx: Datapath component context
 *
 * Return: None
 */
void wlan_dp_stc_print_sampling_table(struct wlan_dp_psoc_context *dp_ctx);

/**
 * wlan_dp_stc_print_classified_table() - Dump the classified table
 * @dp_ctx: Datapath component context
 *
 * Return: None
 */
void wlan_dp_stc_print_classified_table(struct wlan_dp_psoc_context *dp_ctx);

/**
 * wlan_dp_stc_print_active_traffic_map() - Dump the active traffic map
 *					    for all the valid peers
 * @dp_ctx: Datapath component context
 *
 * Return: None
 */
void wlan_dp_stc_print_active_traffic_map(struct wlan_dp_psoc_context *dp_ctx);

/**
 * wlan_dp_stc_attach() - STC attach
 * @dp_ctx: DP global psoc context
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wlan_dp_stc_attach(struct wlan_dp_psoc_context *dp_ctx);

/**
 * wlan_dp_stc_detach() - STC detach
 * @dp_ctx: DP global psoc context
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wlan_dp_stc_detach(struct wlan_dp_psoc_context *dp_ctx);
#else
static inline void
wlan_dp_stc_populate_flow_tuple(struct flow_info *flow_tuple,
				struct cdp_rx_flow_tuple_info *flow_tuple_info)
{
}

static inline bool
dp_stc_is_remove_flow_allowed(uint8_t classified, uint8_t selected_to_sample,
			      uint64_t inactivity_timeout, uint64_t active_ts,
			      uint64_t cur_ts)
{
	return true;
}

static inline void
wlan_dp_indicate_flow_add(struct wlan_dp_psoc_context *dp_ctx,
			  enum wlan_dp_flow_dir dir,
			  struct flow_info *flow_tuple, uint32_t flow_id)
{
}

static inline void
wlan_dp_stc_tx_flow_retire_ind(struct wlan_dp_psoc_context *dp_ctx,
			       uint8_t classified,
			       uint8_t c_flow_id,
			       uint8_t flow_evict_success_code)
{
}

static inline void
wlan_dp_stc_rx_flow_retire_ind(struct wlan_dp_psoc_context *dp_ctx,
			       uint8_t classified,
			       uint8_t c_flow_id,
			       uint8_t flow_evict_success_code)
{
}

static inline void
wlan_dp_stc_mark_ping_ts(struct wlan_dp_psoc_context *dp_ctx,
			 uint16_t peer_id)
{
}

static inline QDF_STATUS
wlan_dp_stc_check_n_track_rx_flow_features(struct wlan_dp_psoc_context *dp_ctx,
					   qdf_nbuf_t nbuf)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS
wlan_dp_stc_check_n_track_tx_flow_features(struct wlan_dp_psoc_context *dp_ctx,
					   qdf_nbuf_t nbuf,
					   uint32_t flow_track_enabled,
					   uint16_t flow_id, uint8_t vdev_id,
					   uint16_t peer_id, uint32_t metadata)
{
	return QDF_STATUS_SUCCESS;
}

static inline void wlan_dp_stc_cfg_init(struct wlan_dp_psoc_cfg *config,
					struct wlan_objmgr_psoc *psoc)
{
}

static inline bool wlan_dp_cfg_is_stc_enabled(struct wlan_dp_psoc_cfg *dp_cfg)
{
	return false;
}

static inline
uint32_t wlan_dp_stc_get_logmask(struct wlan_dp_psoc_context *dp_ctx)
{
	return 0;
}

static inline
void wlan_dp_stc_update_logmask(struct wlan_dp_psoc_context *dp_ctx,
				uint32_t mask)
{
}

static inline void
wlan_dp_stc_dump_periodic_stats(struct wlan_dp_psoc_context *dp_ctx)
{
}

static inline void
wlan_dp_stc_print_sampling_table(struct wlan_dp_psoc_context *dp_ctx)
{
}

static inline void
wlan_dp_stc_print_classified_table(struct wlan_dp_psoc_context *dp_ctx)
{
}

static inline void
wlan_dp_stc_print_active_traffic_map(struct wlan_dp_psoc_context *dp_ctx)
{
}

static inline
QDF_STATUS wlan_dp_stc_attach(struct wlan_dp_psoc_context *dp_ctx)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS wlan_dp_stc_detach(struct wlan_dp_psoc_context *dp_ctx)
{
	return QDF_STATUS_SUCCESS;
}
#endif
/* Function Declaration - END */
#endif
