/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

 /**
  * DOC: wlan_ipa_logging.h
  *
  *
  */

#ifndef _WLAN_IP_LOGGING_H_
#define _WLAN_IP_LOGGING_H_

#include "qdf_threads.h"
#include "qdf_event.h"
#include "wlan_cfg80211.h"
#include <wlan_nlink_srv.h>
#define MAX_LOG_PAYLOAD_LENGTH 384
#define WLAN_IPA_PREFIX_BUFFER_LEN_MAX 128
#define MAX_LOG_LENGTH MAX_LOG_PAYLOAD_LENGTH + WLAN_IPA_PREFIX_BUFFER_LEN_MAX
#define WLAN_IPA_MAX_LIST_SIZE 64
#define WLAN_IPA_LOGGING(arg, ...) \
	WLAN_IPA_LOGGING_FUNC(__func__, arg, ##__VA_ARGS__)
#define WLAN_IPA_LOGGING_RL(arg, ...) \
	do { \
		static ulong __last_ticks; \
		ulong __ticks = jiffies; \
		if (time_after(__ticks, __last_ticks + HZ)) { \
			WLAN_IPA_LOGGING_FUNC(__func__, arg, ##__VA_ARGS__); \
			__last_ticks = __ticks; \
		} \
	} while (0)

#define WLAN_IPA_LOGGING_FUNC wlan_ipa_log_message
#define WLAN_IPA_LOG_MSG_LENGTH_MAX 2048
#define WLAN_IPA_HOST_MSG_MARKER "OPT_DP_HOST"

#ifdef IPA_OPT_WIFI_DP_LOGGING
/**
 * enum wlan_ipa_logging_thread_state - enum to keep track of
 * logging thread state
 * @WLAN_IPA_LOGGING_THREAD_INVALID: initial invalid state
 * @WLAN_IPA_LOGGING_THREAD_RUNNING: logging thread functional(NOT suspended,
 *                      processing logs or waiting on a wait_queue)
 * @WLAN_IPA_LOGGING_THREAD_CANCEL_INPROGESS: logging thread is cancel
 * inprogress
 * @WLAN_IPA_LOGGING_THREAD_CANCELLED: logging thread cancelled
 */
enum wlan_ipa_logging_thread_state {
	WLAN_IPA_LOGGING_THREAD_INVALID,
	WLAN_IPA_LOGGING_THREAD_RUNNING,
	WLAN_IPA_LOGGING_THREAD_CANCEL_INPROGESS,
	WLAN_IPA_LOGGING_THREAD_CANCELLED,
};

/**
 * struct wlan_ipa_log_context - structure holding resources for ipa logging
 * @free_list: free node list which can be used for filling logs
 * @filled_list: filled nodes list having logs to send to upper layer
 * @lock: Lock to synchronize access to shared logging resource
 * @payload: final payload to be send to userspace
 * @wait_q: Wait queue for Logger thread
 * @thread: logger thread
 * @drop_count: log dropped
 * @event_flag: event flag to post events to logger thread
 * @log_truncation: log truncation indication
 * @thread_state: logging thread state
 * @wmi_fw_log_msg_stat: number of wmi msg received from FW
 * @fw_log_msg_to_nl_stat: number of fw log msg sent to nl
 */
struct wlan_ipa_log_context {
	qdf_list_t free_list;
	qdf_list_t filled_list;
	qdf_spinlock_t lock;
	char payload[WLAN_IPA_LOG_MSG_LENGTH_MAX];
	qdf_wait_queue_head_t wait_q;
	qdf_thread_t *thread;
	uint16_t drop_count;
	unsigned long event_flag;
	bool log_truncation;
	enum wlan_ipa_logging_thread_state thread_state;
	uint32_t wmi_fw_log_msg_stat;
	uint32_t fw_log_msg_to_nl_stat;
};

/**
 * struct wlan_ipa_log_msg - structure holding log msg
 * @node: filled list node
 * @logbuf: buffer to hold log msg
 */
struct wlan_ipa_log_msg {
	qdf_list_node_t node;
	char logbuf[MAX_LOG_LENGTH];
};

/**
 * wlan_ipa_log_message() - get the logs from all the context
 * and post to logger thread
 * @func: logging function
 * @msg: actual log to send
 */
void wlan_ipa_log_message(const char *func, const char *msg, ...);

/**
 * enum wlan_ipa_nl_msg_type - netlink msg type
 * @WLAN_IPA_NL_MSG_HOST_TYPE: msg type for host logs
 *		related to opt_dp
 * @WLAN_IPA_NL_MSG_FW_TYPE: msg type for FW logs
 *		related to opt_dp
 */
enum wlan_ipa_nl_msg_type {
	WLAN_IPA_NL_MSG_HOST_TYPE = 0,
	WLAN_IPA_NL_MSG_FW_TYPE = 1,
};

/** struct nl_msg_header - netlink msg header
 * @nlh: netlink header
 * @type: message type
 * @length: actual payload length
 */
struct nl_msg_header {
	struct nlmsghdr nlh;
	unsigned short type;
	unsigned short length;
};

/**
 * ipa_fw_nl_broadcast() - send netlink msg to userspace
 *			   for fw logs
 * @buffer: fw logs
 * @len: length of logs
 */
int ipa_fw_nl_broadcast(const uint8_t *buffer, uint32_t len);

/**
 * wlan_ipa_logging_sock_init() - init ipa logging resources
 */
QDF_STATUS wlan_ipa_logging_sock_init(void);

/**
 * wlan_ipa_logging_sock_deinit() - deinit ipa logging resources
 */
void wlan_ipa_logging_sock_deinit(void);

/**
 * ipa_fw_log_received_stats() - no. of wmi msg received for fw log
 */
void ipa_fw_log_received_stats(void);

/**
 * ipa_dump_logging_stats() - print stats related to ipa logging
 */
void ipa_dump_logging_stats(void);

#else
static inline
void wlan_ipa_log_message(const char *func, const char *msg, ...)
{
}

static inline
QDF_STATUS wlan_ipa_logging_sock_init(void)
{
	return QDF_STATUS_SUCCESS;
}

static inline
void wlan_ipa_logging_sock_deinit(void)
{
}

static inline
void ipa_fw_log_received_stats(void)
{
}

static inline
void ipa_dump_logging_stats(void)
{
}
#endif
#endif /* _WLAN_IP_LOGGING_H_ */
