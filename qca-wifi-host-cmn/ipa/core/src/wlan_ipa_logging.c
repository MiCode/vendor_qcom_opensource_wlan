/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

 /**
  * DOC: wlan_ipa_logging.c
  *
  *
  */

/* Include Files */
#include <wlan_ipa_main.h>
#include "cnss_nl.h"
#define WLAN_IPA_THREAD_NAME_MAX 20
#define WLAN_IPA_TEMP_BUF_LEN_MAX 20
#define WLAN_IPA_POST_HOST_LOG 0x001
#define WLAN_IPA_SHUTDOWN_LOGGING_THREAD 0x002
#define WLAN_IPA_MAX_WAIT_TIME 100
#define WLAN_IPA_SLEEP_TIME 10

#ifdef IPA_OPT_WIFI_DP_LOGGING
struct wlan_ipa_log_context g_ipa_logging_ctx;
static struct wlan_ipa_log_msg *g_ipa_log_msg;

int ipa_fw_nl_broadcast(const uint8_t *buffer, uint32_t len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int payload_len;
	struct nl_msg_header *wnl;
	int tot_msg_len;

	payload_len = len + sizeof(wnl->type) + sizeof(wnl->length);
	tot_msg_len = NLMSG_SPACE(payload_len);

	skb = dev_alloc_skb(tot_msg_len);
	if (!skb)
		return QDF_STATUS_E_FAILURE;

	nlh = nlmsg_put(skb, 0, 0, WLAN_NL_MSG_OPT_DP_LOG,
			payload_len, NLM_F_REQUEST);
	if (!nlh) {
		dev_kfree_skb(skb);
		return QDF_STATUS_E_FAILURE;
	}

	wnl = (struct nl_msg_header *)nlh;
	wnl->type = WLAN_IPA_NL_MSG_FW_TYPE;
	wnl->length = len;
	qdf_mem_copy(nlmsg_data(nlh) + sizeof(wnl->type) +
		     sizeof(wnl->length), buffer, len);
	nl_srv_bcast(skb, CLD80211_MCGRP_OPT_DP_LOGS,
		     WLAN_NL_MSG_OPT_DP_LOG);
	g_ipa_logging_ctx.fw_log_msg_to_nl_stat += 1;
	return QDF_STATUS_SUCCESS;
}

static inline
QDF_STATUS wlan_ipa_nl_broadcast(int length, char *buf)
{
	int tot_msg_len;
	int payload_len;
	struct nl_msg_header *wnl;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh;
	static int nlmsg_seq;

	payload_len = length + sizeof(wnl->type) + sizeof(wnl->length);
	tot_msg_len = NLMSG_SPACE(payload_len);

	skb = dev_alloc_skb(tot_msg_len);
	if (!skb)
		return QDF_STATUS_E_FAILURE;

	nlh = nlmsg_put(skb, 0, nlmsg_seq++, WLAN_NL_MSG_OPT_DP_LOG,
			payload_len, NLM_F_REQUEST);
	if (!nlh) {
		dev_kfree_skb(skb);
		return QDF_STATUS_E_FAILURE;
	}

	wnl = (struct nl_msg_header *)nlh;
	wnl->type = WLAN_IPA_NL_MSG_HOST_TYPE;
	wnl->length = length;
	qdf_mem_copy(nlmsg_data(nlh) + sizeof(wnl->type) +
		     sizeof(wnl->length), buf, length);
	nl_srv_bcast(skb, CLD80211_MCGRP_OPT_DP_LOGS,
		     WLAN_NL_MSG_OPT_DP_LOG);
	return QDF_STATUS_SUCCESS;
}

static inline
bool wlan_ipa_is_logging_thread_running(void)
{
	if (g_ipa_logging_ctx.thread_state ==
	    WLAN_IPA_LOGGING_THREAD_RUNNING)
		return true;

	return false;
}

static inline
QDF_STATUS wlan_ipa_send_to_userspace(bool flush_log)
{
	struct wlan_ipa_log_msg *curr_node = NULL;
	char *str;
	int len = 0;
	int num_log = 0;
	int ret = 0;

	str = g_ipa_logging_ctx.payload;
	while (g_ipa_log_msg &&
	       !qdf_list_empty(&g_ipa_logging_ctx.filled_list) &&
	       (wlan_ipa_is_logging_thread_running() || flush_log)) {
		qdf_spin_lock_bh(&g_ipa_logging_ctx.lock);
		qdf_list_remove_front(&g_ipa_logging_ctx.filled_list,
				      (qdf_list_node_t **)&curr_node);
		qdf_spin_unlock_bh(&g_ipa_logging_ctx.lock);
		if (!curr_node) {
			ipa_err_rl("log msg freed already");
			continue;
		}

		if (len + qdf_str_len(curr_node->logbuf) +
		    sizeof(struct nl_msg_header) >
		    WLAN_IPA_LOG_MSG_LENGTH_MAX) {
			ret = wlan_ipa_nl_broadcast(len, str);
			if (QDF_IS_STATUS_ERROR(ret)) {
				ipa_err_rl("nl broadcast failure");
				g_ipa_logging_ctx.drop_count += num_log;
			}
			num_log = 0;
			len = 0;
			qdf_mem_set(str, WLAN_IPA_LOG_MSG_LENGTH_MAX, '\0');
		}

		len += qdf_scnprintf(str + len,
				     WLAN_IPA_LOG_MSG_LENGTH_MAX - len, "%s",
				     curr_node->logbuf);
		num_log++;
		qdf_spin_lock_bh(&g_ipa_logging_ctx.lock);
		qdf_list_insert_back(&g_ipa_logging_ctx.free_list,
				     (qdf_list_node_t *)curr_node);
		qdf_spin_unlock_bh(&g_ipa_logging_ctx.lock);
	}

	if (len > 0) {
		ret = wlan_ipa_nl_broadcast(len, str);
		if (QDF_IS_STATUS_ERROR(ret)) {
			ipa_err_rl("nl broadcast failure");
			g_ipa_logging_ctx.drop_count += num_log;
		}
	}

	return ret;
}

static inline int wlan_ipa_logging_thread(void *arg)
{
	int ret_wait_status = 0;
	int ret;

	g_ipa_logging_ctx.thread_state = WLAN_IPA_LOGGING_THREAD_RUNNING;
	ipa_info("ipa logging thread in running state");
	while (true) {
		ret_wait_status =
			qdf_wait_queue_interruptible(
				g_ipa_logging_ctx.wait_q,
				 (qdf_atomic_test_bit(
					 WLAN_IPA_POST_HOST_LOG,
					 &g_ipa_logging_ctx.event_flag) ||
				 qdf_atomic_test_bit(
					 WLAN_IPA_SHUTDOWN_LOGGING_THREAD,
					 &g_ipa_logging_ctx.event_flag)));

		if (ret_wait_status == -ERESTARTSYS) {
			ipa_err_rl("wait_evt_interrupt returned -ERESTARTSYS");
			break;
		}

		if (qdf_atomic_test_and_clear_bit(
					WLAN_IPA_SHUTDOWN_LOGGING_THREAD,
					&g_ipa_logging_ctx.event_flag))
			break;

		if (qdf_atomic_test_and_clear_bit(
					WLAN_IPA_POST_HOST_LOG,
					&g_ipa_logging_ctx.event_flag)) {
			ret = wlan_ipa_send_to_userspace(false);
			if (ret)
				ipa_err_rl("failed to send log, ret - %d",
					   ret);
		}
	}

	g_ipa_logging_ctx.thread_state = WLAN_IPA_LOGGING_THREAD_CANCELLED;
	ipa_info("exit ipa logging thread");
	return 0;
}

static inline QDF_STATUS wlan_ipa_allocate_log_msg(void)
{
	int i;

	g_ipa_log_msg = qdf_mem_malloc(WLAN_IPA_MAX_LIST_SIZE *
				       sizeof(struct wlan_ipa_log_msg));
	if (!g_ipa_log_msg)
		return QDF_STATUS_E_NOMEM;

	qdf_spin_lock_bh(&g_ipa_logging_ctx.lock);
	for (i = 0; i < WLAN_IPA_MAX_LIST_SIZE; i++) {
		qdf_list_insert_back(&g_ipa_logging_ctx.free_list,
				     &g_ipa_log_msg[i].node);
	}

	qdf_spin_unlock_bh(&g_ipa_logging_ctx.lock);
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_ipa_logging_sock_init(void)
{
	char log_thread_name[WLAN_IPA_THREAD_NAME_MAX] = {0};

	ipa_info("Init IPA logging infra");
	g_ipa_logging_ctx.thread_state = WLAN_IPA_LOGGING_THREAD_INVALID;
	qdf_scnprintf(log_thread_name, sizeof(log_thread_name),
		      "ipa_log_thread");
	qdf_list_create(&g_ipa_logging_ctx.free_list,
			WLAN_IPA_MAX_LIST_SIZE);
	qdf_list_create(&g_ipa_logging_ctx.filled_list,
			WLAN_IPA_MAX_LIST_SIZE);
	qdf_spinlock_create(&g_ipa_logging_ctx.lock);
	if (QDF_IS_STATUS_ERROR(wlan_ipa_allocate_log_msg())) {
		ipa_err("Could not allocate memory for log_msg");
		qdf_spinlock_destroy(&g_ipa_logging_ctx.lock);
		return QDF_STATUS_E_FAILURE;
	}

	g_ipa_logging_ctx.event_flag = 0;
	qdf_init_waitqueue_head(&g_ipa_logging_ctx.wait_q);
	g_ipa_logging_ctx.thread = qdf_create_thread(wlan_ipa_logging_thread,
						     NULL,
						     log_thread_name);
	if (!g_ipa_logging_ctx.thread) {
		ipa_err("could not create ipa_log_thread");
		qdf_mem_free(g_ipa_log_msg);
		qdf_spinlock_destroy(&g_ipa_logging_ctx.lock);
		return QDF_STATUS_E_FAILURE;
	}

	qdf_wake_up_process(g_ipa_logging_ctx.thread);
	qdf_sleep(WLAN_IPA_MAX_WAIT_TIME);
	g_ipa_logging_ctx.drop_count = 0;
	g_ipa_logging_ctx.log_truncation = false;
	g_ipa_logging_ctx.wmi_fw_log_msg_stat = 0;
	g_ipa_logging_ctx.fw_log_msg_to_nl_stat = 0;
	return QDF_STATUS_SUCCESS;
}

void wlan_ipa_logging_sock_deinit(void)
{
	int wait_count = 0;

	ipa_info("Deinit IPA logging infra");
	if (!qdf_list_empty(&g_ipa_logging_ctx.filled_list)) {
		qdf_atomic_set_bit(WLAN_IPA_POST_HOST_LOG,
				   &g_ipa_logging_ctx.event_flag);
		qdf_wake_up_interruptible(&g_ipa_logging_ctx.wait_q);
		qdf_sleep(WLAN_IPA_MAX_WAIT_TIME);
	}

	qdf_atomic_set_bit(WLAN_IPA_SHUTDOWN_LOGGING_THREAD,
			   &g_ipa_logging_ctx.event_flag);
	g_ipa_logging_ctx.thread_state =
		WLAN_IPA_LOGGING_THREAD_CANCEL_INPROGESS;
	qdf_atomic_clear_bit(WLAN_IPA_POST_HOST_LOG,
			     &g_ipa_logging_ctx.event_flag);
	qdf_wake_up_interruptible(&g_ipa_logging_ctx.wait_q);
	while (g_ipa_logging_ctx.thread_state !=
	       WLAN_IPA_LOGGING_THREAD_CANCELLED) {
		qdf_sleep(WLAN_IPA_SLEEP_TIME);
		wait_count++;
		if (wait_count > WLAN_IPA_MAX_WAIT_TIME) {
			ipa_err("IPA thread failed to cancel");
			break;
		}
	}

	if (!qdf_list_empty(&g_ipa_logging_ctx.filled_list)) {
		ipa_err("send log from deinit");
		wlan_ipa_send_to_userspace(true);
	}

	qdf_spinlock_destroy(&g_ipa_logging_ctx.lock);
	qdf_mem_free(g_ipa_log_msg);
	g_ipa_log_msg = NULL;
}

static inline
const char *current_process_name(void)
{
	if (in_irq())
		return "irq";

	if (in_softirq())
		return "soft_irq";

	return current->comm;
}

static inline
int wlan_ipa_add_process_time_stamp(char *tbuf, size_t tbuf_sz,
				    uint64_t ts, const char *func)
{
	char time_buf[WLAN_IPA_TEMP_BUF_LEN_MAX];

	qdf_get_time_of_the_day_in_hr_min_sec_usec(time_buf, sizeof(time_buf));

	return qdf_scnprintf(tbuf, tbuf_sz, "[%.6s][0x%llx]%s[%d]%s%s: ",
			 current_process_name(), ts,
			 time_buf, in_interrupt() ? 0 : current->pid,
			 g_ipa_logging_ctx.log_truncation ? "**" : "",
			 func);
}

static inline
QDF_STATUS wlan_ipa_send_to_filled_list(char *log, int length, const char *func)
{
	char tbuf[WLAN_IPA_PREFIX_BUFFER_LEN_MAX];
	int tlen;
	uint64_t ts;
	int total_log_len, header_len, payload_len_avail;
	char *ptr;
	struct wlan_ipa_log_msg *curr_node = NULL;
	char msg_header[WLAN_IPA_TEMP_BUF_LEN_MAX];

	if (!wlan_ipa_is_logging_thread_running()) {
		ipa_err_rl("ipa_logging framework is not active");
		return QDF_STATUS_E_FAILURE;
	}

	if (qdf_list_empty(&g_ipa_logging_ctx.free_list)) {
		ipa_err_rl("no free entries available in list");
		g_ipa_logging_ctx.log_truncation = true;
		g_ipa_logging_ctx.drop_count++;
		return QDF_STATUS_E_FAILURE;
	}

	qdf_spin_lock_bh(&g_ipa_logging_ctx.lock);
	qdf_list_remove_front(&g_ipa_logging_ctx.free_list,
			      (qdf_list_node_t **)&curr_node);
	qdf_spin_unlock_bh(&g_ipa_logging_ctx.lock);
	ptr = curr_node->logbuf;
	if (!ptr) {
		ipa_err_rl("error on fetching log buffer");
		return QDF_STATUS_E_FAILURE;
	}

	header_len = qdf_scnprintf(msg_header, sizeof(msg_header), "[%s]",
				   WLAN_IPA_HOST_MSG_MARKER);

	ts = qdf_get_log_timestamp();
	tlen = wlan_ipa_add_process_time_stamp(tbuf, sizeof(tbuf), ts, func);
	qdf_mem_copy(ptr, msg_header, header_len);
	qdf_mem_copy(&ptr[header_len], tbuf, tlen);
	payload_len_avail = MAX_LOG_LENGTH - 2 - (tlen + header_len);
	if (payload_len_avail > length) {
		total_log_len = length + tlen + header_len;
		payload_len_avail = length;
	} else {
		total_log_len = MAX_LOG_LENGTH - 2;
	}

	qdf_mem_copy(&ptr[header_len + tlen], log, payload_len_avail);
	ptr[total_log_len] = '\n';
	ptr[total_log_len + 1] = '\0';
	qdf_spin_lock_bh(&g_ipa_logging_ctx.lock);
	qdf_list_insert_back(&g_ipa_logging_ctx.filled_list,
			     (qdf_list_node_t *)curr_node);
	qdf_spin_unlock_bh(&g_ipa_logging_ctx.lock);
	qdf_atomic_set_bit(WLAN_IPA_POST_HOST_LOG,
			   &g_ipa_logging_ctx.event_flag);
	qdf_wake_up_interruptible(&g_ipa_logging_ctx.wait_q);
	return QDF_STATUS_SUCCESS;
}

void wlan_ipa_log_message(const char *func, const char *msg, ...)
{
	char buffer[MAX_LOG_PAYLOAD_LENGTH];
	qdf_va_list args;

	qdf_va_start(args, msg);
	qdf_vscnprintf(buffer, MAX_LOG_PAYLOAD_LENGTH, msg, args);
	wlan_ipa_send_to_filled_list(buffer, qdf_str_len(buffer), func);
	qdf_va_end(args);
}

void ipa_fw_log_received_stats(void)
{
	g_ipa_logging_ctx.wmi_fw_log_msg_stat += 1;
}

void ipa_dump_logging_stats(void)
{
	ipa_debug("No. WMI msg received for FW logging - %d",
		  g_ipa_logging_ctx.wmi_fw_log_msg_stat);
	ipa_debug("No. of FW msg sent to NL - %d",
		  g_ipa_logging_ctx.fw_log_msg_to_nl_stat);
}
#endif
