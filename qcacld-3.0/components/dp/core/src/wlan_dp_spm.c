/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <dp_types.h>
#include <dp_internal.h>
#include <wlan_dp_spm.h>
#include "dp_htt.h"
#include "wlan_dp_fim.h"
#include "wlan_dp_stc.h"

#define DP_SPM_FLOW_FLAG_IN_USE         BIT(0)
#define DP_SPM_FLOW_FLAG_SVC_METADATA   BIT(1)

#define WLAN_DP_SPM_FLOW_CLASSIFICATION_END_NS (40 * QDF_NSEC_PER_SEC)
#define WLAN_DP_SPM_FLOW_LONG_LIVE_MIN_NS  (5 * QDF_NSEC_PER_SEC)
#define WLAN_DP_SPM_FLOW_LAST_ACTIVE_NS  (1 * QDF_NSEC_PER_SEC)
#define WLAN_DP_SPM_FLOW_LAST_ACTIVE_CEILING_NS  (20 * QDF_NSEC_PER_SEC)
#define WLAN_DP_SPM_FLOW_AGING_PKT_CNT 10

/**
 * wlan_dp_spm_flow_evict_check() - check for evicting Tx flow from tracking
 * @flow: Tx flow entry
 *
 * Return: True if flow can be evicted, else false.
 */
static inline
uint8_t wlan_dp_spm_flow_evict_check(struct wlan_dp_spm_flow_info *flow)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();
	uint64_t active_ts = flow->active_ts;
	uint64_t add_ts = flow->flow_add_ts;
	uint64_t cur_ts = qdf_sched_clock();

	/*
	 * flow_entry with id=0 is an invalid entry and hence marked as
	 * is_populated=1. This entry should never be retired.
	 */
	if (flow->is_reserved)
		return DP_EVICT_DENIED;

	if (cur_ts < active_ts || cur_ts < add_ts)
		return DP_EVICT_DENIED;

	if (!dp_stc_is_remove_flow_allowed(flow->classified,
					   flow->selected_to_sample,
					   flow->inactivity_timeout,
					   active_ts, cur_ts))
		return DP_EVICT_DENIED;

	if ((cur_ts - flow->active_ts) <
	    WLAN_DP_SPM_FLOW_LAST_ACTIVE_NS)
		return DP_EVICT_DENIED;

	/* This is a positive condition to allow eviction */
	if (((cur_ts - flow->flow_add_ts) >
	     WLAN_DP_SPM_FLOW_LONG_LIVE_MIN_NS) &&
	    flow->num_pkts < WLAN_DP_SPM_FLOW_AGING_PKT_CNT)
		return DP_EVICT_SUCCESS_CODE_2;

	/*
	 * If the TX flow was active within certain duration specified by
	 * WLAN_DP_SPM_FLOW_LAST_ACTIVE_CEILING_NS,
	 * do not remove the TX flow if there is a corresponding RX flow,
	 * since it will be used for classification by STC
	 */
	if (cur_ts - flow->active_ts <
				WLAN_DP_SPM_FLOW_LAST_ACTIVE_CEILING_NS &&
	    wlan_dp_find_dl_flow(dp_ctx, flow->flow_tuple_hash))
		return DP_EVICT_DENIED;

	return DP_EVICT_SUCCESS_CODE_1;
}

#ifdef WLAN_FEATURE_SAWFISH
/**
 * wlan_dp_spm_get_context(): Get SPM context from DP PSOC interface
 *
 * Return: SPM context handle
 */
static inline
struct wlan_dp_spm_context *wlan_dp_spm_get_context(void)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();

	return dp_ctx ? dp_ctx->spm_ctx : NULL;
}

/**
 * wlan_dp_spm_update_svc_metadata(): Update service metadata for a service
 *                                    class
 * @svc_class: Service class for which metadata is required
 * @peer_id: Peer ID
 *
 * Return: Service metadata
 */
static inline uint8_t
wlan_dp_spm_update_svc_metadata(struct wlan_dp_spm_svc_class *svc_class,
				uint16_t peer_id)
{
	/**
	 * TBD: Will be implemented when message interface is set for SAWFISH
	 * (peer_id != svc_class->queue_info.peer_id ||
	 *   !svc_class->queue_info.metadata) {
	 * dp_htt_send_svc_map_msg()
	 */

	return WLAN_DP_SPM_INVALID_METADATA;
}

/**
 * wlan_dp_spm_match_flow_to_policy(): Match flow to a policy's parameters
 * @flow: Flow to be matched
 * @policy: Policy which needs to be matched with
 *
 * Return: True/False
 */
static bool wlan_dp_spm_match_flow_to_policy(struct flow_info *flow,
					struct wlan_dp_spm_policy_info *policy)
{
	struct flow_info *policy_flow = &policy->flow;

	if (flow->flags & DP_FLOW_TUPLE_FLAGS_IPV4) {
		if (flow->flags & DP_FLOW_TUPLE_FLAGS_SRC_IP)
			if (flow->src_ip.ipv4_addr !=
				policy_flow->src_ip.ipv4_addr)
				return false;
		if (flow->flags & DP_FLOW_TUPLE_FLAGS_DST_IP)
			if (flow->dst_ip.ipv4_addr !=
				policy_flow->dst_ip.ipv4_addr)
				return false;
	} else if (flow->flags & DP_FLOW_TUPLE_FLAGS_IPV6) {
		if (flow->flags & DP_FLOW_TUPLE_FLAGS_SRC_IP)
			if (qdf_mem_cmp(flow->src_ip.ipv6_addr,
					policy_flow->src_ip.ipv6_addr,
					sizeof(struct in6_addr)))
				return false;
		if (flow->flags & DP_FLOW_TUPLE_FLAGS_DST_IP)
			if (qdf_mem_cmp(flow->dst_ip.ipv6_addr,
					policy_flow->dst_ip.ipv6_addr,
					sizeof(struct in6_addr)))
				return false;
	}

	if (!policy->is_5tuple)
		return true;

	if (flow->flags & DP_FLOW_TUPLE_FLAGS_PROTO)
		if (flow->proto != policy_flow->proto)
			return false;

	if (flow->flags & DP_FLOW_TUPLE_FLAGS_SRC_PORT)
		if (flow->src_port != policy_flow->src_port)
			return false;
	if (flow->flags & DP_FLOW_TUPLE_FLAGS_DST_PORT)
		if (flow->dst_port != policy_flow->dst_port)
			return false;

	return true;
}

/**
 * wlan_dp_spm_flow_get_service(): Find service for an incoming flow
 * @new_flow: Flow info
 *
 * Return: None
 */
static void wlan_dp_spm_flow_get_service(struct wlan_dp_spm_flow_info *new_flow)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_svc_class **svc_class;
	struct wlan_dp_spm_policy_info *policy;
	int i;

	svc_class = spm_ctx->svc_class_db;
	for (i = 0; i < spm_ctx->max_supported_svc_class; i++) {
		if (!svc_class[i] || !svc_class[i]->policy_list.count)
			continue;

		qdf_list_for_each(&svc_class[i]->policy_list, policy, node) {
			if (wlan_dp_spm_match_flow_to_policy(&new_flow->info,
							     policy)) {
				new_flow->svc_metadata =
				wlan_dp_spm_update_svc_metadata(svc_class[i],
							new_flow->peer_id);
				/* If svc metadata is not present, this loop
				 * will be repeated again, hence skipping here
				 */
				if (new_flow->svc_metadata ==
						WLAN_DP_SPM_INVALID_METADATA)
					return;
				new_flow->flags |=
						DP_SPM_FLOW_FLAG_SVC_METADATA;
				new_flow->svc_id = i;
				policy->flows_attached++;
				return;
			}
		}
	}
}

/**
 * wlan_dp_spm_unmap_svc_to_flow(): Unmap flow from a service
 * @svc_id: Service ID
 * @flow: Flow info to be checked against policies
 *
 * Return: None
 */
static inline
void wlan_dp_spm_unmap_svc_to_flow(uint16_t svc_id, struct flow_info *flow)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_svc_class *svc_class = spm_ctx->svc_class_db[svc_id];
	struct wlan_dp_spm_policy_info *policy;

	if (svc_id == WLAN_DP_SPM_INVALID_METADATA)
		return;

	qdf_list_for_each(&svc_class->policy_list, policy, node) {
		if (wlan_dp_spm_match_flow_to_policy(flow, policy)) {
			policy->flows_attached--;
			return;
		}
	}
}

/**
 * wlan_dp_spm_flow_retire(): Retire flows in active flow table
 * @spm_intf: SPM interface
 * @clear_tbl: Set to clear the entire table
 *
 * Return: None
 */
static void wlan_dp_spm_flow_retire(struct wlan_dp_spm_intf_context *spm_intf,
				    bool clear_tbl)
{
	struct wlan_dp_spm_flow_info *cursor;
	uint64_t curr_ts = qdf_sched_clock();
	int i;

	qdf_spinlock_acquire(&spm_intf->flow_list_lock);
	for (i = 0; i < WLAN_DP_SPM_FLOW_REC_TBL_MAX; i++, cursor++) {
		cursor = spm_intf->origin_aft[i];
		if (!cursor)
			continue;

		if (clear_tbl) {
			qdf_list_insert_back(&spm_intf->o_flow_rec_freelist,
					     &cursor->node);
		} else if (wlan_dp_spm_flow_low_tput(cursor)) {
			wlan_dp_spm_unmap_svc_to_flow(cursor->svc_id,
						      &cursor->info);
			qdf_mem_zero(cursor,
				     sizeof(struct wlan_dp_spm_flow_info));
			cursor->id = i;
			qdf_list_insert_back(&spm_intf->o_flow_rec_freelist,
					     &cursor->node);
			spm_intf->o_stats.active--;
			spm_intf->o_stats.deleted++;
		}
	}
	qdf_spinlock_release(&spm_intf->flow_list_lock);
}

/**
 * wlan_dp_spm_match_policy_to_active_flows(): Match policy with active flows
 * @policy: Policy parameters
 * @is_add: Indicates if policy is being added or deleted
 *
 * Return: None
 */
static void
wlan_dp_spm_match_policy_to_active_flows(struct wlan_dp_spm_policy_info *policy,
					 bool is_add)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_flow_info **o_aft;
	int i;

	if (!spm_ctx || !spm_ctx->spm_intf) {
		dp_info("Feature not supported");
		return;
	}

	o_aft = spm_ctx->spm_intf->origin_aft;

	for (i = 0; i < WLAN_DP_SPM_FLOW_REC_TBL_MAX; i++) {
		if (!o_aft[i])
			continue;

		if (wlan_dp_spm_match_flow_to_policy(&o_aft[i]->info, policy)) {
			if (is_add) {
				o_aft[i]->svc_metadata =
				wlan_dp_spm_update_svc_metadata(
					spm_ctx->svc_class_db[policy->svc_id],
					o_aft[i]->peer_id);
				/* If svc metadata is not present, this loop
				 * will be repeated again, hence skipping here
				 */
				if (o_aft[i]->svc_metadata ==
						WLAN_DP_SPM_INVALID_METADATA)
					return;
				o_aft[i]->flags |=
						DP_SPM_FLOW_FLAG_SVC_METADATA;
				o_aft[i]->svc_id = policy->svc_id;
				policy->flows_attached++;
			} else {
				o_aft[i]->svc_id =
						WLAN_DP_SPM_INVALID_METADATA;
				o_aft[i]->svc_metadata =
						WLAN_DP_SPM_INVALID_METADATA;
				policy->flows_attached--;
			}
		}
	}
}

/**
 * wlan_dp_spm_svc_map(): Map flows to a queue when service is attached to a
 *                        queue
 * @svc_class: Service class
 *
 * Return: None
 */
void wlan_dp_spm_svc_map(struct wlan_dp_spm_svc_class *svc_class)
{
	struct wlan_dp_spm_policy_info *policy;

	qdf_list_for_each(&svc_class->policy_list, policy, node) {
		wlan_dp_spm_match_policy_to_active_flows(policy, true);
	}
}

/**
 * wlan_dp_spm_svc_delete(): Delete service and unmap all attached flows
 * @svc_class: Service class
 *
 * Return: None
 */
void wlan_dp_spm_svc_delete(struct wlan_dp_spm_svc_class *svc_class)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_policy_info *policy;

	if (!spm_ctx) {
		dp_info("Feature not supported");
		return;
	}

	while ((policy = qdf_list_first_entry_or_null(&svc_class->policy_list,
						struct wlan_dp_spm_policy_info,
						node))) {
		qdf_list_remove_node(&svc_class->policy_list, &policy->node);
		wlan_dp_spm_match_policy_to_active_flows(policy, false);
	}
	qdf_list_destroy(&svc_class->policy_list);

	/**
	 * TBD: Will be implemented when message interface is set for SAWFISH
	 * if (svc_class->queue_info.metadata != WLAN_DP_SPM_INVALID_METADATA) {
	 * dp_htt_send_svc_map_msg()
	 */

	dp_info("Deleted svc class %u: TID: %u MSDU loss rate %u Policies attached %u Metadata: %u",
		svc_class->id, svc_class->tid, svc_class->msdu_loss_rate,
		svc_class->policy_list.count, svc_class->queue_info.metadata);

	spm_ctx->svc_class_db[svc_class->id] = NULL;
	qdf_mem_free(svc_class);
}

/**
 * wlan_dp_spm_work_handler(): SPM work handler
 * @arg: NULL
 *
 * Return: None
 */
static void wlan_dp_spm_work_handler(void *arg)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();
	struct wlan_dp_spm_context *spm_ctx;
	struct wlan_dp_spm_event *evt;

	if (!dp_ctx || dp_ctx->spm_ctx) {
		dp_info("Feature not supported");
		return;
	}

	spm_ctx = dp_ctx->spm_ctx;

	qdf_spinlock_acquire(&spm_ctx->evt_lock);
	while ((evt = qdf_list_first_entry_or_null(&spm_ctx->evt_list,
						   struct wlan_dp_spm_event,
						   node))) {
		qdf_list_remove_node(&spm_ctx->evt_list, &evt->node);
		qdf_spinlock_release(&spm_ctx->evt_lock);

		switch (evt->type) {
		case WLAN_DP_SPM_EVENT_ACTIVE_FLOW_ADD:
			wlan_dp_spm_flow_get_service(
				(struct wlan_dp_spm_flow_info *)evt->data);
			break;
		case WLAN_DP_SPM_EVENT_ACTIVE_FLOW_RETIRE:
			wlan_dp_spm_flow_retire(
			  (struct wlan_dp_spm_intf_context *)evt->data, false);
			break;
		case WLAN_DP_SPM_EVENT_POLICY_ADD:
			wlan_dp_spm_match_policy_to_active_flows(
			    (struct wlan_dp_spm_policy_info *)evt->data, true);
			break;
		case WLAN_DP_SPM_EVENT_POLICY_DELETE:
			wlan_dp_spm_match_policy_to_active_flows(
			   (struct wlan_dp_spm_policy_info *)evt->data, false);
			qdf_mem_free(evt->data);
			break;
		case WLAN_DP_SPM_EVENT_SERVICE_MAP:
			wlan_dp_spm_svc_map(
				(struct wlan_dp_spm_svc_class *)evt->data);
			break;
		case WLAN_DP_SPM_EVENT_SERVICE_DELETE:
			wlan_dp_spm_svc_delete(
				(struct wlan_dp_spm_svc_class *)evt->data);
			break;
		default:
			dp_info("Unknown %u event type", evt->type);
		}
		qdf_mem_free(evt);
		qdf_spinlock_acquire(&spm_ctx->evt_lock);
	}
	qdf_spinlock_release(&spm_ctx->evt_lock);
}

/**
 * wlan_dp_spm_event_post(): Post event to SPM work
 * @type: Event type
 * @data: Related Data
 *
 * Return: none
 */
static inline
void wlan_dp_spm_event_post(enum wlan_dp_spm_event_type type, void *data)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_event *evt = qdf_mem_malloc(sizeof(*evt));

	if (!evt) {
		dp_err("unable to alloc mem for type %u", type);
		return;
	}

	evt->type = type;
	evt->data = data;

	qdf_spinlock_acquire(&spm_ctx->evt_lock);
	qdf_list_insert_back(&spm_ctx->evt_list, &evt->node);
	qdf_spinlock_release(&spm_ctx->evt_lock);

	qdf_queue_work(0, spm_ctx->spm_wq, &spm_ctx->spm_work);
}

QDF_STATUS wlan_dp_spm_ctx_init(struct wlan_dp_psoc_context *dp_ctx,
				uint32_t queues_per_tid, uint32_t num_tids)
{
	QDF_STATUS status;
	struct wlan_dp_spm_context *ctx;

	if (dp_ctx->spm_ctx) {
		dp_err("SPM module already initialized");
		return QDF_STATUS_E_ALREADY;
	}

	ctx = (struct wlan_dp_spm_context *)qdf_mem_malloc(sizeof(*ctx));
	if (!ctx) {
		dp_err("Unable to allocate spm ctx");
		goto fail;
	}

	/* Move this below creation of DB to WMI ready msg or new HTT msg */
	ctx->max_supported_svc_class = queues_per_tid * num_tids;

	if (ctx->max_supported_svc_class >
		WLAN_DP_SPM_MAX_SERVICE_CLASS_SUPPORT) {
		dp_err("Wrong config recvd queues per tid: %u, num tids: %u",
		       queues_per_tid, num_tids);
		ctx->max_supported_svc_class =
					WLAN_DP_SPM_MAX_SERVICE_CLASS_SUPPORT;
	}

	ctx->svc_class_db = (struct wlan_dp_spm_svc_class **)
			qdf_mem_malloc(sizeof(struct wlan_dp_spm_svc_class *) *
				       queues_per_tid * num_tids);
	if (!ctx->svc_class_db) {
		dp_err("Unable to allocate SPM service class database");
		goto fail_svc_db_alloc;
	}

	qdf_list_create(&ctx->evt_list, 0);

	status = qdf_create_work(NULL, &ctx->spm_work,
				 wlan_dp_spm_work_handler, NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		dp_err("Work creation failed");
		goto fail_work_creation;
	}

	ctx->spm_wq = qdf_alloc_unbound_workqueue("spm_wq");
	if (!ctx->spm_wq) {
		dp_err("SPM Workqueue allocation failed");
		goto fail_workqueue_alloc;
	}

	dp_ctx->spm_ctx = ctx;
	dp_info("Initialized SPM context!");

	return QDF_STATUS_SUCCESS;

fail_workqueue_alloc:
	qdf_destroy_work(NULL, &ctx->spm_work);

fail_work_creation:
	qdf_mem_free(ctx->svc_class_db);

fail_svc_db_alloc:
	qdf_mem_free(ctx);

fail:
	return QDF_STATUS_E_FAILURE;
}

void wlan_dp_spm_ctx_deinit(struct wlan_dp_psoc_context *dp_ctx)
{
	struct wlan_dp_spm_context *ctx;
	struct wlan_dp_spm_svc_class **svc_class;
	int i;

	if (!dp_ctx->spm_ctx) {
		dp_err("SPM module not present!");
		return;
	}

	ctx = dp_ctx->spm_ctx;

	if (ctx->spm_intf)
		wlan_dp_spm_intf_ctx_deinit(NULL);

	svc_class = ctx->svc_class_db;
	for (i = 0; i < ctx->max_supported_svc_class; i++) {
		if (svc_class[i])
			wlan_dp_spm_svc_class_delete(i);
	}

	qdf_flush_workqueue(NULL, ctx->spm_wq);
	qdf_destroy_workqueue(NULL, ctx->spm_wq);
	qdf_flush_work(&ctx->spm_work);
	qdf_destroy_work(NULL, &ctx->spm_work);
	qdf_mem_free(ctx);
	dp_ctx->spm_ctx = NULL;
	dp_info("Deinitialized SPM context!");
}

QDF_STATUS wlan_dp_spm_svc_class_create(struct dp_svc_data *data)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_svc_class *svc_class_new;

	if (!spm_ctx) {
		dp_info("Feature not supported");
		return QDF_STATUS_E_NOSUPPORT;
	}

	if (data->svc_id > spm_ctx->max_supported_svc_class) {
		dp_err("Invalid svc ID %u", data->svc_id);
		return QDF_STATUS_E_FAILURE;
	}

	if (spm_ctx->svc_class_db[data->svc_id]) {
		dp_err("Svc already exists for id: %u", data->svc_id);
		return QDF_STATUS_E_ALREADY;
	}

	svc_class_new = (struct wlan_dp_spm_svc_class *)
				qdf_mem_malloc(sizeof(*svc_class_new));
	if (!svc_class_new) {
		dp_err("Unable to allocate svc class");
		return QDF_STATUS_E_NOMEM;
	}

	svc_class_new->id = data->svc_id;
	svc_class_new->tid = data->tid;
	svc_class_new->msdu_loss_rate = data->msdu_loss_rate;
	qdf_list_create(&svc_class_new->policy_list, 0);

	spm_ctx->svc_class_db[data->svc_id] = svc_class_new;
	/* TBD: send service class WMI cmd to FW */

	dp_info("New service class %u: TID: %u, MSDU loss rate: %u",
		svc_class_new->id, svc_class_new->tid,
		svc_class_new->msdu_loss_rate);

	return QDF_STATUS_SUCCESS;
}

void wlan_dp_spm_svc_class_delete(uint32_t svc_id)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_svc_class *svc_class;

	if (!spm_ctx) {
		dp_info("Feature not supported");
		return;
	}

	svc_class = spm_ctx->svc_class_db[svc_id];
	if (!spm_ctx->svc_class_db[svc_id]) {
		dp_err("Service %u not present", svc_id);
		return;
	}

	if (!svc_class->policy_list.count) {
		dp_info("No policies attached for service: %u", svc_id);
	/**
	 * TBD: Will be implemented when message interface is set for SAWFISH
	 * if (svc_class->queue_info.metadata != WLAN_DP_SPM_INVALID_METADATA) {
	 * dp_htt_send_svc_map_msg()
	 */
		qdf_mem_free(svc_class);
		spm_ctx->svc_class_db[svc_id] = NULL;
		dp_info("Deleted svc class %u: TID: %u MSDU loss rate %u Policies attached %u Metadata: %u",
			svc_class->id, svc_class->tid,
			svc_class->msdu_loss_rate,
			svc_class->policy_list.count,
			svc_class->queue_info.metadata);
	} else {
		wlan_dp_spm_event_post(WLAN_DP_SPM_EVENT_SERVICE_DELETE,
				       (void *)svc_class);
	}
}

uint8_t wlan_dp_spm_svc_get(uint8_t svc_id, struct dp_svc_data *svc_table,
			    uint16_t table_size)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_svc_class *svc_class = NULL;
	int i = 0;

	if (!spm_ctx) {
		dp_info("Feature not supported");
		return i;
	}

	if (svc_id != WLAN_DP_SPM_INVALID_METADATA) {
		if (svc_id < spm_ctx->max_supported_svc_class) {
			svc_class = spm_ctx->svc_class_db[svc_id];
			svc_table[0].svc_id = svc_class->id;
			svc_table[0].tid = svc_class->tid;
			svc_table[0].msdu_loss_rate = svc_class->msdu_loss_rate;
			i++;
		}
	} else {
		for (i = 0; i < spm_ctx->max_supported_svc_class; i++) {
			if (spm_ctx->svc_class_db[svc_id]) {
				svc_class = spm_ctx->svc_class_db[svc_id];
				svc_table[i].svc_id = svc_class->id;
				svc_table[i].tid = svc_class->tid;
				svc_table[i].msdu_loss_rate =
						svc_class->msdu_loss_rate;
			}
		}
	}

	return i;
}

void wlan_dp_spm_svc_set_queue_info(uint32_t *msg_word, qdf_nbuf_t htt_t2h_msg)
{
	/* TBD: Will be implemented when message interface is set for SAWFISH */
}

uint16_t wlan_dp_spm_svc_get_metadata(struct wlan_dp_intf *dp_intf,
				      qdf_nbuf_t skb, uint16_t flow_id,
				      uint64_t cookie)
{
	struct wlan_dp_spm_context *spm_ctx = dp_intf->spm_intf_ctx;
	struct wlan_dp_spm_flow_info *flow;

	flow = spm_intf->origin_aft[flow_id];
	/* Flow can be NULL when evicted or retired */
	if (qdf_unlikely(!flow))
		return WLAN_DP_SPM_FLOW_REC_TBL_MAX;

	if (qdf_unlikely(flow->cookie != cookie)) {
		dp_info("Flow cookie %lu mismatch against table %lu", cookie,
			flow->cookie);
		return QDF_STATUS_E_INVAL;
	}

	flow->active_ts = qdf_sched_clock();
	skb->mark = flow->svc_metadata;
	flow->num_pkts++;

	wlan_dp_stc_check_n_track_tx_flow_features(dp_intf->dp_ctx, skb,
						   flow->track_flow_stats,
						   flow->id,
						   dp_intf->def_link->link_id,
						   flow->peer_id, flow->guid);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_dp_spm_policy_add(struct dp_policy *policy)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_svc_class *svc_class;
	struct wlan_dp_spm_policy_info *new_policy;

	if (!spm_ctx) {
		dp_info("Feature not supported");
		return QDF_STATUS_E_NOSUPPORT;
	}

	if (!spm_ctx->svc_class_db[policy->svc_id]) {
		dp_info("Service class not present");
		return QDF_STATUS_E_EMPTY;
	}
	svc_class = spm_ctx->svc_class_db[policy->svc_id];

	new_policy = (struct wlan_dp_spm_policy_info *)
			qdf_mem_malloc(sizeof(*new_policy));
	if (!new_policy) {
		dp_info("Unable to allocate policy");
		return QDF_STATUS_E_NOMEM;
	}

	qdf_mem_copy(&new_policy->flow, &policy->flow,
		     sizeof(struct flow_info));
	new_policy->id = policy->policy_id;

	if ((policy->flags & DP_FLOW_TUPLE_FLAGS_SRC_PORT) &&
	    (policy->flags & DP_FLOW_TUPLE_FLAGS_DST_PORT))
		new_policy->is_5tuple = true;

	new_policy->svc_id = policy->svc_id;

	qdf_list_insert_back(&svc_class, &new_policy->node);

	wlan_dp_spm_event_post(WLAN_DP_SPM_EVENT_POLICY_ADD,
			       (void *)new_policy);

	spm_ctx->policy_cnt++;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_dp_spm_policy_delete(uint32_t policy_id)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_svc_class **svc_class;
	struct wlan_dp_spm_policy_info *policy, *delete_policy = NULL;
	int i;

	if (!spm_ctx) {
		dp_info("Feature not supported");
		return QDF_STATUS_E_NOSUPPORT;
	}

	svc_class = spm_ctx->svc_class_db;
	for (i = 0; i < spm_ctx->max_supported_svc_class; i++) {
		if (!svc_class[i] || !svc_class[i]->policy_list.count)
			continue;

		qdf_list_for_each(&svc_class[i]->policy_list, policy, node) {
			if (policy->id == policy_id) {
				qdf_list_remove_node(&svc_class[i]->policy_list,
						     &policy->node);
				delete_policy = policy;
				break;
			}
		}
	}

	dp_info("Deleting policy %u attached to svc id: %u", policy_id,
		delete_policy->svc_id);

	if (delete_policy) {
		if (delete_policy->flows_attached) {
			/* policy is deleted in the workqueue context*/
			wlan_dp_spm_event_post(WLAN_DP_SPM_EVENT_POLICY_DELETE,
					       (void *)delete_policy);
		} else {
			qdf_mem_free(delete_policy);
			delete_policy = NULL;
		}
	} else {
		return QDF_STATUS_E_INVAL;
	}

	spm_ctx->policy_cnt--;
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_dp_spm_policy_update(struct dp_policy *policy)
{
	if (wlan_dp_spm_policy_delete(policy->policy_id))
		return wlan_dp_spm_policy_add(policy);
	else
		return QDF_STATUS_E_INVAL;
}
#else
/**
 * wlan_dp_spm_get_context(): Get SPM context from DP PSOC interface
 *
 * Return: SPM context handle
 */
static inline
struct wlan_dp_spm_context *wlan_dp_spm_get_context(void)
{
	return NULL;
}

static inline
void wlan_dp_spm_event_post(enum wlan_dp_spm_event_type type, void *data)
{
}

static void dp_spm_add_flow_to_freelist(qdf_rcu_head_t *rp)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();
	struct wlan_dp_spm_flow_info *flow_rec =
			container_of(rp, struct wlan_dp_spm_flow_info, rcu);
	uint16_t flow_id;

	if (!dp_ctx)
		return;

	flow_id = flow_rec->id;
	qdf_spinlock_acquire(&dp_ctx->flow_list_lock);
	qdf_mem_zero(flow_rec, sizeof(struct wlan_dp_spm_flow_info));
	flow_rec->id = flow_id;
	qdf_list_insert_back(&dp_ctx->o_flow_rec_freelist, &flow_rec->node);
	qdf_spinlock_release(&dp_ctx->flow_list_lock);
}

static void wlan_dp_spm_flow_retire(struct wlan_dp_spm_intf_context *spm_intf,
				    bool clear_tbl)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();
	struct qdf_ht *ht_node;
	struct qdf_ht_entry *tmp;
	struct wlan_dp_spm_flow_info *flow_rec;
	uint8_t flow_evict_success_code;
	int i;

	qdf_spinlock_acquire(&dp_ctx->flow_list_lock);
	for (i = 0; i < WLAN_DP_SPM_HASH_TBL_MAX; i++) {
		ht_node = &spm_intf->origin_aft_hlist[i];
		qdf_hl_for_each_entry_safe(flow_rec, tmp, ht_node, hnode) {
			flow_evict_success_code =
					wlan_dp_spm_flow_evict_check(flow_rec);
			if (clear_tbl || flow_evict_success_code) {
				wlan_dp_stc_tx_flow_retire_ind(dp_ctx,
						flow_rec->classified,
						flow_rec->c_flow_id,
						flow_evict_success_code);
				qdf_hl_del_rcu(&flow_rec->hnode);
				qdf_call_rcu(&flow_rec->rcu,
					     dp_spm_add_flow_to_freelist);
				spm_intf->o_stats.active--;
				spm_intf->o_stats.deleted++;
			}
		}
	}
	qdf_spinlock_release(&dp_ctx->flow_list_lock);

	dp_info_rl("post retire count: %u",
		   dp_ctx->o_flow_rec_freelist.count);
}

void wlan_dp_spm_dump_tx_aft(struct wlan_dp_psoc_context *dp_ctx)
{
	struct wlan_dp_spm_flow_info *flow;
	int i, count = 0;
	uint32_t num_entries = WLAN_DP_SPM_FLOW_REC_TBL_MAX;
	uint8_t buf[BUF_LEN_MAX];

	if (!dp_ctx->gl_flow_recs)
		return;

	dp_info("cur_ts %llu", qdf_sched_clock());
	dp_info("Flow <id> [<tuple>] <num_pkts> <classified> <selected_to_sample> <track_flow_stats> <c_flow_id> <inactivity_timeout> <ul_tid> <active_ts> ");
	for (i = 0; i < num_entries; i++) {
		flow = &dp_ctx->gl_flow_recs[i];
		if (qdf_unlikely(!flow->is_populated))
			continue;

		count++;
		dp_info("Flow %u [%s] %llu %u %u %u %u %llu %u: %llu",
			i,  dp_print_tuple_to_str(&flow->info, buf,
						  BUF_LEN_MAX),
			flow->num_pkts, flow->classified,
			flow->selected_to_sample, flow->track_flow_stats,
			flow->c_flow_id, flow->inactivity_timeout, flow->ul_tid,
			flow->active_ts);
	}

	dp_info("Printed %d flow entries of TX AFT", count);
}

#ifdef WLAN_DP_FEATURE_STC
static inline
void wlan_dp_spm_update_tx_flow_hash(struct wlan_dp_psoc_context *dp_ctx,
				     struct wlan_dp_spm_flow_info *flow_rec)
{
	struct flow_info flow_info_reverse = {0};
	struct flow_info *flow_info = &flow_rec->info;

	/* Switching direction to match Rx flow hash for bi-di flows*/
	if (flow_info->flags & FLOW_INFO_PRESENT_IPV4_SRC_IP) {
		flow_info_reverse.src_ip.ipv4_addr =
						flow_info->dst_ip.ipv4_addr;
		flow_info_reverse.dst_ip.ipv4_addr =
						flow_info->src_ip.ipv4_addr;
		flow_rec->is_ipv4 = true;
	} else if (flow_info->flags & FLOW_INFO_PRESENT_IPV6_SRC_IP) {
		flow_info_reverse.src_ip.ipv6_addr[0] =
						flow_info->dst_ip.ipv6_addr[0];
		flow_info_reverse.src_ip.ipv6_addr[1] =
						flow_info->dst_ip.ipv6_addr[1];
		flow_info_reverse.src_ip.ipv6_addr[2] =
						flow_info->dst_ip.ipv6_addr[2];
		flow_info_reverse.src_ip.ipv6_addr[3] =
						flow_info->dst_ip.ipv6_addr[3];

		flow_info_reverse.dst_ip.ipv6_addr[0] =
						flow_info->src_ip.ipv6_addr[0];
		flow_info_reverse.dst_ip.ipv6_addr[1] =
						flow_info->src_ip.ipv6_addr[1];
		flow_info_reverse.dst_ip.ipv6_addr[2] =
						flow_info->src_ip.ipv6_addr[2];
		flow_info_reverse.dst_ip.ipv6_addr[3] =
						flow_info->src_ip.ipv6_addr[3];
	}

	flow_info_reverse.src_port = flow_info->dst_port;
	flow_info_reverse.dst_port = flow_info->src_port;
	flow_info_reverse.proto =
				wlan_dp_ip_proto_to_stc_proto(flow_info->proto);
	flow_info_reverse.flags = 0;

	flow_rec->flow_tuple_hash = wlan_dp_get_flow_hash(dp_ctx,
							  &flow_info_reverse);
}
#else
static inline
void wlan_dp_spm_update_tx_flow_hash(struct wlan_dp_psoc_context *dp_ctx,
				     struct wlan_dp_spm_flow_info *flow_rec);
{
}
#endif

#define DP_SPM_FLOW_TUPLE_CHECK_NUM_PKTS 8
#define DP_SPM_FLOW_TUPLE_CHECK_TIME_MAX (1 * QDF_NSEC_PER_SEC)

/* Flow Unique ID generator */
static uint32_t flow_guid_gen;

static inline void
dp_spm_check_n_update_flow_info(struct wlan_dp_spm_flow_info *flow,
				qdf_nbuf_t skb, uint64_t curr_ts)
{
	struct wlan_dp_psoc_context *dp_ctx = dp_get_context();
	struct flow_info flow_tuple = {0};
	struct sock *sk;

	sk = skb->sk;
	if (sk->sk_type != SOCK_DGRAM && sk->sk_type != SOCK_RAW)
		return;

	if (!((flow->num_pkts & (DP_SPM_FLOW_TUPLE_CHECK_NUM_PKTS - 1)) == 0 ||
	      curr_ts - flow->active_ts > DP_SPM_FLOW_TUPLE_CHECK_TIME_MAX))
		return;

	dp_fim_parse_skb_flow_info(skb, &flow_tuple);

	if (!dp_flow_info_exact_match(&flow->info, &flow_tuple)) {
		uint8_t old_tuple_str[BUF_LEN_MAX];
		uint8_t new_tuple_str[BUF_LEN_MAX];

		dp_info("Flow %d mdata 0x%x old_tuple %s new_tuple %s",
			flow->id, flow->guid,
			dp_print_tuple_to_str(&flow->info, old_tuple_str,
					      BUF_LEN_MAX),
			dp_print_tuple_to_str(&flow_tuple, new_tuple_str,
					      BUF_LEN_MAX));
		qdf_mem_copy(&flow->info, &flow_tuple, sizeof(flow->info));
		flow->guid = flow_guid_gen++;
		flow->num_pkts = 1;
		flow->flow_add_ts = curr_ts;
		wlan_dp_spm_update_tx_flow_hash(dp_ctx, flow);
	}
}

static inline
void wlan_dp_spm_update_flow_features(struct wlan_dp_intf *dp_intf,
				      struct wlan_dp_spm_flow_info *flow,
				      qdf_nbuf_t skb)
{
	uint64_t curr_ts = qdf_sched_clock();

	flow->num_pkts++;

	dp_spm_check_n_update_flow_info(flow, skb, curr_ts);

	flow->active_ts = curr_ts;
	wlan_dp_stc_check_n_track_tx_flow_features(dp_intf->dp_ctx, skb,
						   flow->track_flow_stats,
						   flow->id,
						   dp_intf->def_link->link_id,
						   flow->peer_id, flow->guid);
}

uint16_t wlan_dp_spm_svc_get_metadata(struct wlan_dp_intf *dp_intf,
				      qdf_nbuf_t nbuf, uint16_t flow_id,
				      uint64_t cookie)
{
	struct wlan_dp_spm_intf_context *spm_intf = dp_intf->spm_intf_ctx;
	struct qdf_ht *ht_node = &spm_intf->origin_aft_hlist[flow_id];
	struct wlan_dp_spm_flow_info *flow;

	qdf_rcu_read_lock_bh();
	qdf_hl_for_each_entry_rcu(flow, ht_node, hnode) {
		if (flow->cookie == cookie) {
			qdf_rcu_read_unlock_bh();
			wlan_dp_spm_update_flow_features(dp_intf, flow, nbuf);
			if (DP_STC_IS_CLASSIFIED_KNOWN(flow->classified) &&
			    flow->ul_tid != WLAN_DP_STC_UL_TID_INVALID) {
				nbuf->mark =
				      WLAN_DP_STC_ENCRYPT_UL_TID(flow->ul_tid);
				return QDF_STATUS_SUCCESS;
			}
			return QDF_STATUS_E_CANCELED;
		}
	}
	qdf_rcu_read_unlock_bh();

	return QDF_STATUS_E_NOENT;
}
#endif

QDF_STATUS wlan_dp_spm_intf_ctx_init(struct wlan_dp_intf *dp_intf)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_psoc_context *dp_ctx = dp_intf->dp_ctx;
	struct wlan_dp_spm_intf_context *spm_intf;
	struct qdf_ht *hl_head;
	int i;

	if (!dp_ctx->gl_flow_recs || dp_intf->device_mode != QDF_STA_MODE)
		return QDF_STATUS_E_NOSUPPORT;

	if (dp_intf->spm_intf_ctx) {
		dp_info("Module already initialized!");
		return QDF_STATUS_E_ALREADY;
	}

	spm_intf = (struct wlan_dp_spm_intf_context *)
					qdf_mem_malloc(sizeof(*spm_intf));
	if (!spm_intf) {
		dp_err("Unable to allocate spm interface");
		return QDF_STATUS_E_NOMEM;
	}

	qdf_mem_zero(&spm_intf->screen_flow_ctx.s_tbl[0],
		     sizeof(struct wlan_dp_spm_screening_entry) *
		     WLAN_DP_SPM_S_TBL_SIZE);

	hl_head = &spm_intf->origin_aft_hlist[0];
	for (i = 0; i < WLAN_DP_SPM_HASH_TBL_MAX; i++)
		qdf_hl_init(hl_head);

	dp_intf->spm_intf_ctx = spm_intf;
	if (spm_ctx)
		spm_ctx->spm_intf = spm_intf;
	dp_info("SPM interface created");

	return QDF_STATUS_SUCCESS;
}

void wlan_dp_spm_intf_ctx_deinit(struct wlan_dp_intf *dp_intf)
{
	struct wlan_dp_spm_context *spm_ctx = wlan_dp_spm_get_context();
	struct wlan_dp_spm_intf_context *spm_intf;

	if (dp_intf->device_mode != QDF_STA_MODE)
		return;

	if (!dp_intf->spm_intf_ctx) {
		dp_info("Module already uninitialized!");
		return;
	}

	spm_intf = dp_intf->spm_intf_ctx;

	wlan_dp_spm_flow_retire(spm_intf, true);

	qdf_mem_free(spm_intf);
	dp_intf->spm_intf_ctx = NULL;

	if (spm_ctx)
		spm_ctx->spm_intf = NULL;
	dp_info("SPM interface deinitialized!");
}

#if defined(WLAN_FEATURE_SAWFISH) || defined(WLAN_DP_FEATURE_STC)
void wlan_dp_spm_flow_table_attach(struct wlan_dp_psoc_context *dp_ctx)
{
	struct wlan_dp_spm_flow_info *flow_rec;
	int i;

	dp_ctx->gl_flow_recs =
		__qdf_mem_malloc(sizeof(struct wlan_dp_spm_flow_info) *
				 WLAN_DP_SPM_FLOW_REC_TBL_MAX,
				 __func__, __LINE__);
	if (!dp_ctx->gl_flow_recs) {
		dp_err("Failed to SPM Tx flow table");
		return;
	}

	qdf_list_create(&dp_ctx->o_flow_rec_freelist,
			WLAN_DP_SPM_FLOW_REC_TBL_MAX);
	qdf_spinlock_create(&dp_ctx->flow_list_lock);

	for (i = 0; i < WLAN_DP_SPM_FLOW_REC_TBL_MAX; i++) {
		flow_rec = &dp_ctx->gl_flow_recs[i];
		qdf_mem_zero(flow_rec, sizeof(struct wlan_dp_spm_flow_info));
		flow_rec->id = i;
		/* flow_id 0 is invalid and hence do not add it to freelist.
		 * But it is necessary to have the indexing start from 0 for
		 * consistent/contiguous indexing in global Tx flow table.
		 *
		 * Global Tx flow table index will be (intf_id << 6 | idx)
		 */
		if (!(i & SAWFISH_FLOW_ID_MAX)) {
			flow_rec->is_reserved = 1;
			continue;
		}
		qdf_list_insert_back(&dp_ctx->o_flow_rec_freelist,
				     &flow_rec->node);
	}

}

void wlan_dp_spm_flow_table_detach(struct wlan_dp_psoc_context *dp_ctx)
{
	if (!dp_ctx->gl_flow_recs)
		return;

	qdf_spinlock_destroy(&dp_ctx->flow_list_lock);
	__qdf_mem_free(dp_ctx->gl_flow_recs);
	dp_ctx->gl_flow_recs = NULL;
}
#endif

/**
 * wlan_dp_spm_s_flow_retire_check() - Check flow pkt rate in smaller timespan
 * @entry: Entry in the table obtained from masking skb hash
 * @curr_ts: Current timestamp
 *
 * Return: True if current entry can be replaced with new entry, else false.
 */
static inline
bool wlan_dp_spm_s_flow_retire_check(struct wlan_dp_spm_screening_entry *entry,
				     uint64_t curr_ts)
{
	uint64_t time_delta_ns = (curr_ts - entry->init_ts);

	/* to retire a flow, check if threshold timespan has passed and then
	 * check if packet rate is met.
	 */
	if ((time_delta_ns > WLAN_DP_SPM_S_TBL_RETIRE_TIME_DELTA_NS) &&
	    ((entry->num_pkts * QDF_NSEC_PER_SEC / time_delta_ns) <
	      WLAN_DP_SPM_MIN_PKT_CNT_PER_SEC))
		return true;

	return false;
}

/**
 * wlan_dp_spm_s_tbl_check_n_add_flow() - Add new flow to screening table
 * @screen_ctx: Screening table context
 * @entry: Entry in the table obtained from masking skb hash
 * @hash: skb hash value
 *
 * If entry has null values, entry will be filled with hash but if entry already
 * contains a flow, and its pkt rate is not met in threshold timespan, replace,
 * that entry.
 *
 * Return: None
 */
static inline void
wlan_dp_spm_s_tbl_check_n_add_flow(struct wlan_dp_spm_screening_ctx *screen_ctx,
				   struct wlan_dp_spm_screening_entry *entry,
				   uint32_t hash)
{
	uint64_t curr_ts = qdf_sched_clock();

	if (qdf_atomic_test_and_set_bit(WLAN_DP_SPM_S_ENTRY_FLAG_ACCESS_BIT,
					&entry->flags))
		return;

	if (!entry->skb_hash) {
		entry->skb_hash = hash;
	} else if (wlan_dp_spm_s_flow_retire_check(entry, curr_ts)) {
		screen_ctx->s_flows_active--;
		entry->skb_hash = hash;
	} else {
		qdf_atomic_clear_bit(WLAN_DP_SPM_S_ENTRY_FLAG_ACCESS_BIT,
				     &entry->flags);
		return;
	}

	entry->init_ts = curr_ts;
	entry->num_pkts = 1;
	screen_ctx->s_flows_active++;

	if (entry->skb_hash == hash)
		qdf_atomic_clear_bit(WLAN_DP_SPM_S_ENTRY_FLAG_ACCESS_BIT,
				     &entry->flags);
}

bool wlan_dp_spm_flow_screening(struct wlan_dp_intf *dp_intf,
				qdf_nbuf_t skb)
{
	struct wlan_dp_spm_screening_ctx *screen_ctx =
					&dp_intf->spm_intf_ctx->screen_flow_ctx;
	struct wlan_dp_spm_screening_entry *entry;
	uint32_t hash, idx;
	bool rate_met = false;
	uint64_t curr_ts;

	hash = qdf_nbuf_get_hash(skb);
	idx = hash & WLAN_DP_SPM_S_TBL_IDX_MASK;
	entry = &screen_ctx->s_tbl[idx];

	if (qdf_atomic_test_bit(WLAN_DP_SPM_S_ENTRY_FLAG_ACCESS_BIT,
				&entry->flags))
		return false;

	if (qdf_unlikely(!entry->skb_hash || (entry->skb_hash != hash))) {
		wlan_dp_spm_s_tbl_check_n_add_flow(screen_ctx, entry, hash);
		return false;
	}

	entry->num_pkts++;

	/* flow pkt count reaches pkt rate count per second, check the timespan
	 * for this flow to confirm if packet rate was met
	 */
	if (qdf_unlikely(entry->num_pkts >= WLAN_DP_SPM_MIN_PKT_CNT_PER_SEC)) {
		if (qdf_atomic_test_and_set_bit(
					WLAN_DP_SPM_S_ENTRY_FLAG_ACCESS_BIT,
					&entry->flags))
			return false;

		curr_ts = qdf_sched_clock();
		rate_met = (curr_ts - entry->init_ts) <= QDF_NSEC_PER_SEC ?
			   true : false;

		if (rate_met) {
			screen_ctx->s_flows_active--;
			qdf_mem_zero((uint8_t *)entry + sizeof(entry->flags),
				     sizeof(entry) - sizeof(entry->flags));
			qdf_atomic_clear_bit(
					WLAN_DP_SPM_S_ENTRY_FLAG_ACCESS_BIT,
					&entry->flags);
		} else {
			entry->init_ts = curr_ts;
			entry->num_pkts = 1;
			qdf_atomic_clear_bit(
					WLAN_DP_SPM_S_ENTRY_FLAG_ACCESS_BIT,
					&entry->flags);
		}
	}

	return rate_met;
}

QDF_STATUS wlan_dp_spm_get_flow_id_origin(struct wlan_dp_intf *dp_intf,
					  uint16_t *flow_id,
					  struct flow_info *flow_info,
					  uint64_t cookie_sk, uint16_t peer_id)
{
	struct wlan_dp_spm_intf_context *spm_intf;
	struct wlan_dp_spm_flow_info *flow_rec = NULL;
	struct wlan_dp_psoc_context *dp_ctx = dp_intf->dp_ctx;
	uint16_t ht_idx;

	if (!dp_intf->spm_intf_ctx) {
		dp_info("Feature not supported");
		return QDF_STATUS_E_NOSUPPORT;
	}

	spm_intf = dp_intf->spm_intf_ctx;

	qdf_spinlock_acquire(&dp_ctx->flow_list_lock);
	qdf_list_remove_front(&dp_ctx->o_flow_rec_freelist,
			      (qdf_list_node_t **)&flow_rec);
	if (!flow_rec) {
		qdf_spinlock_release(&dp_ctx->flow_list_lock);
		*flow_id = SAWFISH_INVALID_FLOW_ID;
		wlan_dp_spm_flow_retire(dp_intf->spm_intf_ctx, false);
		return QDF_STATUS_E_EMPTY;
	}

	ht_idx = flow_rec->id & SAWFISH_FLOW_ID_MAX;
	qdf_hl_add_head_rcu(&flow_rec->hnode,
			    &spm_intf->origin_aft_hlist[ht_idx]);
	flow_rec->flags |= DP_SPM_FLOW_FLAG_IN_USE;
	flow_rec->cookie = cookie_sk;
	*flow_id = ht_idx;
	qdf_spinlock_release(&dp_ctx->flow_list_lock);

	/* Copy data to flow record */
	flow_rec->flow_add_ts = qdf_sched_clock();
	flow_rec->guid = flow_guid_gen++;
	flow_rec->peer_id = peer_id;
	flow_rec->vdev_id = dp_intf->def_link->link_id;
	qdf_mem_copy(&flow_rec->info, flow_info, sizeof(struct flow_info));
	flow_rec->svc_id = WLAN_DP_SPM_INVALID_METADATA;
	flow_rec->svc_metadata = WLAN_DP_SPM_INVALID_METADATA;
	flow_rec->is_populated = 1;
	flow_rec->active_ts = qdf_sched_clock();

	wlan_dp_spm_update_tx_flow_hash(dp_ctx, flow_rec);

	spm_intf->o_stats.active++;

	wlan_dp_indicate_flow_add(dp_ctx, WLAN_DP_FLOW_DIR_TX,
				  &flow_rec->info, flow_rec->id);

	/* Trigger flow retiring event at threshold */
	if (qdf_unlikely(dp_ctx->o_flow_rec_freelist.count <
				WLAN_DP_SPM_LOW_AVAILABLE_FLOWS_WATERMARK)) {
		if (!wlan_dp_spm_get_context())
			wlan_dp_spm_flow_retire(dp_intf->spm_intf_ctx, false);
		else
			wlan_dp_spm_event_post(
					WLAN_DP_SPM_EVENT_ACTIVE_FLOW_RETIRE,
					dp_intf->spm_intf_ctx);
	}

	return QDF_STATUS_SUCCESS;
}
