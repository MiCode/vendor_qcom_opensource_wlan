/*
 * Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: contains MLO manager public file containing link reconfiguration
 * functionality
 */
#ifndef _WLAN_MLO_LINK_RECFG_H_
#define _WLAN_MLO_LINK_RECFG_H_

#include <wlan_mlo_mgr_public_structs.h>
#include <wlan_cm_public_struct.h>

#define WLAN_MAX_ML_RECFG_LINK_COUNT 16
#define WLAN_MIN_DIALOG_TOKEN         1
#define WLAN_MAX_DIALOG_TOKEN         0xFF

struct mlo_link_recfg_context;
struct link_recfg_rx_rsp;

/**
 * enum wlan_link_recfg_sm_state - Link Reconfiguration states
 * @WLAN_LINK_RECFG_S_INIT: Default state, IDLE state
 * @WLAN_LINK_RECFG_S_START: State when Link Reconfig starts
 * @WLAN_LINK_RECFG_S_ADD_LINK: State for Link Add request
 * @WLAN_LINK_RECFG_S_XMIT_REQ: State for Link recfg request frame sending
 * @WLAN_LINK_RECFG_S_DEL_LINK: State for Link Del request
 * @WLAN_LINK_RECFG_S_COMPLETED: State when Link Reconfig is completed
 * @WLAN_LINK_RECFG_S_ABORT: State when Link Reconfig is Aborted
 * @WLAN_LINK_RECFG_S_TTLM: State when Link Reconfig TTLM handling
 * @WLAN_LINK_RECFG_S_MAX: Max State
 * @WLAN_LINK_RECFG_SS_IDLE: Link Reconfig substate Idle
 * @WLAN_LINK_RECFG_SS_START_PENDING: Link reconfig start pending for
 * serialization active
 * @WLAN_LINK_RECFG_SS_START_ACTIVE: Link reconfig for serialization active
 * @WLAN_LINK_RECFG_SS_DEL_LINK_WAIT_SET_LINK: Link Reconfig is Del link wait
 * for set link cmd rsp
 * @WLAN_LINK_RECFG_SS_DEL_LINK_WAIT_LINK_SW: Link Reconfig is wait for link
 * switch delete/disconnect
 * @WLAN_LINK_RECFG_SS_DEL_LINK_ABORT_WAIT_SET_LINK: Link Reconfig abort wait
 * for set link cmd rsp
 * @WLAN_LINK_RECFG_SS_DEL_LINK_ABORT_WAIT_LINK_SW: Link Reconfig abort wait
 * for link switch done
 * @WLAN_LINK_RECFG_SS_ADD_LINK_WAIT_ADD_CONN: Link Reconfig is Add link as
 * partner
 * @WLAN_LINK_RECFG_SS_ADD_LINK_WAIT_LINK_SW: Link Reconfig is wait for link
 * switch add/connect
 * @WLAN_LINK_RECFG_SS_ADD_LINK_ABORT_WAIT_ADD_CONN: Link Reconfig is Aborted
 * while add link
 * @WLAN_LINK_RECFG_SS_ADD_LINK_ABORT_WAIT_LINK_SW: Link Reconfig is Aborted
 * while wait for link switch
 * @WLAN_LINK_RECFG_SS_MAX: Max SubState
 */
enum wlan_link_recfg_sm_state {
	WLAN_LINK_RECFG_S_INIT,
	WLAN_LINK_RECFG_S_START,
	WLAN_LINK_RECFG_S_DEL_LINK,
	WLAN_LINK_RECFG_S_XMIT_REQ,
	WLAN_LINK_RECFG_S_ADD_LINK,
	WLAN_LINK_RECFG_S_COMPLETED,
	WLAN_LINK_RECFG_S_ABORT,
	WLAN_LINK_RECFG_S_TTLM,
	WLAN_LINK_RECFG_S_MAX,
	/* substates */
	WLAN_LINK_RECFG_SS_IDLE,
	WLAN_LINK_RECFG_SS_START_PENDING,
	WLAN_LINK_RECFG_SS_START_ACTIVE,
	WLAN_LINK_RECFG_SS_DEL_LINK_WAIT_SET_LINK,
	WLAN_LINK_RECFG_SS_DEL_LINK_WAIT_LINK_SW,
	WLAN_LINK_RECFG_SS_DEL_LINK_ABORT_WAIT_SET_LINK,
	WLAN_LINK_RECFG_SS_DEL_LINK_ABORT_WAIT_LINK_SW,
	WLAN_LINK_RECFG_SS_ADD_LINK_WAIT_ADD_CONN,
	WLAN_LINK_RECFG_SS_ADD_LINK_WAIT_LINK_SW,
	WLAN_LINK_RECFG_SS_ADD_LINK_ABORT_WAIT_ADD_CONN,
	WLAN_LINK_RECFG_SS_ADD_LINK_ABORT_WAIT_LINK_SW,
	WLAN_LINK_RECFG_SS_MAX,
};

/**
 * enum wlan_link_recfg_sm_evt - Link Reconfig related events
 * Note: make sure to update ttlm_sm_event_names on updating this enum
 * @WLAN_LINK_RECFG_SM_EV_USER_REQ: Link Reconfiguration request from STA
 * @WLAN_LINK_RECFG_SM_EV_FW_IND: Link Reconfiguration AP initiated request
 * @WLAN_LINK_RECFG_SM_EV_START: Link Reconfiguration start event
 * @WLAN_LINK_RECFG_SM_EV_ACTIVE: Link Reconfiguration is active
 * @WLAN_LINK_RECFG_SM_EV_DEL_LINK: Link Reconfiguration for delete link
 * @WLAN_LINK_RECFG_SM_EV_ADD_LINK: Link Reconfiguration for add link
 * @WLAN_LINK_RECFG_SM_EV_XMIT_REQ: Link Reconfiguration event for TX req
 * @WLAN_LINK_RECFG_SM_EV_XMIT_STATUS: Link Reconfiguration event for TX status
 * @WLAN_LINK_RECFG_SM_EV_RX_RSP: Link Reconfiguration event for RX response
 * @WLAN_LINK_RECFG_SM_EV_SET_LINK_RSP: Link Reconfiguration event response for
 * set link
 * @WLAN_LINK_RECFG_SM_EV_LINK_SWITCH_IND: Link switch indication event
 * @WLAN_LINK_RECFG_SM_EV_LINK_SWITCH_RSP: Link reconfiguration event for link
 * switch.
 * @WLAN_LINK_RECFG_SM_EV_ADD_CONN_RSP: Link Reconfiguration event for add
 * connect rsp
 * @WLAN_LINK_RECFG_SM_EV_DISCONNECT_IND: Link Reconfiguration event for
 * disconnect ind
 * @WLAN_LINK_RECFG_SM_EV_ROAM_START_IND: Link Reconfiguration event for roam
 * start ind
 * @WLAN_LINK_RECFG_SM_EV_COMPLETED: Link Reconfiguration completed
 * @WLAN_LINK_RECFG_SM_EV_SER_TIMEOUT: Link Reconfiguration serialization
 * timeout
 * @WLAN_LINK_RECFG_SM_EV_SM_TIMEOUT: generic timeout in substate
 * @WLAN_LINK_RECFG_SM_EV_RX_RSP_TIMEOUT: Link Reconfig response timed out
 * @WLAN_LINK_RECFG_SM_EV_UPDATE_TTLM: Update TTLM due to link reconfig
 * @WLAN_LINK_RECFG_SM_EV_MAX: Max event
 */
enum wlan_link_recfg_sm_evt {
	WLAN_LINK_RECFG_SM_EV_USER_REQ,
	WLAN_LINK_RECFG_SM_EV_FW_IND,
	WLAN_LINK_RECFG_SM_EV_START,
	WLAN_LINK_RECFG_SM_EV_ACTIVE,
	WLAN_LINK_RECFG_SM_EV_DEL_LINK,
	WLAN_LINK_RECFG_SM_EV_ADD_LINK,
	WLAN_LINK_RECFG_SM_EV_XMIT_REQ,
	WLAN_LINK_RECFG_SM_EV_XMIT_STATUS,
	WLAN_LINK_RECFG_SM_EV_RX_RSP,
	WLAN_LINK_RECFG_SM_EV_SET_LINK_RSP,
	WLAN_LINK_RECFG_SM_EV_LINK_SWITCH_IND,
	WLAN_LINK_RECFG_SM_EV_LINK_SWITCH_RSP,
	WLAN_LINK_RECFG_SM_EV_ADD_CONN_RSP,
	WLAN_LINK_RECFG_SM_EV_DISCONNECT_IND,
	WLAN_LINK_RECFG_SM_EV_ROAM_START_IND,
	WLAN_LINK_RECFG_SM_EV_COMPLETED,
	WLAN_LINK_RECFG_SM_EV_SER_TIMEOUT,
	WLAN_LINK_RECFG_SM_EV_SM_TIMEOUT,
	WLAN_LINK_RECFG_SM_EV_RX_RSP_TIMEOUT,
	WLAN_LINK_RECFG_SM_EV_UPDATE_TTLM,
	WLAN_LINK_RECFG_SM_EV_MAX,
};

/**
 * enum link_recfg_failure_reason - link recfg failure reason code enum
 * @link_recfg_success: link recfg successfully
 * @link_recfg_create_tran_failed: can't create transition list
 * @link_recfg_set_link_cmd_timeout: set link cmd timeout
 * @link_recfg_set_link_cmd_rejected: set link cmd rejected
 * @link_recfg_del_link_wait_fw_link_switch_timeout: wait for fw link switch
 * timeout
 * @link_recfg_del_link_fw_link_switch_rejected: fw link switch rejected in
 * delete link
 * @link_recfg_del_link_link_switch_comp_with_fail: link switch complete
 * with failure
 * @link_recfg_rsp_timeout: Link Reconfiguration response timeout.
 * @link_recfg_concurrency_failed: Link reconfig failed due to concurrency
 * @link_recfg_aborted_neg_ttlm_ongoing: Link Reconfiguration aborted
 * due to ongoing TTLM.
 * @link_recfg_nb_sb_disconnect: nb/sb disconnect causing abort
 * @link_recfg_tx_failed: tx status is failed
 * @link_recfg_rsp_status_failure: response status is error.
 */
enum link_recfg_failure_reason {
	link_recfg_success = 0,
	link_recfg_create_tran_failed = 1,
	link_recfg_set_link_cmd_timeout = 2,
	link_recfg_set_link_cmd_rejected = 3,
	link_recfg_del_link_wait_fw_link_switch_timeout = 4,
	link_recfg_del_link_fw_link_switch_rejected = 5,
	link_recfg_del_link_link_switch_comp_with_fail = 6,
	link_recfg_rsp_timeout = 7,
	link_recfg_concurrency_failed = 8,
	link_recfg_aborted_neg_ttlm_ongoing = 9,
	link_recfg_nb_sb_disconnect = 10,
	link_recfg_tx_failed = 11,
	link_recfg_rsp_status_failure = 12,
};

/**
 * enum link_recfg_type - link recfg type enum
 * @link_recfg_undefined: link recfg type undefined.
 * @link_recfg_del_only: delete link only
 * @link_recfg_add_only: add link only
 * @link_recfg_del_add_common_link: delete and add link with common link
 * present
 * @link_recfg_del_add_no_common_link: delete and add link with no
 * common link present
 * @link_recfg_two_frm_del_add_common_link: del and add by 2 action
 * frame with common link present
 */
enum link_recfg_type {
	link_recfg_undefined,
	link_recfg_del_only,
	link_recfg_add_only,
	link_recfg_del_add_common_link,
	link_recfg_del_add_no_common_link,
	link_recfg_two_frm_del_add_common_link,
};

/**
 * struct wlan_mlo_link_recfg_req - Data Structure because of link
 *  reconfiguration request
 * @vdev_id: Hold information regarding all the links of ml connection
 * @add_link_info: Add link info struct
 * @del_link_info: Delete link info struct
 * @is_user_req: Request received from user/framework
 * @is_curr_req: Is current link reconfig request active
 * @is_fw_ind_received: if fw link recfg evt is received or not
 * @recfg_type: link recfg type
 * @join_pending_vdev_id: used on for no-common link recfg,
 * use vdev with join_pending_vdev_id to trigger peer assoc after
 * receive recfg response.
 * @fw_ind_param: received fw link recfg evt params
 * @mld_addr: mld address
 * @send_two_link_recfg_frms: Split 1 Link Recfg request in 2 frames
 */
struct wlan_mlo_link_recfg_req {
	uint8_t vdev_id;
	struct wlan_mlo_link_recfg_info add_link_info;
	struct wlan_mlo_link_recfg_info del_link_info;
	bool is_user_req;
	bool is_curr_req;
	bool is_fw_ind_received;
	enum link_recfg_type recfg_type;
	uint8_t join_pending_vdev_id;
	struct wlan_mlo_link_recfg_ind_param fw_ind_param;
	uint8_t mld_addr[QDF_MAC_ADDR_SIZE];
	bool send_two_link_recfg_frms;
};

/**
 * struct mlo_link_recfg_state_req - Link Reconfig add/del/xmit state
 * request param
 * @add_link_info: add link info
 * @del_link_info: del link info
 * @dialog_token: Dialog token
 * @peer_mac: peer mac address to indicate on which link to send recfg frame
 */
struct mlo_link_recfg_state_req {
	struct wlan_mlo_link_recfg_info add_link_info;
	struct wlan_mlo_link_recfg_info del_link_info;
	uint8_t dialog_token;
	struct qdf_mac_addr peer_mac;
};

/**
 * typedef state_abort_handler - link recfg abort callback
 * @psoc: psoc object
 *
 * Return: QDF_STATUS
 */
typedef QDF_STATUS (*state_abort_handler)(struct wlan_objmgr_psoc *psoc);

/**
 * typedef state_pre_link_add_handler - pre link add callback
 * @recfg_ctx: recfg context
 * @req: link recfg request
 *
 * Used in non-common link case, to be invoked when trigger connect to new
 * Added link.
 *
 * Return: QDF_STATUS
 */
typedef QDF_STATUS (*state_pre_link_add_handler)(
			struct mlo_link_recfg_context *recfg_ctx,
			struct mlo_link_recfg_state_req *req);

/**
 * typedef state_defer_rsp_handler - defer the action frame response handler
 * @recfg_ctx: recfg context
 * @recfg_resp_data: recfg response data
 * @event_data_len: recfg response data len
 *
 * Return: QDF_STATUS
 */
typedef QDF_STATUS (*state_defer_rsp_handler)(
			struct mlo_link_recfg_context *recfg_ctx,
			struct link_recfg_rx_rsp *recfg_resp_data,
			uint16_t event_data_len);

/**
 * typedef state_proc_defer_rsp_handler - process deferred the action
 * frame response handler
 * @recfg_ctx: recfg context
 *
 * Return: QDF_STATUS
 */
typedef QDF_STATUS (*state_proc_defer_rsp_handler)(
			struct mlo_link_recfg_context *recfg_ctx);
typedef QDF_STATUS (*two_frm_handler)(struct mlo_link_recfg_context *recfg_ctx);

/**
 * struct mlo_link_recfg_state_tran - Link Reconfig state transition
 * info
 * @state: target tansition state
 * @event: first event id for the state
 * @req: state request param, also the event data
 * @abort_handler: error handler if error happends in the state,
 * it will be invoked after link config completed
 * @two_frame_xmit_handler: two frame xmit handler callback
 * @pre_link_add_handler: pre link add callback
 * @defer_rsp_handler: defer response processing
 * @proc_defer_rsp_handler: process deferred response
 */
struct mlo_link_recfg_state_tran {
	enum wlan_link_recfg_sm_state state;
	enum wlan_link_recfg_sm_evt event;
	struct mlo_link_recfg_state_req req;
	state_abort_handler abort_handler;
	two_frm_handler two_frame_xmit_handler;
	state_pre_link_add_handler pre_link_add_handler;
	state_defer_rsp_handler defer_rsp_handler;
	state_proc_defer_rsp_handler proc_defer_rsp_handler;
};

/* WLAN_LINK_RECFG_SM_EV_XMIT_TX_DONE */
struct link_recfg_tx_result {
	QDF_STATUS status;
};

/* WLAN_LINK_RECFG_SM_EV_RX_RSP */
struct link_recfg_rx_rsp {
	QDF_STATUS status;
};

/**
 * struct set_link_resp - event data of
 * WLAN_LINK_RECFG_SM_EV_SET_LINK_RSP
 * @status: 0 for set link success, otherwise set link failed
 */
struct set_link_resp {
	uint32_t status;
};

/**
 * struct link_switch_ind - event data of
 * WLAN_LINK_RECFG_SM_EV_LINK_SWITCH_IND
 * @status: link witch start status code
 */
struct link_switch_ind {
	QDF_STATUS status;
};

/**
 * struct link_switch_rsp - event data of
 * WLAN_LINK_RECFG_SM_EV_LINK_SWITCH_RSP
 * @status: link witch rsp status code
 */
struct link_switch_rsp {
	QDF_STATUS status;
};

/* struct add_link_conn_resp - event data of
 * WLAN_LINK_RECFG_SM_EV_ADD_CONN_RSP
 * @status: connect resp status code
 */
struct add_link_conn_rsp {
	QDF_STATUS status;
};

/* WLAN_LINK_RECFG_SM_EV_DISCONNECT_IND */
struct disconnect_ind {
};

/* WLAN_LINK_RECFG_SM_EV_ROAM_START_IND */
struct roam_ind {
};

/* WLAN_LINK_RECFG_SM_EV_COMPLETED */
struct recfg_completed {
};

#define MAX_RECFG_TRANSITION 7

/**
 * struct mlo_link_recfg_state_sm - Link Reconfig state machine
 * @mlrc_sm_lock: SM lock
 * @sm_hdl: SM handlers
 * @link_recfg_state: Current state
 * @link_recfg_substate: Current substate
 * @state_list: link reconfig state transition list
 * @curr_state_idx: current transition index
 * @sm_timer: state machine timer
 */
struct mlo_link_recfg_state_sm {
	qdf_mutex_t mlrc_sm_lock;
	struct wlan_sm *sm_hdl;
	enum wlan_link_recfg_sm_state link_recfg_state;
	enum wlan_link_recfg_sm_state link_recfg_substate;
	struct mlo_link_recfg_state_tran state_list[MAX_RECFG_TRANSITION];
	int8_t curr_state_idx;
	qdf_mc_timer_t sm_timer;
};

/**
 * struct mlo_link_recfg_status_list - Data Structure for link
 * reconfiguration response status list
 * @link_id: IEEE Link id
 * @status_code: wlan protocol status code
 */
struct mlo_link_recfg_status_list {
	uint8_t link_id;
	enum wlan_status_code status_code;
};

/**
 * struct wlan_mlo_link_recfg_rsp - Data Structure for link
 * reconfiguration response
 * @is_valid: Set to true if link reconfig resp is valid
 * @dialog_token: dialog token received in Link Recfg response frame.
 * @count: number of reconfig status duple in the mlo_link_recfg_status_list
 * @recfg_status_list: Reconfiguration status duple list
 * @grp_key_data: Group key data len and ptr
 * @oci_ie: OCI IE
 * @mlo_ie: Basic Multi link IE
 */
struct wlan_mlo_link_recfg_rsp {
	bool is_valid;
	uint8_t dialog_token;
	uint8_t count;
	struct mlo_link_recfg_status_list recfg_status_list[WLAN_MAX_ML_RECFG_LINK_COUNT];
	struct element_info grp_key_data;
	struct element_info oci_ie;
	struct element_info mlo_ie;
};

/**
 * struct recfg_done_data_hdr - recfg done ctx header
 * @node: list node
 */
struct recfg_done_data_hdr {
	qdf_list_node_t node;
};

#define MAX_NUM_FRAMES 4
/**
 * struct wlan_mlo_link_recfg_bitmap: User based Link reconfig bitmap
 * @num_frames: Number of frames used to send link reconfig request
 * @add_link_bitmap: Bitmap of link IDs of links to be added
 * @delete_link_bitmap: Bitmap of link IDs of links to be removed
 */
struct wlan_mlo_link_recfg_bitmap {
	uint8_t num_frames;
	uint16_t add_link_bitmap[MAX_NUM_FRAMES];
	uint16_t delete_link_bitmap[MAX_NUM_FRAMES];
};

/**
 * struct mlo_link_recfg_context - Link reconfiguration data structure.
 * @psoc: psoc object
 * @ml_dev: ml dev context
 * @curr_recfg_req: Last link recfg request received from FW or user
 * @curr_recfg_rsp: Last link recfg response received from AP
 * @sm: link reconfig sm context
 * @set_link_req: set link req for link recfg
 * @macaddr_updating_vdev_id: mac addr updating vdev for link add
 * @old_macaddr_updating_vdev: old mac addr of updating vdev
 * @req_frame: Link Reconfiguration request frame
 * @rsp_frame: Link Reconfiguration response frame
 * @link_recfg_bm: User configured Link Reconfiguration bitmap
 * @rsp_rx_frame: Link reconfig response with mac header
 * @link_recfg_rsp_timer: Link Reconfiguration rsp timed out
 * @link_recfg_status: Link Reconfiguration status
 * @last_dialog_token: Last used dialog token
 * @internal_reason_code: Internal failure reason code
 * @copied_recfg_req: Copied recfg req
 * @recfg_indication_work: recfg done work queue
 * @recfg_done_list: recfg done data struct list
 */
struct mlo_link_recfg_context {
	struct wlan_objmgr_psoc *psoc;
	struct wlan_mlo_dev_context *ml_dev;
	struct wlan_mlo_link_recfg_req curr_recfg_req;
	struct wlan_mlo_link_recfg_rsp curr_recfg_rsp;
	struct mlo_link_recfg_state_sm sm;
	struct mlo_link_set_active_req *set_link_req;
	uint8_t macaddr_updating_vdev_id;
	struct qdf_mac_addr old_macaddr_updating_vdev;
	struct element_info req_frame;
	struct element_info rsp_frame;
	struct wlan_mlo_link_recfg_bitmap link_recfg_bm;
	struct element_info rsp_rx_frame;
	qdf_mc_timer_t link_recfg_rsp_timer;
	QDF_STATUS link_recfg_status;
	uint8_t last_dialog_token;
	enum link_recfg_failure_reason internal_reason_code;
	struct wlan_mlo_link_recfg_req copied_recfg_req;
	qdf_work_t recfg_indication_work;
	qdf_list_t recfg_done_list;
};

static inline void
ml_link_recfg_sm_lock_create(struct wlan_mlo_dev_context *mldev)
{
	qdf_mutex_create(&mldev->link_recfg_ctx->sm.mlrc_sm_lock);
}

static inline void
ml_link_recfg_sm_lock_destroy(struct wlan_mlo_dev_context *mldev)
{
	qdf_mutex_destroy(&mldev->link_recfg_ctx->sm.mlrc_sm_lock);
}

static inline void
ml_link_recfg_sm_lock_acquire(struct wlan_mlo_dev_context *mldev)
{
	qdf_mutex_acquire(&mldev->link_recfg_ctx->sm.mlrc_sm_lock);
}

static inline void
ml_link_recfg_sm_lock_release(struct wlan_mlo_dev_context *mldev)
{
	qdf_mutex_release(&mldev->link_recfg_ctx->sm.mlrc_sm_lock);
}

#ifdef WLAN_FEATURE_11BE_MLO
/**
 * mlo_link_recfg_validate_roam_invoke() - Validate roam invoke
 * allow if link recfg is in-progress
 * @psoc: psoc object
 * @vdev: vdev object
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlo_link_recfg_validate_roam_invoke(
		struct wlan_objmgr_psoc *psoc,
		struct wlan_objmgr_vdev *vdev);

/**
 * mlo_link_recfg_set_mac_addr_resp() - handle link recfg set mac
 * addr response
 * @vdev: vdev object
 * @resp_status: set mac resp result
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlo_link_recfg_set_mac_addr_resp(struct wlan_objmgr_vdev *vdev,
					    uint8_t resp_status);

/**
 * mlo_link_recfg_set_link_resp() - Handle link recfg set link
 * response event
 * @vdev: vdev object
 * @result: set link response result
 *
 * Return: void
 */
void mlo_link_recfg_set_link_resp(struct wlan_objmgr_vdev *vdev,
				  uint32_t result);

/**
 * mlo_link_recfg_get_add_partner_links() - Get current added
 * partner links
 * @vdev: vdev object
 * @ml_partner_info: New added partner links
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlo_link_recfg_get_add_partner_links(
		struct wlan_objmgr_vdev *vdev,
		struct mlo_partner_info *ml_partner_info);

/**
 * mlo_mgr_link_recfg_indication_event_handler() - Handle fw link recfg event
 * @psoc: psoc object
 * @evt_params: fw link recfg event data
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlo_mgr_link_recfg_indication_event_handler(
			struct wlan_objmgr_psoc *psoc,
			struct wlan_mlo_link_recfg_ind_param *evt_params);

/**
 * mlo_link_recfg_init_state() - Set the current state of link switch
 * to init state.
 * @mlo_dev_ctx: MLO dev context
 *
 * Sets the current state of link switch to MLO_LINK_SWITCH_STATE_IDLE with
 * MLO dev context lock held.
 *
 * Return: void
 */
void mlo_link_recfg_init_state(struct wlan_mlo_dev_context *mlo_dev_ctx);

/**
 * mlo_link_recfg_trans_next_state() - Transition to next state based
 * on current state.
 * @mlo_dev_ctx: MLO dev context
 *
 * Move to next state in link recfg process based on current state with
 * SM link reconfig lock held.
 *
 * Return: void
 */
QDF_STATUS
mlo_link_recfg_trans_next_state(struct wlan_mlo_dev_context *mlo_dev_ctx);

/**
 * mlo_link_recfg_trans_abort_state() - Transition to abort trans state.
 * @mlo_dev_ctx: ML dev context pointer of VDEV
 *
 * Transition the current link recfg state to ABORT
 * state, no further state transitions are allowed in the ongoing link recfg
 * request.
 *
 * Return: void
 */
void
mlo_link_recfg_trans_abort_state(struct wlan_mlo_dev_context *mlo_dev_ctx);

/**
 * mlo_is_link_recfg_in_progress() - Check in MLO dev context
 * if the last received link recfg is in progress.
 * @vdev: VDEV object manager
 *
 * The API is to be called for VDEV which has MLO dev context and link reconfig
 * context initialized. Returns the value of 'is_in_progress' flag in last received
 * link reconfig request.
 *
 * Return: bool
 */
bool mlo_is_link_recfg_in_progress(struct wlan_objmgr_vdev *vdev);

/**
 * mlo_link_recfg_notify() - API to notify registered link recfg notify
 * callbacks.
 * @vdev: VDEV object manager
 * @req: Link recfg request params from FW.
 *
 * The API calls all the registered link recfg notifiers with appropriate
 * reason for notifications. Callback handlers to take necessary action based
 * on the reason.
 * If any callback returns error API will return error or else success.
 *
 * Return: QDF_STATUS.
 */
QDF_STATUS
mlo_link_recfg_notify(struct wlan_objmgr_vdev *vdev,
		      struct wlan_mlo_link_recfg_req *req);

/**
 * mlo_link_recfg_validate_request() - Validate link reconfiguration request
 * received from FW.
 * @vdev: VDEV object manager
 * @req: Request params from FW
 *
 * The API performs initial validation of link recfg params received from FW
 * before serializing the link recfg cmd. If any of the params is invalid or
 * the current status of MLO manager can't allow link recfg, the API returns
 * failure and link recfg has to be terminated.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlo_link_recfg_validate_request(struct wlan_objmgr_vdev *vdev,
				struct wlan_mlo_link_recfg_req *req);

/**
 * mlo_is_link_recfg_supported() - API to check link recfg
 * support with vdev
 * @vdev: vdev object
 *
 * Return: bool
 */
bool
mlo_is_link_recfg_supported(struct wlan_objmgr_vdev *vdev);

/**
 * mlo_link_recfg_request_params() - Link recfg request params from FW.
 * @psoc: PSOC object manager
 * @evt_params: Link recfg params received from FW.
 *
 * The @params contain link recfg request parameters received from FW or user
 * as an indication to host to trigger link recfg sequence.
 * If the @params are not valid link recfg will be terminated.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlo_link_recfg_request_params(struct wlan_objmgr_psoc *psoc,
					 void *evt_params);

/**
 * mlo_link_recfg_init() - API to initialize link reconfiguration
 * @psoc: PSOC object manager
 * @ml_dev: MLO dev context
 *
 * Initializes the MLO link recfg context in @ml_dev and allocates various
 * buffers needed.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlo_link_recfg_init(struct wlan_objmgr_psoc *psoc,
			       struct wlan_mlo_dev_context *ml_dev);

/**
 * mlo_link_recfg_timer_init() - API to initialize link recfg
 * rsp timer
 *@recfg_ctx: ML Reconfig context
 *
 * Initialize the MLO link reconfiguration rsp timer
 *
 * Return: void
 */
void mlo_link_recfg_timer_init(struct mlo_link_recfg_context *recfg_ctx);

/**
 * mlo_link_recfg_deinit() - API to de-initialize link recfg
 * @ml_dev: MLO dev context
 *
 * De-initialize the MLO link reconfiguration context
 * in @ml_dev on and frees memory
 * allocated as part of initialization.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlo_link_recfg_deinit(struct wlan_mlo_dev_context *ml_dev);

/**
 * mlo_link_recfg_timer_deinit() - API to de-initialize link recfg timer
 * @recfg_ctx: ML Reconfig context
 *
 * De-initialize the MLO link reconfiguration timer
 *
 * Return: void
 */
void mlo_link_recfg_timer_deinit(struct mlo_link_recfg_context *recfg_ctx);

/**
 * mlo_link_recfg_rx_rsp_timeout_cb() - API to handle link recfg
 * response timeout callback.
 * @user_data: ML Reconfig context
 *
 * Callback api to handle link recfg rsp timed out
 *
 * Return: void
 */
void mlo_link_recfg_rx_rsp_timeout_cb(void *user_data);

/**
 * mlo_link_recfg_get_state() - API to get SM link recfg state
 * @mlo_dev_ctx: MLO dev context
 *
 * API to get current SM link reconfiguration state
 *
 * Return: QDF_STATUS
 */
enum wlan_link_recfg_sm_state
mlo_link_recfg_get_state(struct wlan_mlo_dev_context *mlo_dev_ctx);

/**
 * mlo_link_recfg_get_substate() - API to get SM link recfg sub state
 * @mlo_dev_ctx: MLO dev context
 *
 * API to get current SM link reconfiguration sub state
 *
 * Return: QDF_STATUS
 */
enum wlan_link_recfg_sm_state
mlo_link_recfg_get_substate(struct wlan_mlo_dev_context *mlo_dev_ctx);

/**
 * mlo_link_recfg_sm_deliver_event() - Delivers event to Link Reconfiguraion
 * manager SM
 * @mlo_dev_ctx: ML dev context
 * @event: Link reconfig SM event
 * @data_len: data size
 * @data: event data
 *
 * API to dispatch event to Link reconfig SM with lock. To be used while posting
 * events from API called from public API. i.e. indication/response/request
 * from any other module or NB/SB req/resp.
 *
 * Context: Can be called from any context, This should be called in case
 * SM lock is not taken, the API will take the lock before posting to SM.
 *
 * Return: SUCCESS: on handling event
 *         FAILURE: If event not handled
 */
QDF_STATUS
mlo_link_recfg_sm_deliver_event(struct wlan_mlo_dev_context *mlo_dev_ctx,
				enum wlan_link_recfg_sm_evt event,
				uint16_t data_len, void *data);

/**
 * mlo_link_recfg_sm_deliver_event_sync() - Delivers event to Link Reconfiguration SM while
 * holding lock
 * @mlo_dev_ctx: mlo dev ctx
 * @event: Link Reconfiguration event
 * @data_len: data size
 * @data: event data
 *
 * API to dispatch event to Link Reconfiguration SM without lock,
 * in case lock is already held.
 *
 * Context: Can be called from any context, This should be called in case
 * SM lock is already taken. If lock is not taken use
 * mlo_mgr_link_recfg_sm_deliver_event API instead.
 *
 * Return: SUCCESS: on handling event
 *         FAILURE: If event not handled
 */
QDF_STATUS
mlo_link_recfg_sm_deliver_event_sync(struct wlan_mlo_dev_context *mlo_dev_ctx,
				     enum wlan_link_recfg_sm_evt event,
				     uint16_t data_len, void *data);

/**
 * mlo_link_recfg_linksw_start_indication() - Delivers link switch start event
 * @vdev: vdev
 * @start_status: link switch start status
 *
 * API to dispatch Link switch start event to reconfig sm.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlo_link_recfg_linksw_start_indication(struct wlan_objmgr_vdev *vdev,
				       QDF_STATUS start_status);

/**
 * mlo_link_recfg_linksw_completion_indication() - Delivers link switch
 * completion event
 * @vdev: vdev
 * @comp_status: link switch completion status
 *
 * API to dispatch Link switch completion event to reconfig sm.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlo_link_recfg_linksw_completion_indication(struct wlan_objmgr_vdev *vdev,
					    QDF_STATUS comp_status);

/**
 * mlo_link_recfg_add_connect_done_indication() - Delivers link add connect
 * completion event
 * @vdev: vdev
 * @comp_status: link add connect completion status
 *
 * API to dispatch Link add connect completion event to reconfig sm.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlo_link_recfg_add_connect_done_indication(
				struct wlan_objmgr_vdev *vdev,
				QDF_STATUS comp_status);

QDF_STATUS
mlo_link_recfg_create_transition_list(
			struct mlo_link_recfg_context *recfg_ctx,
			struct wlan_mlo_link_recfg_req *recfg_req);
/**
 * mlo_link_recfg_send_request_frame() - Send Link Reconfiguration action
 * request frame
 * @recfg_ctx: recfg ctx pointer
 * @req: Link Reconfig event data pointer
 *
 * API to send Link Reconfiguration action request frame
 *
 * Return: qdf status
 */
QDF_STATUS
mlo_link_recfg_send_request_frame(
		struct mlo_link_recfg_context *recfg_ctx,
		struct mlo_link_recfg_state_req *req);

/**
 * mlo_link_recfg_rx_rsp() - Handler for Link Reconfiguration
 * action response frame
 * @vdev: vdev pointer
 * @event: Link reconfig SM event
 * @rx_pkt_info: RX frame
 *
 * API to send Link Reconfiguration action response frame
 *
 * Return: qdf status
 */
QDF_STATUS mlo_link_recfg_rx_rsp(struct wlan_objmgr_vdev *vdev,
				 enum wlan_link_recfg_sm_evt event,
				 uint8_t *rx_pkt_info);

/**
 * mlo_link_recfg_link_add_join_req() - handle add link join request
 * @vdev: vdev pointer
 *
 * API to handle add link join request for non-common link case
 *
 * Return: qdf status
 */
QDF_STATUS
mlo_link_recfg_link_add_join_req(struct wlan_objmgr_vdev *vdev);

/**
 * mlo_link_recfg_is_start_as_active() - check link start as active state
 * when vdev is started on the link
 * @vdev: vdev pointer
 *
 * For no-common link cases, L1 -> L2, or L1 L2 -> L3, the added link
 * has to be active state. The flag will be sent in vdev start.
 *
 * Return: true if start the link with active state after vdev started
 */
bool mlo_link_recfg_is_start_as_active(struct wlan_objmgr_vdev *vdev);

/**
 * mlo_link_recfg_dialog_token() - Generate dialog token for
 * for Link Reconfiguration action request frame
 * @recfg_ctx: Link reconfig context pointer
 * @req: mlo link reconfig req pointer
 *
 * API to generate dialog token for Link Reconfiguration
 * action request frame
 *
 * Return: uint8_t
 */
uint8_t
mlo_link_recfg_dialog_token(struct mlo_link_recfg_context *recfg_ctx,
			    struct mlo_link_recfg_state_req *req);

/**
 * mlo_link_recfg_ctx_free_ies() -Free link recfg ctx ies
 * @ctx: link reconfig ctx pointer
 *
 * API to free link reconfig context ies
 *
 * Return: none
 */
void
mlo_link_recfg_ctx_free_ies(struct mlo_link_recfg_context *ctx);

/**
 * mlo_link_recfg_store_key() -Store unicast key
 * @ctx: link reconfig ctx pointer
 * @req: Link recfg request pointer
 *
 * API to stote unicast keys during link reconfig addition.
 *
 * Return: qdf_status success/fail
 */
QDF_STATUS
mlo_link_recfg_store_key(struct mlo_link_recfg_context *ctx,
			 struct mlo_link_recfg_state_req *req);

/**
 * mlo_link_recfg_save_unicast_key() -Save unicast keys for added link
 * @ctx: link reconfig ctx pointer
 * @vdev: vdev obj pointer
 * @link_addr: self link address
 * @ap_link_addr: AP link address
 * @link_id: link id
 *
 * API to save unicast keys for added link
 *
 * Return: qdf_status success/fail
 */
QDF_STATUS
mlo_link_recfg_save_unicast_key(struct mlo_link_recfg_context *ctx,
				struct wlan_objmgr_vdev *vdev,
				struct qdf_mac_addr *link_addr,
				struct qdf_mac_addr *ap_link_addr,
				uint8_t link_id);
/**
 * mlo_link_recfg_install_unicast_keys() -Install unicast keys for added link
 * @vdev: vdev obj pointer
 *
 * API to install unicast keys for added link
 *
 * Return: none
 */
void
mlo_link_recfg_install_unicast_keys(struct wlan_objmgr_vdev *vdev);

#ifdef WLAN_FEATURE_11BE_MLO_ADV_FEATURE
/**
 * mlo_mgr_link_recfg_req_cmd_handler() - Handle link recfg req
 * from user space
 * @psoc: psoc object
 * @req: userspace link recfg command
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlo_mgr_link_recfg_req_cmd_handler(
			struct wlan_objmgr_psoc *psoc,
			struct  mlo_link_recfg_user_req_params *req);
#endif
/**
 * mlo_link_recfg_abort_if_in_progress() -Abort link recfg in progress
 * @vdev: Vdev pointer
 * @is_link_switch_discon: is link switch disconnect
 *
 * API to abort link reconfig if in progress.
 * Return: none
 */
void
mlo_link_recfg_abort_if_in_progress(struct wlan_objmgr_vdev *vdev,
				    bool is_link_switch_discon);
#else
static inline QDF_STATUS
mlo_link_recfg_validate_roam_invoke(
		struct wlan_objmgr_psoc *psoc,
		struct wlan_objmgr_vdev *vdev)
{
	return QDF_STATUS_SUCCESS;
}

static inline void
mlo_link_recfg_install_unicast_keys(struct wlan_objmgr_vdev *vdev)
{
}

static inline QDF_STATUS
mlo_link_recfg_save_unicast_key(struct mlo_link_recfg_context *ctx,
				struct wlan_objmgr_vdev *vdev,
				struct qdf_mac_addr *link_addr,
				struct qdf_mac_addr *ap_link_addr,
				uint8_t link_id)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline QDF_STATUS
mlo_link_recfg_store_key(struct mlo_link_recfg_context *ctx,
			 struct mlo_link_recfg_state_req *req)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline void
mlo_link_recfg_abort_if_in_progress(struct wlan_objmgr_vdev *vdev,
				    bool is_link_switch_discon)
{
}

static inline void
mlo_link_recfg_ctx_free_ies(struct mlo_link_recfg_context *ctx)
{
}

static inline QDF_STATUS
mlo_link_recfg_set_mac_addr_resp(struct wlan_objmgr_vdev *vdev,
				 uint8_t resp_status)
{
	return QDF_STATUS_SUCCESS;
}

static inline void
mlo_link_recfg_set_link_resp(struct wlan_objmgr_vdev *vdev,
			     uint32_t result)
{
}

static inline QDF_STATUS
mlo_link_recfg_get_add_partner_links(
		struct wlan_objmgr_vdev *vdev,
		struct mlo_partner_info *ml_partner_info)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS
mlo_mgr_link_recfg_indication_event_handler(
			struct wlan_objmgr_psoc *psoc,
			struct wlan_mlo_link_recfg_ind_param *evt_params)
{
	return QDF_STATUS_SUCCESS;
}

static inline uint8_t
mlo_link_recfg_dialog_token(struct mlo_link_recfg_context *recfg_ctx,
			    struct mlo_link_recfg_state_req *req)
{
	return 0;
}

static inline QDF_STATUS
mlo_link_recfg_send_request_frame(
		struct mlo_link_recfg_context *recfg_ctx,
		struct mlo_link_recfg_state_req *req)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline QDF_STATUS
mlo_link_recfg_rx_rsp(struct wlan_objmgr_vdev *vdev,
		      enum wlan_link_recfg_sm_evt event,
		      uint8_t *rx_pkt_info)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline QDF_STATUS
mlo_link_recfg_link_add_join_req(struct wlan_objmgr_vdev *vdev)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline bool
mlo_link_recfg_is_start_as_active(struct wlan_objmgr_vdev *vdev)
{
	return false;
}

static inline QDF_STATUS
mlo_link_recfg_sm_deliver_event(struct wlan_mlo_dev_context *mlo_dev_ctx,
				enum wlan_link_recfg_sm_evt event,
				uint16_t data_len, void *data)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline QDF_STATUS
mlo_link_recfg_sm_deliver_event_sync(struct wlan_mlo_dev_context *mlo_dev_ctx,
				     enum wlan_link_recfg_sm_evt event,
				     uint16_t data_len, void *data)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline QDF_STATUS
mlo_link_recfg_linksw_start_indication(struct wlan_objmgr_vdev *vdev,
				       QDF_STATUS start_status)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS
mlo_link_recfg_linksw_completion_indication(struct wlan_objmgr_vdev *vdev,
					    QDF_STATUS comp_status)
{
	return QDF_STATUS_SUCCESS;
}

static inline enum wlan_link_recfg_sm_state
mlo_link_recfg_get_state(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
	return WLAN_LINK_RECFG_S_MAX;
}

static inline enum wlan_link_recfg_sm_state
mlo_link_recfg_get_substate(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
	return WLAN_LINK_RECFG_SS_MAX;
}

static inline bool
mlo_is_link_recfg_supported(struct wlan_objmgr_vdev *vdev)
{
	return false;
}

static inline QDF_STATUS
mlo_link_recfg_init(struct wlan_objmgr_psoc *psoc,
		    struct wlan_mlo_dev_context *ml_dev)
{
	return QDF_STATUS_SUCCESS;
}

static inline void
mlo_link_recfg_init_state(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
}

static inline QDF_STATUS
mlo_link_recfg_trans_next_state(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
	return QDF_STATUS_E_INVAL;
}

static inline void
mlo_link_recfg_trans_abort_state(struct wlan_mlo_dev_context *mlo_dev_ctx)
{
}

static inline bool
mlo_is_link_recfg_in_progress(struct wlan_objmgr_vdev *vdev)
{
	return false;
}

static inline QDF_STATUS
mlo_link_recfg_notify(struct wlan_objmgr_vdev *vdev,
		      struct wlan_mlo_link_recfg_req *req)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline QDF_STATUS
mlo_link_recfg_validate_request(struct wlan_objmgr_vdev *vdev,
				struct wlan_mlo_link_recfg_req *req)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline QDF_STATUS
mlo_link_recfg_request_params(struct wlan_objmgr_psoc *psoc,
			      void *evt_params)
{
	return QDF_STATUS_E_NOSUPPORT;
}

static inline QDF_STATUS
mlo_link_recfg_create_transition_list(
			struct mlo_link_recfg_context *recfg_ctx,
			struct wlan_mlo_link_recfg_req *recfg_req)
{
	return QDF_STATUS_E_NOSUPPORT;
}
#endif
#endif
