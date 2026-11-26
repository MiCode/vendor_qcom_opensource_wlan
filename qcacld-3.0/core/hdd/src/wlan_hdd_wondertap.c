/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <wlan_hdd_wondertap.h>
#include <wlan_hdd_main.h>
#include <osif_psoc_sync.h>
#include <osif_vdev_sync.h>
#include <wlan_hdd_regulatory.h>
#include <wlan_hdd_power.h>
#include <wlan_hdd_object_manager.h>
#include <wlan_hdd_packet_filter_api.h>
#include <wlan_dp_ucfg_api.h>
#include <wlan_vdev_mgr_api.h>
#include <wlan_fwol_ucfg_api.h>
#include <wma_api.h>
#include "cds_api.h"
#include "cdp_txrx_ctrl.h"

static struct hdd_wondertap_context *g_wt_ctx;
static DEFINE_MUTEX(g_wt_ctx_mutex);

static enum phy_ch_width
__wlan_hdd_convert_wt_bandwidth_to_phy_ch_width(qdf_wondertap_rate_bw_t bw)
{
	switch (bw) {
	case WONDERTAP_RATE_BW_20:
		return CH_WIDTH_20MHZ;
	case WONDERTAP_RATE_BW_40:
		return CH_WIDTH_40MHZ;
	case WONDERTAP_RATE_BW_80:
		return CH_WIDTH_80MHZ;
	case WONDERTAP_RATE_BW_160:
		return CH_WIDTH_160MHZ;
	case WONDERTAP_RATE_BW_320:
		return CH_WIDTH_320MHZ;
	default:
		hdd_err("Incorrect bandwidth value:%d", bw);
		return CH_WIDTH_INVALID;
	};
}

static enum hw_mode_bandwidth
wlan_hdd_wondertap_bw_to_hw_mode_bw(qdf_wondertap_rate_bw_t bw)
{
	switch (bw) {
	case WONDERTAP_RATE_BW_20:
		return HW_MODE_20_MHZ;
	case WONDERTAP_RATE_BW_40:
		return HW_MODE_40_MHZ;
	case WONDERTAP_RATE_BW_80:
		return HW_MODE_80_MHZ;
	case WONDERTAP_RATE_BW_160:
		return HW_MODE_160_MHZ;
	case WONDERTAP_RATE_BW_320:
		return HW_MODE_320_MHZ;
	default:
		return HW_MODE_BW_NONE;
	}
}

static QDF_STATUS
__wlan_hdd_set_wondertap_channel(struct hdd_context *hdd_ctx,
				 struct hdd_adapter *adapter,
				 const qdf_wondertap_set_freq_params_t *params)
{
	struct channel_change_req req = {0};
	struct ch_params ch_params = {0};
	enum phy_ch_width ch_width;
	cdp_config_param_type val;
	QDF_STATUS status;
	int ret;

	if (wlan_hdd_change_hw_mode_for_given_chnl(adapter, params->freq,
						   POLICY_MGR_UPDATE_REASON_SET_OPER_CHAN)) {
		hdd_err("Failed to change HW mode");
		return QDF_STATUS_E_FAILURE;
	}

	ch_width =
	     __wlan_hdd_convert_wt_bandwidth_to_phy_ch_width(params->bandwidth);
	if (ch_width == CH_WIDTH_INVALID)
		return QDF_STATUS_E_INVAL;

	ret = hdd_validate_channel_and_bandwidth(adapter, params->freq,
						 0, ch_width);
	if (ret) {
		hdd_err("Invalid freq:%d and bw:%d combo", params->freq,
			ch_width);
		return QDF_STATUS_E_INVAL;
	}

	req.vdev_id = adapter->deflink->vdev_id;
	req.target_chan_freq = params->freq;
	req.ch_width = ch_width;

	ch_params.ch_width = req.ch_width;
	wlan_reg_set_channel_params_for_pwrmode(hdd_ctx->pdev,
						req.target_chan_freq, 0,
						&ch_params,
						REG_CURRENT_PWR_MODE);

	req.sec_ch_offset = ch_params.sec_ch_offset;
	req.center_freq_seg0 = ch_params.center_freq_seg0;
	req.center_freq_seg1 = ch_params.center_freq_seg1;

	sme_fill_channel_change_request(hdd_ctx->mac_handle, &req,
					eCSR_DOT11_MODE_11be);

	hdd_debug("dot11mode:%d nw_type:%d", req.dot11mode, req.nw_type);

	status = qdf_event_reset(&g_wt_ctx->wondertap_vdev_event);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("wondertap vdev up event reset failed:%d", status);
		goto channel_change_req_failed;
	}

	if (ucfg_scan_get_pdev_status(hdd_ctx->pdev) !=
	    SCAN_NOT_IN_PROGRESS)
		wlan_abort_scan(hdd_ctx->pdev,
				wlan_objmgr_pdev_get_pdev_id(hdd_ctx->pdev),
				INVAL_VDEV_ID, INVAL_SCAN_ID, true);

	status = sme_send_channel_change_req(hdd_ctx->mac_handle, &req);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("channel change request failed");
		goto channel_change_req_failed;
	}

	status = qdf_wait_for_event_completion(&g_wt_ctx->wondertap_vdev_event,
					       WLAN_WONDERTAP_VDEV_OP_TIMEOUT_MS);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("wondertap vdev up failed:%d", status);
	} else {
		val.cdp_passthru_vdev_freq = params->freq;
		cdp_txrx_set_vdev_param(cds_get_context(QDF_MODULE_ID_SOC),
					adapter->deflink->vdev_id,
					CDP_VDEV_SET_PASSTHRU_FREQ, val);
	}

channel_change_req_failed:

	return status;
}

static WMI_RATE_PREAMBLE
wlan_hdd_convert_wonder_preamble_to_wmi(qdf_wondertap_rate_preamble_t preamble)
{
	switch (preamble) {
	case WONDERTAP_RATE_PREAMBLE_HT:
		return WMI_RATE_PREAMBLE_HT;
	case WONDERTAP_RATE_PREAMBLE_VHT:
		return WMI_RATE_PREAMBLE_VHT;
	case WONDERTAP_RATE_PREAMBLE_HE:
		return WMI_RATE_PREAMBLE_HE;
	case WONDERTAP_RATE_PREAMBLE_EHT:
		return WMI_RATE_PREAMBLE_EHT;
	case WONDERTAP_RATE_PREAMBLE_LEGACY:
	default:
		return WMI_RATE_PREAMBLE_CCK;
	}
}

static int
__wlan_hdd_wondertap_set_fixed_tx_rate(struct hdd_adapter *adapter,
				       const qdf_wondertap_tx_rate_params_t *params)
{
	WMI_RATE_PREAMBLE preamble;
	uint32_t rate_code;
	uint8_t gi;
	int ret;

	preamble = wlan_hdd_convert_wonder_preamble_to_wmi(params->preamble);
	rate_code = hdd_assemble_rate_code(preamble, params->nss - 1,
					   params->mcs);

	ret = wma_cli_set_command(adapter->deflink->vdev_id,
				  wmi_vdev_param_fixed_rate,
				  rate_code, VDEV_CMD);
	if (ret)
		hdd_err("Set fixed tx rate for wondertap failed:%d", ret);

	switch (params->gi) {
	case WONDERTAP_RATE_GI_SHORT:
		gi = 1;
		break;
	case WONDERTAP_RATE_GI_1_6_US:
		gi = 2;
		break;
	case WONDERTAP_RATE_GI_3_2_US:
		gi = 3;
		break;
	case WONDERTAP_RATE_GI_DEFAULT:
	case WONDERTAP_RATE_GI_0_8_US:
	default:
		gi = 0;
		break;
	}

	ret = wma_cli_set_command(adapter->deflink->vdev_id,
				  wmi_vdev_param_sgi,
				  gi, VDEV_CMD);
	if (ret)
		hdd_err("Set GI for wondertap failed:%d", ret);

	ret = wma_cli_set_command(adapter->deflink->vdev_id,
				  wmi_vdev_param_chwidth,
				  params->bw, VDEV_CMD);
	if (ret)
		hdd_err("Set rate bw for wondertap failed:%d", ret);

	return ret;
}

static
void __wlan_hdd_destroy_wondertap_intf(struct hdd_context *hdd_ctx,
				       struct hdd_adapter *adapter)
{
	hdd_close_adapter(hdd_ctx, adapter, true);
}

static struct hdd_adapter *
__wlan_hdd_create_wondertap_intf(struct hdd_context *hdd_ctx,
				 void **handle,
				 const qdf_wondertap_init_params_t *params)
{
	struct hdd_adapter_create_param create_params = {0};
	struct hdd_adapter *adapter;
	uint8_t mac_addr[QDF_MAC_ADDR_SIZE];

	create_params.num_sessions = 1;

	qdf_mem_copy(mac_addr, params->mac_addr, QDF_MAC_ADDR_SIZE);

	adapter = hdd_open_adapter(hdd_ctx, QDF_PASSTHRU_MODE, "wondertap%d",
				   mac_addr, NET_NAME_UNKNOWN, true,
				   &create_params);

	return adapter;
}

static
int __wlan_hdd_stop_wondertap_intf(struct hdd_context *hdd_ctx,
				   struct hdd_adapter *adapter)
{
	QDF_STATUS status;

	wlan_hdd_netif_queue_control(adapter,
				     WLAN_STOP_ALL_NETIF_QUEUE_N_CARRIER,
				     WLAN_CONTROL_PATH);

	ASSERT_RTNL();

	dev_close(adapter->dev);

	status = qdf_event_reset(&g_wt_ctx->wondertap_vdev_event);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("wondertap vdev up event reset failed:%d", status);
		goto done;
	}

	sme_delete_pe_session(hdd_ctx->mac_handle, adapter->deflink->vdev_id,
			      QDF_PASSTHRU_MODE);

	status = qdf_wait_for_event_completion(&g_wt_ctx->wondertap_vdev_event,
					       WLAN_WONDERTAP_VDEV_OP_TIMEOUT_MS);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("wondertap vdev teardown failed:%d", status);
		goto done;
	}

	policy_mgr_decr_session_set_pcl(hdd_ctx->psoc, QDF_PASSTHRU_MODE,
					adapter->deflink->vdev_id);

	hdd_stop_adapter(hdd_ctx, adapter);
	hdd_deinit_adapter(hdd_ctx, adapter, true);
	clear_bit(DEVICE_IFACE_OPENED, &adapter->event_flags);

	ucfg_fwol_configure_global_params(hdd_ctx->psoc, hdd_ctx->pdev);

	wma_enable_disable_imps(hdd_ctx->pdev->pdev_objmgr.wlan_pdev_id, 1);

	if (!hdd_is_any_interface_open(hdd_ctx))
		hdd_psoc_idle_timer_start(hdd_ctx);

done:
	return qdf_status_to_os_return(status);
}

static
int __wlan_hdd_start_wondertap_intf(struct hdd_context *hdd_ctx,
				    struct hdd_adapter *adapter,
				    const qdf_wondertap_init_params_t *params)
{
	struct wlan_objmgr_vdev *vdev = NULL;
	struct ol_txrx_desc_type txrx_desc = {0};
	struct hdd_adapter *sta_adapter;
	struct wlan_hdd_link_info *sta_link_info;
	enum phy_ch_width ch_width;
	QDF_STATUS status;
	int ret;

	ret = hdd_start_adapter(adapter, true);
	if (ret) {
		hdd_err("Failed to start wondertap adapter %d", ret);
		return ret;
	}
	set_bit(DEVICE_IFACE_OPENED, &adapter->event_flags);

	if (!policy_mgr_allow_concurrency(hdd_ctx->psoc,
					  PM_PASSTHRU_MODE,
					  params->channel.freq,
					  wlan_hdd_wondertap_bw_to_hw_mode_bw(params->channel.bandwidth),
					  0, adapter->deflink->vdev_id)) {
		ret = -EPERM;
		goto stop_adapter;
	}

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_DP_ID);
	if (!vdev) {
		ret = -EINVAL;
		goto stop_adapter;
	}

	status = wlan_vdev_mgr_set_param_bssid(vdev, &params->bssid[0]);
	if (QDF_IS_STATUS_ERROR(status)) {
		ret = qdf_status_to_os_return(status);
		goto stop_adapter;
	}

	status = sme_create_pe_session(hdd_ctx->mac_handle,
				       adapter->mac_addr.bytes,
				       adapter->deflink->vdev_id,
				       QDF_PASSTHRU_MODE);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("pe session create failed:%d", status);
		ret = qdf_status_to_os_return(status);
		goto stop_adapter;
	}

	/* Disable Roaming on all adapters before doing channel change */
	wlan_hdd_set_roaming_state(adapter->deflink, RSO_PASSTHRU_SET_CHANNEL,
				   false);

	status = __wlan_hdd_set_wondertap_channel(hdd_ctx, adapter,
						  &params->channel);
	if (QDF_IS_STATUS_ERROR(status)) {
		ret = qdf_status_to_os_return(status);
		goto delete_pe_session;
	}

	ret = __wlan_hdd_wondertap_set_fixed_tx_rate(adapter, &params->tx_rate);
	if (ret)
		goto delete_pe_session;

	sme_set_vdev_sw_retry(adapter->deflink->vdev_id,
			      params->data_retry_limit,
			      WMI_VDEV_CUSTOM_SW_RETRY_TYPE_AGGR);

	sme_set_vdev_sw_retry(adapter->deflink->vdev_id,
			      params->mgmt_retry_limit,
			      WMI_VDEV_CUSTOM_SW_RETRY_TYPE_NONAGGR);

	policy_mgr_incr_active_session(hdd_ctx->psoc, QDF_PASSTHRU_MODE,
				       adapter->deflink->vdev_id,
				       true);

	status = ucfg_dp_passthrough_register_txrx_ops(vdev);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("wondertap tx/rx ops register failed:%d", status);
		ret = qdf_status_to_os_return(status);
		goto delete_pe_session;
	}

	qdf_mem_copy(txrx_desc.peer_addr.bytes, adapter->mac_addr.bytes,
		     QDF_MAC_ADDR_SIZE);
	txrx_desc.is_qos_enabled = 1;
	ch_width =
		__wlan_hdd_convert_wt_bandwidth_to_phy_ch_width(params->channel.bandwidth);
	txrx_desc.bw = hdd_convert_ch_width_to_cdp_peer_bw(ch_width);

	status = cdp_peer_register(hdd_ctx->psoc->dp_handle, OL_TXRX_PDEV_ID,
				   &txrx_desc);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("peer registration failed for wondertap:%d", status);
		ret = qdf_status_to_os_return(status);
		goto delete_pe_session;
	}

	ucfg_fwol_set_ilp_config(hdd_ctx->psoc, hdd_ctx->pdev, 0);

	if (wma_enable_disable_imps(hdd_ctx->pdev->pdev_objmgr.wlan_pdev_id, 0))
		hdd_err("IMPS feature disable failed");

	sta_adapter = hdd_get_adapter(hdd_ctx, QDF_STA_MODE);
	if (sta_adapter) {
		hdd_adapter_for_each_active_link_info(sta_adapter,
						      sta_link_info)
			wlan_hdd_set_powersave(sta_link_info, false, 0);
	}

	hdd_change_peer_state(adapter->deflink, adapter->mac_addr.bytes,
			      OL_TXRX_PEER_STATE_AUTH);

	/*
	 * Stop and restart of bus bw periodic work would happen
	 * as part of close adapter so no need to explicitly invoke
	 * ucfg_dp_bus_bw_compute_timer_try_stop API in cleanup.
	 */
	ucfg_dp_bus_bw_compute_timer_start(hdd_ctx->psoc);

	hdd_debug("Enabling queues");
	wlan_hdd_netif_queue_control(adapter,
				     WLAN_START_ALL_NETIF_QUEUE_N_CARRIER,
				     WLAN_CONTROL_PATH);

	dev_open(adapter->dev, NULL);

	hdd_objmgr_put_vdev_by_user(vdev, WLAN_DP_ID);

	return 0;

delete_pe_session:
	wlan_hdd_set_roaming_state(adapter->deflink, RSO_PASSTHRU_SET_CHANNEL,
				   true);

	sme_delete_pe_session(hdd_ctx->mac_handle,
			      adapter->deflink->vdev_id,
			      QDF_PASSTHRU_MODE);

stop_adapter:
	if (vdev)
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_DP_ID);
	hdd_stop_no_trans(adapter->dev);

	return ret;
}

/**
 * wlan_hdd_wondertap_init() - Initialize wondertap interface
 * @handle: Pointer to store the wondertap handle
 * @params: Initialization parameters for wondertap interface
 *
 * This function initializes the wondertap interface with the provided
 * parameters. It allocates necessary resources and prepares the interface
 * for operation.
 *
 * Return: 0 on success, negative error code on failure
 */
static
int wlan_hdd_wondertap_init(void **handle,
			    const qdf_wondertap_init_params_t *params)
{
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	struct osif_vdev_sync *vdev_sync;
	struct hdd_adapter *adapter;
	struct hdd_wondertap_context *wt_ctx;
	uint8_t curr_cc[REG_ALPHA2_LEN + 1] = {0};
	QDF_STATUS status;
	int errno;

	hdd_enter();

	if (!hdd_ctx || !params || !handle)
		return -EINVAL;

	hdd_info("Self MAC:" QDF_MAC_ADDR_FMT " BSSID:" QDF_MAC_ADDR_FMT " freq:%d bandwidth:%d",
		 QDF_MAC_ADDR_REF(params->mac_addr),
		 QDF_MAC_ADDR_REF(params->bssid), params->channel.freq,
		 params->channel.bandwidth);

	hdd_info("Fixed Tx rate preamble:%d bw:%d gi:%d nss:%d mcs:%d",
		 params->tx_rate.preamble, params->tx_rate.bw,
		 params->tx_rate.gi, params->tx_rate.nss,
		 params->tx_rate.mcs);

	if (params->channel.bandwidth > WONDERTAP_RATE_BW_320 ||
	    params->tx_rate.bw > WONDERTAP_RATE_BW_320 ||
	    params->tx_rate.preamble > WONDERTAP_RATE_PREAMBLE_EHT ||
	    params->tx_rate.gi > WONDERTAP_RATE_GI_3_2_US ||
	    !params->tx_rate.nss)
		return -EINVAL;

	ASSERT_RTNL();

	errno = osif_vdev_sync_create_and_trans(hdd_ctx->parent_dev,
						&vdev_sync);
	if (errno)
		return errno;

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		goto destroy_sync;

	if (hdd_get_conparam() != QDF_GLOBAL_MISSION_MODE) {
		hdd_err("Command not allowed in mode:%d", hdd_get_conparam());
		goto destroy_sync;
	}

	if (hdd_is_connection_in_progress(NULL, NULL)) {
		errno = -EBUSY;
		goto destroy_sync;
	}

	errno = hdd_trigger_psoc_idle_restart(hdd_ctx);
	if (errno) {
		hdd_err("Idle restart failed %d", errno);
		goto destroy_sync;
	}

	ucfg_reg_get_current_country(hdd_ctx->psoc, curr_cc);

	hdd_info("set regulatory cc:%s curr_cc:%s", params->country_code,
		 curr_cc);

	errno = hdd_reg_set_country(hdd_ctx, (char *)params->country_code);
	if (errno) {
		hdd_info("set country code failed:%d", errno);
		goto destroy_sync;
	}

	wt_ctx = qdf_mem_malloc(sizeof(*wt_ctx));
	if (!wt_ctx) {
		hdd_err("wondertap memory alloc failed");
		errno = -ENOMEM;
		goto mem_malloc_failed;
	}

	status = qdf_event_create(&wt_ctx->wondertap_vdev_event);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("wondertap vdev up event creation failed");
		errno = qdf_status_to_os_return(status);
		goto create_wondertap_event_failed;
	}

	mutex_lock(&g_wt_ctx_mutex);
	g_wt_ctx = wt_ctx;
	mutex_unlock(&g_wt_ctx_mutex);

	status = qdf_runtime_lock_init(&wt_ctx->wondertap_rtpm_lock);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("passthrough mode rtpm lock creation failed");
		errno = qdf_status_to_os_return(status);
		goto create_rtpm_lock_failed;
	}

	status = qdf_wake_lock_create(&wt_ctx->wondertap_wakelock,
				      "wlan_passthrough");
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("passthrough mode wakelock creation failed");
		errno = qdf_status_to_os_return(status);
		goto create_wake_lock_failed;
	}

	qdf_wake_lock_acquire(&wt_ctx->wondertap_wakelock,
			      WIFI_POWER_EVENT_WAKELOCK_PASSTHRU);
	qdf_runtime_pm_prevent_suspend_sync(&wt_ctx->wondertap_rtpm_lock);

	adapter = __wlan_hdd_create_wondertap_intf(hdd_ctx, handle, params);
	if (IS_ERR_OR_NULL(adapter)) {
		errno = qdf_status_to_os_return(QDF_STATUS_E_FAILURE);
		goto create_wondertap_intf_failed;
	}

	osif_vdev_sync_register(adapter->dev, vdev_sync);

	errno = __wlan_hdd_start_wondertap_intf(hdd_ctx, adapter, params);
	if (errno)
		goto start_wondertap_intf_failed;

	wt_ctx->hdd_ctx = hdd_ctx;
	wt_ctx->wt_adapter = adapter;
	wt_ctx->magic = get_random_u32();

	*handle = (void *)wt_ctx->magic;

	osif_vdev_sync_trans_stop(vdev_sync);

	return errno;

start_wondertap_intf_failed:
	osif_vdev_sync_unregister(adapter->dev);
	__wlan_hdd_destroy_wondertap_intf(hdd_ctx, adapter);

create_wondertap_intf_failed:
	qdf_runtime_pm_allow_suspend(&wt_ctx->wondertap_rtpm_lock);
	qdf_wake_lock_release(&wt_ctx->wondertap_wakelock,
			      WIFI_POWER_EVENT_WAKELOCK_PASSTHRU);
	qdf_wake_lock_destroy(&wt_ctx->wondertap_wakelock);

create_wake_lock_failed:
	qdf_runtime_lock_deinit(&wt_ctx->wondertap_rtpm_lock);

create_rtpm_lock_failed:
	mutex_lock(&g_wt_ctx_mutex);
	qdf_event_destroy(&wt_ctx->wondertap_vdev_event);
	g_wt_ctx = NULL;
	mutex_unlock(&g_wt_ctx_mutex);

create_wondertap_event_failed:
	qdf_mem_free(wt_ctx);

mem_malloc_failed:
	hdd_reg_set_country(hdd_ctx, curr_cc);

destroy_sync:
	osif_vdev_sync_trans_stop(vdev_sync);
	osif_vdev_sync_destroy(vdev_sync);

	return errno;
}

/**
 * wlan_hdd_wondertap_deinit() - Deinitialize wondertap interface
 * @handle: Wondertap handle to deinitialize
 * @params: deinit parameters
 *
 * This function deinitializes the wondertap interface and releases all
 * resources allocated during initialization.
 *
 * Return: None
 */
static
void wlan_hdd_wondertap_deinit(void *handle,
			       const qdf_wondertap_deinit_params_t *params)
{
	struct hdd_context *hdd_ctx;
	struct hdd_adapter *wt_adapter;
	struct hdd_adapter *sta_adapter;
	struct wlan_hdd_link_info *sta_link_info;
	struct pkt_filter_cfg filter_req = {0};
	struct osif_vdev_sync *vdev_sync;
	int errno;

	hdd_enter();
	if (!g_wt_ctx || handle != (void *)g_wt_ctx->magic) {
		hdd_debug("Incorrect handle received - rejecting deinit");
		return;
	}

	ASSERT_RTNL();

	hdd_ctx = g_wt_ctx->hdd_ctx;
	wt_adapter = g_wt_ctx->wt_adapter;

	errno = osif_vdev_sync_trans_start_wait(wt_adapter->dev, &vdev_sync);
	if (errno)
		return;

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		goto destroy_sync;

	if (g_wt_ctx->is_frame_filter_set) {
		filter_req.filter_action = HDD_RCV_FILTER_CLEAR;
		errno = wlan_hdd_set_filter(hdd_ctx, &filter_req,
					    wt_adapter->deflink->vdev_id);
		if (errno)
			hdd_debug("Clear frame type/subtype based filter failed:%d",
				  errno);
	}

	wlan_hdd_set_roaming_state(wt_adapter->deflink, RSO_PASSTHRU_SET_CHANNEL,
				   true);

	errno = __wlan_hdd_stop_wondertap_intf(hdd_ctx, wt_adapter);
	if (errno)
		goto destroy_sync;

	osif_vdev_sync_unregister(wt_adapter->dev);
	osif_vdev_sync_wait_for_ops(vdev_sync);

	__wlan_hdd_destroy_wondertap_intf(hdd_ctx, wt_adapter);

	errno = hdd_reg_set_country(hdd_ctx, (char *)params->country_code);
	if (errno)
		hdd_info("set country code failed:%d", errno);

	sta_adapter = hdd_get_adapter(hdd_ctx, QDF_STA_MODE);
	if (sta_adapter) {
		hdd_adapter_for_each_active_link_info(sta_adapter,
						      sta_link_info)
			wlan_hdd_set_powersave(sta_link_info, true, 0);
	}

	qdf_runtime_pm_allow_suspend(&g_wt_ctx->wondertap_rtpm_lock);
	qdf_wake_lock_release(&g_wt_ctx->wondertap_wakelock,
			      WIFI_POWER_EVENT_WAKELOCK_PASSTHRU);
	qdf_wake_lock_destroy(&g_wt_ctx->wondertap_wakelock);
	qdf_runtime_lock_deinit(&g_wt_ctx->wondertap_rtpm_lock);

	mutex_lock(&g_wt_ctx_mutex);
	qdf_event_destroy(&g_wt_ctx->wondertap_vdev_event);
	qdf_mem_free(g_wt_ctx);
	g_wt_ctx = NULL;
	mutex_unlock(&g_wt_ctx_mutex);

destroy_sync:
	osif_vdev_sync_trans_stop(vdev_sync);
	osif_vdev_sync_destroy(vdev_sync);
	hdd_exit();

	return;
}

/**
 * wlan_hdd_wondertap_set_freq() - Set operating frequency
 * @handle: Wondertap handle
 * @params: Channel parameters including frequency and bandwidth
 *
 * This function configures the operating frequency and bandwidth
 * for the wondertap interface based on the provided parameters.
 *
 * Return: 0 on success, negative error code on failure
 */
static
int wlan_hdd_wondertap_set_freq(void *handle,
				const qdf_wondertap_set_freq_params_t *params)
{
	struct hdd_context *hdd_ctx;
	struct hdd_adapter *wt_adapter;
	struct osif_vdev_sync *vdev_sync;
	QDF_STATUS status;
	int errno;

	hdd_info("set_freq:%d bandwidth:%d",
		 params->freq, params->bandwidth);

	if (!g_wt_ctx || handle != (void *)g_wt_ctx->magic) {
		hdd_debug("Incorrect handle received - rejecting set_freq");
		return -EINVAL;
	}

	hdd_ctx = g_wt_ctx->hdd_ctx;
	wt_adapter = g_wt_ctx->wt_adapter;

	errno = osif_vdev_sync_trans_start(wt_adapter->dev, &vdev_sync);
	if (errno)
		return errno;

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		goto stop_trans;

	if (!policy_mgr_is_chan_change_allowed_for_passthru(hdd_ctx->psoc,
							    wt_adapter->deflink->vdev_id,
							    params->freq,
							    wlan_hdd_wondertap_bw_to_hw_mode_bw(params->bandwidth))) {
		hdd_debug("Channel change not allowed freq:%d bw:%d",
			  params->freq, params->bandwidth);
		errno = -EINVAL;
		goto stop_trans;
	}

	status = __wlan_hdd_set_wondertap_channel(hdd_ctx, wt_adapter, params);
	errno = qdf_status_to_os_return(status);

stop_trans:
	osif_vdev_sync_trans_stop(vdev_sync);

	return errno;
}

/**
 * wlan_hdd_wondertap_set_filter() - Configure a specific hardware packet
 *  filter
 * @handle: Wondertap handle
 * @filter_type: type of filter to configure
 * @params: void pointer to filter-specific parameter structure.
 *
 * This function configures a specific hardware packet
 * for the wondertap interface based on the provided parameters.
 *
 * Return: 0 on success, negative error code on failure
 */
static
int wlan_hdd_wondertap_set_filter(void *handle,
				  qdf_wondertap_filter_type_t filter_type,
				  const void *params)
{
	struct hdd_context *hdd_ctx;
	struct hdd_adapter *wt_adapter;
	struct osif_vdev_sync *vdev_sync;
	struct pkt_filter_cfg filter_req = {0};
	qdf_wondertap_frame_filter_params_t *filter_params;
	QDF_STATUS status;
	int errno;

	if (!g_wt_ctx || handle != (void *)g_wt_ctx->magic) {
		hdd_debug("Incorrect handle received - rejecting set_filter");
		return -EINVAL;
	}

	if (filter_type != QDF_WONDERTAP_FILTER_TYPE_FRAME) {
		hdd_debug("Invalid filter type:%d", filter_type);
		return -EINVAL;
	}

	/* validate the input params */
	filter_params = (qdf_wondertap_frame_filter_params_t *)params;
	if (!filter_params->enabled && !g_wt_ctx->is_frame_filter_set) {
		hdd_debug("No active filter to disable");
		return -EINVAL;
	}

	hdd_ctx = g_wt_ctx->hdd_ctx;
	wt_adapter = g_wt_ctx->wt_adapter;

	errno = osif_vdev_sync_op_start(wt_adapter->dev, &vdev_sync);
	if (errno)
		return errno;

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		goto stop_op;

	/* Support only one filter for now so override with latest one*/
	if (g_wt_ctx->is_frame_filter_set) {
		filter_req.filter_action = HDD_RCV_FILTER_CLEAR;
		status = wlan_hdd_set_filter(hdd_ctx, &filter_req,
					     wt_adapter->deflink->vdev_id);
		hdd_debug("clear frame type/subtype based filter status:%d",
			  status);
		if (!filter_params->enabled || status) {
			errno = qdf_status_to_os_return(status);
			goto stop_op;
		}
	}

	filter_req.filter_action = HDD_RCV_FILTER_SET;
	filter_req.num_params = 1;
	filter_req.params_data[0].protocol_layer = HDD_FILTER_PROTO_TYPE_MAC;
	filter_req.params_data[0].compare_flag = HDD_FILTER_CMP_TYPE_EQUAL;
	filter_req.params_data[0].data_length = 1;
	filter_req.params_data[0].data_offset = 0;
	filter_req.params_data[0].compare_data[0] =
		(filter_params->frame_type | filter_params->frame_subtype);
	filter_req.params_data[0].data_mask[0] = 0xFC;

	status = wlan_hdd_set_filter(hdd_ctx, &filter_req,
				    wt_adapter->deflink->vdev_id);
	if (status) {
		hdd_debug("Set frame type/subtype based filter failed:%d",
			  status);
		errno = qdf_status_to_os_return(status);
		goto stop_op;
	}

	g_wt_ctx->is_frame_filter_set = true;
	g_wt_ctx->frame_filter = filter_req.params_data[0].compare_data[0];

stop_op:
	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

/**
 * wlan_hdd_wondertap_set_fixed_tx_rate() - Set fixed TX rate
 * @handle: Wondertap handle
 * @params: TX rate parameters including MCS, NSS, and preamble type
 *
 * This function configures a fixed transmission rate for the wondertap
 * interface. When set, all packets will be transmitted at the specified
 * rate instead of using rate adaptation.
 *
 * Return: 0 on success, negative error code on failure
 */
static int
wlan_hdd_wondertap_set_fixed_tx_rate(void *handle,
				const qdf_wondertap_tx_rate_params_t *params)
{
	struct hdd_context *hdd_ctx;
	struct hdd_adapter *wt_adapter;
	struct osif_vdev_sync *vdev_sync;
	int errno;

	hdd_info("fixed Tx rate preamble:%d bw:%d gi:%d nss:%d mcs:%d",
		 params->preamble, params->bw, params->gi,
		 params->nss, params->mcs);

	if (!g_wt_ctx || handle != (void *)g_wt_ctx->magic) {
		hdd_debug("Incorrect handle received - rejecting set_fixed_tx_rate");
		return -EINVAL;
	}

	if (params->bw > WONDERTAP_RATE_BW_320 ||
	    params->preamble > WONDERTAP_RATE_PREAMBLE_EHT ||
	    params->gi > WONDERTAP_RATE_GI_3_2_US ||
	    !params->nss)
		return -EINVAL;

	hdd_ctx = g_wt_ctx->hdd_ctx;
	wt_adapter = g_wt_ctx->wt_adapter;

	errno = osif_vdev_sync_trans_start(wt_adapter->dev, &vdev_sync);
	if (errno) {
		/* Cache the command?? */
		return errno;
	}

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		goto stop_trans;

	errno = __wlan_hdd_wondertap_set_fixed_tx_rate(wt_adapter, params);

stop_trans:
	osif_vdev_sync_trans_stop(vdev_sync);

	return errno;
}

/**
 * wlan_hdd_wondertap_set_tx_rate_mask() - Set TX rate mask
 * @handle: Wondertap handle
 * @params: TX rate mask parameters specifying allowed rates
 *
 * This function configures a mask of allowed transmission rates for the
 * wondertap interface. The rate adaptation algorithm will only select
 * rates that are enabled in the mask.
 *
 * Return: 0 on success, negative error code on failure
 */
static int
wlan_hdd_wondertap_set_tx_rate_mask(void *handle,
			const qdf_wondertap_tx_rate_mask_params_t *params)
{
	return -EPERM;
}

/**
 * wlan_hdd_wondertap_get_capabilities() - Populate supported capabilities
 * @handle: Wondertap handle
 * @features: Pointer to structure to store supported features
 *
 * This function populates the list of features that the
 * driver supports for the wondertap operation.
 *
 * Return: 0 on success, negative error code on failure
 */
static int
wlan_hdd_wondertap_get_capabilities(void *handle,
				    qdf_wondertap_capability_t *features)
{
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	int ret;

	if (!hdd_ctx)
		return -EBUSY;

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		return ret;

	qdf_mem_zero(features, sizeof(*features));

	features->bits.dynamic_freq = 1;
	features->bits.dynamic_fixed_tx_rate = 1;
	features->bits.frame_type_filter = 1;
	features->bits.custom_mgmt_retry_limit = 1;
	features->bits.custom_data_retry_limit = 1;
	features->bits.frame_type_filter = 1;
	if (policy_mgr_is_hw_dbs_capable(hdd_ctx->psoc))
		features->bits.sta_coexist = 1;

	return ret;
}

void hdd_sme_passthrough_mode_callback(uint8_t vdev_id, bool is_up)
{
	hdd_debug("Channel change successful for wondertap");

	mutex_lock(&g_wt_ctx_mutex);
	if (g_wt_ctx)
		qdf_event_set(&g_wt_ctx->wondertap_vdev_event);

	mutex_unlock(&g_wt_ctx_mutex);
}

/**
 * wlan_drv_wondertap_ops - Wondertap operations structure
 *
 * This structure defines the set of operations that the WLAN driver
 * provides to the wondertap framework. It includes callbacks for
 * initialization, configuration, and feature queries.
 */
static const qdf_wondertap_ops_t wlan_drv_wondertap_ops = {
	.init = wlan_hdd_wondertap_init,
	.deinit = wlan_hdd_wondertap_deinit,
	.set_freq = wlan_hdd_wondertap_set_freq,
	.set_filter = wlan_hdd_wondertap_set_filter,
	.set_fixed_tx_rate = wlan_hdd_wondertap_set_fixed_tx_rate,
	.set_tx_rate_mask = wlan_hdd_wondertap_set_tx_rate_mask,
	.get_capabilities = wlan_hdd_wondertap_get_capabilities,
};

/**
 * wlan_drv_wondertap_priv - Wondertap private data structure
 *
 * wondertap private data structure that holds the wonder
 * version supported and the operations table.
 */
static const qdf_wondertap_priv_t wlan_drv_wondertap_priv = {
	.ver = WONDER_VERSION_1_4_1,
	.wonder_ops = &wlan_drv_wondertap_ops,
};

int wlan_hdd_wondertap_register_ops(struct device *dev)
{
	return pld_set_vendor_wonder_priv_data(dev, &wlan_drv_wondertap_priv);
}

void wlan_hdd_wondertap_unregister_ops(struct device *dev, bool force_cleanup)
{
	struct hdd_context *hdd_ctx;
	struct hdd_adapter *adapter;
	struct osif_vdev_sync *vdev_sync;
	QDF_STATUS status;

	hdd_enter();
	pld_set_vendor_wonder_priv_data(dev, NULL);
	hdd_debug("g_wt_ctx_valid %d force %d",
		  g_wt_ctx ? 1 : 0, force_cleanup);

	hdd_hold_rtnl_lock();

	if (force_cleanup && g_wt_ctx) {
		hdd_ctx = g_wt_ctx->hdd_ctx;
		adapter = g_wt_ctx->wt_adapter;

		wlan_hdd_netif_queue_control(adapter,
				     WLAN_STOP_ALL_NETIF_QUEUE_N_CARRIER,
				     WLAN_CONTROL_PATH);

		dev_close(adapter->dev);

		qdf_event_reset(&g_wt_ctx->wondertap_vdev_event);
		sme_delete_pe_session(hdd_ctx->mac_handle, adapter->deflink->vdev_id,
				      QDF_PASSTHRU_MODE);

		status = qdf_wait_for_event_completion(&g_wt_ctx->wondertap_vdev_event,
						       WLAN_WONDERTAP_VDEV_OP_TIMEOUT_MS);
		if (QDF_IS_STATUS_ERROR(status))
			hdd_err("wondertap vdev teardown failed:%d", status);

		policy_mgr_decr_session_set_pcl(hdd_ctx->psoc, QDF_PASSTHRU_MODE,
						adapter->deflink->vdev_id);

		hdd_stop_adapter(hdd_ctx, adapter);
		hdd_deinit_adapter(hdd_ctx, adapter, true);

		vdev_sync = osif_vdev_sync_unregister(adapter->dev);
		osif_vdev_sync_destroy(vdev_sync);

		__wlan_hdd_destroy_wondertap_intf(hdd_ctx, adapter);

		qdf_runtime_pm_allow_suspend(&g_wt_ctx->wondertap_rtpm_lock);
		qdf_wake_lock_release(&g_wt_ctx->wondertap_wakelock,
				      WIFI_POWER_EVENT_WAKELOCK_PASSTHRU);
		qdf_wake_lock_destroy(&g_wt_ctx->wondertap_wakelock);
		qdf_runtime_lock_deinit(&g_wt_ctx->wondertap_rtpm_lock);

		mutex_lock(&g_wt_ctx_mutex);
		qdf_event_destroy(&g_wt_ctx->wondertap_vdev_event);
		qdf_mem_free(g_wt_ctx);
		g_wt_ctx = NULL;
		mutex_unlock(&g_wt_ctx_mutex);
	}

	hdd_release_rtnl_lock();
	hdd_exit();
}
