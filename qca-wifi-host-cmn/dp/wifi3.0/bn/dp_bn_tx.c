/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include "cdp_txrx_cmn_struct.h"
#include "dp_types.h"
#include "dp_tx.h"
#include "dp_be_tx.h"
#include "dp_bn_tx.h"
#include "dp_tx_desc.h"
#include "hal_tx.h"
#include <hal_be_api.h>
#include <hal_be_tx.h>
#include <hal_bn_tx.h>
#include <dp_htt.h>
#include "dp_internal.h"
#include "wlan_ipa_obj_mgmt_api.h"

__used struct tqm2sw_completion_ring tqm2sw_tx_comp_symbol;
__used struct tcl_assist_cmd tcl_assist_cmd_symbol;

/**
 * dp_tx_get_rbm_id_bn() - Get the RBM ID for data transmission completion.
 * @soc: DP soc structure pointer
 * @ring_id: Transmit Queue/ring_id to be used when XPS is enabled
 *
 * Return: RBM ID corresponding to TCL ring_id
 */
static inline uint8_t dp_tx_get_rbm_id_bn(struct dp_soc *soc,
					  uint8_t ring_id)
{
	uint8_t rbm;

	rbm = wlan_cfg_get_rbm_id_for_index(soc->wlan_cfg_ctx, ring_id);
	dp_verbose_debug("tcl_id %u rbm %u", ring_id, rbm);
	return rbm;
}

static inline void
dp_tx_vdev_id_set_hal_tx_desc(uint32_t *hal_tx_desc_cached,
			      struct dp_vdev *vdev,
			      struct dp_tx_msdu_info_s *msdu_info)
{
	hal_tx_desc_set_vdev_id(hal_tx_desc_cached, vdev->vdev_id);
}

#ifdef QCA_SUPPORT_TX_MIN_RATES_FOR_SPECIAL_FRAMES

/**
 * dp_tx_set_min_rates_for_critical_frames()- sets min-rates for critical pkts
 * @soc: DP soc structure pointer
 * @hal_tx_desc: HAL descriptor where fields are set
 * @nbuf: skb to be considered for min rates
 *
 * The function relies on upper layers to set QDF_NBUF_CB_TX_EXTRA_IS_CRITICAL
 * and uses it to determine if the frame is critical. For a critical frame,
 * flow override bits are set to classify the frame into HW's high priority
 * queue. The HW will pick pre-configured min rates for such packets.
 *
 * Return: None
 */
static void
dp_tx_set_min_rates_for_critical_frames(struct dp_soc *soc,
					uint32_t *hal_tx_desc,
					qdf_nbuf_t nbuf)
{
	/*
	 * Critical frames should be queued to the high priority queue for the
	 * TID on which they are sent out (for the concerned peer).
	 * HOL queue= TXPT_CLASSIFY_INFO_BANK1 and index 0, udp entry of peer.
	 */
	if (QDF_NBUF_CB_TX_EXTRA_IS_CRITICAL(nbuf)) {
		hal_tx_desc_txpt_ci_sel(hal_tx_desc, 0);
		hal_tx_desc_txpt_ci_use_udp_flow_entry(hal_tx_desc, 1);
		hal_tx_desc_set_tx_notify_frame(hal_tx_desc,
						TX_SEMI_HARD_NOTIFY_E);
	}
}
#else
static inline void
dp_tx_set_min_rates_for_critical_frames(struct dp_soc *soc,
					uint32_t *hal_tx_desc_cached,
					qdf_nbuf_t nbuf)
{
}
#endif

#ifdef QCA_WIFI_EMULATION
/**
 * dp_tx_dump_tcl_desc()- Dump TCL descriptor before enqueue
 * @cached_desc: TCL descriptor
 *
 * Debug dump of TCL descriptor.
 *
 * Return: None
 */
static inline void dp_tx_dump_tcl_desc(uint8_t *cached_desc)
{
	struct tcl_assist_cmd *tcl_desc = (struct tcl_assist_cmd *)cached_desc;

	dp_verbose_debug("buffer_addr_info 0-31 0x%x 32-39 0x%x rbm 0x%x "
			 " sw_cookie 0x%x",
			 tcl_desc->buf_addr_info.buffer_addr_31_0,
			 tcl_desc->buf_addr_info.buffer_addr_39_32,
			 tcl_desc->buf_addr_info.return_buffer_manager,
			 tcl_desc->buf_addr_info.sw_buffer_cookie);
	dp_verbose_debug("buf_or_ext_desc_type 0x%x "
			 "bank_id 0x%x "
			 "vdev_id 0x%x "
			 "data_length 0x%x "
			 "to_fw_tqm 0x%x "
			 "reserved_2a 0x%x "
			 "reserved_3a 0x%x "
			 "metadata_length 0x%x "
			 "txpt_classify_info_index 0x%x "
			 "txpt_classify_info_sel 0x%x "
			 "txpt_classify_info_override 0x%x "
			 "flow_override_enable 0x%x "
			 "flow_select 0x%x "
			 "hlos_tid 0x%x "
			 "hlos_tid_overwrite 0x%x "
			 "tos_tc_value 0x%x "
			 "reserved_4a 0x%x "
			 "reserved_5a 0x%x "
			 "l3_type 0x%x "
			 "l4_protocol 0x%x "
			 "l4_port 0x%x "
			 "l4_port_type 0x%x "
			 "da_is_bcast_mcast 0x%x "
			 "da_is_bcast 0x%x "
			 "reserved_6a 0x%x "
			 "ip_address_31_0 0x%x "
			 "ip_address_63_32 0x%x ",
			 tcl_desc->buf_or_ext_desc_type,
			 tcl_desc->bank_id,
			 tcl_desc->vdev_id,
			 tcl_desc->data_length,
			 tcl_desc->to_fw_tqm,
			 tcl_desc->reserved_2a,
			 tcl_desc->reserved_3a,
			 tcl_desc->metadata_length,
			 tcl_desc->txpt_classify_info_index,
			 tcl_desc->txpt_classify_info_sel,
			 tcl_desc->txpt_classify_info_override,
			 tcl_desc->flow_override_enable,
			 tcl_desc->flow_select,
			 tcl_desc->hlos_tid,
			 tcl_desc->hlos_tid_overwrite,
			 tcl_desc->tos_tc_value,
			 tcl_desc->reserved_4a,
			 tcl_desc->reserved_5a,
			 tcl_desc->l3_type,
			 tcl_desc->l4_protocol,
			 tcl_desc->l4_port,
			 tcl_desc->l4_port_type,
			 tcl_desc->da_is_bcast_mcast,
			 tcl_desc->da_is_bcast,
			 tcl_desc->reserved_6a,
			 tcl_desc->ip_address_31_0,
			 tcl_desc->ip_address_63_32);

	dp_verbose_debug("ip_address_95_64 0x%x "
			 "ip_address_127_96 0x%x "
			 "ip_da_or_sa 0x%x "
			 "encap_length_change 0x%x "
			 "encap_length_decrease 0x%x "
			 "encap_length_override 0x%x "
			 "type_or_length 0x%x "
			 "snap_oui_zero_or_f8 0x%x "
			 "snap_oui_not_zero_and_not_f8 0x%x "
			 "msdu_color 0x%x "
			 "tx_notify_frame 0x%x "
			 "tqm_no_drop 0x%x "
			 "reserved_11a 0x%x "
			 "l3_checksum_enable 0x%x "
			 "l4_checksum_enable 0x%x "
			 "buffer_timestamp 0x%x "
			 "buffer_timestamp_valid 0x%x "
			 "s_vlan_tag_present 0x%x "
			 "c_vlan_tag_present 0x%x "
			 "wmac_hdr_len 0x%x "
			 "metadatareserved_12a 0x%x ",
			 tcl_desc->ip_address_95_64,
			 tcl_desc->ip_address_127_96,
			 tcl_desc->ip_da_or_sa,
			 tcl_desc->encap_length_change,
			 tcl_desc->encap_length_decrease,
			 tcl_desc->encap_length_override,
			 tcl_desc->type_or_length,
			 tcl_desc->snap_oui_zero_or_f8,
			 tcl_desc->snap_oui_not_zero_and_not_f8,
			 tcl_desc->msdu_color,
			 tcl_desc->tx_notify_frame,
			 tcl_desc->tqm_no_drop,
			 tcl_desc->reserved_11a,
			 tcl_desc->l3_checksum_enable,
			 tcl_desc->l4_checksum_enable,
			 tcl_desc->buffer_timestamp,
			 tcl_desc->buffer_timestamp_valid,
			 tcl_desc->s_vlan_tag_present,
			 tcl_desc->c_vlan_tag_present,
			 tcl_desc->wmac_hdr_len,
			 tcl_desc->reserved_12a);

	dp_verbose_debug("tcl_cmd_number 0x%x "
			 "reserved_14a 0x%x "
			 "reserved_15a 0x%x "
			 "ring_id 0x%x "
			 "looping_count 0x%x ",
			 tcl_desc->tcl_cmd_number,
			 tcl_desc->reserved_14a,
			 tcl_desc->reserved_15a,
			 tcl_desc->ring_id,
			 tcl_desc->looping_count);
}

#else /* QCA_WIFI_EMULATION */
static inline void dp_tx_dump_tcl_desc(uint8_t *cached_desc)
{
}
#endif /* QCA_WIFI_EMULATION */

QDF_STATUS
dp_tx_hw_enqueue_bn(struct dp_soc *soc, struct dp_vdev *vdev,
		    struct dp_tx_desc_s *tx_desc, uint16_t fw_metadata,
		    struct cdp_tx_exception_metadata *tx_exc_metadata,
		    struct dp_tx_msdu_info_s *msdu_info)
{
	void *hal_tx_desc;
	uint32_t *hal_tx_desc_cached;
	int coalesce = 0;
	struct dp_tx_queue *tx_q = &msdu_info->tx_queue;
	uint8_t ring_id = tx_q->ring_id;
	uint8_t tid;
	struct dp_vdev_be *be_vdev;
	uint8_t cached_desc[HAL_TX_DESC_LEN_BYTES] = { 0 };
	uint8_t bm_id = dp_tx_get_rbm_id_bn(soc, ring_id);
	hal_ring_handle_t hal_ring_hdl = NULL;
	QDF_STATUS status = QDF_STATUS_E_RESOURCES;
	uint8_t num_desc_bytes = HAL_TX_DESC_LEN_BYTES;
	uint32_t hp;
	qdf_nbuf_t nbuf = tx_desc->nbuf;

	be_vdev = dp_get_be_vdev_from_dp_vdev(vdev);

	if (!dp_tx_is_desc_id_valid(soc, tx_desc->id)) {
		dp_err_rl("Invalid tx desc id:%d", tx_desc->id);
		return QDF_STATUS_E_RESOURCES;
	}

	hal_tx_desc_cached = (void *)cached_desc;

	hal_tx_desc_set_buf_addr_bn(soc->hal_soc, hal_tx_desc_cached,
				    tx_desc->dma_addr, bm_id, tx_desc->id,
				    (tx_desc->flags & DP_TX_DESC_FLAG_FRAG));

	/*
	 * Bank_ID is used as DSCP_TABLE number in beryllium/boron
	 * So there is no explicit field used for DSCP_TID_TABLE_NUM.
	 */
	hal_tx_desc_set_fw_metadata(hal_tx_desc_cached, fw_metadata);
	hal_tx_desc_set_buf_length(hal_tx_desc_cached, tx_desc->length);
	hal_tx_desc_set_buf_offset(hal_tx_desc_cached, tx_desc->pkt_offset);

	if (tx_desc->flags & DP_TX_DESC_FLAG_TO_FW)
		hal_tx_desc_set_to_fw(hal_tx_desc_cached, 1);

	/* verify checksum offload configuration*/
	if ((qdf_nbuf_get_tx_cksum(tx_desc->nbuf) ==
				   QDF_NBUF_TX_CKSUM_TCP_UDP) ||
	      qdf_nbuf_is_tso(tx_desc->nbuf)) {
		hal_tx_desc_set_l3_checksum_en(hal_tx_desc_cached, 1);
		hal_tx_desc_set_l4_checksum_en(hal_tx_desc_cached, 1);
	}

	hal_tx_desc_set_bank_id(hal_tx_desc_cached, vdev->bank_id);

	dp_tx_vdev_id_set_hal_tx_desc(hal_tx_desc_cached, vdev, msdu_info);

	if (qdf_likely(QDF_NBUF_CB_TXPT_CLASSIFY_INFO_VALID(nbuf))) {
		hal_tx_desc_set_peer_txpt_ci_index(hal_tx_desc_cached,
					     QDF_NBUF_CB_TXPT_IDX_VALUE(nbuf));
	} else {
		dp_err_rl("TXPT classify_info idx invalid");
		DP_STATS_INC(soc, tx.inv_txpt_ci, 1);
	}

	hal_tx_desc_set_peer_txpt_ci_tos_tc_val(hal_tx_desc_cached,
						msdu_info->ip_dscp);

	hal_tx_desc_set_da_is_bcast_mcast(hal_tx_desc_cached,
					  msdu_info->is_bcast,
					  msdu_info->is_mcast);

	hal_tx_desc_set_l3_type(hal_tx_desc_cached, msdu_info->l3_type);
	hal_tx_desc_set_l4_protocol(hal_tx_desc_cached, msdu_info->l4_proto);
	hal_tx_desc_set_type_or_length(hal_tx_desc_cached,
				       msdu_info->type_or_length);
	hal_tx_desc_set_dport(hal_tx_desc_cached,
			      msdu_info->l4_dport);
	hal_tx_desc_set_snap_oui_zero_or_f8(hal_tx_desc_cached,
					    msdu_info->snap_oui_zero_or_f8);
	hal_tx_desc_set_snap_oui_not_zero_or_not_f8(hal_tx_desc_cached,
					msdu_info->snap_oui_not_zero_or_not_f8);
	hal_tx_desc_set_s_vlan_tag(hal_tx_desc_cached, msdu_info->is_s_vlan);
	hal_tx_desc_set_c_vlan_tag(hal_tx_desc_cached, msdu_info->is_c_vlan);

	tid = msdu_info->tid;
	if (tid != HTT_TX_EXT_TID_INVALID)
		hal_tx_desc_set_hlos_tid(hal_tx_desc_cached, tid);

	dp_tx_set_min_rates_for_critical_frames(soc, hal_tx_desc_cached,
						tx_desc->nbuf);
	if (!dp_tx_desc_set_ktimestamp(vdev, tx_desc))
		dp_tx_desc_set_timestamp(tx_desc);

	hal_ring_hdl = dp_tx_get_hal_ring_hdl(soc, ring_id);

	if (qdf_unlikely(dp_tx_hal_ring_access_start(soc, hal_ring_hdl))) {
		dp_err("HAL RING Access Failed -- %pK", hal_ring_hdl);
		DP_STATS_INC(soc, tx.tcl_ring_full[ring_id], 1);
		DP_STATS_INC(vdev,
			     tx_i[msdu_info->xmit_type].dropped.enqueue_fail,
			     1);
		return status;
	}

	hal_tx_desc = hal_srng_src_get_next(soc->hal_soc, hal_ring_hdl);
	if (qdf_unlikely(!hal_tx_desc)) {
		dp_verbose_debug("TCL ring full ring_id:%d", ring_id);
		DP_STATS_INC(soc, tx.tcl_ring_full[ring_id], 1);
		DP_STATS_INC(vdev,
			     tx_i[msdu_info->xmit_type].dropped.enqueue_fail,
			     1);
		goto ring_access_fail;
	}

	tx_desc->flags |= DP_TX_DESC_FLAG_QUEUED_TX;
	dp_vdev_peer_stats_update_protocol_cnt_tx(vdev, tx_desc->nbuf);

	/* Sync cached descriptor with HW */
	hal_tx_desc_sync(hal_tx_desc_cached, hal_tx_desc, num_desc_bytes);

	dp_tx_update_proto_stats(vdev, tx_desc->nbuf, ring_id,
				 TX_ENQUEUE_HW);

	coalesce = dp_tx_attempt_coalescing(soc, vdev, tx_desc, tid,
					    msdu_info, ring_id);

	if (qdf_unlikely(dp_tx_pkt_tracepoints_enabled())) {
		hp = hal_srng_src_get_hp(hal_ring_hdl);
		qdf_trace_dp_tx_enqueue(tx_desc->nbuf, hp, ring_id, coalesce);
	}

	DP_STATS_INC_PKT(vdev, tx_i[msdu_info->xmit_type].processed, 1,
			 dp_tx_get_pkt_len(tx_desc));
	DP_STATS_INC(soc, tx.tcl_enq[ring_id], 1);
	dp_tx_update_stats(soc, tx_desc, ring_id);
	status = QDF_STATUS_SUCCESS;

	dp_tx_dump_tcl_desc(cached_desc);
	dp_tx_hw_desc_update_evt((uint8_t *)hal_tx_desc_cached,
				 hal_ring_hdl, soc, ring_id);

ring_access_fail:
	dp_tx_ring_access_end_wrapper(soc, hal_ring_hdl, coalesce);
	dp_pkt_add_timestamp(vdev, QDF_PKT_TX_DRIVER_EXIT,
			     qdf_get_log_timestamp(), tx_desc->nbuf);
	return status;
}
