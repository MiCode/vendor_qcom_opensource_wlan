/*
 * Copyright (c) 2016-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
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

#ifndef _HAL_BE_GENERIC_API_H_
#define _HAL_BE_GENERIC_API_H_

#include <hal_be_hw_headers.h>
#include "hal_be_tx.h"
#include "hal_be_reo.h"
#include <hal_api_mon.h>
#include <hal_generic_api.h>
#include <hal_be_api_mon.h>

/**
 * Debug macro to print the TLV header tag
 */
#define SHOW_DEFINED(x) do {} while (0)

#if defined(WLAN_FEATURE_TSF_UPLINK_DELAY) || defined(CONFIG_SAWF)
static inline void
hal_tx_comp_get_buffer_timestamp_be(void *desc,
				    struct hal_tx_completion_status *ts)
{
	ts->buffer_timestamp = HAL_TX_DESC_GET(desc, WBM2SW_COMPLETION_RING_TX,
					       BUFFER_TIMESTAMP);
}
#else /* !WLAN_FEATURE_TSF_UPLINK_DELAY || CONFIG_SAWF */
static inline void
hal_tx_comp_get_buffer_timestamp_be(void *desc,
				    struct hal_tx_completion_status *ts)
{
}
#endif /* WLAN_FEATURE_TSF_UPLINK_DELAY || CONFIG_SAWF */

/**
 * hal_tx_comp_get_status() - TQM Release reason
 * @hal_desc: completion ring Tx status
 *
 * This function will parse the WBM completion descriptor and populate in
 * HAL structure
 *
 * Return: none
 */
static inline void
hal_tx_comp_get_status_generic_be(void *desc, void *ts1,
				  struct hal_soc *hal)
{
	uint8_t rate_stats_valid = 0;
	uint32_t rate_stats = 0;
	struct hal_tx_completion_status *ts =
		(struct hal_tx_completion_status *)ts1;

	ts->ppdu_id = HAL_TX_DESC_GET(desc, WBM2SW_COMPLETION_RING_TX,
				      TQM_STATUS_NUMBER);
	ts->ack_frame_rssi = HAL_TX_DESC_GET(desc, WBM2SW_COMPLETION_RING_TX,
					     ACK_FRAME_RSSI);
	ts->first_msdu = HAL_TX_DESC_GET(desc, WBM2SW_COMPLETION_RING_TX,
					 FIRST_MSDU);
	ts->last_msdu = HAL_TX_DESC_GET(desc, WBM2SW_COMPLETION_RING_TX,
					LAST_MSDU);
#if 0
	// TODO -  This has to be calculated form first and last msdu
	ts->msdu_part_of_amsdu = HAL_TX_DESC_GET(desc,
						 WBM2SW_COMPLETION_RING_TX,
						 MSDU_PART_OF_AMSDU);
#endif

	ts->peer_id = HAL_TX_DESC_GET(desc, WBM2SW_COMPLETION_RING_TX,
				      SW_PEER_ID);
	ts->tid = HAL_TX_DESC_GET(desc, WBM2SW_COMPLETION_RING_TX, TID);
	ts->transmit_cnt = HAL_TX_DESC_GET(desc, WBM2SW_COMPLETION_RING_TX,
					   TRANSMIT_COUNT);

	rate_stats = HAL_TX_DESC_GET(desc, HAL_TX_COMP, TX_RATE_STATS);

	rate_stats_valid = HAL_TX_MS(TX_RATE_STATS_INFO,
			TX_RATE_STATS_INFO_VALID, rate_stats);

	ts->valid = rate_stats_valid;

	if (rate_stats_valid) {
		ts->bw = HAL_TX_MS(TX_RATE_STATS_INFO, TRANSMIT_BW,
				rate_stats);
		ts->pkt_type = HAL_TX_MS(TX_RATE_STATS_INFO,
				TRANSMIT_PKT_TYPE, rate_stats);
		ts->stbc = HAL_TX_MS(TX_RATE_STATS_INFO,
				TRANSMIT_STBC, rate_stats);
		ts->ldpc = HAL_TX_MS(TX_RATE_STATS_INFO, TRANSMIT_LDPC,
				rate_stats);
		ts->sgi = HAL_TX_MS(TX_RATE_STATS_INFO, TRANSMIT_SGI,
				rate_stats);
		ts->mcs = HAL_TX_MS(TX_RATE_STATS_INFO, TRANSMIT_MCS,
				rate_stats);
		ts->ofdma = HAL_TX_MS(TX_RATE_STATS_INFO, OFDMA_TRANSMISSION,
				rate_stats);
		ts->tones_in_ru = HAL_TX_MS(TX_RATE_STATS_INFO, TONES_IN_RU,
				rate_stats);
	}

	ts->release_src = hal_tx_comp_get_buffer_source_generic_be(desc);
	ts->status = hal_tx_comp_get_release_reason(
					desc,
					hal_soc_to_hal_soc_handle(hal));

	ts->tsf = HAL_TX_DESC_GET(desc, UNIFIED_WBM_RELEASE_RING_6,
			TX_RATE_STATS_INFO_TX_RATE_STATS);
	hal_tx_comp_get_buffer_timestamp_be(desc, ts);
}

/**
 * hal_tx_set_pcp_tid_map_generic_be() - Configure default PCP to TID map table
 * @soc: HAL SoC context
 * @map: PCP-TID mapping table
 *
 * PCP are mapped to 8 TID values using TID values programmed
 * in one set of mapping registers PCP_TID_MAP_<0 to 6>
 * The mapping register has TID mapping for 8 PCP values
 *
 * Return: none
 */
static void hal_tx_set_pcp_tid_map_generic_be(struct hal_soc *soc, uint8_t *map)
{
	uint32_t addr, value;

	addr = HWIO_TCL_R0_PCP_TID_MAP_ADDR(
				MAC_TCL_REG_REG_BASE);

	value = (map[0] |
		(map[1] << HWIO_TCL_R0_PCP_TID_MAP_PCP_1_SHFT) |
		(map[2] << HWIO_TCL_R0_PCP_TID_MAP_PCP_2_SHFT) |
		(map[3] << HWIO_TCL_R0_PCP_TID_MAP_PCP_3_SHFT) |
		(map[4] << HWIO_TCL_R0_PCP_TID_MAP_PCP_4_SHFT) |
		(map[5] << HWIO_TCL_R0_PCP_TID_MAP_PCP_5_SHFT) |
		(map[6] << HWIO_TCL_R0_PCP_TID_MAP_PCP_6_SHFT) |
		(map[7] << HWIO_TCL_R0_PCP_TID_MAP_PCP_7_SHFT));

	HAL_REG_WRITE(soc, addr, (value & HWIO_TCL_R0_PCP_TID_MAP_RMSK));
}

/**
 * hal_tx_update_pcp_tid_generic_be() - Update the pcp tid map table with
 *					value received from user-space
 * @soc: HAL SoC context
 * @pcp: pcp value
 * @tid : tid value
 *
 * Return: void
 */
static void
hal_tx_update_pcp_tid_generic_be(struct hal_soc *soc,
				 uint8_t pcp, uint8_t tid)
{
	uint32_t addr, value, regval;

	addr = HWIO_TCL_R0_PCP_TID_MAP_ADDR(
				MAC_TCL_REG_REG_BASE);

	value = (uint32_t)tid << (HAL_TX_BITS_PER_TID * pcp);

	/* Read back previous PCP TID config and update
	 * with new config.
	 */
	regval = HAL_REG_READ(soc, addr);
	regval &= ~(HAL_TX_TID_BITS_MASK << (HAL_TX_BITS_PER_TID * pcp));
	regval |= value;

	HAL_REG_WRITE(soc, addr,
		      (regval & HWIO_TCL_R0_PCP_TID_MAP_RMSK));
}

/**
 * hal_tx_update_tidmap_prty_generic_be() - Update the tid map priority
 * @soc: HAL SoC context
 * @val: priority value
 *
 * Return: void
 */
static
void hal_tx_update_tidmap_prty_generic_be(struct hal_soc *soc, uint8_t value)
{
	uint32_t addr;

	addr = HWIO_TCL_R0_TID_MAP_PRTY_ADDR(
				MAC_TCL_REG_REG_BASE);

	HAL_REG_WRITE(soc, addr,
		      (value & HWIO_TCL_R0_TID_MAP_PRTY_RMSK));
}

/**
 * hal_rx_get_tlv_size_generic_be() - Get rx packet tlv size
 * @rx_pkt_tlv_size: TLV size for regular RX packets
 * @rx_mon_pkt_tlv_size: TLV size for monitor mode packets
 *
 * Return: size of rx pkt tlv before the actual data
 */
static void hal_rx_get_tlv_size_generic_be(uint16_t *rx_pkt_tlv_size,
					   uint16_t *rx_mon_pkt_tlv_size)
{
	*rx_pkt_tlv_size = RX_PKT_TLVS_LEN;
	/* For now mon pkt tlv is same as rx pkt tlv */
	*rx_mon_pkt_tlv_size = RX_PKT_TLVS_LEN;
}

/**
 * hal_rx_flow_get_tuple_info_be() - Setup a flow search entry in HW FST
 * @fst: Pointer to the Rx Flow Search Table
 * @hal_hash: HAL 5 tuple hash
 * @tuple_info: 5-tuple info of the flow returned to the caller
 *
 * Return: Success/Failure
 */
static void *
hal_rx_flow_get_tuple_info_be(uint8_t *rx_fst, uint32_t hal_hash,
			      uint8_t *flow_tuple_info)
{
	struct hal_rx_fst *fst = (struct hal_rx_fst *)rx_fst;
	void *hal_fse = NULL;
	struct hal_flow_tuple_info *tuple_info
		= (struct hal_flow_tuple_info *)flow_tuple_info;

	hal_fse = (uint8_t *)fst->base_vaddr +
		(hal_hash * HAL_RX_FST_ENTRY_SIZE);

	if (!hal_fse || !tuple_info)
		return NULL;

	if (!HAL_GET_FLD(hal_fse, RX_FLOW_SEARCH_ENTRY, VALID))
		return NULL;

	tuple_info->src_ip_127_96 =
				qdf_ntohl(HAL_GET_FLD(hal_fse,
						      RX_FLOW_SEARCH_ENTRY,
						      SRC_IP_127_96));
	tuple_info->src_ip_95_64 =
				qdf_ntohl(HAL_GET_FLD(hal_fse,
						      RX_FLOW_SEARCH_ENTRY,
						      SRC_IP_95_64));
	tuple_info->src_ip_63_32 =
				qdf_ntohl(HAL_GET_FLD(hal_fse,
						      RX_FLOW_SEARCH_ENTRY,
						      SRC_IP_63_32));
	tuple_info->src_ip_31_0 =
				qdf_ntohl(HAL_GET_FLD(hal_fse,
						      RX_FLOW_SEARCH_ENTRY,
						      SRC_IP_31_0));
	tuple_info->dest_ip_127_96 =
				qdf_ntohl(HAL_GET_FLD(hal_fse,
						      RX_FLOW_SEARCH_ENTRY,
						      DEST_IP_127_96));
	tuple_info->dest_ip_95_64 =
				qdf_ntohl(HAL_GET_FLD(hal_fse,
						      RX_FLOW_SEARCH_ENTRY,
						      DEST_IP_95_64));
	tuple_info->dest_ip_63_32 =
				qdf_ntohl(HAL_GET_FLD(hal_fse,
						      RX_FLOW_SEARCH_ENTRY,
						      DEST_IP_63_32));
	tuple_info->dest_ip_31_0 =
				qdf_ntohl(HAL_GET_FLD(hal_fse,
						      RX_FLOW_SEARCH_ENTRY,
						      DEST_IP_31_0));
	tuple_info->dest_port = HAL_GET_FLD(hal_fse,
					    RX_FLOW_SEARCH_ENTRY,
					    DEST_PORT);
	tuple_info->src_port = HAL_GET_FLD(hal_fse,
					   RX_FLOW_SEARCH_ENTRY,
					   SRC_PORT);
	tuple_info->l4_protocol = HAL_GET_FLD(hal_fse,
					      RX_FLOW_SEARCH_ENTRY,
					      L4_PROTOCOL);

	return hal_fse;
}

/**
 * hal_rx_flow_delete_entry_be() - Setup a flow search entry in HW FST
 * @fst: Pointer to the Rx Flow Search Table
 * @hal_rx_fse: Pointer to the Rx Flow that is to be deleted from the FST
 *
 * Return: Success/Failure
 */
static QDF_STATUS
hal_rx_flow_delete_entry_be(uint8_t *rx_fst, void *hal_rx_fse)
{
	uint8_t *fse = (uint8_t *)hal_rx_fse;

	if (!HAL_GET_FLD(fse, RX_FLOW_SEARCH_ENTRY, VALID))
		return QDF_STATUS_E_NOENT;

	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY, VALID);

	return QDF_STATUS_SUCCESS;
}

/**
 * hal_rx_fst_get_fse_size_be() - Retrieve the size of each entry in Rx FST
 *
 * Return: size of each entry/flow in Rx FST
 */
static inline uint32_t
hal_rx_fst_get_fse_size_be(void)
{
	return HAL_RX_FST_ENTRY_SIZE;
}

/*
 * TX MONITOR
 */

#ifdef QCA_MONITOR_2_0_SUPPORT
/**
 * hal_txmon_get_buffer_addr_generic_be() - api to get buffer address
 * @tx_tlv: pointer to TLV header
 * @status: hal mon buffer address status
 *
 * Return: Address to qdf_frag_t
 */
static inline qdf_frag_t
hal_txmon_get_buffer_addr_generic_be(void *tx_tlv,
				     struct hal_mon_buf_addr_status *status)
{
	struct mon_buffer_addr *hal_buffer_addr =
			(struct mon_buffer_addr *)((uint8_t *)tx_tlv +
						   HAL_RX_TLV64_HDR_SIZE);
	qdf_frag_t buf_addr = NULL;

	buf_addr = (qdf_frag_t)(uintptr_t)((hal_buffer_addr->buffer_virt_addr_31_0 |
				((unsigned long long)hal_buffer_addr->buffer_virt_addr_63_32 <<
				 32)));

	/* qdf_frag_t is derived from buffer address tlv */
	if (qdf_unlikely(status)) {
		qdf_mem_copy(status,
			     (uint8_t *)tx_tlv + HAL_RX_TLV64_HDR_SIZE,
			     sizeof(struct hal_mon_buf_addr_status));
		/* update hal_mon_buf_addr_status */
	}

	return buf_addr;
}

#if defined(TX_MONITOR_WORD_MASK)
/**
 * hal_txmon_get_num_users() - get num users from tx_fes_setup tlv
 *
 * @tx_tlv: pointer to tx_fes_setup tlv header
 *
 * Return: number of users
 */
static inline uint8_t
hal_txmon_get_num_users(void *tx_tlv)
{
	hal_tx_fes_setup_t *tx_fes_setup = (hal_tx_fes_setup_t *)tx_tlv;

	return tx_fes_setup->number_of_users;
}

/**
 * hal_txmon_parse_tx_fes_setup() - parse tx_fes_setup tlv
 *
 * @tx_tlv: pointer to tx_fes_setup tlv header
 * @ppdu_info: pointer to hal_tx_ppdu_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_tx_fes_setup(void *tx_tlv,
			     struct hal_tx_ppdu_info *tx_ppdu_info)
{
	hal_tx_fes_setup_t *tx_fes_setup = (hal_tx_fes_setup_t *)tx_tlv;

	tx_ppdu_info->num_users = tx_fes_setup->number_of_users;
	if (tx_ppdu_info->num_users == 0)
		tx_ppdu_info->num_users = 1;
	tx_ppdu_info->ppdu_id = tx_fes_setup->schedule_id;
}

/**
 * hal_txmon_parse_pcu_ppdu_setup_init() - parse pcu_ppdu_setup_init tlv
 *
 * @tx_tlv: pointer to pcu_ppdu_setup_init tlv header
 * @data_status_info: pointer to data hal_tx_status_info
 * @prot_status_info: pointer to protection hal_tx_status_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_pcu_ppdu_setup_init(void *tx_tlv,
				    struct hal_tx_status_info *data_status_info,
				    struct hal_tx_status_info *prot_status_info)
{
}

/**
 * hal_txmon_parse_peer_entry() - parse peer entry tlv
 *
 * @tx_tlv: pointer to peer_entry tlv header
 * @user_id: user_id
 * @tx_ppdu_info: pointer to hal_tx_ppdu_info
 * @tx_status_info: pointer to hal_tx_status_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_peer_entry(void *tx_tlv,
			   uint8_t user_id,
			   struct hal_tx_ppdu_info *tx_ppdu_info,
			   struct hal_tx_status_info *tx_status_info)
{
}

/**
 * hal_txmon_parse_queue_exten() - parse queue exten tlv
 *
 * @tx_tlv: pointer to queue exten tlv header
 * @tx_ppdu_info: pointer to hal_tx_ppdu_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_queue_exten(void *tx_tlv,
			    struct hal_tx_ppdu_info *tx_ppdu_info)
{
}

/**
 * hal_txmon_parse_mpdu_start() - parse mpdu start tlv
 *
 * @tx_tlv: pointer to mpdu start tlv header
 * @user_id: user id
 * @tx_ppdu_info: pointer to hal_tx_ppdu_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_mpdu_start(void *tx_tlv, uint8_t user_id,
			   struct hal_tx_ppdu_info *tx_ppdu_info)
{
}

#else
/**
 * hal_txmon_get_num_users() - get num users from tx_fes_setup tlv
 *
 * @tx_tlv: pointer to tx_fes_setup tlv header
 *
 * Return: number of users
 */
static inline uint8_t
hal_txmon_get_num_users(void *tx_tlv)
{
	uint8_t num_users = HAL_TX_DESC_GET_64(tx_tlv,
					       TX_FES_SETUP, NUMBER_OF_USERS);

	return num_users;
}

/**
 * hal_txmon_parse_tx_fes_setup() - parse tx_fes_setup tlv
 *
 * @tx_tlv: pointer to tx_fes_setup tlv header
 * @ppdu_info: pointer to hal_tx_ppdu_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_tx_fes_setup(void *tx_tlv,
			     struct hal_tx_ppdu_info *tx_ppdu_info)
{
	uint32_t num_users = 0;
	uint32_t ppdu_id = 0;

	num_users = HAL_TX_DESC_GET_64(tx_tlv, TX_FES_SETUP, NUMBER_OF_USERS);
	ppdu_id = HAL_TX_DESC_GET_64(tx_tlv, TX_FES_SETUP, SCHEDULE_ID);

	if (num_users == 0)
		num_users = 1;

	tx_ppdu_info->num_users = num_users;
	tx_ppdu_info->ppdu_id = ppdu_id;
}

/**
 * hal_txmon_parse_pcu_ppdu_setup_init() - parse pcu_ppdu_setup_init tlv
 *
 * @tx_tlv: pointer to pcu_ppdu_setup_init tlv header
 * @data_status_info: pointer to data hal_tx_status_info
 * @prot_status_info: pointer to protection hal_tx_status_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_pcu_ppdu_setup_init(void *tx_tlv,
				    struct hal_tx_status_info *data_status_info,
				    struct hal_tx_status_info *prot_status_info)
{
}

/**
 * hal_txmon_parse_peer_entry() - parse peer entry tlv
 *
 * @tx_tlv: pointer to peer_entry tlv header
 * @user_id: user_id
 * @tx_ppdu_info: pointer to hal_tx_ppdu_info
 * @tx_status_info: pointer to hal_tx_status_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_peer_entry(void *tx_tlv,
			   uint8_t user_id,
			   struct hal_tx_ppdu_info *tx_ppdu_info,
			   struct hal_tx_status_info *tx_status_info)
{
}

/**
 * hal_txmon_parse_queue_exten() - parse queue exten tlv
 *
 * @tx_tlv: pointer to queue exten tlv header
 * @tx_ppdu_info: pointer to hal_tx_ppdu_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_queue_exten(void *tx_tlv,
			    struct hal_tx_ppdu_info *tx_ppdu_info)
{
}

/**
 * hal_txmon_parse_mpdu_start() - parse mpdu start tlv
 *
 * @tx_tlv: pointer to mpdu start tlv header
 * @user_id: user id
 * @tx_ppdu_info: pointer to hal_tx_ppdu_info
 *
 * Return: void
 */
static inline void
hal_txmon_parse_mpdu_start(void *tx_tlv, uint8_t user_id,
			   struct hal_tx_ppdu_info *tx_ppdu_info)
{
}
#endif

/**
 * hal_txmon_status_get_num_users_generic_be() - api to get num users
 * from start of fes window
 *
 * @tx_tlv_hdr: pointer to TLV header
 * @num_users: reference to number of user
 *
 * Return: status
 */
static inline uint32_t
hal_txmon_status_get_num_users_generic_be(void *tx_tlv_hdr, uint8_t *num_users)
{
	uint32_t tlv_tag, user_id, tlv_len;
	uint32_t tlv_status = HAL_MON_TX_STATUS_PPDU_NOT_DONE;
	void *tx_tlv;

	tlv_tag = HAL_RX_GET_USER_TLV32_TYPE(tx_tlv_hdr);
	user_id = HAL_RX_GET_USER_TLV32_USERID(tx_tlv_hdr);
	tlv_len = HAL_RX_GET_USER_TLV32_LEN(tx_tlv_hdr);

	tx_tlv = (uint8_t *)tx_tlv_hdr + HAL_RX_TLV64_HDR_SIZE;
	/* window starts with either initiator or response */
	switch (tlv_tag) {
	case WIFITX_FES_SETUP_E:
	{
		*num_users = hal_txmon_get_num_users(tx_tlv);
		if (*num_users == 0)
			*num_users = 1;

		tlv_status = HAL_MON_TX_FES_SETUP;
		break;
	}
	case WIFIRX_RESPONSE_REQUIRED_INFO_E:
	{
		*num_users = HAL_TX_DESC_GET_64(tx_tlv,
						RX_RESPONSE_REQUIRED_INFO,
						RESPONSE_STA_COUNT);
		if (*num_users == 0)
			*num_users = 1;
		tlv_status = HAL_MON_RX_RESPONSE_REQUIRED_INFO;
		break;
	}
	};

	return tlv_status;
}

/**
 * hal_txmon_free_status_buffer() - api to free status buffer
 * @pdev_handle: DP_PDEV handle
 * @status_frag: qdf_frag_t buffer
 * @end_offset: end offset within buffer that has valid data
 *
 * Return status
 */
static inline QDF_STATUS
hal_txmon_status_free_buffer_generic_be(qdf_frag_t status_frag,
					uint32_t end_offset)
{
	uint32_t tlv_tag, tlv_len;
	uint32_t tlv_status = HAL_MON_TX_STATUS_PPDU_NOT_DONE;
	uint8_t *tx_tlv;
	uint8_t *tx_tlv_start;
	qdf_frag_t frag_buf = NULL;
	QDF_STATUS status = QDF_STATUS_E_ABORTED;

	tx_tlv = (uint8_t *)status_frag;
	tx_tlv_start = tx_tlv;
	/* parse tlv and populate tx_ppdu_info */
	do {
		tlv_tag = HAL_RX_GET_USER_TLV64_TYPE(tx_tlv);
		tlv_len = HAL_RX_GET_USER_TLV64_LEN(tx_tlv);

		if (((tx_tlv - tx_tlv_start) + tlv_len) > end_offset)
			return QDF_STATUS_E_ABORTED;

		if (tlv_tag == WIFIMON_BUFFER_ADDR_E) {
			frag_buf = hal_txmon_get_buffer_addr_generic_be(tx_tlv,
									NULL);
			if (frag_buf)
				qdf_frag_free(frag_buf);

			frag_buf = NULL;
		}

		if (WIFITX_FES_STATUS_END_E == tlv_tag ||
		    WIFIRESPONSE_END_STATUS_E == tlv_tag ||
		    WIFIDUMMY_E == tlv_tag) {
			status = QDF_STATUS_SUCCESS;
			break;
		}

		/* need api definition for hal_tx_status_get_next_tlv */
		tx_tlv = hal_tx_status_get_next_tlv(tx_tlv);
		if ((tx_tlv - tx_tlv_start) >= end_offset)
			break;
	} while (tlv_status == HAL_MON_TX_STATUS_PPDU_NOT_DONE);

	return status;
}

/**
 * hal_tx_get_ppdu_info() - api to get tx ppdu info
 * @pdev_handle: DP_PDEV handle
 * @prot_ppdu_info: populate dp_ppdu_info protection
 * @tx_data_ppdu_info: populate dp_ppdu_info data
 * @tlv_tag: Tag
 *
 * Return: dp_tx_ppdu_info pointer
 */
static inline void *
hal_tx_get_ppdu_info(void *data_info, void *prot_info, uint32_t tlv_tag)
{
	struct hal_tx_ppdu_info *prot_ppdu_info = prot_info;

	switch (tlv_tag) {
	case WIFITX_FES_SETUP_E:/* DOWNSTREAM */
	case WIFITX_FLUSH_E:/* DOWNSTREAM */
	case WIFIPCU_PPDU_SETUP_INIT_E:/* DOWNSTREAM */
	case WIFITX_PEER_ENTRY_E:/* DOWNSTREAM */
	case WIFITX_QUEUE_EXTENSION_E:/* DOWNSTREAM */
	case WIFITX_MPDU_START_E:/* DOWNSTREAM */
	case WIFITX_MSDU_START_E:/* DOWNSTREAM */
	case WIFITX_DATA_E:/* DOWNSTREAM */
	case WIFIMON_BUFFER_ADDR_E:/* DOWNSTREAM */
	case WIFITX_MPDU_END_E:/* DOWNSTREAM */
	case WIFITX_MSDU_END_E:/* DOWNSTREAM */
	case WIFITX_LAST_MPDU_FETCHED_E:/* DOWNSTREAM */
	case WIFITX_LAST_MPDU_END_E:/* DOWNSTREAM */
	case WIFICOEX_TX_REQ_E:/* DOWNSTREAM */
	case WIFITX_RAW_OR_NATIVE_FRAME_SETUP_E:/* DOWNSTREAM */
	case WIFINDP_PREAMBLE_DONE_E:/* DOWNSTREAM */
	case WIFISCH_CRITICAL_TLV_REFERENCE_E:/* DOWNSTREAM */
	case WIFITX_LOOPBACK_SETUP_E:/* DOWNSTREAM */
	case WIFITX_FES_SETUP_COMPLETE_E:/* DOWNSTREAM */
	case WIFITQM_MPDU_GLOBAL_START_E:/* DOWNSTREAM */
	case WIFITX_WUR_DATA_E:/* DOWNSTREAM */
	case WIFISCHEDULER_END_E:/* DOWNSTREAM */
	case WIFITX_FES_STATUS_START_PPDU_E:/* UPSTREAM */
	{
		return data_info;
	}
	}

	/*
	 * check current prot_tlv_status is start protection
	 * check current tlv_tag is either start protection or end protection
	 */
	if (TXMON_HAL(prot_ppdu_info,
		      prot_tlv_status) == WIFITX_FES_STATUS_START_PROT_E) {
		return prot_info;
	} else if (tlv_tag == WIFITX_FES_STATUS_PROT_E ||
		   tlv_tag == WIFITX_FES_STATUS_START_PROT_E) {
		TXMON_HAL(prot_ppdu_info, prot_tlv_status) = tlv_tag;
		return prot_info;
	} else {
		TXMON_HAL(prot_ppdu_info, prot_tlv_status) = tlv_tag;
		return data_info;
	}

	return data_info;
}

/**
 * hal_txmon_status_parse_tlv_generic_be() - api to parse status tlv.
 * @data_ppdu_info: hal_txmon data ppdu info
 * @prot_ppdu_info: hal_txmon prot ppdu info
 * @data_status_info: pointer to data status info
 * @prot_status_info: pointer to prot status info
 * @tx_tlv_hdr: fragment of tx_tlv_hdr
 * @status_frag: qdf_frag_t buffer
 *
 * Return: status
 */
static inline uint32_t
hal_txmon_status_parse_tlv_generic_be(void *data_ppdu_info,
				      void *prot_ppdu_info,
				      void *data_status_info,
				      void *prot_status_info,
				      void *tx_tlv_hdr,
				      qdf_frag_t status_frag)
{
	struct hal_tx_ppdu_info *ppdu_info;
	struct hal_tx_status_info *tx_status_info;
	uint32_t tlv_tag, user_id, tlv_len;
	qdf_frag_t frag_buf = NULL;
	uint32_t status = HAL_MON_TX_STATUS_PPDU_NOT_DONE;
	void *tx_tlv;

	tlv_tag = HAL_RX_GET_USER_TLV64_TYPE(tx_tlv_hdr);
	/* user_id start with 1, decrement by 1 to start from 0 */
	user_id = HAL_RX_GET_USER_TLV64_USERID(tx_tlv_hdr) - 1;
	tlv_len = HAL_RX_GET_USER_TLV64_LEN(tx_tlv_hdr);

	tx_tlv = (uint8_t *)tx_tlv_hdr + HAL_RX_TLV64_HDR_SIZE;

	/* parse tlv and populate tx_ppdu_info */
	ppdu_info = hal_tx_get_ppdu_info(data_ppdu_info,
					 prot_ppdu_info, tlv_tag);
	tx_status_info = (ppdu_info->is_data ? data_status_info :
			  prot_status_info);

	user_id = user_id > ppdu_info->num_users ? 0 : ppdu_info->num_users;

	switch (tlv_tag) {
	/* start of initiator FES window */
	case WIFITX_FES_SETUP_E:/* DOWNSTREAM */
	{
		/* initiator PPDU window start */
		hal_txmon_parse_tx_fes_setup(tx_tlv, ppdu_info);

		status = HAL_MON_TX_FES_SETUP;
		SHOW_DEFINED(WIFITX_FES_SETUP_E);
		break;
	}
	/* end of initiator FES window */
	case WIFITX_FES_STATUS_END_E:/* UPSTREAM */
	{
		/* initiator PPDU window end */
		status = HAL_MON_TX_FES_STATUS_END;
		SHOW_DEFINED(WIFITX_FES_STATUS_END_E);
		break;
	}
	/* response window open */
	case WIFIRX_RESPONSE_REQUIRED_INFO_E:/* UPSTREAM */
	{
		status = HAL_MON_RX_RESPONSE_REQUIRED_INFO;
		SHOW_DEFINED(WIFIRX_RESPONSE_REQUIRED_INFO_E);
		break;
	}
	/* Response window close */
	case WIFIRESPONSE_END_STATUS_E:/* UPSTREAM */
	{
		/* response PPDU window end */
		status = HAL_MON_RESPONSE_END_STATUS_INFO;
		SHOW_DEFINED(WIFIRESPONSE_END_STATUS_E);
		break;
	}
	case WIFITX_FLUSH_E:/* DOWNSTREAM */
	{
		SHOW_DEFINED(WIFITX_FLUSH_E);
		break;
	}

	/* Downstream tlv */
	case WIFIPCU_PPDU_SETUP_INIT_E:/* DOWNSTREAM */
	{
		hal_txmon_parse_pcu_ppdu_setup_init(tx_tlv, data_status_info,
						    prot_status_info);

		status = HAL_MON_TX_PCU_PPDU_SETUP_INIT;
		SHOW_DEFINED(WIFIPCU_PPDU_SETUP_INIT_E);
		break;
	}
	case WIFITX_PEER_ENTRY_E:/* DOWNSTREAM */
	{
		hal_txmon_parse_peer_entry(tx_tlv, user_id,
					   ppdu_info, tx_status_info);
		SHOW_DEFINED(WIFITX_PEER_ENTRY_E);
		break;
	}
	case WIFITX_QUEUE_EXTENSION_E:/* DOWNSTREAM */
	{
		status = HAL_MON_TX_QUEUE_EXTENSION;
		hal_txmon_parse_queue_exten(tx_tlv, ppdu_info);

		SHOW_DEFINED(WIFITX_QUEUE_EXTENSION_E);
		break;
	}
	/* payload and data frame handling */
	case WIFITX_MPDU_START_E:/* DOWNSTREAM */
	{
		hal_txmon_parse_mpdu_start(tx_tlv, user_id, ppdu_info);

		status = HAL_MON_TX_MPDU_START;
		SHOW_DEFINED(WIFITX_MPDU_START_E);
		break;
	}
	case WIFITX_MSDU_START_E:/* DOWNSTREAM */
	{
		/* compacted */
		/* we expect frame to be 802.11 frame type */
		status = HAL_MON_TX_MSDU_START;
		SHOW_DEFINED(WIFITX_MSDU_START_E);
		break;
	}
	case WIFITX_DATA_E:/* DOWNSTREAM */
	{
		/*
		 * reference of the status buffer will be held in
		 * dp_tx_update_ppdu_info_status()
		 */
		status = HAL_MON_TX_DATA;
		SHOW_DEFINED(WIFITX_DATA_E);
		break;
	}
	case WIFIMON_BUFFER_ADDR_E:
	{
		frag_buf = hal_txmon_get_buffer_addr_generic_be(tx_tlv, NULL);
		if (frag_buf)
			qdf_frag_free(frag_buf);
		frag_buf = NULL;
		status = HAL_MON_TX_BUFFER_ADDR;

		SHOW_DEFINED(WIFIMON_BUFFER_ADDR_E);
		break;
	}
	case WIFITX_MPDU_END_E:/* DOWNSTREAM */
	{
		/* no tlv content */
		SHOW_DEFINED(WIFITX_MPDU_END_E);
		break;
	}
	case WIFITX_MSDU_END_E:/* DOWNSTREAM */
	{
		/* no tlv content */
		SHOW_DEFINED(WIFITX_MSDU_END_E);
		break;
	}
	case WIFITX_LAST_MPDU_FETCHED_E:/* DOWNSTREAM */
	{
		/* no tlv content */
		SHOW_DEFINED(WIFITX_LAST_MPDU_FETCHED_E);
		break;
	}
	case WIFITX_LAST_MPDU_END_E:/* DOWNSTREAM */
	{
		/* no tlv content */
		SHOW_DEFINED(WIFITX_LAST_MPDU_END_E);
		break;
	}
	case WIFICOEX_TX_REQ_E:/* DOWNSTREAM */
	{
		/*
		 * transmitting power
		 * minimum transmitting power
		 * desired nss
		 * tx chain mask
		 * desired bw
		 * duration of transmit and response
		 *
		 * since most of the field we are deriving from other tlv
		 * we don't need to enable this in our tlv.
		 */
		SHOW_DEFINED(WIFICOEX_TX_REQ_E);
		break;
	}
	case WIFITX_RAW_OR_NATIVE_FRAME_SETUP_E:/* DOWNSTREAM */
	{
		/* user tlv */
		/*
		 * All Tx monitor will have 802.11 hdr
		 * we don't need to enable this TLV
		 */
		SHOW_DEFINED(WIFITX_RAW_OR_NATIVE_FRAME_SETUP_E);
		break;
	}
	case WIFINDP_PREAMBLE_DONE_E:/* DOWNSTREAM */
	{
		/*
		 * no tlv content
		 *
		 * TLV that indicates to TXPCU that preamble phase for the NDP
		 * frame transmission is now over
		 */
		SHOW_DEFINED(WIFINDP_PREAMBLE_DONE_E);
		break;
	}
	case WIFISCH_CRITICAL_TLV_REFERENCE_E:/* DOWNSTREAM */
	{
		/*
		 * no tlv content
		 *
		 * TLV indicates to the SCH that all timing critical TLV
		 * has been passed on to the transmit path
		 */
		SHOW_DEFINED(WIFISCH_CRITICAL_TLV_REFERENCE_E);
		break;
	}
	case WIFITX_LOOPBACK_SETUP_E:/* DOWNSTREAM */
	{
		/*
		 * Loopback specific setup info - not needed for Tx monitor
		 */
		SHOW_DEFINED(WIFITX_LOOPBACK_SETUP_E);
		break;
	}
	case WIFITX_FES_SETUP_COMPLETE_E:/* DOWNSTREAM */
	{
		/*
		 * no tlv content
		 *
		 * TLV indicates that other modules besides the scheduler can
		 * now also start generating TLV's
		 * prevent colliding or generating TLV's out of order
		 */
		SHOW_DEFINED(WIFITX_FES_SETUP_COMPLETE_E);
		break;
	}
	case WIFITQM_MPDU_GLOBAL_START_E:/* DOWNSTREAM */
	{
		/*
		 * no tlv content
		 *
		 * TLV indicates to SCH that a burst of MPDU info will
		 * start to come in over the TLV
		 */
		SHOW_DEFINED(WIFITQM_MPDU_GLOBAL_START_E);
		break;
	}
	case WIFITX_WUR_DATA_E:/* DOWNSTREAM */
	{
		SHOW_DEFINED(WIFITX_WUR_DATA_E);
		break;
	}
	case WIFISCHEDULER_END_E:/* DOWNSTREAM */
	{
		/*
		 * no tlv content
		 *
		 * TLV indicates END of all TLV's within the scheduler TLV
		 */
		SHOW_DEFINED(WIFISCHEDULER_END_E);
		break;
	}

	/* Upstream tlv */
	case WIFIPDG_TX_REQ_E:
	{
		SHOW_DEFINED(WIFIPDG_TX_REQ_E);
		break;
	}
	case WIFITX_FES_STATUS_START_E:
	{
		/*
		 * TLV indicating that first transmission on the medium
		 */
		status = HAL_MON_TX_FES_STATUS_START;
		SHOW_DEFINED(WIFITX_FES_STATUS_START_E);
		break;
	}
	case WIFITX_FES_STATUS_PROT_E:
	{
		/*
		 * generated by TXPCU to indicate the result of having
		 * received of the expected protection frame
		 */

		status = HAL_MON_TX_FES_STATUS_PROT;
		SHOW_DEFINED(WIFITX_FES_STATUS_PROT_E);
		break;
	}
	case WIFITX_FES_STATUS_START_PROT_E:
	{
		status = HAL_MON_TX_FES_STATUS_START_PROT;
		SHOW_DEFINED(WIFITX_FES_STATUS_START_PROT_E);
		break;
	}
	case WIFIPROT_TX_END_E:
	{
		/*
		 * no tlv content
		 *
		 * generated by TXPCU the moment that protection frame
		 * transmission has finished on the medium
		 */
		SHOW_DEFINED(WIFIPROT_TX_END_E);
		break;
	}
	case WIFITX_FES_STATUS_START_PPDU_E:
	{
		status = HAL_MON_TX_FES_STATUS_START_PPDU;
		SHOW_DEFINED(WIFITX_FES_STATUS_START_PPDU_E);
		break;
	}
	case WIFITX_FES_STATUS_USER_PPDU_E:
	{
		/* user tlv */
		status = HAL_MON_TX_FES_STATUS_USER_PPDU;
		SHOW_DEFINED(WIFITX_FES_STATUS_USER_PPDU_E);
		break;
	}
	case WIFIPPDU_TX_END_E:
	{
		/*
		 * no tlv content
		 *
		 * generated by TXPCU the moment that PPDU transmission has
		 * finished on the medium
		 */
		SHOW_DEFINED(WIFIPPDU_TX_END_E);
		break;
	}

	case WIFITX_FES_STATUS_USER_RESPONSE_E:
	{
		/*
		 * TLV contains the FES transmit result of the each
		 * of the MAC users. TLV are forwarded to HWSCH
		 */
		SHOW_DEFINED(WIFITX_FES_STATUS_USER_RESPONSE_E);
		break;
	}
	case WIFITX_FES_STATUS_ACK_OR_BA_E:
	{
		/* user tlv */
		/*
		 * TLV generated by RXPCU and provide information related to
		 * the received BA or ACK frame
		 */
		SHOW_DEFINED(WIFITX_FES_STATUS_ACK_OR_BA_E);
		break;
	}
	case WIFITX_FES_STATUS_1K_BA_E:
	{
		/* user tlv */
		/*
		 * TLV generated by RXPCU and providing information related
		 * to the received BA frame in case of 512/1024 bitmaps
		 */
		SHOW_DEFINED(WIFITX_FES_STATUS_1K_BA_E);
		break;
	}
	case WIFIRECEIVED_RESPONSE_USER_7_0_E:
	{
		SHOW_DEFINED(WIFIRECEIVED_RESPONSE_USER_7_0_E);
		break;
	}
	case WIFIRECEIVED_RESPONSE_USER_15_8_E:
	{
		SHOW_DEFINED(WIFIRECEIVED_RESPONSE_USER_15_8_E);
		break;
	}
	case WIFIRECEIVED_RESPONSE_USER_23_16_E:
	{
		SHOW_DEFINED(WIFIRECEIVED_RESPONSE_USER_23_16_E);
		break;
	}
	case WIFIRECEIVED_RESPONSE_USER_31_24_E:
	{
		SHOW_DEFINED(WIFIRECEIVED_RESPONSE_USER_31_24_E);
		break;
	}
	case WIFIRECEIVED_RESPONSE_USER_36_32_E:
	{
		/*
		 * RXPCU generates this TLV when it receives a response frame
		 * that TXPCU pre-announced it was waiting for and in
		 * RXPCU_SETUP TLV, TLV generated before the
		 * RECEIVED_RESPONSE_INFO TLV.
		 *
		 * received info user fields are there which is not needed
		 * for TX monitor
		 */
		SHOW_DEFINED(WIFIRECEIVED_RESPONSE_USER_36_32_E);
		break;
	}

	case WIFITXPCU_BUFFER_STATUS_E:
	{
		SHOW_DEFINED(WIFITXPCU_BUFFER_STATUS_E);
		break;
	}
	case WIFITXPCU_USER_BUFFER_STATUS_E:
	{
		/*
		 * WIFITXPCU_USER_BUFFER_STATUS_E - user tlv
		 * for TX monitor we aren't interested in this tlv
		 */
		SHOW_DEFINED(WIFITXPCU_USER_BUFFER_STATUS_E);
		break;
	}
	case WIFITXDMA_STOP_REQUEST_E:
	{
		/*
		 * no tlv content
		 *
		 * TLV is destined to TXDMA and informs TXDMA to stop
		 * pushing data into the transmit path.
		 */
		SHOW_DEFINED(WIFITXDMA_STOP_REQUEST_E);
		break;
	}
	case WIFITX_CBF_INFO_E:
	{
		/*
		 * After NDPA + NDP is received, RXPCU sends the TX_CBF_INFO to
		 * TXPCU to respond the CBF frame
		 *
		 * compressed beamforming pkt doesn't has mac header
		 * Tx monitor not interested in this pkt.
		 */
		SHOW_DEFINED(WIFITX_CBF_INFO_E);
		break;
	}
	case WIFITX_MPDU_COUNT_TRANSFER_END_E:
	{
		/*
		 * no tlv content
		 *
		 * TLV indicates that TXPCU has finished generating the
		 * TQM_UPDATE_TX_MPDU_COUNT TLV for all users
		 */
		SHOW_DEFINED(WIFITX_MPDU_COUNT_TRANSFER_END_E);
		break;
	}
	case WIFIPDG_RESPONSE_E:
	{
		/*
		 * most of the feilds are already covered in
		 * other TLV
		 * This is generated by TX_PCU to PDG to calculate
		 * all the PHY header info.
		 *
		 * some useful fields like min transmit power,
		 * rate used for transmitting packet is present.
		 */
		SHOW_DEFINED(WIFIPDG_RESPONSE_E);
		break;
	}
	case WIFIPDG_TRIG_RESPONSE_E:
	{
		/* no tlv content */
		SHOW_DEFINED(WIFIPDG_TRIG_RESPONSE_E);
		break;
	}
	case WIFIRECEIVED_TRIGGER_INFO_E:
	{
		/*
		 * TLV generated by RXPCU to inform the scheduler that
		 * a trigger frame has been received
		 */
		SHOW_DEFINED(WIFIRECEIVED_TRIGGER_INFO_E);
		break;
	}
	case WIFIOFDMA_TRIGGER_DETAILS_E:
	{
		SHOW_DEFINED(WIFIOFDMA_TRIGGER_DETAILS_E);
		break;
	}
	case WIFIRX_FRAME_BITMAP_ACK_E:
	{
		/* user tlv */
		status = HAL_MON_RX_FRAME_BITMAP_ACK;
		SHOW_DEFINED(WIFIRX_FRAME_BITMAP_ACK_E);
		break;
	}
	case WIFIRX_FRAME_1K_BITMAP_ACK_E:
	{
		/* user tlv */
		status = HAL_MON_RX_FRAME_BITMAP_BLOCK_ACK_1K;
		SHOW_DEFINED(WIFIRX_FRAME_1K_BITMAP_ACK_E);
		break;
	}
	case WIFIRESPONSE_START_STATUS_E:
	{
		/*
		 * TLV indicates which HW response the TXPCU
		 * started generating
		 *
		 * HW generated frames like
		 * ACK frame - handled
		 * CTS frame - handled
		 * BA frame - handled
		 * MBA frame - handled
		 * CBF frame - no frame header
		 * Trigger response - TODO
		 * NDP LMR - no frame header
		 */
		SHOW_DEFINED(WIFIRESPONSE_START_STATUS_E);
		break;
	}
	case WIFIRX_START_PARAM_E:
	{
		/*
		 * RXPCU send this TLV after PHY RX detected a frame
		 * in the medium
		 *
		 * TX monitor not interested in this TLV
		 */
		SHOW_DEFINED(WIFIRX_START_PARAM_E);
		break;
	}
	case WIFIRXPCU_EARLY_RX_INDICATION_E:
	{
		/*
		 * early indication of pkt type and mcs rate
		 * already captured in other tlv
		 */
		SHOW_DEFINED(WIFIRXPCU_EARLY_RX_INDICATION_E);
		break;
	}
	case WIFIRX_PM_INFO_E:
	{
		SHOW_DEFINED(WIFIRX_PM_INFO_E);
		break;
	}

	/* Active window */
	case WIFITX_FLUSH_REQ_E:
	{
		SHOW_DEFINED(WIFITX_FLUSH_REQ_E);
		break;
	}
	case WIFICOEX_TX_STATUS_E:
	{
		/* duration are retrieved from coex tx status */
		status = HAL_MON_COEX_TX_STATUS;
		SHOW_DEFINED(WIFICOEX_TX_STATUS_E);
		break;
	}
	case WIFIR2R_STATUS_END_E:
	{
		SHOW_DEFINED(WIFIR2R_STATUS_END_E);
		break;
	}
	case WIFIRX_PREAMBLE_E:
	{
		SHOW_DEFINED(WIFIRX_PREAMBLE_E);
		break;
	}
	case WIFIMACTX_SERVICE_E:
	{
		SHOW_DEFINED(WIFIMACTX_SERVICE_E);
		break;
	}

	case WIFIMACTX_U_SIG_EHT_SU_MU_E:
	{
		SHOW_DEFINED(WIFIMACTX_U_SIG_EHT_SU_MU_E);
		break;
	}
	case WIFIMACTX_U_SIG_EHT_TB_E:
	{
		/* TODO: no radiotap info available */
		SHOW_DEFINED(WIFIMACTX_U_SIG_EHT_TB_E);
		break;
	}
	case WIFIMACTX_EHT_SIG_USR_OFDMA_E:
	{
		SHOW_DEFINED(WIFIMACTX_EHT_SIG_USR_OFDMA_E);
		break;
	}
	case WIFIMACTX_EHT_SIG_USR_MU_MIMO_E:
	{
		SHOW_DEFINED(WIFIMACTX_EHT_SIG_USR_MU_MIMO_E);
		break;
	}
	case WIFIMACTX_EHT_SIG_USR_SU_E:
	{
		SHOW_DEFINED(WIFIMACTX_EHT_SIG_USR_SU_E);
		/* TODO: no radiotap info available */
		break;
	}

	case WIFIMACTX_HE_SIG_A_SU_E:
	{
		SHOW_DEFINED(WIFIMACTX_HE_SIG_A_SU_E);
		break;
	}
	case WIFIMACTX_HE_SIG_A_MU_DL_E:
	{
		SHOW_DEFINED(WIFIMACTX_HE_SIG_A_MU_DL_E);
		break;
	}
	case WIFIMACTX_HE_SIG_A_MU_UL_E:
	{
		SHOW_DEFINED(WIFIMACTX_HE_SIG_A_MU_UL_E);
		break;
	}
	case WIFIMACTX_HE_SIG_B1_MU_E:
	{
		status = HAL_MON_MACTX_HE_SIG_B1_MU;
		SHOW_DEFINED(WIFIMACTX_HE_SIG_B1_MU_E);
		break;
	}
	case WIFIMACTX_HE_SIG_B2_MU_E:
	{
		/* user tlv */
		status = HAL_MON_MACTX_HE_SIG_B2_MU;
		SHOW_DEFINED(WIFIMACTX_HE_SIG_B2_MU_E);
		break;
	}
	case WIFIMACTX_HE_SIG_B2_OFDMA_E:
	{
		/* user tlv */
		status = HAL_MON_MACTX_HE_SIG_B2_OFDMA;
		SHOW_DEFINED(WIFIMACTX_HE_SIG_B2_OFDMA_E);
		break;
	}
	case WIFIMACTX_L_SIG_A_E:
	{
		status = HAL_MON_MACTX_L_SIG_A;
		SHOW_DEFINED(WIFIMACTX_L_SIG_A_E);
		break;
	}
	case WIFIMACTX_L_SIG_B_E:
	{
		status = HAL_MON_MACTX_L_SIG_B;
		SHOW_DEFINED(WIFIMACTX_L_SIG_B_E);
		break;
	}
	case WIFIMACTX_HT_SIG_E:
	{
		status = HAL_MON_MACTX_HT_SIG;
		SHOW_DEFINED(WIFIMACTX_HT_SIG_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_A_E:
	{
		status = HAL_MON_MACTX_VHT_SIG_A;
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_A_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_B_MU160_E:
	{
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_B_MU160_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_B_MU80_E:
	{
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_B_MU80_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_B_MU40_E:
	{
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_B_MU40_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_B_MU20_E:
	{
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_B_MU20_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_B_SU160_E:
	{
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_B_SU160_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_B_SU80_E:
	{
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_B_SU80_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_B_SU40_E:
	{
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_B_SU40_E);
		break;
	}
	case WIFIMACTX_VHT_SIG_B_SU20_E:
	{
		SHOW_DEFINED(WIFIMACTX_VHT_SIG_B_SU20_E);
		break;
	}
	case WIFIPHYTX_PPDU_HEADER_INFO_REQUEST_E:
	{
		SHOW_DEFINED(WIFIPHYTX_PPDU_HEADER_INFO_REQUEST_E);
		break;
	}
	case WIFIMACTX_USER_DESC_PER_USER_E:
	{
		status = HAL_MON_MACTX_USER_DESC_PER_USER;
		SHOW_DEFINED(WIFIMACTX_USER_DESC_PER_USER_E);
		break;
	}
	case WIFIMACTX_USER_DESC_COMMON_E:
	{
		SHOW_DEFINED(WIFIMACTX_USER_DESC_COMMON_E);
		break;
	}
	case WIFIMACTX_PHY_DESC_E:
	{
		status = HAL_MON_MACTX_PHY_DESC;
		SHOW_DEFINED(WIFIMACTX_PHY_DESC_E);
		break;
	}
	case WIFICOEX_RX_STATUS_E:
	{
		SHOW_DEFINED(WIFICOEX_RX_STATUS_E);
		break;
	}
	case WIFIRX_PPDU_ACK_REPORT_E:
	{
		SHOW_DEFINED(WIFIRX_PPDU_ACK_REPORT_E);
		break;
	}
	case WIFIRX_PPDU_NO_ACK_REPORT_E:
	{
		SHOW_DEFINED(WIFIRX_PPDU_NO_ACK_REPORT_E);
		break;
	}
	case WIFITXPCU_PHYTX_OTHER_TRANSMIT_INFO32_E:
	{
		SHOW_DEFINED(WIFITXPCU_PHYTX_OTHER_TRANSMIT_INFO32_E);
		break;
	}
	case WIFITXPCU_PHYTX_DEBUG32_E:
	{
		SHOW_DEFINED(WIFITXPCU_PHYTX_DEBUG32_E);
		break;
	}
	case WIFITXPCU_PREAMBLE_DONE_E:
	{
		SHOW_DEFINED(WIFITXPCU_PREAMBLE_DONE_E);
		break;
	}
	case WIFIRX_PHY_SLEEP_E:
	{
		SHOW_DEFINED(WIFIRX_PHY_SLEEP_E);
		break;
	}
	case WIFIRX_FRAME_BITMAP_REQ_E:
	{
		SHOW_DEFINED(WIFIRX_FRAME_BITMAP_REQ_E);
		break;
	}
	case WIFIRXPCU_TX_SETUP_CLEAR_E:
	{
		SHOW_DEFINED(WIFIRXPCU_TX_SETUP_CLEAR_E);
		break;
	}
	case WIFIRX_TRIG_INFO_E:
	{
		SHOW_DEFINED(WIFIRX_TRIG_INFO_E);
		break;
	}
	case WIFIEXPECTED_RESPONSE_E:
	{
		SHOW_DEFINED(WIFIEXPECTED_RESPONSE_E);
		break;
	}
	case WIFITRIGGER_RESPONSE_TX_DONE_E:
	{
		SHOW_DEFINED(WIFITRIGGER_RESPONSE_TX_DONE_E);
		break;
	}
	}

	return status;
}
#endif /* QCA_MONITOR_2_0_SUPPORT */

#ifdef REO_SHARED_QREF_TABLE_EN
static void hal_reo_shared_qaddr_cache_clear_be(hal_soc_handle_t hal_soc_hdl)
{
	struct hal_soc *hal = (struct hal_soc *)hal_soc_hdl;
	uint32_t reg_val = 0;

	/* Set Qdesc clear bit to erase REO internal storage for Qdesc pointers
	 * of 37 peer/tids
	 */
	reg_val = HAL_REG_READ(hal, HWIO_REO_R0_QDESC_ADDR_READ_ADDR(REO_REG_REG_BASE));
	reg_val |= HAL_SM(HWIO_REO_R0_QDESC_ADDR_READ, CLEAR_QDESC_ARRAY, 1);
	HAL_REG_WRITE(hal,
		      HWIO_REO_R0_QDESC_ADDR_READ_ADDR(REO_REG_REG_BASE),
		      reg_val);

	/* Clear Qdesc clear bit to erase REO internal storage for Qdesc pointers
	 * of 37 peer/tids
	 */
	reg_val &= ~(HAL_SM(HWIO_REO_R0_QDESC_ADDR_READ, CLEAR_QDESC_ARRAY, 1));
	HAL_REG_WRITE(hal,
		      HWIO_REO_R0_QDESC_ADDR_READ_ADDR(REO_REG_REG_BASE),
		      reg_val);

	hal_verbose_debug("hal_soc: %pK :Setting CLEAR_DESC_ARRAY field of"
			  "WCSS_UMAC_REO_R0_QDESC_ADDR_READ and resetting back"
			  "to erase stale entries in reo storage: regval:%x", hal, reg_val);
}

/* hal_reo_shared_qaddr_write(): Write REO tid queue addr
 * LUT shared by SW and HW at the index given by peer id
 * and tid.
 *
 * @hal_soc: hal soc pointer
 * @reo_qref_addr: pointer to index pointed to be peer_id
 * and tid
 * @tid: tid queue number
 * @hw_qdesc_paddr: reo queue addr
 */

static void hal_reo_shared_qaddr_write_be(hal_soc_handle_t hal_soc_hdl,
					  uint16_t peer_id,
					  int tid,
					  qdf_dma_addr_t hw_qdesc_paddr)
{
	struct hal_soc *hal = (struct hal_soc *)hal_soc_hdl;
	struct rx_reo_queue_reference *reo_qref;
	uint32_t peer_tid_idx;

	/* Plug hw_desc_addr in Host reo queue reference table */
	if (HAL_PEER_ID_IS_MLO(peer_id)) {
		peer_tid_idx = ((peer_id - HAL_ML_PEER_ID_START) *
				DP_MAX_TIDS) + tid;
		reo_qref = (struct rx_reo_queue_reference *)
			&hal->reo_qref.mlo_reo_qref_table_vaddr[peer_tid_idx];
	} else {
		peer_tid_idx = (peer_id * DP_MAX_TIDS) + tid;
		reo_qref = (struct rx_reo_queue_reference *)
			&hal->reo_qref.non_mlo_reo_qref_table_vaddr[peer_tid_idx];
	}
	reo_qref->rx_reo_queue_desc_addr_31_0 =
		hw_qdesc_paddr & 0xffffffff;
	reo_qref->rx_reo_queue_desc_addr_39_32 =
		(hw_qdesc_paddr & 0xff00000000) >> 32;
	if (hw_qdesc_paddr != 0)
		reo_qref->receive_queue_number = tid;
	else
		reo_qref->receive_queue_number = 0;

	hal_reo_shared_qaddr_cache_clear_be(hal_soc_hdl);
	hal_verbose_debug("hw_qdesc_paddr: %pK, tid: %d, reo_qref:%pK,"
			  "rx_reo_queue_desc_addr_31_0: %x,"
			  "rx_reo_queue_desc_addr_39_32: %x",
			  (void *)hw_qdesc_paddr, tid, reo_qref,
			  reo_qref->rx_reo_queue_desc_addr_31_0,
			  reo_qref->rx_reo_queue_desc_addr_39_32);
}

/**
 * hal_reo_shared_qaddr_setup() - Allocate MLO and Non MLO reo queue
 * reference table shared between SW and HW and initialize in Qdesc Base0
 * base1 registers provided by HW.
 *
 * @hal_soc: HAL Soc handle
 *
 * Return: None
 */
static void hal_reo_shared_qaddr_setup_be(hal_soc_handle_t hal_soc_hdl)
{
	struct hal_soc *hal = (struct hal_soc *)hal_soc_hdl;

	hal->reo_qref.reo_qref_table_en = 1;

	hal->reo_qref.mlo_reo_qref_table_vaddr =
		(uint64_t *)qdf_mem_alloc_consistent(
				hal->qdf_dev, hal->qdf_dev->dev,
				REO_QUEUE_REF_ML_TABLE_SIZE,
				&hal->reo_qref.mlo_reo_qref_table_paddr);
	hal->reo_qref.non_mlo_reo_qref_table_vaddr =
		(uint64_t *)qdf_mem_alloc_consistent(
				hal->qdf_dev, hal->qdf_dev->dev,
				REO_QUEUE_REF_NON_ML_TABLE_SIZE,
				&hal->reo_qref.non_mlo_reo_qref_table_paddr);

	hal_verbose_debug("MLO table start paddr:%pK,"
			  "Non-MLO table start paddr:%pK,"
			  "MLO table start vaddr: %pK,"
			  "Non MLO table start vaddr: %pK",
			  (void *)hal->reo_qref.mlo_reo_qref_table_paddr,
			  (void *)hal->reo_qref.non_mlo_reo_qref_table_paddr,
			  hal->reo_qref.mlo_reo_qref_table_vaddr,
			  hal->reo_qref.non_mlo_reo_qref_table_vaddr);
}

/**
 * hal_reo_shared_qaddr_init() - Zero out REO qref LUT and
 * write start addr of MLO and Non MLO table in HW
 *
 * @hal_soc: HAL Soc handle
 *
 * Return: None
 */
static void hal_reo_shared_qaddr_init_be(hal_soc_handle_t hal_soc_hdl)
{
	struct hal_soc *hal = (struct hal_soc *)hal_soc_hdl;

	qdf_mem_zero(hal->reo_qref.mlo_reo_qref_table_vaddr,
		     REO_QUEUE_REF_ML_TABLE_SIZE);
	qdf_mem_zero(hal->reo_qref.non_mlo_reo_qref_table_vaddr,
		     REO_QUEUE_REF_NON_ML_TABLE_SIZE);
	/* LUT_BASE0 and BASE1 registers expect upper 32bits of LUT base address
	 * and lower 8 bits to be 0. Shift the physical address by 8 to plug
	 * upper 32bits only
	 */
	HAL_REG_WRITE(hal,
		      HWIO_REO_R0_QDESC_LUT_BASE0_ADDR_ADDR(REO_REG_REG_BASE),
		      hal->reo_qref.non_mlo_reo_qref_table_paddr >> 8);
	HAL_REG_WRITE(hal,
		      HWIO_REO_R0_QDESC_LUT_BASE1_ADDR_ADDR(REO_REG_REG_BASE),
		      hal->reo_qref.mlo_reo_qref_table_paddr >> 8);
	HAL_REG_WRITE(hal,
		      HWIO_REO_R0_QDESC_ADDR_READ_ADDR(REO_REG_REG_BASE),
		      HAL_SM(HWIO_REO_R0_QDESC_ADDR_READ, LUT_FEATURE_ENABLE,
			     1));
	HAL_REG_WRITE(hal,
		      HWIO_REO_R0_QDESC_MAX_SW_PEER_ID_ADDR(REO_REG_REG_BASE),
		      HAL_MS(HWIO_REO_R0_QDESC, MAX_SW_PEER_ID_MAX_SUPPORTED,
			     0x1fff));
}

/**
 * hal_reo_shared_qaddr_detach() - Free MLO and Non MLO reo queue
 * reference table shared between SW and HW
 *
 * @hal_soc: HAL Soc handle
 *
 * Return: None
 */
static void hal_reo_shared_qaddr_detach_be(hal_soc_handle_t hal_soc_hdl)
{
	struct hal_soc *hal = (struct hal_soc *)hal_soc_hdl;

	HAL_REG_WRITE(hal,
		      HWIO_REO_R0_QDESC_LUT_BASE0_ADDR_ADDR(REO_REG_REG_BASE),
		      0);
	HAL_REG_WRITE(hal,
		      HWIO_REO_R0_QDESC_LUT_BASE1_ADDR_ADDR(REO_REG_REG_BASE),
		      0);

	qdf_mem_free_consistent(hal->qdf_dev, hal->qdf_dev->dev,
				REO_QUEUE_REF_ML_TABLE_SIZE,
				hal->reo_qref.mlo_reo_qref_table_vaddr,
				hal->reo_qref.mlo_reo_qref_table_paddr, 0);
	qdf_mem_free_consistent(hal->qdf_dev, hal->qdf_dev->dev,
				REO_QUEUE_REF_NON_ML_TABLE_SIZE,
				hal->reo_qref.non_mlo_reo_qref_table_vaddr,
				hal->reo_qref.non_mlo_reo_qref_table_paddr, 0);
}
#endif
#endif /* _HAL_BE_GENERIC_API_H_ */
