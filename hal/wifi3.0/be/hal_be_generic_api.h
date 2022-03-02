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
						   HAL_RX_TLV32_HDR_SIZE);
	qdf_frag_t buf_addr = NULL;

	buf_addr = (qdf_frag_t)(uintptr_t)((hal_buffer_addr->buffer_virt_addr_31_0 |
				((unsigned long long)hal_buffer_addr->buffer_virt_addr_63_32 <<
				 32)));

	/* qdf_frag_t is derived from buffer address tlv */
	if (qdf_unlikely(status)) {
		qdf_mem_copy(status,
			     (uint8_t *)tx_tlv + HAL_RX_TLV32_HDR_SIZE,
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
	uint8_t num_users = HAL_TX_DESC_GET(tx_tlv,
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
	tx_ppdu_info->num_users = HAL_TX_DESC_GET(tx_tlv,
						  TX_FES_SETUP,
						  NUMBER_OF_USERS);
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

	tx_tlv = (uint8_t *)tx_tlv_hdr + HAL_RX_TLV32_HDR_SIZE;
	/* window starts with either initiator or response */
	switch (tlv_tag) {
	case WIFITX_FES_SETUP_E:
	{
		*num_users = hal_txmon_get_num_users(tx_tlv);

		tlv_status = HAL_MON_TX_FES_SETUP;
		break;
	}
	case WIFIRX_RESPONSE_REQUIRED_INFO_E:
	{
		*num_users = HAL_TX_DESC_GET(tx_tlv,
					     RX_RESPONSE_REQUIRED_INFO,
					     RESPONSE_STA_COUNT);
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
 *
 * Return void
 */
static inline void
hal_txmon_status_free_buffer_generic_be(qdf_frag_t status_frag)
{
	uint32_t tlv_tag, tlv_len;
	uint32_t tlv_status = HAL_MON_TX_STATUS_PPDU_NOT_DONE;
	uint8_t *tx_tlv;
	uint8_t *tx_tlv_start;
	qdf_frag_t frag_buf = NULL;

	tx_tlv = (uint8_t *)status_frag;
	tx_tlv_start = tx_tlv;
	/* parse tlv and populate tx_ppdu_info */
	do {
		/* TODO: check config_length is full monitor mode */
		tlv_tag = HAL_RX_GET_USER_TLV32_TYPE(tx_tlv);
		tlv_len = HAL_RX_GET_USER_TLV32_LEN(tx_tlv);

		if (tlv_tag == WIFIMON_BUFFER_ADDR_E) {
			frag_buf = hal_txmon_get_buffer_addr_generic_be(tx_tlv,
									NULL);
			if (frag_buf)
				qdf_frag_free(frag_buf);

			frag_buf = NULL;
		}
		/* need api definition for hal_tx_status_get_next_tlv */
		tx_tlv = hal_tx_status_get_next_tlv(tx_tlv);
		if ((tx_tlv - tx_tlv_start) >= TX_MON_STATUS_BUF_SIZE)
			break;
	} while (tlv_status == HAL_MON_TX_STATUS_PPDU_NOT_DONE);
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
	struct hal_tx_ppdu_info *tx_ppdu_info;
	struct hal_tx_status_info *tx_status_info;
	uint32_t tlv_tag, user_id, tlv_len;
	qdf_frag_t frag_buf = NULL;
	uint32_t status = HAL_MON_TX_STATUS_PPDU_NOT_DONE;
	void *tx_tlv;

	tlv_tag = HAL_RX_GET_USER_TLV32_TYPE(tx_tlv_hdr);
	user_id = HAL_RX_GET_USER_TLV32_USERID(tx_tlv_hdr);
	tlv_len = HAL_RX_GET_USER_TLV32_LEN(tx_tlv_hdr);

	tx_tlv = (uint8_t *)tx_tlv_hdr + HAL_RX_TLV32_HDR_SIZE;

	tx_ppdu_info = hal_tx_get_ppdu_info(data_ppdu_info,
					    prot_ppdu_info, tlv_tag);
	tx_status_info = (tx_ppdu_info->is_data ? data_status_info :
			  prot_status_info);

	/* parse tlv and populate tx_ppdu_info */
	switch (tlv_tag) {
	case WIFIMON_BUFFER_ADDR_E:
	{
		frag_buf = hal_txmon_get_buffer_addr_generic_be(tx_tlv, NULL);
		if (frag_buf)
			qdf_frag_free(frag_buf);
		frag_buf = NULL;
		status = HAL_MON_TX_BUFFER_ADDR;
		break;
	}
	case WIFITX_FES_STATUS_START_PROT_E:
	{
		TXMON_HAL(tx_ppdu_info, prot_tlv_status) = tlv_tag;
		break;
	}
	}

	return status;
}
#endif /* QCA_MONITOR_2_0_SUPPORT */

#ifdef REO_SHARED_QREF_TABLE_EN
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

	hal_verbose_debug("hw_qdesc_paddr: %llx, tid: %d, reo_qref:%pK,"
			  "rx_reo_queue_desc_addr_31_0: %x,"
			  "rx_reo_queue_desc_addr_39_32: %x",
			  hw_qdesc_paddr, tid, reo_qref,
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

	hal_verbose_debug("MLO table start paddr:%llx,"
			  "Non-MLO table start paddr:%llx,"
			  "MLO table start vaddr: %pK,"
			  "Non MLO table start vaddr: %pK",
			  hal->reo_qref.mlo_reo_qref_table_paddr,
			  hal->reo_qref.non_mlo_reo_qref_table_paddr,
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
