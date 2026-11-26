/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef _HAL_BN_TX_H_
#define _HAL_BN_TX_H_

#include "hal_be_hw_headers.h"
#include "hal_be_tx.h"
#include "hal_tx.h"

/*---------------------------------------------------------------------------
 * Structures
 * ---------------------------------------------------------------------------
 */
/**
 * union hal_tx_bank_config - SW config bank params
 * @epd: EPD indication flag
 * @encap_type: encapsulation type
 * @encrypt_type: encrypt type
 * @src_buffer_swap: big-endia switch for packet buffer
 * @link_meta_swap: big-endian switch for link metadata
 * @mesh_enable:mesh enable flag
 * @vdev_id_check_en: vdev id check
 * @dscp_tid_map_id: DSCP to TID map id
 * @reserved: unused bits
 * @val: value representing bank config
 */
union hal_tx_bank_config {
	struct {
		uint32_t epd:1,
			 encap_type:2,
			 encrypt_type:4,
			 src_buffer_swap:1,
			 link_meta_swap:1,
			 mesh_enable:2,
			 vdev_id_check_en:1,
			 dscp_tid_map_id:6,
			 reserved:7;
	};
	uint32_t val;
};

/*---------------------------------------------------------------------------
 *  Function declarations and documentation
 * ---------------------------------------------------------------------------
 */

/*---------------------------------------------------------------------------
 *  TCL Descriptor accessor APIs
 *---------------------------------------------------------------------------
 */

/**
 * hal_tx_desc_set_tx_notify_frame() - Set TX notify_frame field in Tx desc
 * @desc: Handle to Tx Descriptor
 * @val: Value to be set
 *
 * Return: None
 */
static inline void hal_tx_desc_set_tx_notify_frame(void *desc,
						   uint8_t val)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TX_NOTIFY_FRAME) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TX_NOTIFY_FRAME, val);
}

/**
 * hal_tx_desc_txpt_ci_sel() - Select Tx flow entry, used for custom flow select
 *			       Configure this to choose TXPT_CLASSIFY_INFO entry
 *			       within TXPT_CLASSIFY_INFO group.
 *
 * @desc: Handle to Tx Descriptor
 * @txpt_ci_sel: Value to be set TXPT_CLASSIFY_INFO_SEL, implicit to set
 *		 TXPT_CLASSIFY_INFO_OVERRIDE
 *
 * Return: None
 */
static inline void  hal_tx_desc_txpt_ci_sel(void *desc, uint8_t txpt_ci_sel)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_SEL) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_SEL, txpt_ci_sel);

	/* TXPT_CLASSIFY_INFO_OVERRIDE is implicit to enable above config */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_OVERRIDE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_OVERRIDE, 1);
}

/**
 * hal_tx_desc_txpt_ci_use_udp_flow_entry() - Select udp or non-udp flow entry
 *					      within TXPT_CI entry, used for
 *					      custom flow select, this is used
 *					      to override default udp/non-udp
 *					      flow
 *
 * @desc: Handle to Tx Descriptor
 * @use_udp_entry: Choose UDP/non-udp entry within entry selected by txpt_ci
 *		 entry, implicit to
 *
 * Return: None
 */
static inline void hal_tx_desc_txpt_ci_use_udp_flow_entry(void *desc,
							  uint8_t use_udp_entry)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, FLOW_SELECT) |=
		HAL_TX_SM(TCL_ASSIST_CMD, FLOW_SELECT, use_udp_entry);

	/* FLOW_OVERRIDE_ENABLE is implicit to enable above config */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, FLOW_OVERRIDE_ENABLE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, FLOW_OVERRIDE_ENABLE, 1);
}

/**
 * hal_tx_desc_set_buf_length() - Set Data length in bytes in Tx Descriptor
 * @desc: Handle to Tx Descriptor
 * @data_length: MSDU length in case of direct descriptor.
 *              Length of link extension descriptor in case of Link extension
 *              descriptor.Includes the length of Metadata
 * Return: None
 */
static inline void hal_tx_desc_set_buf_length(void *desc, uint16_t data_length)
{
	/* TODO: add generic macro which can be used for other fields */
	if (qdf_unlikely(data_length & ~(TCL_ASSIST_CMD_DATA_LENGTH_MASK >>
					TCL_ASSIST_CMD_DATA_LENGTH_LSB))) {
		hal_err("data_length overflow %d", data_length);
		qdf_assert_always(0);
	}
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, DATA_LENGTH) |=
		HAL_TX_SM(TCL_ASSIST_CMD, DATA_LENGTH, data_length);
}

/**
 * hal_tx_desc_set_buf_offset() - Sets Packet Offset field in Tx descriptor
 * @desc: Handle to Tx Descriptor
 * @offset: Packet offset from Metadata in case of direct buffer descriptor.
 *
 * Return: void
 */
static inline void hal_tx_desc_set_buf_offset(void *desc,
					      uint8_t offset)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, METADATA_LENGTH) |=
		HAL_TX_SM(TCL_ASSIST_CMD, METADATA_LENGTH, offset);
}

/**
 * hal_tx_desc_set_l4_checksum_en() -  Set TCP/IP checksum enable flags
 *                                     Tx Descriptor for MSDU_buffer type
 * @desc: Handle to Tx Descriptor
 * @en: UDP/TCP over ipv4/ipv6 checksum enable flags (5 bits)
 *
 * Return: void
 */
static inline void hal_tx_desc_set_l4_checksum_en(void *desc,
						  uint8_t en)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, L4_CHECKSUM_ENABLE) |=
		 HAL_TX_SM(TCL_ASSIST_CMD, L4_CHECKSUM_ENABLE, en);
}

/**
 * hal_tx_desc_set_l3_checksum_en() -  Set IPv4 checksum enable flag in
 *                                     Tx Descriptor for MSDU_buffer type
 * @desc: Handle to Tx Descriptor
 * @en: ipv4 checksum enable flags
 *
 * Return: void
 */
static inline void hal_tx_desc_set_l3_checksum_en(void *desc,
						  uint8_t en)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, L3_CHECKSUM_ENABLE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, L3_CHECKSUM_ENABLE, en);
}

/**
 * hal_tx_desc_set_fw_metadata() - Sets the metadata that is part of TCL
 *				   descriptor
 * @desc: Handle to Tx Descriptor
 * @metadata: Metadata to be sent to Firmware
 *
 * Return: void
 */
static inline void hal_tx_desc_set_fw_metadata(void *desc,
					       uint16_t metadata)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TCL_CMD_NUMBER) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TCL_CMD_NUMBER, metadata);
}

/**
 * hal_tx_desc_set_to_fw() - Set To_FW bit in Tx Descriptor.
 * @desc: Handle to Tx Descriptor
 * @to_fw: if set, Forward packet to FW along with classification result
 *
 * Return: void
 */
static inline void hal_tx_desc_set_to_fw(void *desc, uint8_t to_fw)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TO_FW_TQM) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TO_FW_TQM, to_fw);
}

/**
 * hal_tx_desc_set_dport() - Set dport in Tx Descriptor.
 * @desc: Handle to Tx Descriptor
 * @l4_port: port
 *
 * Return: void
 */
static inline void  hal_tx_desc_set_dport(void *desc, uint16_t l4_port)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, L4_PORT) |=
		HAL_TX_SM(TCL_ASSIST_CMD, L4_PORT, l4_port);

	HAL_SET_FLD(desc, TCL_ASSIST_CMD, L4_PORT_TYPE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, L4_PORT_TYPE, 1);
}

/**
 * hal_tx_desc_set_hlos_tid() - Set the TID value (override DSCP/PCP fields in
 *                              frame) to be used for Tx Frame
 * @desc: Handle to Tx Descriptor
 * @hlos_tid: HLOS TID
 *
 * Return: void
 */
static inline void hal_tx_desc_set_hlos_tid(void *desc,
					    uint8_t hlos_tid)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, HLOS_TID) |=
		HAL_TX_SM(TCL_ASSIST_CMD, HLOS_TID, hlos_tid);

	HAL_SET_FLD(desc, TCL_ASSIST_CMD, HLOS_TID_OVERWRITE) |=
	   HAL_TX_SM(TCL_ASSIST_CMD, HLOS_TID_OVERWRITE, 1);
}

/**
 * hal_tx_desc_sync() - Commit the descriptor to Hardware
 * @hal_tx_desc_cached: Cached descriptor that software maintains
 * @hw_desc: Hardware descriptor to be updated
 * @num_bytes: descriptor size
 */
static inline void hal_tx_desc_sync(void *hal_tx_desc_cached,
				    void *hw_desc, uint8_t num_bytes)
{
	qdf_mem_copy(hw_desc, hal_tx_desc_cached, num_bytes);
}

/**
 * hal_tx_desc_set_vdev_id() - set vdev id to the descriptor to Hardware
 * @desc: Cached descriptor that software maintains
 * @vdev_id: vdev id
 */
static inline void hal_tx_desc_set_vdev_id(void *desc, uint8_t vdev_id)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, VDEV_ID) |=
		HAL_TX_SM(TCL_ASSIST_CMD, VDEV_ID, vdev_id);
}

/**
 * hal_tx_desc_set_bank_id() - set bank id to the descriptor to Hardware
 * @desc: Cached descriptor that software maintains
 * @bank_id: bank id
 */
static inline void hal_tx_desc_set_bank_id(void *desc, uint8_t bank_id)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, BANK_ID) |=
		HAL_TX_SM(TCL_ASSIST_CMD, BANK_ID, bank_id);
}

/*---------------------------------------------------------------------------
 * WBM Descriptor accessor APIs for Tx completions
 * ---------------------------------------------------------------------------
 */

/**
 * hal_tx_get_wbm_sw0_bm_id() - Get the BM ID for first tx completion ring
 *
 * Return: BM ID for first tx completion ring
 */
static inline uint32_t hal_tx_get_wbm_sw0_bm_id(void)
{
	return HAL_BE_WBM_SW0_BM_ID;
}

/**
 * hal_tx_comp_get_desc_id() - Get TX descriptor id within comp descriptor
 * @hal_desc: completion ring descriptor pointer
 *
 * This function will tx descriptor id, cookie, within hardware completion
 * descriptor. For cases when cookie conversion is disabled, the sw_cookie
 * is present in the 2nd DWORD.
 *
 * Return: cookie
 */
static inline uint32_t hal_tx_comp_get_desc_id(void *hal_desc)
{
	uint32_t comp_desc =
		*(uint32_t *)(((uint8_t *)hal_desc) +
			       BUFFER_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET);

	/* Cookie is placed on 2nd word */
	return (comp_desc & BUFFER_ADDR_INFO_SW_BUFFER_COOKIE_MASK) >>
		BUFFER_ADDR_INFO_SW_BUFFER_COOKIE_LSB;
}

/**
 * hal_tx_comp_get_paddr() - Get paddr within comp descriptor
 * @hal_desc: completion ring descriptor pointer
 *
 * This function will get buffer physical address within hardware completion
 * descriptor
 *
 * Return: Buffer physical address
 */
static inline qdf_dma_addr_t hal_tx_comp_get_paddr(void *hal_desc)
{
	uint32_t paddr_lo;
	uint32_t paddr_hi;

	paddr_lo = *(uint32_t *)(((uint8_t *)hal_desc) +
			BUFFER_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET);

	paddr_hi = *(uint32_t *)(((uint8_t *)hal_desc) +
			BUFFER_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET);

	paddr_hi = (paddr_hi & BUFFER_ADDR_INFO_BUFFER_ADDR_39_32_MASK) >>
		BUFFER_ADDR_INFO_BUFFER_ADDR_39_32_LSB;

	return (qdf_dma_addr_t)(paddr_lo | (((uint64_t)paddr_hi) << 32));
}

#ifdef DP_HW_COOKIE_CONVERT_EXCEPTION
/* HW set dowrd-2 bit30 to 1 if HW CC is done */
/**
 * hal_tx_comp_get_cookie_convert_done() - Get cookie conversion done flag
 * @hal_desc: completion ring descriptor pointer
 *
 * This function will get the bit value that indicate HW cookie
 * conversion done or not
 *
 * Return: 1 - HW cookie conversion done, 0 - not
 */
static inline uint8_t hal_tx_comp_get_cookie_convert_done(void *hal_desc)
{
	return HAL_TX_DESC_GET(hal_desc, TQM2SW_COMPLETION_RING,
			       COOKIE_CONVERSION_STATUS);
}
#endif

/**
 * hal_tx_comp_set_desc_va_63_32() - Set bit 32~63 value for 64 bit VA
 * @hal_desc: completion ring descriptor pointer
 * @val: value to be set
 *
 * Return: None
 */
static inline void hal_tx_comp_set_desc_va_63_32(void *hal_desc, uint32_t val)
{
	HAL_SET_FLD(hal_desc,
		    TQM2SW_COMPLETION_RING,
		    BUF_OR_DESC_VIRT_ADDR_OR_ADDR_INFO_BUFFER_ADDR_39_32) = val;
}

/**
 * hal_tx_comp_get_desc_va() - Get Desc virtual address within completion Desc
 * @hal_desc: completion ring descriptor pointer
 *
 * This function will get the TX Desc virtual address
 *
 * Return: TX desc virtual address
 */
static inline uint64_t hal_tx_comp_get_desc_va(void *hal_desc)
{
	uint64_t va_from_desc;

	va_from_desc =
	qdf_le64_to_cpu(HAL_TX_DESC_GET(hal_desc, TQM2SW_COMPLETION_RING,
	    BUF_OR_DESC_VIRT_ADDR_OR_ADDR_INFO_BUFFER_ADDR_31_0) |
	    (((uint64_t)HAL_TX_DESC_GET(hal_desc, TQM2SW_COMPLETION_RING,
	    BUF_OR_DESC_VIRT_ADDR_OR_ADDR_INFO_BUFFER_ADDR_39_32)) << 32) |
	    (((uint64_t)HAL_TX_DESC_GET(hal_desc, TQM2SW_COMPLETION_RING,
	    BUF_OR_DESC_VIRT_ADDR_OR_ADDR_INFO_RETURN_BUFFER_MANAGER)) << 40) |
	    (((uint64_t)HAL_TX_DESC_GET(hal_desc, TQM2SW_COMPLETION_RING,
	    BUF_OR_DESC_VIRT_ADDR_OR_ADDR_INFO_SW_BUFFER_COOKIE)) << 44));

	return va_from_desc;
}

/*---------------------------------------------------------------------------
 * TX BANK register accessor APIs
 * ---------------------------------------------------------------------------
 */
/**
 * hal_tx_desc_set_buf_addr_bn() - Fill Buffer Address information in Tx Desc
 * @hal_soc_hdl: HAL SoC context
 * @desc: Handle to Tx Descriptor
 * @paddr: Physical Address
 * @rbm_id: Return Buffer Manager ID
 * @desc_id: Descriptor ID
 * @type: 0 - Address points to a MSDU buffer
 *        1 - Address points to MSDU extension descriptor
 *
 * Return: void
 */
#ifdef DP_TX_IMPLICIT_RBM_MAPPING
static inline void
hal_tx_desc_set_buf_addr_bn(hal_soc_handle_t hal_soc_hdl, void *desc,
			    dma_addr_t paddr, uint8_t rbm_id,
			    uint32_t desc_id, uint8_t type)
{
	/* Set buffer_addr_info.buffer_addr_31_0 */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, BUF_ADDR_INFO_BUFFER_ADDR_31_0) =
	       HAL_TX_SM(TCL_ASSIST_CMD, BUF_ADDR_INFO_BUFFER_ADDR_31_0, paddr);

	/* Set buffer_addr_info.buffer_addr_39_32 */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, BUF_ADDR_INFO_BUFFER_ADDR_39_32) |=
		HAL_TX_SM(TCL_ASSIST_CMD, BUF_ADDR_INFO_BUFFER_ADDR_39_32,
			  (((uint64_t)paddr) >> 32));

	/* Set buffer_addr_info.sw_buffer_cookie = desc_id */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD,
		    BUF_ADDR_INFO_SW_BUFFER_COOKIE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, BUF_ADDR_INFO_SW_BUFFER_COOKIE,
			  desc_id);

	/* Set  Buffer or Ext Descriptor Type */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD,
		    BUF_OR_EXT_DESC_TYPE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, BUF_OR_EXT_DESC_TYPE, type);
}
#else
static inline void
hal_tx_desc_set_buf_addr_bn(hal_soc_handle_t hal_soc_hdl, void *desc,
			    dma_addr_t paddr, uint8_t rbm_id,
			    uint32_t desc_id, uint8_t type)
{
	/* Set buffer_addr_info.buffer_addr_31_0 */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, BUF_ADDR_INFO_BUFFER_ADDR_31_0) =
	       HAL_TX_SM(TCL_ASSIST_CMD, BUF_ADDR_INFO_BUFFER_ADDR_31_0, paddr);

	/* Set buffer_addr_info.buffer_addr_39_32 */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, BUF_ADDR_INFO_BUFFER_ADDR_39_32) |=
		HAL_TX_SM(TCL_ASSIST_CMD, BUF_ADDR_INFO_BUFFER_ADDR_39_32,
			  (((uint64_t)paddr) >> 32));

	/* Set buffer_addr_info.return_buffer_manager = rbm id */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD,
		    BUF_ADDR_INFO_RETURN_BUFFER_MANAGER) |=
			HAL_TX_SM(TCL_ASSIST_CMD,
				  BUF_ADDR_INFO_RETURN_BUFFER_MANAGER, rbm_id);

	/* Set buffer_addr_info.sw_buffer_cookie = desc_id */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, BUF_ADDR_INFO_SW_BUFFER_COOKIE) |=
	     HAL_TX_SM(TCL_ASSIST_CMD, BUF_ADDR_INFO_SW_BUFFER_COOKIE, desc_id);

	/* Set  Buffer or Ext Descriptor Type */
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, BUF_OR_EXT_DESC_TYPE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, BUF_OR_EXT_DESC_TYPE, type);
}
#endif

/**
 * hal_tx_desc_set_peer_txpt_ci_index() -  Set txpt_classify_info_index
 *
 * @desc: Handle to Tx Descriptor
 * @peer_txpt_ci_index: peer txpt_classify_info index
 *
 * Return: void
 */
static inline void
hal_tx_desc_set_peer_txpt_ci_index(void *desc, uint8_t peer_txpt_ci_index)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_INDEX) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_INDEX,
			  peer_txpt_ci_index);
}

/**
 * hal_tx_desc_set_peer_txpt_ci_sel() -  Set txpt_classify_info_sel in txpt_ci
 *					 group.
 *
 * @desc: Handle to Tx Descriptor
 * @txpt_ci_sel: txpt_ci entry select in group.
 *
 * Return: void
 */
static inline void hal_tx_desc_set_peer_txpt_ci_sel(void *desc,
						    uint8_t txpt_ci_sel)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_SEL) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_SEL, txpt_ci_sel);
}

/**
 * hal_tx_desc_set_peer_txpt_ci_sel_en() -  Set txpt_classify_info_sel_en
 *					    enables selection txpt_ci_sel
 *
 * @desc: Handle to Tx Descriptor
 * @txpt_ci_sel_en: Enables the txpt_ci entry selection via txpt_ci_sel
 *
 * Return: void
 */
static inline void hal_tx_desc_set_peer_txpt_ci_sel_en(void *desc,
						       uint8_t txpt_ci_sel_en)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_OVERRIDE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TXPT_CLASSIFY_INFO_OVERRIDE,
			  txpt_ci_sel_en);
}

/**
 * hal_tx_desc_set_peer_txpt_ci_flow_override_en() - Enables flow_sel field
 *					    to select entry in txpt_ci when TID
 *					    based flow is not enabled.
 * @desc: Handle to Tx Descriptor
 * @flow_override_en: enable flow override
 *
 * Return: None
 */
static inline void
hal_tx_desc_set_peer_txpt_ci_flow_override_en(void *desc,
					      uint8_t flow_override_en)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, FLOW_OVERRIDE_ENABLE) |=
	     HAL_TX_SM(TCL_ASSIST_CMD, FLOW_OVERRIDE_ENABLE, flow_override_en);
}

/**
 * hal_tx_desc_set_peer_txpt_ci_flow_select() - select UDP/non-udp entry in
 *						txpt_ci entry pair.
 *
 * @desc: Handle to Tx Descriptor
 * @txpt_ci_flow_sel: entry select
 *
 * Return: void
 */
static inline void
hal_tx_desc_set_peer_txpt_ci_flow_select(void *desc, uint8_t txpt_ci_flow_sel)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, FLOW_SELECT) |=
		HAL_TX_SM(TCL_ASSIST_CMD, FLOW_SELECT, txpt_ci_flow_sel);
}

/**
 * hal_tx_desc_set_peer_txpt_ci_tos_tc_val() - Program dscp value to select TID
 *					       based txpt_ci entry selection
 *
 * @desc: Handle to Tx Descriptor
 * @tos_tc_val: DSCP value
 *
 * Return: void
 */
static inline void
hal_tx_desc_set_peer_txpt_ci_tos_tc_val(void *desc, uint8_t tos_tc_val)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TOS_TC_VALUE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TOS_TC_VALUE, tos_tc_val);
}

/**
 * hal_tx_desc_set_l3_type() - Set l3_type, IPV4/IPV6...
 *
 * @desc: Handle to Tx Descriptor
 * @l3_type: L3 type
 *
 * Return: void
 */
static inline void hal_tx_desc_set_l3_type(void *desc, uint16_t l3_type)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, L3_TYPE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, L3_TYPE, l3_type);
}

/**
 * hal_tx_desc_set_l4_protocol() - Set l4_protocol
 *
 * @desc: Handle to Tx Descriptor
 * @l4_protocol: l4_protocol type
 *
 * Return: void
 */
static inline void hal_tx_desc_set_l4_protocol(void *desc, uint8_t l4_protocol)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, L4_PROTOCOL) |=
		HAL_TX_SM(TCL_ASSIST_CMD, L4_PROTOCOL, l4_protocol);
}

/*TODO: Add LCE HAL APIs */

/**
 * hal_tx_desc_set_encap_length() - Set encap_length_change
 *
 * @desc: Handle to Tx Descriptor
 * @encap_length: encap_length for packet type
 *
 * Return: void
 */
static inline void hal_tx_desc_set_encap_length(void *desc,
						uint8_t encap_length)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, ENCAP_LENGTH_CHANGE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, ENCAP_LENGTH_CHANGE, encap_length);
}

/**
 * hal_tx_desc_is_encap_len_descreased() - is_encap_len_descreased
 *
 * @desc: Handle to Tx Descriptor
 * @is_encap_len_descreased: is_encap_len_descreased
 *
 * Return: void
 */
static inline void
hal_tx_desc_is_encap_len_descreased(void *desc,	uint8_t is_encap_len_descreased)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, ENCAP_LENGTH_DECREASE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, ENCAP_LENGTH_DECREASE,
			  is_encap_len_descreased);
}

/**
 * hal_tx_desc_set_encap_length_override() - encap_length_override
 *
 * @desc: Handle to Tx Descriptor
 * @encap_length_override: encap_length_override
 *
 * Return: void
 */
static inline void
hal_tx_desc_set_encap_length_override(void *desc, uint8_t encap_length_override)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, ENCAP_LENGTH_OVERRIDE) |=
		HAL_TX_SM(TCL_ASSIST_CMD, ENCAP_LENGTH_OVERRIDE,
			  encap_length_override);
}

/**
 * hal_tx_desc_set_type_or_length() - Set type_or_length
 *
 * @desc: Handle to Tx Descriptor
 * @type_or_length: type_or_length
 *
 * Return: void
 */
static inline void hal_tx_desc_set_type_or_length(void *desc,
						  uint8_t type_or_length)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, TYPE_OR_LENGTH) |=
		HAL_TX_SM(TCL_ASSIST_CMD, TYPE_OR_LENGTH, type_or_length);
}

/* TODO: SNAP_OUI_FIELDS_REQUIRED */

/**
 * hal_tx_desc_set_s_vlan_tag() - Set S_VLAN_TAG_PRESENT
 *
 * @desc: Handle to Tx Descriptor
 * @s_vlan_present: is s_vlan present
 *
 * Return: void
 */
static inline void hal_tx_desc_set_s_vlan_tag(void *desc,
					      uint8_t s_vlan_present)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, S_VLAN_TAG_PRESENT) |=
		HAL_TX_SM(TCL_ASSIST_CMD, S_VLAN_TAG_PRESENT, s_vlan_present);
}

/**
 * hal_tx_desc_set_c_vlan_tag() - Set C_VLAN_TAG_PRESENT
 *
 * @desc: Handle to Tx Descriptor
 * @c_vlan_present: is c_vlan present
 *
 * Return: void
 */
static inline void hal_tx_desc_set_c_vlan_tag(void *desc,
					      uint8_t c_vlan_present)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, C_VLAN_TAG_PRESENT) |=
		HAL_TX_SM(TCL_ASSIST_CMD, C_VLAN_TAG_PRESENT, c_vlan_present);
}

/**
 * hal_tx_desc_set_snap_oui_zero_or_f8() - Set snap_oui_zero_or_f8
 *
 * @desc: Handle to Tx Descriptor
 * @is_snap_oui_zero_or_f8: is snap_oui_zero_or_f8 present
 *
 * Return: void
 */
static inline void
hal_tx_desc_set_snap_oui_zero_or_f8(void *desc, uint8_t is_snap_oui_zero_or_f8)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, SNAP_OUI_ZERO_OR_F8) |=
	 HAL_TX_SM(TCL_ASSIST_CMD, SNAP_OUI_ZERO_OR_F8, is_snap_oui_zero_or_f8);
}

/**
 * hal_tx_desc_set_snap_oui_not_zero_or_not_f8() - Set
 *						snap_oui_not_zero_or_not_f8
 *
 * @desc: Handle to Tx Descriptor
 * @is_snap_oui_not_zero_or_not_f8: is snap_oui_not_zero_or_f8 present
 *
 * Return: void
 */
static inline void hal_tx_desc_set_snap_oui_not_zero_or_not_f8(void *desc,
					uint8_t is_snap_oui_not_zero_or_not_f8)
{
	HAL_SET_FLD(desc, TCL_ASSIST_CMD, SNAP_OUI_NOT_ZERO_AND_NOT_F8) |=
	 HAL_TX_SM(TCL_ASSIST_CMD, SNAP_OUI_NOT_ZERO_AND_NOT_F8,
		   is_snap_oui_not_zero_or_not_f8);
}

/**
 * hal_tx_desc_set_da_is_bcast_mcast() - Set da is bcast or mcast
 *
 * @desc: Handle to Tx Descriptor
 * @is_bcast: is broadcast
 * @is_mcast: is multicast
 *
 * Return: void
 */
static inline void hal_tx_desc_set_da_is_bcast_mcast(void *desc,
						     uint8_t is_bcast,
						     uint8_t is_mcast)
{
	/* It is more optimal to do this check at caller, but this is
	 * HAL specific, so checking here.
	 */
	if (qdf_unlikely(is_bcast || is_mcast))
		HAL_SET_FLD(desc, TCL_ASSIST_CMD, DA_IS_BCAST_MCAST) |=
			HAL_TX_SM(TCL_ASSIST_CMD, DA_IS_BCAST_MCAST, 1);

	HAL_SET_FLD(desc, TCL_ASSIST_CMD, DA_IS_BCAST) |=
		HAL_TX_SM(TCL_ASSIST_CMD, DA_IS_BCAST, is_bcast);
}
#endif /* _HAL_BN_TX_H_ */
