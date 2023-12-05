/*
 * Copyright (c) 2020-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include "qdf_types.h"
#include "qdf_util.h"
#include "qdf_types.h"
#include "qdf_lock.h"
#include "qdf_mem.h"
#include "qdf_nbuf.h"
#include "hal_internal.h"
#include "hal_api.h"
#include "target_type.h"
#include "wcss_version.h"
#include "qdf_module.h"
#include "hal_flow.h"
#include "rx_flow_search_entry.h"
#include "hal_rx_flow_info.h"

#define UNIFIED_RXPCU_PPDU_END_INFO_8_RX_PPDU_DURATION_OFFSET \
	RXPCU_PPDU_END_INFO_9_RX_PPDU_DURATION_OFFSET
#define UNIFIED_RXPCU_PPDU_END_INFO_8_RX_PPDU_DURATION_MASK \
	RXPCU_PPDU_END_INFO_9_RX_PPDU_DURATION_MASK
#define UNIFIED_RXPCU_PPDU_END_INFO_8_RX_PPDU_DURATION_LSB \
	RXPCU_PPDU_END_INFO_9_RX_PPDU_DURATION_LSB
#define UNIFIED_PHYRX_HT_SIG_0_HT_SIG_INFO_PHYRX_HT_SIG_INFO_DETAILS_OFFSET \
	PHYRX_L_SIG_B_0_PHYRX_L_SIG_B_INFO_DETAILS_RATE_OFFSET
#define UNIFIED_PHYRX_L_SIG_B_0_L_SIG_B_INFO_PHYRX_L_SIG_B_INFO_DETAILS_OFFSET \
	PHYRX_L_SIG_B_0_PHYRX_L_SIG_B_INFO_DETAILS_RATE_OFFSET
#define UNIFIED_PHYRX_L_SIG_A_0_L_SIG_A_INFO_PHYRX_L_SIG_A_INFO_DETAILS_OFFSET \
	PHYRX_L_SIG_A_0_PHYRX_L_SIG_A_INFO_DETAILS_RATE_OFFSET
#define UNIFIED_PHYRX_VHT_SIG_A_0_VHT_SIG_A_INFO_PHYRX_VHT_SIG_A_INFO_DETAILS_OFFSET \
	PHYRX_VHT_SIG_A_0_PHYRX_VHT_SIG_A_INFO_DETAILS_BANDWIDTH_OFFSET
#define UNIFIED_PHYRX_HE_SIG_A_SU_0_HE_SIG_A_SU_INFO_PHYRX_HE_SIG_A_SU_INFO_DETAILS_OFFSET \
	PHYRX_HE_SIG_A_SU_0_PHYRX_HE_SIG_A_SU_INFO_DETAILS_FORMAT_INDICATION_OFFSET
#define UNIFIED_PHYRX_HE_SIG_A_MU_DL_0_HE_SIG_A_MU_DL_INFO_PHYRX_HE_SIG_A_MU_DL_INFO_DETAILS_OFFSET \
	PHYRX_HE_SIG_A_MU_DL_0_PHYRX_HE_SIG_A_MU_DL_INFO_DETAILS_DL_UL_FLAG_OFFSET
#define UNIFIED_PHYRX_HE_SIG_B1_MU_0_HE_SIG_B1_MU_INFO_PHYRX_HE_SIG_B1_MU_INFO_DETAILS_OFFSET \
	PHYRX_HE_SIG_B1_MU_0_PHYRX_HE_SIG_B1_MU_INFO_DETAILS_RU_ALLOCATION_OFFSET
#define UNIFIED_PHYRX_HE_SIG_B2_MU_0_HE_SIG_B2_MU_INFO_PHYRX_HE_SIG_B2_MU_INFO_DETAILS_OFFSET \
	PHYRX_HE_SIG_B2_MU_0_PHYRX_HE_SIG_B2_MU_INFO_DETAILS_STA_ID_OFFSET
#define UNIFIED_PHYRX_HE_SIG_B2_OFDMA_0_HE_SIG_B2_OFDMA_INFO_PHYRX_HE_SIG_B2_OFDMA_INFO_DETAILS_OFFSET \
	PHYRX_HE_SIG_B2_OFDMA_0_PHYRX_HE_SIG_B2_OFDMA_INFO_DETAILS_STA_ID_OFFSET

#define UNIFIED_PHYRX_RSSI_LEGACY_3_RECEIVE_RSSI_INFO_PRE_RSSI_INFO_DETAILS_OFFSET \
	PHYRX_RSSI_LEGACY_3_RECEIVE_RSSI_INFO_PRE_RSSI_INFO_DETAILS_OFFSET
#define UNIFIED_PHYRX_RSSI_LEGACY_19_RECEIVE_RSSI_INFO_PREAMBLE_RSSI_INFO_DETAILS_OFFSET \
	PHYRX_RSSI_LEGACY_19_PREAMBLE_RSSI_INFO_DETAILS_RSSI_PRI20_CHAIN0_OFFSET
#define UNIFIED_RX_MPDU_START_0_RX_MPDU_INFO_RX_MPDU_INFO_DETAILS_OFFSET \
	RX_MPDU_START_0_RX_MPDU_INFO_DETAILS_RXPT_CLASSIFY_INFO_DETAILS_REO_DESTINATION_INDICATION_OFFSET
#define UNIFIED_RX_MSDU_LINK_8_RX_MSDU_DETAILS_MSDU_0_OFFSET \
	RX_MSDU_LINK_8_RX_MSDU_DETAILS_MSDU_0_OFFSET
#define UNIFIED_RX_MSDU_DETAILS_2_RX_MSDU_DESC_INFO_RX_MSDU_DESC_INFO_DETAILS_OFFSET \
	RX_MSDU_DETAILS_2_RX_MSDU_DESC_INFO_RX_MSDU_DESC_INFO_DETAILS_OFFSET
#define UNIFIED_RX_MPDU_DETAILS_2_RX_MPDU_DESC_INFO_RX_MPDU_DESC_INFO_DETAILS_OFFSET \
	RX_MPDU_DETAILS_2_RX_MPDU_DESC_INFO_RX_MPDU_DESC_INFO_DETAILS_OFFSET
#define UNIFIED_REO_DESTINATION_RING_2_RX_MPDU_DESC_INFO_RX_MPDU_DESC_INFO_DETAILS_OFFSET \
	REO_DESTINATION_RING_2_RX_MPDU_DESC_INFO_RX_MPDU_DESC_INFO_DETAILS_OFFSET
#define UNIFORM_REO_STATUS_HEADER_STATUS_HEADER_GENERIC \
	UNIFORM_REO_STATUS_HEADER_STATUS_HEADER
#define UNIFIED_RX_MSDU_DETAILS_2_RX_MSDU_DESC_INFO_RX_MSDU_DESC_INFO_DETAILS_OFFSET \
	RX_MSDU_DETAILS_2_RX_MSDU_DESC_INFO_RX_MSDU_DESC_INFO_DETAILS_OFFSET
#define UNIFIED_RX_MSDU_LINK_8_RX_MSDU_DETAILS_MSDU_0_OFFSET \
	RX_MSDU_LINK_8_RX_MSDU_DETAILS_MSDU_0_OFFSET

#define UNIFIED_TCL_DATA_CMD_0_BUFFER_ADDR_INFO_BUF_ADDR_INFO_OFFSET \
	TCL_DATA_CMD_0_BUF_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET
#define UNIFIED_BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_LSB \
	BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_LSB
#define UNIFIED_BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_MASK \
	BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_MASK
#define UNIFIED_TCL_DATA_CMD_1_BUFFER_ADDR_INFO_BUF_ADDR_INFO_OFFSET \
	TCL_DATA_CMD_1_BUF_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET
#define UNIFIED_BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_LSB \
	BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_LSB
#define UNIFIED_BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_MASK \
	BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_MASK
#define UNIFIED_BUFFER_ADDR_INFO_1_RETURN_BUFFER_MANAGER_LSB \
	BUFFER_ADDR_INFO_1_RETURN_BUFFER_MANAGER_LSB
#define UNIFIED_BUFFER_ADDR_INFO_1_RETURN_BUFFER_MANAGER_MASK \
	BUFFER_ADDR_INFO_1_RETURN_BUFFER_MANAGER_MASK
#define UNIFIED_BUFFER_ADDR_INFO_1_SW_BUFFER_COOKIE_LSB \
	BUFFER_ADDR_INFO_1_SW_BUFFER_COOKIE_LSB
#define UNIFIED_BUFFER_ADDR_INFO_1_SW_BUFFER_COOKIE_MASK \
	BUFFER_ADDR_INFO_1_SW_BUFFER_COOKIE_MASK
#define UNIFIED_TCL_DATA_CMD_2_BUF_OR_EXT_DESC_TYPE_OFFSET \
	TCL_DATA_CMD_2_BUF_OR_EXT_DESC_TYPE_OFFSET
#define UNIFIED_TCL_DATA_CMD_2_BUF_OR_EXT_DESC_TYPE_LSB \
	TCL_DATA_CMD_2_BUF_OR_EXT_DESC_TYPE_LSB
#define UNIFIED_TCL_DATA_CMD_2_BUF_OR_EXT_DESC_TYPE_MASK \
	TCL_DATA_CMD_2_BUF_OR_EXT_DESC_TYPE_MASK

#include "hal_wcn6450_tx.h"
#include "hal_wcn6450_rx.h"
#include <hal_generic_api.h>
#include "hal_rh_rx.h"
#include "hal_rh_api.h"
#include "hal_api_mon.h"
#include "hal_rh_generic_api.h"

struct hal_hw_srng_config hw_srng_table_wcn6450[] = {
	/* TODO: max_rings can populated by querying HW capabilities */
	{/* REO_DST */ 0},
	{/* REO_EXCEPTION */ 0},
	{/* REO_REINJECT */ 0},
	{/* REO_CMD */ 0},
	{/* REO_STATUS */ 0},
	{/* TCL_DATA */ 0},
	{/* TCL_CMD */ 0},
	{/* TCL_STATUS */ 0},
	{/* CE_SRC */ 0},
	{/* CE_DST */ 0},
	{/* CE_DST_STATUS */ 0},
	{/* WBM_IDLE_LINK */ 0},
	{/* SW2WBM_RELEASE */ 0},
	{/* WBM2SW_RELEASE */ 0},
	{ /* RXDMA_BUF */
		.start_ring_id = HAL_SRNG_WMAC1_SW2RXDMA0_BUF0,
#ifdef IPA_OFFLOAD
		.max_rings = 3,
#else
		.max_rings = 2,
#endif
		.entry_size = sizeof(struct wbm_buffer_ring) >> 2,
		.lmac_ring = TRUE,
		.ring_dir = HAL_SRNG_SRC_RING,
		/* reg_start is not set because LMAC rings are not accessed
		 * from host
		 */
		.reg_start = {},
		.reg_size = {},
		.max_size = HAL_RXDMA_MAX_RING_SIZE,
	},
	{ /* RXDMA_DST */
		.start_ring_id = HAL_SRNG_WMAC1_RXDMA2SW0,
		.max_rings = 1,
		.entry_size = sizeof(struct reo_entrance_ring) >> 2,
		.lmac_ring =  TRUE,
		.ring_dir = HAL_SRNG_DST_RING,
		/* reg_start is not set because LMAC rings are not accessed
		 * from host
		 */
		.reg_start = {},
		.reg_size = {},
		.max_size = HAL_RXDMA_MAX_RING_SIZE,
	},
	{/* RXDMA_MONITOR_BUF */ 0},
	{ /* RXDMA_MONITOR_STATUS */
		.start_ring_id = HAL_SRNG_WMAC1_SW2RXDMA1_STATBUF,
		.max_rings = 1,
		.entry_size = sizeof(struct wbm_buffer_ring) >> 2,
		.lmac_ring = TRUE,
		.ring_dir = HAL_SRNG_SRC_RING,
		/* reg_start is not set because LMAC rings are not accessed
		 * from host
		 */
		.reg_start = {},
		.reg_size = {},
		.max_size = HAL_RXDMA_MAX_RING_SIZE,
	},
	{/* RXDMA_MONITOR_DST */ 0},
	{/* RXDMA_MONITOR_DESC */ 0},
	{/* DIR_BUF_RX_DMA_SRC */
		.start_ring_id = HAL_SRNG_DIR_BUF_RX_SRC_DMA_RING,
		/*
		 * one ring is for spectral scan
		 * the other is for cfr
		 */
		.max_rings = 2,
		.entry_size = 2,
		.lmac_ring = TRUE,
		.ring_dir = HAL_SRNG_SRC_RING,
		/* reg_start is not set because LMAC rings are not accessed
		 * from host
		 */
		.reg_start = {},
		.reg_size = {},
		.max_size = HAL_RXDMA_MAX_RING_SIZE,
	},
#ifdef WLAN_FEATURE_CIF_CFR
	{/* WIFI_POS_SRC */
		.start_ring_id = HAL_SRNG_WIFI_POS_SRC_DMA_RING,
		.max_rings = 1,
		.entry_size = sizeof(wmi_oem_dma_buf_release_entry)  >> 2,
		.lmac_ring = TRUE,
		.ring_dir = HAL_SRNG_SRC_RING,
		/* reg_start is not set because LMAC rings are not accessed
		 * from host
		 */
		.reg_start = {},
		.reg_size = {},
		.max_size = HAL_RXDMA_MAX_RING_SIZE,
	},
#endif
	{ /* REO2PPE */ 0},
	{ /* PPE2TCL */ 0},
	{ /* PPE_RELEASE */ 0},
	{ /* TX_MONITOR_BUF */ 0},
	{ /* TX_MONITOR_DST */ 0},
	{ /* SW2RXDMA_NEW */ 0},
	{ /* SW2RXDMA_LINK_RELEASE */
		.start_ring_id = HAL_SRNG_WMAC1_SW2RXDMA_LINK_RING,
		.max_rings = 1,
		.entry_size = sizeof(struct wbm_buffer_ring) >> 2,
		.lmac_ring = TRUE,
		.ring_dir = HAL_SRNG_SRC_RING,
		/* reg_start is not set because LMAC rings are not accessed
		 * from host
		 */
		.reg_start = {},
		.reg_size = {},
		.max_size = HAL_RXDMA_MAX_RING_SIZE,
	},

};

static void hal_get_hw_hptp_6450(struct hal_soc *hal_soc,
				 hal_ring_handle_t hal_ring_hdl,
				 uint32_t *headp, uint32_t *tailp,
				 uint8_t ring)
{
}

static void hal_reo_setup_6450(struct hal_soc *soc, void *reoparams,
			       int qref_reset)
{
}

static void hal_reo_set_err_dst_remap_6450(void *hal_soc)
{
}

static void hal_tx_desc_set_dscp_tid_table_id_6450(void *desc, uint8_t id)
{
}

static void hal_tx_set_dscp_tid_map_6450(struct hal_soc *hal_soc,
					 uint8_t *map, uint8_t id)
{
}

static void hal_tx_update_dscp_tid_6450(struct hal_soc *hal_soc, uint8_t tid,
					uint8_t id, uint8_t dscp)
{
}

static uint8_t hal_tx_comp_get_release_reason_6450(void *hal_desc)
{
	return 0;
}

static uint8_t hal_get_wbm_internal_error_6450(void *hal_desc)
{
	return 0;
}

static void hal_tx_init_cmd_credit_ring_6450(hal_soc_handle_t hal_soc_hdl,
					     hal_ring_handle_t hal_ring_hdl)
{
}

#define LINK_DESC_SIZE (NUM_OF_DWORDS_RX_MSDU_LINK << 2)
static uint32_t hal_get_link_desc_size_6450(void)
{
	return LINK_DESC_SIZE;
}

static void hal_reo_status_get_header_6450(hal_ring_desc_t ring_desc,
					   int b, void *h1)
{
}

static void hal_rx_wbm_err_info_get_6450(void *wbm_desc,
					 void *wbm_er_info1)
{
}

static bool hal_rx_is_unicast_6450(uint8_t *buf)
{
	return true;
}

static uint32_t hal_rx_tid_get_6450(hal_soc_handle_t hal_soc_hdl, uint8_t *buf)
{
	return 0;
}

static void *hal_rx_msdu0_buffer_addr_lsb_6450(void *link_desc_va)
{
	return NULL;
}

static void *hal_rx_msdu_desc_info_ptr_get_6450(void *msdu0)
{
	return NULL;
}

static void *hal_ent_mpdu_desc_info_6450(void *ent_ring_desc)
{
	return NULL;
}

static void *hal_dst_mpdu_desc_info_6450(void *dst_ring_desc)
{
	return NULL;
}

static uint8_t hal_rx_get_fc_valid_6450(uint8_t *buf)
{
	return HAL_RX_GET_FC_VALID(buf);
}

static uint8_t hal_rx_get_to_ds_flag_6450(uint8_t *buf)
{
	return HAL_RX_GET_TO_DS_FLAG(buf);
}

static uint8_t hal_rx_get_mac_addr2_valid_6450(uint8_t *buf)
{
	return HAL_RX_GET_MAC_ADDR2_VALID(buf);
}

static uint8_t hal_rx_get_filter_category_6450(uint8_t *buf)
{
	return HAL_RX_GET_FILTER_CATEGORY(buf);
}

static void hal_reo_config_6450(struct hal_soc *soc,
				uint32_t reg_val,
				struct hal_reo_params *reo_params)
{
}

/**
 * hal_rx_msdu_flow_idx_get_6450: API to get flow index
 * from rx_msdu_end TLV
 * @buf: pointer to the start of RX PKT TLV headers
 *
 * Return: flow index value from MSDU END TLV
 */
static inline uint32_t hal_rx_msdu_flow_idx_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	return HAL_RX_MSDU_END_FLOW_IDX_GET(msdu_end);
}

static void hal_compute_reo_remap_ix2_ix3_6450(uint32_t *ring,
					       uint32_t num_rings,
					       uint32_t *remap1,
					       uint32_t *remap2)
{
}

static void
hal_setup_link_idle_list_6450(struct hal_soc *soc,
			      qdf_dma_addr_t scatter_bufs_base_paddr[],
			      void *scatter_bufs_base_vaddr[],
			      uint32_t num_scatter_bufs,
			      uint32_t scatter_buf_size,
			      uint32_t last_buf_end_offset,
			      uint32_t num_entries)
{
}

static void hal_compute_reo_remap_ix0_6450(uint32_t *remap0)
{
}

#define UMAC_WINDOW_REMAP_RANGE 0x14
#define CE_WINDOW_REMAP_RANGE 0X37
#define CMEM_WINDOW_REMAP_RANGE 0x2

/**
 * hal_get_window_address_6450(): Function to get the ioremap address
 * @hal_soc: Pointer to hal_soc
 * @addr: address offset of register
 *
 * Return: modified address offset of register
 */
static inline qdf_iomem_t hal_get_window_address_6450(struct hal_soc *hal_soc,
						      qdf_iomem_t addr)
{
	uint32_t offset;
	uint32_t window;
	uint8_t scale;

	offset = addr - hal_soc->dev_base_addr;
	window = (offset >> WINDOW_SHIFT) & WINDOW_VALUE_MASK;

	/* UMAC: 2nd window(unused) CE: 3rd window, CMEM: 4th window */
	switch (window) {
	case UMAC_WINDOW_REMAP_RANGE:
		scale = 1;
		break;
	case CE_WINDOW_REMAP_RANGE:
		scale = 2;
		break;
	case CMEM_WINDOW_REMAP_RANGE:
		scale = 3;
		break;
	default:
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
			  "%s: ERROR: Accessing Wrong register\n", __func__);
		qdf_assert_always(0);
		return 0;
	}

	return hal_soc->dev_base_addr + (scale * WINDOW_START) +
		(offset & WINDOW_RANGE_MASK);
}

/*
 * hal_rx_msdu_start_nss_get_6450(): API to get the NSS
 * Interval from rx_msdu_start
 *
 * @buf: pointer to the start of RX PKT TLV header
 * Return: uint32_t(nss)
 */
static uint32_t hal_rx_msdu_start_nss_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_start *msdu_start =
		&pkt_tlvs->msdu_start_tlv.rx_msdu_start;
	uint8_t mimo_ss_bitmap;

	mimo_ss_bitmap = HAL_RX_MSDU_START_MIMO_SS_BITMAP(msdu_start);

	return qdf_get_hweight8(mimo_ss_bitmap);
}

/**
 * hal_rx_mon_hw_desc_get_mpdu_status_6450(): Retrieve MPDU status
 *
 * @hw_desc_addr: Start address of Rx HW TLVs
 * @rs: Status for monitor mode
 *
 * Return: void
 */
static void hal_rx_mon_hw_desc_get_mpdu_status_6450(void *hw_desc_addr,
						    struct mon_rx_status *rs)
{
	struct rx_msdu_start *rx_msdu_start;
	struct rx_pkt_tlvs *rx_desc = (struct rx_pkt_tlvs *)hw_desc_addr;
	uint32_t reg_value;
	const uint32_t sgi_hw_to_cdp[] = {
		CDP_SGI_0_8_US,
		CDP_SGI_0_4_US,
		CDP_SGI_1_6_US,
		CDP_SGI_3_2_US,
	};

	rx_msdu_start = &rx_desc->msdu_start_tlv.rx_msdu_start;

	HAL_RX_GET_MSDU_AGGREGATION(rx_desc, rs);

	rs->ant_signal_db = HAL_RX_GET(rx_msdu_start,
				       RX_MSDU_START_5, USER_RSSI);
	rs->is_stbc = HAL_RX_GET(rx_msdu_start, RX_MSDU_START_5, STBC);

	reg_value = HAL_RX_GET(rx_msdu_start, RX_MSDU_START_5, SGI);
	rs->sgi = sgi_hw_to_cdp[reg_value];

	reg_value = HAL_RX_GET(rx_msdu_start, RX_MSDU_START_5, RECEPTION_TYPE);
	rs->beamformed = (reg_value == HAL_RX_RECEPTION_TYPE_MU_MIMO) ? 1 : 0;
	/* TODO: rs->beamformed should be set for SU beamforming also */
}

/*
 * hal_rx_get_tlv_6450(): API to get the tlv
 *
 * @rx_tlv: TLV data extracted from the rx packet
 * Return: uint8_t
 */
static uint8_t hal_rx_get_tlv_6450(void *rx_tlv)
{
	return HAL_RX_GET(rx_tlv, PHYRX_RSSI_LEGACY_0, RECEIVE_BANDWIDTH);
}

/**
 * hal_rx_proc_phyrx_other_receive_info_tlv_6450()
 *                                  - process other receive info TLV
 * @rx_tlv_hdr: pointer to TLV header
 * @ppdu_info_handle: pointer to ppdu_info
 *
 * Return: None
 */
static
void hal_rx_proc_phyrx_other_receive_info_tlv_6450(void *rx_tlv_hdr,
						   void *ppdu_info_handle)
{
	uint32_t tlv_tag, tlv_len;
	uint32_t temp_len, other_tlv_len, other_tlv_tag;
	void *rx_tlv = (uint8_t *)rx_tlv_hdr + HAL_RX_TLV32_HDR_SIZE;
	void *other_tlv_hdr = NULL;
	void *other_tlv = NULL;

	tlv_tag = HAL_RX_GET_USER_TLV32_TYPE(rx_tlv_hdr);
	tlv_len = HAL_RX_GET_USER_TLV32_LEN(rx_tlv_hdr);
	temp_len = 0;

	other_tlv_hdr = rx_tlv + HAL_RX_TLV32_HDR_SIZE;

	other_tlv_tag = HAL_RX_GET_USER_TLV32_TYPE(other_tlv_hdr);
	other_tlv_len = HAL_RX_GET_USER_TLV32_LEN(other_tlv_hdr);
	temp_len += other_tlv_len;
	other_tlv = other_tlv_hdr + HAL_RX_TLV32_HDR_SIZE;

	switch (other_tlv_tag) {
	default:
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
			  "%s unhandled TLV type: %d, TLV len:%d",
			  __func__, other_tlv_tag, other_tlv_len);
		break;
	}
}

/**
 * hal_rx_dump_msdu_start_tlv_6450() : dump RX msdu_start TLV in structured
 *				       human readable format.
 * @pkttlvs: pointer to pkttlvs.
 * @dbg_level: log level.
 *
 * Return: void
 */
static void hal_rx_dump_msdu_start_tlv_6450(void *pkttlvs, uint8_t dbg_level)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)pkttlvs;
	struct rx_msdu_start *msdu_start =
					&pkt_tlvs->msdu_start_tlv.rx_msdu_start;

	hal_verbose_debug(
			  "rx_msdu_start tlv (1/2) - "
			  "rxpcu_mpdu_filter_in_category: %x "
			  "sw_frame_group_id: %x "
			  "phy_ppdu_id: %x "
			  "msdu_length: %x "
			  "ipsec_esp: %x "
			  "l3_offset: %x "
			  "ipsec_ah: %x "
			  "l4_offset: %x "
			  "msdu_number: %x "
			  "decap_format: %x "
			  "ipv4_proto: %x "
			  "ipv6_proto: %x "
			  "tcp_proto: %x "
			  "udp_proto: %x "
			  "ip_frag: %x "
			  "tcp_only_ack: %x "
			  "da_is_bcast_mcast: %x "
			  "ip4_protocol_ip6_next_header: %x "
			  "toeplitz_hash_2_or_4: %x "
			  "flow_id_toeplitz: %x "
			  "user_rssi: %x "
			  "pkt_type: %x "
			  "stbc: %x "
			  "sgi: %x "
			  "rate_mcs: %x "
			  "receive_bandwidth: %x "
			  "reception_type: %x "
			  "ppdu_start_timestamp: %u ",
			  msdu_start->rxpcu_mpdu_filter_in_category,
			  msdu_start->sw_frame_group_id,
			  msdu_start->phy_ppdu_id,
			  msdu_start->msdu_length,
			  msdu_start->ipsec_esp,
			  msdu_start->l3_offset,
			  msdu_start->ipsec_ah,
			  msdu_start->l4_offset,
			  msdu_start->msdu_number,
			  msdu_start->decap_format,
			  msdu_start->ipv4_proto,
			  msdu_start->ipv6_proto,
			  msdu_start->tcp_proto,
			  msdu_start->udp_proto,
			  msdu_start->ip_frag,
			  msdu_start->tcp_only_ack,
			  msdu_start->da_is_bcast_mcast,
			  msdu_start->ip4_protocol_ip6_next_header,
			  msdu_start->toeplitz_hash_2_or_4,
			  msdu_start->flow_id_toeplitz,
			  msdu_start->user_rssi,
			  msdu_start->pkt_type,
			  msdu_start->stbc,
			  msdu_start->sgi,
			  msdu_start->rate_mcs,
			  msdu_start->receive_bandwidth,
			  msdu_start->reception_type,
			  msdu_start->ppdu_start_timestamp);

	hal_verbose_debug(
			  "rx_msdu_start tlv (2/2) - "
			  "sw_phy_meta_data: %x ",
			  msdu_start->sw_phy_meta_data);
}

/**
 * hal_rx_dump_msdu_end_tlv_6450: dump RX msdu_end TLV in structured
 *				  human readable format.
 * @pkttlvs: pointer to pkttlvs.
 * @dbg_level: log level.
 *
 * Return: void
 */
static void hal_rx_dump_msdu_end_tlv_6450(void *pkttlvs,
					  uint8_t dbg_level)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)pkttlvs;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	__QDF_TRACE_RL(dbg_level, QDF_MODULE_ID_DP,
		       "rx_msdu_end tlv (1/3) - "
		       "rxpcu_mpdu_filter_in_category: %x "
		       "sw_frame_group_id: %x "
		       "phy_ppdu_id: %x "
		       "ip_hdr_chksum: %x "
		       "tcp_udp_chksum: %x "
		       "key_id_octet: %x "
		       "cce_super_rule: %x "
		       "cce_classify_not_done_truncat: %x "
		       "cce_classify_not_done_cce_dis: %x "
		       "reported_mpdu_length: %x "
		       "first_msdu: %x "
		       "last_msdu: %x "
		       "sa_idx_timeout: %x "
		       "da_idx_timeout: %x "
		       "msdu_limit_error: %x "
		       "flow_idx_timeout: %x "
		       "flow_idx_invalid: %x "
		       "wifi_parser_error: %x "
		       "amsdu_parser_error: %x",
		       msdu_end->rxpcu_mpdu_filter_in_category,
		       msdu_end->sw_frame_group_id,
		       msdu_end->phy_ppdu_id,
		       msdu_end->ip_hdr_chksum,
		       msdu_end->tcp_udp_chksum,
		       msdu_end->key_id_octet,
		       msdu_end->cce_super_rule,
		       msdu_end->cce_classify_not_done_truncate,
		       msdu_end->cce_classify_not_done_cce_dis,
		       msdu_end->reported_mpdu_length,
		       msdu_end->first_msdu,
		       msdu_end->last_msdu,
		       msdu_end->sa_idx_timeout,
		       msdu_end->da_idx_timeout,
		       msdu_end->msdu_limit_error,
		       msdu_end->flow_idx_timeout,
		       msdu_end->flow_idx_invalid,
		       msdu_end->wifi_parser_error,
		       msdu_end->amsdu_parser_error);

	__QDF_TRACE_RL(dbg_level, QDF_MODULE_ID_DP,
		       "rx_msdu_end tlv (2/3)- "
		       "sa_is_valid: %x "
		       "da_is_valid: %x "
		       "da_is_mcbc: %x "
		       "l3_header_padding: %x "
		       "ipv6_options_crc: %x "
		       "tcp_seq_number: %x "
		       "tcp_ack_number: %x "
		       "tcp_flag: %x "
		       "lro_eligible: %x "
		       "window_size: %x "
		       "da_offset: %x "
		       "sa_offset: %x "
		       "da_offset_valid: %x "
		       "sa_offset_valid: %x "
		       "rule_indication_31_0: %x "
		       "rule_indication_63_32: %x "
		       "sa_idx: %x "
		       "da_idx: %x "
		       "msdu_drop: %x "
		       "reo_destination_indication: %x "
		       "flow_idx: %x "
		       "fse_metadata: %x "
		       "cce_metadata: %x "
		       "sa_sw_peer_id: %x ",
		       msdu_end->sa_is_valid,
		       msdu_end->da_is_valid,
		       msdu_end->da_is_mcbc,
		       msdu_end->l3_header_padding,
		       msdu_end->ipv6_options_crc,
		       msdu_end->tcp_seq_number,
		       msdu_end->tcp_ack_number,
		       msdu_end->tcp_flag,
		       msdu_end->lro_eligible,
		       msdu_end->window_size,
		       msdu_end->da_offset,
		       msdu_end->sa_offset,
		       msdu_end->da_offset_valid,
		       msdu_end->sa_offset_valid,
		       msdu_end->rule_indication_31_0,
		       msdu_end->rule_indication_63_32,
		       msdu_end->sa_idx,
		       msdu_end->da_idx_or_sw_peer_id,
		       msdu_end->msdu_drop,
		       msdu_end->reo_destination_indication,
		       msdu_end->flow_idx,
		       msdu_end->fse_metadata,
		       msdu_end->cce_metadata,
		       msdu_end->sa_sw_peer_id);
	__QDF_TRACE_RL(dbg_level, QDF_MODULE_ID_DP,
		       "rx_msdu_end tlv (3/3)"
		       "aggregation_count %x "
		       "flow_aggregation_continuation %x "
		       "fisa_timeout %x "
		       "cumulative_l4_checksum %x "
		       "cumulative_ip_length %x",
		       msdu_end->aggregation_count,
		       msdu_end->flow_aggregation_continuation,
		       msdu_end->fisa_timeout,
		       msdu_end->cumulative_l4_checksum,
		       msdu_end->cumulative_ip_length);
}

/*
 * Get tid from RX_MPDU_START
 */
#define HAL_RX_MPDU_INFO_TID_GET(_rx_mpdu_info) \
	(_HAL_MS((*_OFFSET_TO_WORD_PTR((_rx_mpdu_info),	\
		RX_MPDU_INFO_7_TID_OFFSET)),		\
		RX_MPDU_INFO_7_TID_MASK,		\
		RX_MPDU_INFO_7_TID_LSB))

static uint32_t hal_rx_mpdu_start_tid_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
			&pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;
	uint32_t tid;

	tid = HAL_RX_MPDU_INFO_TID_GET(&mpdu_start->rx_mpdu_info_details);

	return tid;
}

#define HAL_RX_MSDU_START_RECEPTION_TYPE_GET(_rx_msdu_start) \
	(_HAL_MS((*_OFFSET_TO_WORD_PTR((_rx_msdu_start),	\
	RX_MSDU_START_5_RECEPTION_TYPE_OFFSET)),	\
	RX_MSDU_START_5_RECEPTION_TYPE_MASK,		\
	RX_MSDU_START_5_RECEPTION_TYPE_LSB))

/*
 * hal_rx_msdu_start_reception_type_get(): API to get the reception type
 * Interval from rx_msdu_start
 *
 * @buf: pointer to the start of RX PKT TLV header
 * Return: uint32_t(reception_type)
 */
static
uint32_t hal_rx_msdu_start_reception_type_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_start *msdu_start =
		&pkt_tlvs->msdu_start_tlv.rx_msdu_start;
	uint32_t reception_type;

	reception_type = HAL_RX_MSDU_START_RECEPTION_TYPE_GET(msdu_start);

	return reception_type;
}

/**
 * hal_rx_msdu_end_da_idx_get_6450: API to get da_idx
 * from rx_msdu_end TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: da index
 */
static uint16_t hal_rx_msdu_end_da_idx_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;
	uint16_t da_idx;

	da_idx = HAL_RX_MSDU_END_DA_IDX_GET(msdu_end);

	return da_idx;
}

/**
 * hal_rx_msdu_desc_info_get_ptr_6450() - Get msdu desc info ptr
 * @msdu_details_ptr: Pointer to msdu_details_ptr
 *
 * Return - Pointer to rx_msdu_desc_info structure.
 *
 */
static void *hal_rx_msdu_desc_info_get_ptr_6450(void *msdu_details_ptr)
{
	return HAL_RX_MSDU_DESC_INFO_GET(msdu_details_ptr);
}

/**
 * hal_rx_link_desc_msdu0_ptr_6450 - Get pointer to rx_msdu details
 * @link_desc: Pointer to link desc
 *
 * Return - Pointer to rx_msdu_details structure
 *
 */
static void *hal_rx_link_desc_msdu0_ptr_6450(void *link_desc)
{
	return HAL_RX_LINK_DESC_MSDU0_PTR(link_desc);
}

/**
 * hal_rx_get_rx_fragment_number_6450(): Function to retrieve rx fragment number
 *
 * @buf: Network buffer
 * Returns: rx fragment number
 */
static
uint8_t hal_rx_get_rx_fragment_number_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = hal_rx_get_pkt_tlvs(buf);
	struct rx_mpdu_info *rx_mpdu_info = hal_rx_get_mpdu_info(pkt_tlvs);

	/* Return first 4 bits as fragment number */
	return (HAL_RX_MPDU_GET_SEQUENCE_NUMBER(rx_mpdu_info) &
		DOT11_SEQ_FRAG_MASK);
}

/**
 * hal_rx_msdu_end_da_is_mcbc_get_6450(): API to check if pkt is MCBC
 * from rx_msdu_end TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: da_is_mcbc
 */
static uint8_t
hal_rx_msdu_end_da_is_mcbc_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	return HAL_RX_MSDU_END_DA_IS_MCBC_GET(msdu_end);
}

/**
 * hal_rx_msdu_end_sa_is_valid_get_6450(): API to get_6450 the
 * sa_is_valid bit from rx_msdu_end TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: sa_is_valid bit
 */
static uint8_t
hal_rx_msdu_end_sa_is_valid_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;
	uint8_t sa_is_valid;

	sa_is_valid = HAL_RX_MSDU_END_SA_IS_VALID_GET(msdu_end);

	return sa_is_valid;
}

/**
 * hal_rx_msdu_end_sa_idx_get_6450(): API to get_6450 the
 * sa_idx from rx_msdu_end TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: sa_idx (SA AST index)
 */
static
uint16_t hal_rx_msdu_end_sa_idx_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;
	uint16_t sa_idx;

	sa_idx = HAL_RX_MSDU_END_SA_IDX_GET(msdu_end);

	return sa_idx;
}

/**
 * hal_rx_desc_is_first_msdu_6450() - Check if first msdu
 *
 * @hw_desc_addr: hardware descriptor address
 *
 * Return: 0 - success/ non-zero failure
 */
static uint32_t hal_rx_desc_is_first_msdu_6450(void *hw_desc_addr)
{
	struct rx_pkt_tlvs *rx_tlvs = (struct rx_pkt_tlvs *)hw_desc_addr;
	struct rx_msdu_end *msdu_end = &rx_tlvs->msdu_end_tlv.rx_msdu_end;

	return HAL_RX_GET(msdu_end, RX_MSDU_END_10, FIRST_MSDU);
}

/**
 * hal_rx_msdu_end_l3_hdr_padding_get_6450(): API to get_6450 the
 * l3_header padding from rx_msdu_end TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: number of l3 header padding bytes
 */
static uint32_t hal_rx_msdu_end_l3_hdr_padding_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;
	uint32_t l3_header_padding;

	l3_header_padding = HAL_RX_MSDU_END_L3_HEADER_PADDING_GET(msdu_end);

	return l3_header_padding;
}

/*
 * @ hal_rx_encryption_info_valid_6450: Returns encryption type.
 *
 * @ buf: rx_tlv_hdr of the received packet
 * @ Return: encryption type
 */
static uint32_t hal_rx_encryption_info_valid_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
				 &pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;
	struct rx_mpdu_info *mpdu_info = &mpdu_start->rx_mpdu_info_details;
	uint32_t encryption_info = HAL_RX_MPDU_ENCRYPTION_INFO_VALID(mpdu_info);

	return encryption_info;
}

/*
 * @ hal_rx_print_pn_6450: Prints the PN of rx packet.
 *
 * @ buf: rx_tlv_hdr of the received packet
 * @ Return: void
 */
static void hal_rx_print_pn_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
				 &pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;
	struct rx_mpdu_info *mpdu_info = &mpdu_start->rx_mpdu_info_details;

	uint32_t pn_31_0 = HAL_RX_MPDU_PN_31_0_GET(mpdu_info);
	uint32_t pn_63_32 = HAL_RX_MPDU_PN_63_32_GET(mpdu_info);
	uint32_t pn_95_64 = HAL_RX_MPDU_PN_95_64_GET(mpdu_info);
	uint32_t pn_127_96 = HAL_RX_MPDU_PN_127_96_GET(mpdu_info);

	hal_debug("PN number pn_127_96 0x%x pn_95_64 0x%x pn_63_32 0x%x pn_31_0 0x%x",
		  pn_127_96, pn_95_64, pn_63_32, pn_31_0);
}

/**
 * hal_rx_msdu_end_first_msdu_get_6450: API to get first msdu status
 * from rx_msdu_end TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: first_msdu
 */
static uint8_t hal_rx_msdu_end_first_msdu_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;
	uint8_t first_msdu;

	first_msdu = HAL_RX_MSDU_END_FIRST_MSDU_GET(msdu_end);

	return first_msdu;
}

/**
 * hal_rx_msdu_end_da_is_valid_get_6450: API to check if da is valid
 * from rx_msdu_end TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: da_is_valid
 */
static uint8_t hal_rx_msdu_end_da_is_valid_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;
	uint8_t da_is_valid;

	da_is_valid = HAL_RX_MSDU_END_DA_IS_VALID_GET(msdu_end);

	return da_is_valid;
}

/**
 * hal_rx_msdu_end_last_msdu_get_6450: API to get last msdu status
 * from rx_msdu_end TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: last_msdu
 */
static uint8_t hal_rx_msdu_end_last_msdu_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;
	uint8_t last_msdu;

	last_msdu = HAL_RX_MSDU_END_LAST_MSDU_GET(msdu_end);

	return last_msdu;
}

/*
 * hal_rx_get_mpdu_mac_ad4_valid_6450(): Retrieves if mpdu 4th addr is valid
 *
 * @nbuf: Network buffer
 * Returns: value of mpdu 4th address valid field
 */
static bool hal_rx_get_mpdu_mac_ad4_valid_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = hal_rx_get_pkt_tlvs(buf);
	struct rx_mpdu_info *rx_mpdu_info = hal_rx_get_mpdu_info(pkt_tlvs);
	bool ad4_valid = 0;

	ad4_valid = HAL_RX_MPDU_GET_MAC_AD4_VALID(rx_mpdu_info);

	return ad4_valid;
}

/**
 * hal_rx_mpdu_start_sw_peer_id_get_6450: Retrieve sw peer_id
 * @buf: network buffer
 *
 * Return: sw peer_id
 */
static uint32_t hal_rx_mpdu_start_sw_peer_id_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
			&pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;

	return HAL_RX_MPDU_INFO_SW_PEER_ID_GET(
			&mpdu_start->rx_mpdu_info_details);
}

/**
 * hal_rx_mpdu_get_to_ds_6450(): API to get the tods info
 * from rx_mpdu_start
 *
 * @buf: pointer to the start of RX PKT TLV header
 * Return: uint32_t(to_ds)
 */
static uint32_t hal_rx_mpdu_get_to_ds_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
				 &pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;

	struct rx_mpdu_info *mpdu_info = &mpdu_start->rx_mpdu_info_details;

	return HAL_RX_MPDU_GET_TODS(mpdu_info);
}

/*
 * hal_rx_mpdu_get_fr_ds_6450(): API to get the from ds info
 * from rx_mpdu_start
 *
 * @buf: pointer to the start of RX PKT TLV header
 * Return: uint32_t(fr_ds)
 */
static uint32_t hal_rx_mpdu_get_fr_ds_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
				 &pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;

	struct rx_mpdu_info *mpdu_info = &mpdu_start->rx_mpdu_info_details;

	return HAL_RX_MPDU_GET_FROMDS(mpdu_info);
}

/*
 * hal_rx_get_mpdu_frame_control_valid_6450(): Retrieves mpdu
 * frame control valid
 *
 * @nbuf: Network buffer
 * Returns: value of frame control valid field
 */
static uint8_t hal_rx_get_mpdu_frame_control_valid_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = hal_rx_get_pkt_tlvs(buf);
	struct rx_mpdu_info *rx_mpdu_info = hal_rx_get_mpdu_info(pkt_tlvs);

	return HAL_RX_MPDU_GET_FRAME_CONTROL_VALID(rx_mpdu_info);
}

/*
 * hal_rx_mpdu_get_addr1_6450(): API to check get address1 of the mpdu
 *
 * @buf: pointer to the start of RX PKT TLV headera
 * @mac_addr: pointer to mac address
 * Return: success/failure
 */
static QDF_STATUS hal_rx_mpdu_get_addr1_6450(uint8_t *buf, uint8_t *mac_addr)
{
	struct __attribute__((__packed__)) hal_addr1 {
		uint32_t ad1_31_0;
		uint16_t ad1_47_32;
	};

	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
				 &pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;

	struct rx_mpdu_info *mpdu_info = &mpdu_start->rx_mpdu_info_details;
	struct hal_addr1 *addr = (struct hal_addr1 *)mac_addr;
	uint32_t mac_addr_ad1_valid;

	mac_addr_ad1_valid = HAL_RX_MPDU_MAC_ADDR_AD1_VALID_GET(mpdu_info);

	if (mac_addr_ad1_valid) {
		addr->ad1_31_0 = HAL_RX_MPDU_AD1_31_0_GET(mpdu_info);
		addr->ad1_47_32 = HAL_RX_MPDU_AD1_47_32_GET(mpdu_info);
		return QDF_STATUS_SUCCESS;
	}

	return QDF_STATUS_E_FAILURE;
}

/*
 * hal_rx_mpdu_get_addr2_6450(): API to check get address2 of the mpdu
 * in the packet
 *
 * @buf: pointer to the start of RX PKT TLV header
 * @mac_addr: pointer to mac address
 * Return: success/failure
 */
static QDF_STATUS hal_rx_mpdu_get_addr2_6450(uint8_t *buf,
					     uint8_t *mac_addr)
{
	struct __attribute__((__packed__)) hal_addr2 {
		uint16_t ad2_15_0;
		uint32_t ad2_47_16;
	};

	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
				 &pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;

	struct rx_mpdu_info *mpdu_info = &mpdu_start->rx_mpdu_info_details;
	struct hal_addr2 *addr = (struct hal_addr2 *)mac_addr;
	uint32_t mac_addr_ad2_valid;

	mac_addr_ad2_valid = HAL_RX_MPDU_MAC_ADDR_AD2_VALID_GET(mpdu_info);

	if (mac_addr_ad2_valid) {
		addr->ad2_15_0 = HAL_RX_MPDU_AD2_15_0_GET(mpdu_info);
		addr->ad2_47_16 = HAL_RX_MPDU_AD2_47_16_GET(mpdu_info);
		return QDF_STATUS_SUCCESS;
	}

	return QDF_STATUS_E_FAILURE;
}

/*
 * hal_rx_mpdu_get_addr3_6450(): API to get address3 of the mpdu
 * in the packet
 *
 * @buf: pointer to the start of RX PKT TLV header
 * @mac_addr: pointer to mac address
 * Return: success/failure
 */
static QDF_STATUS hal_rx_mpdu_get_addr3_6450(uint8_t *buf, uint8_t *mac_addr)
{
	struct __attribute__((__packed__)) hal_addr3 {
		uint32_t ad3_31_0;
		uint16_t ad3_47_32;
	};

	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
				 &pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;

	struct rx_mpdu_info *mpdu_info = &mpdu_start->rx_mpdu_info_details;
	struct hal_addr3 *addr = (struct hal_addr3 *)mac_addr;
	uint32_t mac_addr_ad3_valid;

	mac_addr_ad3_valid = HAL_RX_MPDU_MAC_ADDR_AD3_VALID_GET(mpdu_info);

	if (mac_addr_ad3_valid) {
		addr->ad3_31_0 = HAL_RX_MPDU_AD3_31_0_GET(mpdu_info);
		addr->ad3_47_32 = HAL_RX_MPDU_AD3_47_32_GET(mpdu_info);
		return QDF_STATUS_SUCCESS;
	}

	return QDF_STATUS_E_FAILURE;
}

/*
 * hal_rx_mpdu_get_addr4_6450(): API to get address4 of the mpdu
 * in the packet
 *
 * @buf: pointer to the start of RX PKT TLV header
 * @mac_addr: pointer to mac address
 * Return: success/failure
 */
static QDF_STATUS hal_rx_mpdu_get_addr4_6450(uint8_t *buf, uint8_t *mac_addr)
{
	struct __attribute__((__packed__)) hal_addr4 {
		uint32_t ad4_31_0;
		uint16_t ad4_47_32;
	};

	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_mpdu_start *mpdu_start =
				 &pkt_tlvs->mpdu_start_tlv.rx_mpdu_start;

	struct rx_mpdu_info *mpdu_info = &mpdu_start->rx_mpdu_info_details;
	struct hal_addr4 *addr = (struct hal_addr4 *)mac_addr;
	uint32_t mac_addr_ad4_valid;

	mac_addr_ad4_valid = HAL_RX_MPDU_MAC_ADDR_AD4_VALID_GET(mpdu_info);

	if (mac_addr_ad4_valid) {
		addr->ad4_31_0 = HAL_RX_MPDU_AD4_31_0_GET(mpdu_info);
		addr->ad4_47_32 = HAL_RX_MPDU_AD4_47_32_GET(mpdu_info);
		return QDF_STATUS_SUCCESS;
	}

	return QDF_STATUS_E_FAILURE;
}

/*
 * hal_rx_get_mpdu_sequence_control_valid_6450(): Get mpdu
 * sequence control valid
 *
 * @nbuf: Network buffer
 * Returns: value of sequence control valid field
 */
static uint8_t hal_rx_get_mpdu_sequence_control_valid_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = hal_rx_get_pkt_tlvs(buf);
	struct rx_mpdu_info *rx_mpdu_info = hal_rx_get_mpdu_info(pkt_tlvs);

	return HAL_RX_MPDU_GET_SEQUENCE_CONTROL_VALID(rx_mpdu_info);
}

/**
 * hal_rx_hw_desc_get_ppduid_get_6450(): retrieve ppdu id
 * @rx_tlv_hdr: rx tlv header
 * @rxdma_dst_ring_desc: rxdma HW descriptor
 *
 * Return: ppdu id
 */
static uint32_t hal_rx_hw_desc_get_ppduid_get_6450(void *rx_tlv_hdr,
						   void *rxdma_dst_ring_desc)
{
	struct rx_mpdu_info *rx_mpdu_info;
	struct rx_pkt_tlvs *rx_desc = (struct rx_pkt_tlvs *)rx_tlv_hdr;

	rx_mpdu_info =
		&rx_desc->mpdu_start_tlv.rx_mpdu_start.rx_mpdu_info_details;

	return HAL_RX_GET(rx_mpdu_info, RX_MPDU_INFO_9, PHY_PPDU_ID);
}

static uint32_t
hal_rx_get_ppdu_id_6450(uint8_t *buf)
{
	return HAL_RX_GET_PPDU_ID(buf);
}

/**
 * hal_rx_msdu_flow_idx_invalid_6450: API to get flow index invalid
 * from rx_msdu_end TLV
 * @buf: pointer to the start of RX PKT TLV headers
 *
 * Return: flow index invalid value from MSDU END TLV
 */
static bool hal_rx_msdu_flow_idx_invalid_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	return HAL_RX_MSDU_END_FLOW_IDX_INVALID_GET(msdu_end);
}

/**
 * hal_rx_msdu_flow_idx_timeout_6450: API to get flow index timeout
 * from rx_msdu_end TLV
 * @buf: pointer to the start of RX PKT TLV headers
 *
 * Return: flow index timeout value from MSDU END TLV
 */
static bool hal_rx_msdu_flow_idx_timeout_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	return HAL_RX_MSDU_END_FLOW_IDX_TIMEOUT_GET(msdu_end);
}

/**
 * hal_rx_msdu_fse_metadata_get_6450: API to get FSE metadata
 * from rx_msdu_end TLV
 * @buf: pointer to the start of RX PKT TLV headers
 *
 * Return: fse metadata value from MSDU END TLV
 */
static uint32_t hal_rx_msdu_fse_metadata_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	return HAL_RX_MSDU_END_FSE_METADATA_GET(msdu_end);
}

/**
 * hal_rx_msdu_cce_metadata_get_6450: API to get CCE metadata
 * from rx_msdu_end TLV
 * @buf: pointer to the start of RX PKT TLV headers
 *
 * Return: cce_metadata
 */
static uint16_t
hal_rx_msdu_cce_metadata_get_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	return HAL_RX_MSDU_END_CCE_METADATA_GET(msdu_end);
}

/**
 * hal_rx_msdu_get_flow_params_6450: API to get flow index, flow index invalid
 * and flow index timeout from rx_msdu_end TLV
 * @buf: pointer to the start of RX PKT TLV headers
 * @flow_invalid: pointer to return value of flow_idx_valid
 * @flow_timeout: pointer to return value of flow_idx_timeout
 * @flow_index: pointer to return value of flow_idx
 *
 * Return: none
 */
static inline void
hal_rx_msdu_get_flow_params_6450(uint8_t *buf,
				 bool *flow_invalid,
				 bool *flow_timeout,
				 uint32_t *flow_index)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	*flow_invalid = HAL_RX_MSDU_END_FLOW_IDX_INVALID_GET(msdu_end);
	*flow_timeout = HAL_RX_MSDU_END_FLOW_IDX_TIMEOUT_GET(msdu_end);
	*flow_index = HAL_RX_MSDU_END_FLOW_IDX_GET(msdu_end);
}

/**
 * hal_rx_tlv_get_tcp_chksum_6450() - API to get tcp checksum
 * @buf: rx_tlv_hdr
 *
 * Return: tcp checksum
 */
static uint16_t
hal_rx_tlv_get_tcp_chksum_6450(uint8_t *buf)
{
	return HAL_RX_TLV_GET_TCP_CHKSUM(buf);
}

/**
 * hal_rx_get_rx_sequence_6450(): Function to retrieve rx sequence number
 *
 * @buf: Network buffer
 * Returns: rx sequence number
 */
static
uint16_t hal_rx_get_rx_sequence_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = hal_rx_get_pkt_tlvs(buf);
	struct rx_mpdu_info *rx_mpdu_info = hal_rx_get_mpdu_info(pkt_tlvs);

	return HAL_RX_MPDU_GET_SEQUENCE_NUMBER(rx_mpdu_info);
}

/**
 * hal_rx_get_fisa_cumulative_l4_checksum_6450() - Retrieve cumulative
 *                                                 checksum
 * @buf: buffer pointer
 *
 * Return: cumulative checksum
 */
static inline
uint16_t hal_rx_get_fisa_cumulative_l4_checksum_6450(uint8_t *buf)
{
	return HAL_RX_TLV_GET_FISA_CUMULATIVE_L4_CHECKSUM(buf);
}

/**
 * hal_rx_get_fisa_cumulative_ip_length_6450() - Retrieve cumulative
 *                                               ip length
 * @buf: buffer pointer
 *
 * Return: cumulative length
 */
static inline
uint16_t hal_rx_get_fisa_cumulative_ip_length_6450(uint8_t *buf)
{
	return HAL_RX_TLV_GET_FISA_CUMULATIVE_IP_LENGTH(buf);
}

/**
 * hal_rx_get_udp_proto_6450() - Retrieve udp proto value
 * @buf: buffer
 *
 * Return: udp proto bit
 */
static inline
bool hal_rx_get_udp_proto_6450(uint8_t *buf)
{
	return HAL_RX_TLV_GET_UDP_PROTO(buf);
}

/**
 * hal_rx_get_flow_agg_continuation_6450() - retrieve flow agg
 *                                           continuation
 * @buf: buffer
 *
 * Return: flow agg
 */
static inline
bool hal_rx_get_flow_agg_continuation_6450(uint8_t *buf)
{
	return HAL_RX_TLV_GET_FLOW_AGGR_CONT(buf);
}

/**
 * hal_rx_get_flow_agg_count_6450()- Retrieve flow agg count
 * @buf: buffer
 *
 * Return: flow agg count
 */
static inline
uint8_t hal_rx_get_flow_agg_count_6450(uint8_t *buf)
{
	return HAL_RX_TLV_GET_FLOW_AGGR_COUNT(buf);
}

/**
 * hal_rx_get_fisa_timeout_6450() - Retrieve fisa timeout
 * @buf: buffer
 *
 * Return: fisa timeout
 */
static inline
bool hal_rx_get_fisa_timeout_6450(uint8_t *buf)
{
	return HAL_RX_TLV_GET_FISA_TIMEOUT(buf);
}

/**
 * hal_rx_mpdu_start_tlv_tag_valid_6450 () - API to check if RX_MPDU_START
 * tlv tag is valid
 *
 *@rx_tlv_hdr: start address of rx_pkt_tlvs
 *
 * Return: true if RX_MPDU_START is valid, else false.
 */
static uint8_t hal_rx_mpdu_start_tlv_tag_valid_6450(void *rx_tlv_hdr)
{
	struct rx_pkt_tlvs *rx_desc = (struct rx_pkt_tlvs *)rx_tlv_hdr;
	uint32_t tlv_tag;

	tlv_tag = HAL_RX_GET_USER_TLV32_TYPE(&rx_desc->mpdu_start_tlv);

	return tlv_tag == WIFIRX_MPDU_START_E ? true : false;
}

/*
 * hal_rx_flow_setup_fse_6450() - Setup a flow search entry in HW FST
 * @fst: Pointer to the Rx Flow Search Table
 * @table_offset: offset into the table where the flow is to be setup
 * @flow: Flow Parameters
 *
 * Flow table entry fields are updated in host byte order, little endian order.
 *
 * Return: Success/Failure
 */
static void *
hal_rx_flow_setup_fse_6450(uint8_t *rx_fst, uint32_t table_offset,
			   uint8_t *rx_flow)
{
	struct hal_rx_fst *fst = (struct hal_rx_fst *)rx_fst;
	struct hal_rx_flow *flow = (struct hal_rx_flow *)rx_flow;
	uint8_t *fse;
	bool fse_valid;

	if (table_offset >= fst->max_entries) {
		QDF_TRACE(QDF_MODULE_ID_TXRX, QDF_TRACE_LEVEL_ERROR,
			  "HAL FSE table offset %u exceeds max entries %u",
			  table_offset, fst->max_entries);
		return NULL;
	}

	fse = (uint8_t *)fst->base_vaddr +
		(table_offset * HAL_RX_FST_ENTRY_SIZE);

	fse_valid = HAL_GET_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, VALID);

	if (fse_valid) {
		QDF_TRACE(QDF_MODULE_ID_TXRX, QDF_TRACE_LEVEL_DEBUG,
			  "HAL FSE %pK already valid", fse);
		return NULL;
	}

	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_0, SRC_IP_127_96) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_0, SRC_IP_127_96,
			       (flow->tuple_info.src_ip_127_96));

	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_1, SRC_IP_95_64) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_1, SRC_IP_95_64,
			       (flow->tuple_info.src_ip_95_64));

	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_2, SRC_IP_63_32) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_2, SRC_IP_63_32,
			       (flow->tuple_info.src_ip_63_32));

	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_3, SRC_IP_31_0) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_3, SRC_IP_31_0,
			       (flow->tuple_info.src_ip_31_0));

	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_4, DEST_IP_127_96) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_4, DEST_IP_127_96,
			       (flow->tuple_info.dest_ip_127_96));

	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_5, DEST_IP_95_64) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_5, DEST_IP_95_64,
			       (flow->tuple_info.dest_ip_95_64));

	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_6, DEST_IP_63_32) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_6, DEST_IP_63_32,
			       (flow->tuple_info.dest_ip_63_32));

	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_7, DEST_IP_31_0) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_7, DEST_IP_31_0,
			       (flow->tuple_info.dest_ip_31_0));

	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_8, DEST_PORT);
	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_8, DEST_PORT) |=
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_8, DEST_PORT,
			       (flow->tuple_info.dest_port));

	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_8, SRC_PORT);
	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_8, SRC_PORT) |=
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_8, SRC_PORT,
			       (flow->tuple_info.src_port));

	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, L4_PROTOCOL);
	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, L4_PROTOCOL) |=
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_9, L4_PROTOCOL,
			       flow->tuple_info.l4_protocol);

	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, REO_DESTINATION_HANDLER);
	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, REO_DESTINATION_HANDLER) |=
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_9, REO_DESTINATION_HANDLER,
			       flow->reo_destination_handler);

	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, VALID);
	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, VALID) |=
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_9, VALID, 1);

	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_10, METADATA);
	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_10, METADATA) =
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_10, METADATA,
			       (flow->fse_metadata));

	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, REO_DESTINATION_INDICATION);
	HAL_SET_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, REO_DESTINATION_INDICATION) |=
		HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_9,
			       REO_DESTINATION_INDICATION,
			       flow->reo_destination_indication);

	/* Reset all the other fields in FSE */
	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, RESERVED_9);
	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_9, MSDU_DROP);
	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_11, MSDU_COUNT);
	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_12, MSDU_BYTE_COUNT);
	HAL_CLR_FLD(fse, RX_FLOW_SEARCH_ENTRY_13, TIMESTAMP);

	return fse;
}

/*
 * hal_rx_flow_setup_cmem_fse_6450() - Setup a flow search entry in HW CMEM FST
 * @hal_soc: hal_soc reference
 * @cmem_ba: CMEM base address
 * @table_offset: offset into the table where the flow is to be setup
 * @flow: Flow Parameters
 *
 * Return: Success/Failure
 */
static uint32_t
hal_rx_flow_setup_cmem_fse_6450(struct hal_soc *hal_soc, uint32_t cmem_ba,
				uint32_t table_offset, uint8_t *rx_flow)
{
	struct hal_rx_flow *flow = (struct hal_rx_flow *)rx_flow;
	uint32_t fse_offset;
	uint32_t value;

	fse_offset = cmem_ba + (table_offset * HAL_RX_FST_ENTRY_SIZE);

	/* Reset the Valid bit */
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_9,
							VALID), 0);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_0, SRC_IP_127_96,
				(flow->tuple_info.src_ip_127_96));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_0,
							SRC_IP_127_96), value);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_1, SRC_IP_95_64,
				(flow->tuple_info.src_ip_95_64));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_1,
							SRC_IP_95_64), value);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_2, SRC_IP_63_32,
				(flow->tuple_info.src_ip_63_32));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_2,
							SRC_IP_63_32), value);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_3, SRC_IP_31_0,
				(flow->tuple_info.src_ip_31_0));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_3,
							SRC_IP_31_0), value);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_4, DEST_IP_127_96,
				(flow->tuple_info.dest_ip_127_96));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_4,
							DEST_IP_127_96), value);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_5, DEST_IP_95_64,
				(flow->tuple_info.dest_ip_95_64));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_5,
							DEST_IP_95_64), value);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_6, DEST_IP_63_32,
				(flow->tuple_info.dest_ip_63_32));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_6,
							DEST_IP_63_32), value);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_7, DEST_IP_31_0,
				(flow->tuple_info.dest_ip_31_0));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_7,
							DEST_IP_31_0), value);

	value = 0 | HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_8, DEST_PORT,
				(flow->tuple_info.dest_port));
	value |= HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_8, SRC_PORT,
				(flow->tuple_info.src_port));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_8,
							SRC_PORT), value);

	value  = HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_10, METADATA,
				(flow->fse_metadata));
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_10,
							METADATA), value);

	/* Reset all the other fields in FSE */
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_11,
							MSDU_COUNT), 0);
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_12,
							MSDU_BYTE_COUNT), 0);
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_13,
							TIMESTAMP), 0);

	value = 0 | HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_9, L4_PROTOCOL,
				   flow->tuple_info.l4_protocol);
	value |= HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_9, REO_DESTINATION_HANDLER,
				flow->reo_destination_handler);
	value |= HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_9,
				REO_DESTINATION_INDICATION,
				flow->reo_destination_indication);
	value |= HAL_SET_FLD_SM(RX_FLOW_SEARCH_ENTRY_9, VALID, 1);
	HAL_CMEM_WRITE(hal_soc, fse_offset + HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_9,
							L4_PROTOCOL), value);

	return fse_offset;
}

/**
 * hal_rx_flow_get_cmem_fse_ts_6450() - Get timestamp field from CMEM FSE
 * @hal_soc: hal_soc reference
 * @fse_offset: CMEM FSE offset
 *
 * Return: Timestamp
 */
static uint32_t hal_rx_flow_get_cmem_fse_ts_6450(struct hal_soc *hal_soc,
						 uint32_t fse_offset)
{
	return HAL_CMEM_READ(hal_soc, fse_offset +
			     HAL_OFFSET(RX_FLOW_SEARCH_ENTRY_13, TIMESTAMP));
}

/**
 * hal_rx_flow_get_cmem_fse_6450() - Get FSE from CMEM
 * @hal_soc: hal_soc reference
 * @fse_offset: CMEM FSE offset
 * @fse: reference where FSE will be copied
 * @len: length of FSE
 *
 * Return: If read is successful or not
 */
static void
hal_rx_flow_get_cmem_fse_6450(struct hal_soc *hal_soc, uint32_t fse_offset,
			      uint32_t *fse, qdf_size_t len)
{
	int i;

	if (len != HAL_RX_FST_ENTRY_SIZE)
		return;

	for (i = 0; i < NUM_OF_DWORDS_RX_FLOW_SEARCH_ENTRY; i++)
		fse[i] = HAL_CMEM_READ(hal_soc, fse_offset + i * 4);
}

/**
 * hal_rx_msdu_get_reo_destination_indication_6450: API to get
 * reo_destination_indication from rx_msdu_end TLV
 * @buf: pointer to the start of RX PKT TLV headers
 * @reo_destination_ind: pointer to return value
 * of reo_destination_indication
 *
 * Return: none
 */
static void
hal_rx_msdu_get_reo_destination_indication_6450(uint8_t *buf,
						uint32_t *reo_destination_ind)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_end *msdu_end = &pkt_tlvs->msdu_end_tlv.rx_msdu_end;

	*reo_destination_ind =
			HAL_RX_MSDU_END_REO_DEST_IND_GET(msdu_end);
}

#ifdef WLAN_FEATURE_MARK_FIRST_WAKEUP_PACKET
static inline uint8_t hal_get_first_wow_wakeup_packet_6450(uint8_t *buf)
{
	return 0;
}
#endif

/**
 * hal_rx_msdu_start_get_len_6450(): API to get the MSDU length
 * from rx_msdu_start TLV
 *
 * @buf: pointer to the start of RX PKT TLV headers
 * Return: (uint32_t)msdu length
 */
static uint32_t hal_rx_msdu_start_get_len_6450(uint8_t *buf)
{
	struct rx_pkt_tlvs *pkt_tlvs = (struct rx_pkt_tlvs *)buf;
	struct rx_msdu_start *msdu_start =
				&pkt_tlvs->msdu_start_tlv.rx_msdu_start;
	uint32_t msdu_len;

	msdu_len = HAL_RX_MSDU_START_MSDU_LEN_GET(msdu_start);

	return msdu_len;
}

static void hal_hw_txrx_ops_attach_wcn6450(struct hal_soc *hal_soc)
{
	/* Initialize setup tx/rx ops here */
	hal_soc->ops->hal_srng_dst_hw_init = hal_srng_dst_hw_init_generic;
	hal_soc->ops->hal_srng_src_hw_init = hal_srng_src_hw_init_generic;
	hal_soc->ops->hal_get_hw_hptp = hal_get_hw_hptp_6450;
	hal_soc->ops->hal_reo_setup = hal_reo_setup_6450;
	hal_soc->ops->hal_get_window_address = hal_get_window_address_6450;
	hal_soc->ops->hal_reo_set_err_dst_remap =
				hal_reo_set_err_dst_remap_6450;

	/* tx */
	hal_soc->ops->hal_tx_desc_set_dscp_tid_table_id =
				hal_tx_desc_set_dscp_tid_table_id_6450;
	hal_soc->ops->hal_tx_set_dscp_tid_map = hal_tx_set_dscp_tid_map_6450;
	hal_soc->ops->hal_tx_update_dscp_tid = hal_tx_update_dscp_tid_6450;
	hal_soc->ops->hal_tx_desc_set_lmac_id = hal_tx_desc_set_lmac_id_6450;
	hal_soc->ops->hal_tx_desc_set_buf_addr =
				hal_tx_desc_set_buf_addr_generic_rh;
	hal_soc->ops->hal_tx_desc_set_search_type =
				hal_tx_desc_set_search_type_generic_rh;
	hal_soc->ops->hal_tx_desc_set_search_index =
				hal_tx_desc_set_search_index_generic_rh;
	hal_soc->ops->hal_tx_desc_set_cache_set_num =
				hal_tx_desc_set_cache_set_num_generic_rh;
	hal_soc->ops->hal_tx_comp_get_status =
				hal_tx_comp_get_status_generic_rh;
	hal_soc->ops->hal_tx_comp_get_release_reason =
				hal_tx_comp_get_release_reason_6450;
	hal_soc->ops->hal_get_wbm_internal_error =
				hal_get_wbm_internal_error_6450;
	hal_soc->ops->hal_tx_desc_set_mesh_en = hal_tx_desc_set_mesh_en_6450;
	hal_soc->ops->hal_tx_init_cmd_credit_ring =
				hal_tx_init_cmd_credit_ring_6450;

	/* rx */
	hal_soc->ops->hal_rx_msdu_start_nss_get =
				hal_rx_msdu_start_nss_get_6450;
	hal_soc->ops->hal_rx_mon_hw_desc_get_mpdu_status =
				hal_rx_mon_hw_desc_get_mpdu_status_6450;
	hal_soc->ops->hal_rx_get_tlv = hal_rx_get_tlv_6450;
	hal_soc->ops->hal_rx_proc_phyrx_other_receive_info_tlv =
				hal_rx_proc_phyrx_other_receive_info_tlv_6450;

	hal_soc->ops->hal_rx_dump_msdu_end_tlv =
					hal_rx_dump_msdu_end_tlv_6450;
	hal_soc->ops->hal_rx_dump_rx_attention_tlv =
					hal_rx_dump_rx_attention_tlv_generic_rh;
	hal_soc->ops->hal_rx_dump_msdu_start_tlv =
					hal_rx_dump_msdu_start_tlv_6450;
	hal_soc->ops->hal_rx_dump_mpdu_start_tlv =
					hal_rx_dump_mpdu_start_tlv_generic_rh;
	hal_soc->ops->hal_rx_dump_mpdu_end_tlv =
					hal_rx_dump_mpdu_end_tlv_generic_rh;
	hal_soc->ops->hal_rx_dump_pkt_hdr_tlv =
					hal_rx_dump_pkt_hdr_tlv_generic_rh;

	hal_soc->ops->hal_get_link_desc_size = hal_get_link_desc_size_6450;
	hal_soc->ops->hal_rx_mpdu_start_tid_get =
				hal_rx_mpdu_start_tid_get_6450;
	hal_soc->ops->hal_rx_msdu_start_reception_type_get =
				hal_rx_msdu_start_reception_type_get_6450;
	hal_soc->ops->hal_rx_msdu_end_da_idx_get =
				hal_rx_msdu_end_da_idx_get_6450;
	hal_soc->ops->hal_rx_msdu_desc_info_get_ptr =
				hal_rx_msdu_desc_info_get_ptr_6450;
	hal_soc->ops->hal_rx_link_desc_msdu0_ptr =
				hal_rx_link_desc_msdu0_ptr_6450;
	hal_soc->ops->hal_reo_status_get_header =
				hal_reo_status_get_header_6450;
	hal_soc->ops->hal_rx_status_get_tlv_info =
				hal_rx_status_get_tlv_info_generic_rh;
	hal_soc->ops->hal_rx_wbm_err_info_get =
				hal_rx_wbm_err_info_get_6450;
	hal_soc->ops->hal_tx_set_pcp_tid_map =
				hal_tx_set_pcp_tid_map_generic_rh;
	hal_soc->ops->hal_tx_update_pcp_tid_map =
				hal_tx_update_pcp_tid_generic_rh;
	hal_soc->ops->hal_tx_set_tidmap_prty =
				hal_tx_update_tidmap_prty_generic_rh;
	hal_soc->ops->hal_rx_get_rx_fragment_number =
				hal_rx_get_rx_fragment_number_6450;
	hal_soc->ops->hal_rx_msdu_end_da_is_mcbc_get =
				hal_rx_msdu_end_da_is_mcbc_get_6450;
	hal_soc->ops->hal_rx_msdu_end_sa_is_valid_get =
				hal_rx_msdu_end_sa_is_valid_get_6450;
	hal_soc->ops->hal_rx_msdu_end_sa_idx_get =
				hal_rx_msdu_end_sa_idx_get_6450;
	hal_soc->ops->hal_rx_desc_is_first_msdu =
				hal_rx_desc_is_first_msdu_6450;
	hal_soc->ops->hal_rx_msdu_end_l3_hdr_padding_get =
				hal_rx_msdu_end_l3_hdr_padding_get_6450;
	hal_soc->ops->hal_rx_encryption_info_valid =
				hal_rx_encryption_info_valid_6450;
	hal_soc->ops->hal_rx_print_pn = hal_rx_print_pn_6450;
	hal_soc->ops->hal_rx_msdu_end_first_msdu_get =
				hal_rx_msdu_end_first_msdu_get_6450;
	hal_soc->ops->hal_rx_msdu_end_da_is_valid_get =
				hal_rx_msdu_end_da_is_valid_get_6450;
	hal_soc->ops->hal_rx_msdu_end_last_msdu_get =
				hal_rx_msdu_end_last_msdu_get_6450;
	hal_soc->ops->hal_rx_get_mpdu_mac_ad4_valid =
				hal_rx_get_mpdu_mac_ad4_valid_6450;
	hal_soc->ops->hal_rx_mpdu_start_sw_peer_id_get =
				hal_rx_mpdu_start_sw_peer_id_get_6450;
	hal_soc->ops->hal_rx_tlv_peer_meta_data_get =
				hal_rx_mpdu_peer_meta_data_get_rh;
	hal_soc->ops->hal_rx_mpdu_get_to_ds = hal_rx_mpdu_get_to_ds_6450;
	hal_soc->ops->hal_rx_mpdu_get_fr_ds = hal_rx_mpdu_get_fr_ds_6450;
	hal_soc->ops->hal_rx_get_mpdu_frame_control_valid =
				hal_rx_get_mpdu_frame_control_valid_6450;
	hal_soc->ops->hal_rx_get_frame_ctrl_field =
				hal_rx_get_frame_ctrl_field_rh;
	hal_soc->ops->hal_rx_mpdu_get_addr1 = hal_rx_mpdu_get_addr1_6450;
	hal_soc->ops->hal_rx_mpdu_get_addr2 = hal_rx_mpdu_get_addr2_6450;
	hal_soc->ops->hal_rx_mpdu_get_addr3 = hal_rx_mpdu_get_addr3_6450;
	hal_soc->ops->hal_rx_mpdu_get_addr4 = hal_rx_mpdu_get_addr4_6450;
	hal_soc->ops->hal_rx_get_mpdu_sequence_control_valid =
			hal_rx_get_mpdu_sequence_control_valid_6450;
	hal_soc->ops->hal_rx_is_unicast = hal_rx_is_unicast_6450;
	hal_soc->ops->hal_rx_tid_get = hal_rx_tid_get_6450;
	hal_soc->ops->hal_rx_hw_desc_get_ppduid_get =
				hal_rx_hw_desc_get_ppduid_get_6450;
	hal_soc->ops->hal_rx_msdu0_buffer_addr_lsb =
				hal_rx_msdu0_buffer_addr_lsb_6450;
	hal_soc->ops->hal_rx_msdu_desc_info_ptr_get =
				hal_rx_msdu_desc_info_ptr_get_6450;
	hal_soc->ops->hal_ent_mpdu_desc_info = hal_ent_mpdu_desc_info_6450;
	hal_soc->ops->hal_dst_mpdu_desc_info = hal_dst_mpdu_desc_info_6450;
	hal_soc->ops->hal_rx_get_fc_valid = hal_rx_get_fc_valid_6450;
	hal_soc->ops->hal_rx_get_to_ds_flag = hal_rx_get_to_ds_flag_6450;
	hal_soc->ops->hal_rx_get_mac_addr2_valid =
				hal_rx_get_mac_addr2_valid_6450;
	hal_soc->ops->hal_rx_get_filter_category =
				hal_rx_get_filter_category_6450;
	hal_soc->ops->hal_rx_get_ppdu_id = hal_rx_get_ppdu_id_6450;
	hal_soc->ops->hal_reo_config = hal_reo_config_6450;
	hal_soc->ops->hal_rx_msdu_flow_idx_get = hal_rx_msdu_flow_idx_get_6450;
	hal_soc->ops->hal_rx_msdu_flow_idx_invalid =
				hal_rx_msdu_flow_idx_invalid_6450;
	hal_soc->ops->hal_rx_msdu_flow_idx_timeout =
				hal_rx_msdu_flow_idx_timeout_6450;
	hal_soc->ops->hal_rx_msdu_fse_metadata_get =
				hal_rx_msdu_fse_metadata_get_6450;
	hal_soc->ops->hal_rx_msdu_cce_match_get =
				hal_rx_msdu_cce_match_get_rh;
	hal_soc->ops->hal_rx_msdu_cce_metadata_get =
				hal_rx_msdu_cce_metadata_get_6450;
	hal_soc->ops->hal_rx_msdu_get_flow_params =
				hal_rx_msdu_get_flow_params_6450;
	hal_soc->ops->hal_rx_tlv_get_tcp_chksum =
				hal_rx_tlv_get_tcp_chksum_6450;
	hal_soc->ops->hal_rx_get_rx_sequence = hal_rx_get_rx_sequence_6450;
#if defined(QCA_WIFI_WCN6450) && defined(WLAN_CFR_ENABLE) && \
    defined(WLAN_ENH_CFR_ENABLE)
	hal_soc->ops->hal_rx_get_bb_info = hal_rx_get_bb_info_6450;
	hal_soc->ops->hal_rx_get_rtt_info = hal_rx_get_rtt_info_6450;
#endif

	/* rx - msdu end fast path info fields */
	hal_soc->ops->hal_rx_msdu_packet_metadata_get =
				hal_rx_msdu_packet_metadata_get_generic_rh;
	hal_soc->ops->hal_rx_get_fisa_cumulative_l4_checksum =
				hal_rx_get_fisa_cumulative_l4_checksum_6450;
	hal_soc->ops->hal_rx_get_fisa_cumulative_ip_length =
				hal_rx_get_fisa_cumulative_ip_length_6450;
	hal_soc->ops->hal_rx_get_udp_proto = hal_rx_get_udp_proto_6450;
	hal_soc->ops->hal_rx_get_fisa_flow_agg_continuation =
				hal_rx_get_flow_agg_continuation_6450;
	hal_soc->ops->hal_rx_get_fisa_flow_agg_count =
				hal_rx_get_flow_agg_count_6450;
	hal_soc->ops->hal_rx_get_fisa_timeout = hal_rx_get_fisa_timeout_6450;
	hal_soc->ops->hal_rx_mpdu_start_tlv_tag_valid =
				hal_rx_mpdu_start_tlv_tag_valid_6450;

	/* rx - TLV struct offsets */
	hal_soc->ops->hal_rx_msdu_end_offset_get =
				hal_rx_msdu_end_offset_get_generic;
	hal_soc->ops->hal_rx_attn_offset_get = hal_rx_attn_offset_get_generic;
	hal_soc->ops->hal_rx_msdu_start_offset_get =
				hal_rx_msdu_start_offset_get_generic;
	hal_soc->ops->hal_rx_mpdu_start_offset_get =
				hal_rx_mpdu_start_offset_get_generic;
	hal_soc->ops->hal_rx_mpdu_end_offset_get =
				hal_rx_mpdu_end_offset_get_generic;
#ifndef NO_RX_PKT_HDR_TLV
	hal_soc->ops->hal_rx_pkt_tlv_offset_get =
				hal_rx_pkt_tlv_offset_get_generic;
#endif
	hal_soc->ops->hal_rx_flow_setup_fse = hal_rx_flow_setup_fse_6450;
	hal_soc->ops->hal_rx_flow_get_tuple_info =
				hal_rx_flow_get_tuple_info_rh;
	hal_soc->ops->hal_rx_flow_delete_entry =
				hal_rx_flow_delete_entry_rh;
	hal_soc->ops->hal_rx_fst_get_fse_size = hal_rx_fst_get_fse_size_rh;
	hal_soc->ops->hal_compute_reo_remap_ix2_ix3 =
				hal_compute_reo_remap_ix2_ix3_6450;

	/* CMEM FSE */
	hal_soc->ops->hal_rx_flow_setup_cmem_fse =
				hal_rx_flow_setup_cmem_fse_6450;
	hal_soc->ops->hal_rx_flow_get_cmem_fse_ts =
				hal_rx_flow_get_cmem_fse_ts_6450;
	hal_soc->ops->hal_rx_flow_get_cmem_fse = hal_rx_flow_get_cmem_fse_6450;
	hal_soc->ops->hal_rx_msdu_get_reo_destination_indication =
			hal_rx_msdu_get_reo_destination_indication_6450;
	hal_soc->ops->hal_setup_link_idle_list =
				hal_setup_link_idle_list_6450;
#ifdef WLAN_FEATURE_MARK_FIRST_WAKEUP_PACKET
	hal_soc->ops->hal_get_first_wow_wakeup_packet =
				hal_get_first_wow_wakeup_packet_6450;
#endif
	hal_soc->ops->hal_compute_reo_remap_ix0 =
				hal_compute_reo_remap_ix0_6450;
	hal_soc->ops->hal_rx_tlv_msdu_len_get =
				hal_rx_msdu_start_get_len_6450;
}

/**
 * hal_wcn6450_attach() - Attach 6450 target specific hal_soc ops,
 *				offset and srng table
 * @hal_soc: HAL Soc handle
 *
 * Return: None
 */
void hal_wcn6450_attach(struct hal_soc *hal_soc)
{
	hal_soc->hw_srng_table = hw_srng_table_wcn6450;
	hal_hw_txrx_default_ops_attach_rh(hal_soc);
	hal_hw_txrx_ops_attach_wcn6450(hal_soc);
}
