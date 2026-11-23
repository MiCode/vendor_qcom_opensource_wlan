/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef _HAL_BN_GENERIC_API_H_
#define _HAL_BN_GENERIC_API_H_

#include <hal_be_hw_headers.h>
#include "hal_be_tx.h"
#include "hal_bn_tx.h"
#include "hal_be_reo.h"
#include <hal_api_mon.h>
#include <hal_generic_api.h>
#include "txmon_tlvs.h"
/**
 * hal_tx_comp_get_release_reason_generic_bn() - TQM Release reason
 * @hal_desc: completion ring descriptor pointer
 *
 * This function will return the type of pointer - buffer or descriptor
 *
 * Return: buffer type
 */
static uint8_t hal_tx_comp_get_release_reason_generic_bn(void *hal_desc)
{
	uint32_t comp_desc = *(uint32_t *)(((uint8_t *)hal_desc) +
			TQM2SW_COMPLETION_RING_TQM_RELEASE_REASON_OFFSET);

	return (comp_desc &
		TQM2SW_COMPLETION_RING_TQM_RELEASE_REASON_MASK) >>
		TQM2SW_COMPLETION_RING_TQM_RELEASE_REASON_LSB;
}

/**
 * hal_tx_populate_bank_register_bn() - populate the bank register with
 *		the software configs.
 * @hal_soc_hdl: HAL soc handle
 * @config: bank config
 * @bank_id: bank id to be configured
 *
 * Returns: None
 */
static inline void
hal_tx_populate_bank_register_bn(hal_soc_handle_t hal_soc_hdl,
				 union hal_tx_bank_config *config,
				 uint8_t bank_id)
{
	struct hal_soc *hal_soc = (struct hal_soc *)hal_soc_hdl;
	uint32_t reg_addr, reg_val = 0;

	reg_addr = HWIO_TCL_R0_SW_CONFIG_BANK_n_ADDR(MAC_TCL_REG_REG_BASE,
						     bank_id);

	reg_val |= (config->epd << HWIO_TCL_R0_SW_CONFIG_BANK_n_EPD_SHFT);
	reg_val |= (config->encap_type <<
			HWIO_TCL_R0_SW_CONFIG_BANK_n_ENCAP_TYPE_SHFT);
	reg_val |= (config->encrypt_type <<
			HWIO_TCL_R0_SW_CONFIG_BANK_n_ENCRYPT_TYPE_SHFT);
	reg_val |= (config->src_buffer_swap <<
			HWIO_TCL_R0_SW_CONFIG_BANK_n_SRC_BUFFER_SWAP_SHFT);
	reg_val |= (config->link_meta_swap <<
			HWIO_TCL_R0_SW_CONFIG_BANK_n_LINK_META_SWAP_SHFT);
	reg_val |= (config->mesh_enable <<
			HWIO_TCL_R0_SW_CONFIG_BANK_n_MESH_ENABLE_SHFT);
	reg_val |= (config->vdev_id_check_en <<
			HWIO_TCL_R0_SW_CONFIG_BANK_n_VDEV_ID_CHECK_EN_SHFT);
	reg_val |= (config->dscp_tid_map_id <<
			HWIO_TCL_R0_SW_CONFIG_BANK_n_DSCP_TID_TABLE_NUM_SHFT);

	HAL_REG_WRITE(hal_soc, reg_addr, reg_val);
}

/**
 * hal_cookie_conversion_reg_cfg_generic_bn() - set cookie conversion relevant
 *						register for REO/TQM
 * @hal_soc_hdl: HAL soc handle
 * @cc_cfg: structure pointer for HW cookie conversion configuration
 *
 * Return: None
 */
static inline
void hal_cookie_conversion_reg_cfg_generic_bn(hal_soc_handle_t hal_soc_hdl,
					      struct hal_hw_cc_config *cc_cfg)
{
	uint32_t reg_addr, reg_val = 0;
	struct hal_soc *soc = (struct hal_soc *)hal_soc_hdl;

	/* REO CFG */
	reg_addr = HWIO_REO_R0_SW_COOKIE_CFG0_ADDR(REO_REG_REG_BASE);
	reg_val = cc_cfg->lut_base_addr_31_0;
	HAL_REG_WRITE(soc, reg_addr, reg_val);

	reg_addr = HWIO_REO_R0_SW_COOKIE_CFG1_ADDR(REO_REG_REG_BASE);
	reg_val = 0;
	reg_val |= HAL_SM(HWIO_REO_R0_SW_COOKIE_CFG1,
			  SW_COOKIE_CONVERT_GLOBAL_ENABLE,
			  cc_cfg->cc_global_en);
	reg_val |= HAL_SM(HWIO_REO_R0_SW_COOKIE_CFG1,
			  SW_COOKIE_CONVERT_ENABLE,
			  cc_cfg->cc_global_en);
	reg_val |= HAL_SM(HWIO_REO_R0_SW_COOKIE_CFG1,
			  PAGE_ALIGNMENT,
			  cc_cfg->page_4k_align);
	reg_val |= HAL_SM(HWIO_REO_R0_SW_COOKIE_CFG1,
			  COOKIE_OFFSET_MSB,
			  cc_cfg->cookie_offset_msb);
	reg_val |= HAL_SM(HWIO_REO_R0_SW_COOKIE_CFG1,
			  COOKIE_PAGE_MSB,
			  cc_cfg->cookie_page_msb);
	reg_val |= HAL_SM(HWIO_REO_R0_SW_COOKIE_CFG1,
			  CMEM_LUT_BASE_ADDR_39_32,
			  cc_cfg->lut_base_addr_39_32);
	HAL_REG_WRITE(soc, reg_addr, reg_val);

	/*
	 * WCSS_UMAC_REO_R0_COOKIE_CONV_EN_RING default value is 0x3FF
	 */
	reg_addr = HWIO_REO_R0_COOKIE_CONV_EN_RING_ADDR(REO_REG_REG_BASE);
	reg_val = 0;
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2FW,
			  cc_cfg->reo2fw_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW9,
			  cc_cfg->reo2sw9_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW8,
			  cc_cfg->reo2sw8_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW7,
			  cc_cfg->reo2sw7_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW6,
			  cc_cfg->reo2sw6_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW5,
			  cc_cfg->reo2sw5_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW4,
			  cc_cfg->reo2sw4_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW3,
			  cc_cfg->reo2sw3_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW2,
			  cc_cfg->reo2sw2_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW1,
			  cc_cfg->reo2sw1_cc_en);
	reg_val |= HAL_SM(HWIO_REO_R0_COOKIE_CONV_EN_RING,
			  REO2SW0,
			  cc_cfg->reo2sw0_cc_en);
	HAL_REG_WRITE(soc, reg_addr, reg_val);

	/* TQM CFG */
	reg_addr = HWIO_TQM_R0_SW_COOKIE_CFG0_ADDR(TQM_REG_REG_BASE);
	reg_val = cc_cfg->lut_base_addr_31_0;
	HAL_REG_WRITE(soc, reg_addr, reg_val);

	reg_addr = HWIO_TQM_R0_SW_COOKIE_CFG1_ADDR(TQM_REG_REG_BASE);
	reg_val = 0;
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CFG1,
			  PAGE_ALIGNMENT,
			  cc_cfg->page_4k_align);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CFG1,
			  COOKIE_OFFSET_MSB,
			  cc_cfg->cookie_offset_msb);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CFG1,
			  COOKIE_PAGE_MSB,
			  cc_cfg->cookie_page_msb);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CFG1,
			  CMEM_LUT_BASE_ADDR_39_32,
			  cc_cfg->lut_base_addr_39_32);
	HAL_REG_WRITE(soc, reg_addr, reg_val);

	/*
	 * WCSS_UMAC_TQM_R0_SW_COOKIE_CONVERT_CFG default value is 0x1FE,
	 */
	reg_addr = HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG_ADDR(TQM_REG_REG_BASE);
	reg_val = 0;
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM_COOKIE_CONV_GLOBAL_ENABLE,
			  cc_cfg->cc_global_en);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM2SW6_COOKIE_CONVERSION_EN,
			  cc_cfg->tqm2sw6_cc_en);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM2SW5_COOKIE_CONVERSION_EN,
			  cc_cfg->tqm2sw5_cc_en);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM2SW4_COOKIE_CONVERSION_EN,
			  cc_cfg->tqm2sw4_cc_en);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM2SW3_COOKIE_CONVERSION_EN,
			  cc_cfg->tqm2sw3_cc_en);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM2SW2_COOKIE_CONVERSION_EN,
			  cc_cfg->tqm2sw2_cc_en);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM2SW1_COOKIE_CONVERSION_EN,
			  cc_cfg->tqm2sw1_cc_en);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM2SW0_COOKIE_CONVERSION_EN,
			  cc_cfg->tqm2sw0_cc_en);
	reg_val |= HAL_SM(HWIO_TQM_R0_SW_COOKIE_CONVERT_CFG,
			  TQM2FW_COOKIE_CONVERSION_EN,
			  cc_cfg->tqm2fw_cc_en);
	HAL_REG_WRITE(soc, reg_addr, reg_val);

	reg_addr = HWIO_TQM_R0_TX_COMPLETION_MISC_CFG_ADDR(TQM_REG_REG_BASE);
	reg_val = 0;
	reg_val |= HAL_SM(HWIO_TQM_R0_TX_COMPLETION_MISC_CFG,
			  COOKIE_DEBUG_SEL,
			  cc_cfg->cc_global_en);

	reg_val |= HAL_SM(HWIO_TQM_R0_TX_COMPLETION_MISC_CFG,
			  COOKIE_CONV_INDICATION_EN,
			  cc_cfg->cc_global_en);

	reg_val |= HAL_SM(HWIO_TQM_R0_TX_COMPLETION_MISC_CFG,
			  ERROR_PATH_COOKIE_CONV_EN,
			  cc_cfg->error_path_cookie_conv_en);

	reg_val |= HAL_SM(HWIO_TQM_R0_TX_COMPLETION_MISC_CFG,
			  RELEASE_PATH_COOKIE_CONV_EN,
			  cc_cfg->release_path_cookie_conv_en);

	HAL_REG_WRITE(soc, reg_addr, reg_val);
}
#endif /* _HAL_BN_GENERIC_API_H_ */
