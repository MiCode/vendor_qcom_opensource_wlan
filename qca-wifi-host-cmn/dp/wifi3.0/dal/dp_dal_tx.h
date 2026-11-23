/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef DP_DAL_TX_H
#define DP_DAL_TX_H

#include "dp_types.h"
#include "cdp_txrx_cmn_struct.h"
#include "dp_dal.h"
#include "qdf_status.h"
#include "dp_tx.h"

/**
 * dp_dal_tx_hw_enqueue - Enqueue a BE TX packet (DAL stub).
 * @soc: DP SOC context.
 * @vdev: DP VDEV context.
 * @tx_desc: TX descriptor for the packet.
 * @fw_metadata: Firmware metadata associated with the packet.
 * @metadata: Exception metadata for TX path.
 * @msdu_info: MSDU information for the packet.
 *
 * This is a placeholder implementation that currently returns
 * %QDF_STATUS_SUCCESS. It should be replaced with the actual
 * hardware enqueue logic.
 *
 * Return: %QDF_STATUS_SUCCESS on success.
 */
QDF_STATUS dp_dal_tx_hw_enqueue(struct dp_soc *soc,
				struct dp_vdev *vdev,
				struct dp_tx_desc_s *tx_desc,
				uint16_t fw_metadata,
				struct cdp_tx_exception_metadata *metadata,
				struct dp_tx_msdu_info_s *msdu_info);
#endif /* DP_DAL_TX_H */
