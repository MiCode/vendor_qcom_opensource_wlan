/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */
#ifndef __DP_BN_TX_H
#define __DP_BN_TX_H
/**
 *  DOC: dp_be_tx.h
 *
 * BN specific TX Datapath header file. Need not be exposed to common DP code.
 *
 */

#include <dp_types.h>
#include "dp_be.h"

/**
 * dp_tx_hw_enqueue_bn() - Enqueue to TCL HW for transmit for BE target
 * @soc: DP Soc Handle
 * @vdev: DP vdev handle
 * @tx_desc: Tx Descriptor Handle
 * @fw_metadata: Metadata to send to Target Firmware along with frame
 * @metadata: Handle that holds exception path meta data
 * @msdu_info: msdu_info containing information about TX buffer
 *
 *  Gets the next free TCL HW DMA descriptor and sets up required parameters
 *  from software Tx descriptor
 *
 * Return: QDF_STATUS_SUCCESS: success
 *         QDF_STATUS_E_RESOURCES: Error return
 */
QDF_STATUS dp_tx_hw_enqueue_bn(struct dp_soc *soc, struct dp_vdev *vdev,
			       struct dp_tx_desc_s *tx_desc,
				uint16_t fw_metadata,
				struct cdp_tx_exception_metadata *metadata,
				struct dp_tx_msdu_info_s *msdu_info);
#endif
