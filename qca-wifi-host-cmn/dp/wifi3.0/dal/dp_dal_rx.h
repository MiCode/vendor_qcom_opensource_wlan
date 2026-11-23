/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef DP_DAL_RX_H
#define DP_DAL_RX_H

#include "dp_dal.h"
#include "qdf_nbuf.h"

/**
 * dp_dal_rx_process_nbuf_list - Process a list of qdf_nbufs for RX path.
 * @soc: DP SOC context.
 * @nbuf_list: Head of the qdf_nbuf list to be processed.
 *
 * This is a placeholder (skeleton) implementation. The actual RX processing
 * logic should be added by the driver developer.
 *
 * Return: %QDF_STATUS_SUCCESS on success, or an appropriate error code.
 */
QDF_STATUS dp_dal_rx_process_nbuf_list(struct dp_soc *soc,
				       qdf_nbuf_t nbuf_list);
#endif /* DP_DAL_RX_H */
