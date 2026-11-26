/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef DP_DAL_H
#define DP_DAL_H

#include <qdf_status.h>
#include "dp_types.h"

/**
 * dp_dal_soc_attach - Attach DP DAL to SOC
 * @soc: pointer to dp_soc structure
 *
 * Return: QDF_STATUS_SUCCESS on success, error code on failure.
 */
QDF_STATUS dp_dal_soc_attach(struct dp_soc *soc);

/**
 * dp_dal_soc_init - Initialize DP DAL for SOC
 * @soc: pointer to dp_soc structure
 *
 * Return: QDF_STATUS_SUCCESS on success, error code on failure.
 */
QDF_STATUS dp_dal_soc_init(struct dp_soc *soc);

/**
 * dp_dal_bus_stop - Stop DP DAL bus
 * @soc: pointer to dp_soc structure
 *
 * This function stops the DP DAL bus associated with the given SOC.
 */
void dp_dal_bus_stop(struct dp_soc *soc);

/**
 * dp_dal_bus_exit - Exit DP DAL bus
 * @soc: pointer to dp_soc structure
 *
 * This function performs cleanup when exiting the DP DAL bus.
 */
void dp_dal_bus_exit(struct dp_soc *soc);

#endif /* DP_DAL_H */
