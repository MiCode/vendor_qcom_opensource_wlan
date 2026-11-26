/*
 * Copyright (c) 2017-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 *
 */

/**
 * DOC: contains nan definitions exposed to other modules
 */

#ifndef _WLAN_NAN_CFG_H_
#define _WLAN_NAN_CFG_H_

#include "qdf_status.h"
#include "wlan_objmgr_psoc_obj.h"

#ifdef WLAN_FEATURE_NAN
/**
 * nan_cfg_psoc_open: Setup NAN priv object params on PSOC open
 * @psoc: Pointer to PSOC object
 *
 * Return: QDF Status of operation
 */
QDF_STATUS nan_cfg_psoc_open(struct wlan_objmgr_psoc *psoc);
#else
static inline
QDF_STATUS nan_cfg_psoc_open(struct wlan_objmgr_psoc *psoc)
{
	return QDF_STATUS_E_NOSUPPORT;
}
#endif /* WLAN_FEATURE_NAN */
#endif /* _WLAN_NAN_CFG_H_ */
