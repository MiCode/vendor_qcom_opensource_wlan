/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: contains ll_sap_definitions specific to the ll_sap module
 */

#ifndef _WLAN_LL_SAP_MAIN_H_
#define _WLAN_LL_SAP_MAIN_H_

#include "wlan_objmgr_psoc_obj.h"

#define ll_sap_err(params...) QDF_TRACE_ERROR(QDF_MODULE_ID_LL_SAP, params)
#define ll_sap_info(params...) QDF_TRACE_INFO(QDF_MODULE_ID_LL_SAP, params)
#define ll_sap_debug(params...) QDF_TRACE_DEBUG(QDF_MODULE_ID_LL_SAP, params)

#define ll_sap_nofl_err(params...) \
	QDF_TRACE_ERROR_NO_FL(QDF_MODULE_ID_LL_SAP, params)
#define ll_sap_nofl_info(params...) \
	QDF_TRACE_INFO_NO_FL(QDF_MODULE_ID_LL_SAP, params)
#define ll_sap_nofl_debug(params...) \
	QDF_TRACE_DEBUG_NO_FL(QDF_MODULE_ID_LL_SAP, params)

/**
 * ll_sap_init() - initializes ll_sap component
 *
 * Return: QDF status
 */
QDF_STATUS ll_sap_init(void);

/**
 * ll_sap_deinit() - De-initializes ll_sap component
 *
 * Return: QDF status
 */
QDF_STATUS ll_sap_deinit(void);

#endif /* _WLAN_LL_SAP_MAIN_H_ */
