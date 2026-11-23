/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

/**
 * DOC: This file contains TWT config related definitions
 */

#ifndef __CFG_TWT_H_
#define __CFG_TWT_H_

#if defined(WLAN_SUPPORT_TWT) && defined(WLAN_TWT_CONV_SUPPORTED)
/*
 * <ini>
 * twt_requestor - twt requestor.
 * @Min: 0
 * @Max: 1
 * @Default: 1
 *
 * This cfg is used to store twt requestor config.
 *
 * Related: NA
 *
 * Supported Feature: 11AX
 *
 * Usage: Internal
 *
 * </ini>
 */
#define CFG_TWT_REQUESTOR CFG_INI_BOOL( \
		"twt_requestor", \
		1, \
		"TWT requestor")

#define CFG_TWT_RESPONDER_BIT_SAP       0
#define CFG_TWT_RESPONDER_BIT_LL_LT_SAP 1
#define CFG_TWT_RESPONDER_BIT_P2P_GO    2
/*
 * <ini>
 * twt_responder - TWT responder enable/disable per VDEV
 * @Min: 0
 * @Max: 0xFF
 * @Default: 0x06
 *
 * This cfg is used to configure the TWT responder.
 * Bitmap for enabling the TWT responder per VDEV
 * BIT 0: SAP
 * BIT 1: LL_LT_SAP
 * BIT 2: P2P GO
 * BIT 3-31: Reserved
 *
 * Related: NA
 *
 * Supported Feature: 11AX
 *
 * Usage: Internal
 *
 * </ini>
 */
#define CFG_TWT_RESPONDER CFG_INI_UINT( \
		"twt_responder", \
		0, \
		0xFF, \
		0x07, \
		CFG_VALUE_OR_DEFAULT, \
		"TWT responder")

/*
 * <ini>
 * enable_twt - Enable Target Wake Time support.
 * @Min: 0
 * @Max: 1
 * @Default: 1
 *
 * This ini is used to enable or disable TWT support.
 *
 * Related: NA
 *
 * Supported Feature: 11AX
 *
 * Usage: External
 *
 * </ini>
 */
#define CFG_ENABLE_TWT CFG_INI_BOOL( \
		"enable_twt", \
		1, \
		"TWT support")

/*
 * <ini>
 * twt_congestion_timeout - Target wake time congestion timeout.
 * @Min: 0
 * @Max: 10000
 * @Default: 100
 *
 * STA uses this timer to continuously monitor channel congestion levels to
 * decide whether to start or stop TWT. This ini is used to configure the
 * target wake time congestion timeout value in the units of milliseconds.
 * A value of Zero indicates that this is a host triggered TWT and all the
 * necessary configuration for TWT will be directed from the host.
 *
 * Related: NA
 *
 * Supported Feature: 11AX
 *
 * Usage: External
 *
 * </ini>
 */
#define CFG_TWT_CONGESTION_TIMEOUT CFG_INI_UINT( \
		"twt_congestion_timeout", \
		0, \
		10000, \
		100, \
		CFG_VALUE_OR_DEFAULT, \
		"twt congestion timeout")
/*
 * <ini>
 * twt_bcast_req_resp_config - To enable broadcast twt requestor and responder.
 * @Min: 0 Disable the extended twt capability
 * @Max: 3
 * @Default: 1
 *
 * This cfg is used to configure the broadcast TWT requestor and responder.
 * Bitmap for enabling the broadcast twt requestor and responder.
 * BIT 0: Enable/Disable broadcast twt requestor.
 * BIT 1: Enable/Disable broadcast twt responder.
 * BIT 2-31: Reserved
 *
 * Related: CFG_ENABLE_TWT
 * Related: CFG_TWT_RESPONDER
 * Related: CFG_TWT_REQUESTOR
 *
 * Supported Feature: 11AX
 *
 * Usage: External
 *
 * </ini>
 */
/* defines to extract the requestor/responder capabilities from cfg */
#define TWT_BCAST_REQ_INDEX    0
#define TWT_BCAST_REQ_BITS     1
#define TWT_BCAST_RES_INDEX    1
#define TWT_BCAST_RES_BITS     1

#define CFG_BCAST_TWT_REQ_RESP CFG_INI_UINT( \
		"twt_bcast_req_resp_config", \
		0, \
		3, \
		3, \
		CFG_VALUE_OR_DEFAULT, \
		"BROADCAST TWT CAPABILITY")

#define CFG_TWT_GET_BCAST_REQ(_bcast_conf) \
	QDF_GET_BITS(_bcast_conf, \
		     TWT_BCAST_REQ_INDEX, \
		     TWT_BCAST_REQ_BITS)

#define CFG_TWT_GET_BCAST_RES(_bcast_conf) \
	QDF_GET_BITS(_bcast_conf, \
		     TWT_BCAST_RES_INDEX, \
		     TWT_BCAST_RES_BITS)

/*
 * <ini>
 * rtwt_req_resp_config - To enable restricted twt requestor and responder.
 * @Min: 0 Disable the extended twt capability
 * @Max: 3
 * @Default: 0
 *
 * This cfg is used to configure the restricted TWT requestor and responder.
 * Bitmap for enabling the restricted twt requestor and responder.
 * BIT 0: Enable/Disable restricted twt requestor.
 * BIT 1: Enable/Disable restricted twt responder.
 * BIT 2-31: Reserved
 *
 * Related: CFG_ENABLE_TWT
 * Related: CFG_TWT_RESPONDER
 * Related: CFG_TWT_REQUESTOR
 *
 * Supported Feature: 11AX
 *
 * Usage: External
 *
 * </ini>
 */
/* defines to extract the requestor/responder capabilities from cfg */
#define RTWT_REQ_INDEX    0
#define RTWT_REQ_BITS     1
#define RTWT_RES_INDEX    1
#define RTWT_RES_BITS     1

#define CFG_RTWT_REQ_RESP CFG_INI_UINT( \
		"rtwt_req_resp_config", \
		0, \
		3, \
		0, \
		CFG_VALUE_OR_DEFAULT, \
		"RESTRICTED TWT CAPABILITY")

#define CFG_GET_RTWT_REQ(_rtwt_conf) \
	QDF_GET_BITS(_rtwt_conf, \
		     RTWT_REQ_INDEX, \
		     RTWT_REQ_BITS)

#define CFG_GET_RTWT_RES(_rtwt_conf) \
	QDF_GET_BITS(_rtwt_conf, \
		     RTWT_RES_INDEX, \
		     RTWT_RES_BITS)

/*
 * <ini>
 * enable_twt_24ghz - Enable Target wake time when STA is connected on 2.4Ghz
 * band.
 * @Min: 0
 * @Max: 1
 * @Default: 1
 *
 * This ini is used to enable/disable the host TWT when STA is connected to AP
 * in 2.4Ghz band.
 *
 * Related: NA
 *
 * Supported Feature: 11AX
 *
 * Usage: External
 *
 * </ini>
 */
#define CFG_ENABLE_TWT_24GHZ CFG_INI_BOOL( \
		"enable_twt_24ghz", \
		true, \
		"enable twt in 2.4Ghz band")

/*
 * <ini>
 * disable_twt_on_scan - Disable target Wake Time during scan
 * @Min: 0
 * @Max: 1
 * @Default: 0
 *
 * This ini is used to enable/disable the TWT during scan
 *
 * Related: NA
 *
 * Supported Feature: 11AX
 *
 * Usage: External
 *
 * </ini>
 */
#define CFG_DISABLE_TWT_ON_SCAN CFG_INI_BOOL( \
		"disable_twt_on_scan", \
		false, \
		"disable twt on scan")

/*
 * <ini>
 * twt_disable_info - Enable/Disable TWT info frame.
 * @Min: 0
 * @Max: 1
 * @Default: 0
 *
 * This ini is used to enable/disable TWT Info frame
 *
 * Related: NA
 *
 * Supported Feature: 11AX
 *
 * Usage: External
 *
 * </ini>
 */
#define CFG_DISABLE_TWT_INFO_FRAME CFG_INI_BOOL( \
		"twt_disable_info", \
		false, \
		"disable twt info frame")

#define CFG_HE_FLEX_TWT_SCHED CFG_BOOL( \
				"he_flex_twt_sched", \
				1, \
				"HE Flex Twt Sched")

/*
 * <ini>
 * twt_req_res_ht_vht - To enable twt requestor and responder support in
 * ht/vht mode.
 * @Min: 0 Disable twt capability for both req/res in ht/vht mode
 * @Max: 3
 * @Default: 0
 *
 * This cfg is used to configure the TWT requestor and responder in ht/vht mode.
 * Bitmap for enabling the twt requestor and responder in ht/vht mode.
 * BIT 0: Enable/Disable twt requestor in ht/vht mode.
 * BIT 1: Enable/Disable twt responder in ht/vht mode.
 * BIT 2-31: Reserved
 *
 * Related: CFG_ENABLE_TWT
 * Related: CFG_TWT_RESPONDER
 * Related: CFG_TWT_REQUESTOR
 *
 * Usage: External
 *
 * </ini>
 */
/* defines to extract the requestor/responder capabilities from cfg */
#define TWT_REQ_HT_VHT_INDEX    0
#define TWT_REQ_HT_VHT_BITS     1
#define TWT_RES_HT_VHT_INDEX    1
#define TWT_RES_HT_VHT_BITS     1

#define CFG_TWT_REQ_RESP_HT_VHT CFG_INI_UINT( \
		"twt_req_res_ht_vht", \
		0, \
		3, \
		0, \
		CFG_VALUE_OR_DEFAULT, \
		"twt req/res capability for ht/vht mode")

#define CFG_GET_TWT_REQ_HT_VHT(_twt_req_res_ht_vht) \
		QDF_GET_BITS(_twt_req_res_ht_vht, \
		TWT_REQ_HT_VHT_INDEX, \
		TWT_REQ_HT_VHT_BITS)

#define CFG_GET_TWT_RES_HT_VHT(_twt_req_res_ht_vht) \
		QDF_GET_BITS(_twt_req_res_ht_vht, \
		TWT_RES_HT_VHT_INDEX, \
		TWT_RES_HT_VHT_BITS)

#define CFG_TWT_ALL \
	CFG(CFG_ENABLE_TWT) \
	CFG(CFG_TWT_REQUESTOR) \
	CFG(CFG_TWT_RESPONDER) \
	CFG(CFG_TWT_CONGESTION_TIMEOUT) \
	CFG(CFG_BCAST_TWT_REQ_RESP) \
	CFG(CFG_ENABLE_TWT_24GHZ) \
	CFG(CFG_DISABLE_TWT_ON_SCAN) \
	CFG(CFG_DISABLE_TWT_INFO_FRAME) \
	CFG(CFG_RTWT_REQ_RESP) \
	CFG(CFG_TWT_REQ_RESP_HT_VHT)
#elif !defined(WLAN_SUPPORT_TWT) && !defined(WLAN_TWT_CONV_SUPPORTED)
#define CFG_TWT_ALL
#endif
#endif /* __CFG_TWT_H_ */
