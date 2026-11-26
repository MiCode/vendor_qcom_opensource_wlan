/*
 * Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

/**
 * DOC: This file contains centralized definitions of CP Stats component
 */
#ifndef __CONFIG_CP_STATS_H
#define __CONFIG_CP_STATS_H

#include "cfg_define.h"

#ifdef WLAN_CHIPSET_STATS
/*
 * <ini>
 * chipset_stats_enable - Enable/Disable chipset stats logging feature
 * @Min: 0
 * @Max: 1
 * @Default: 0
 *
 * This ini is used to enable/disable Chipset Stats Logging. Configurations
 * are as follows:
 * 0 - Disable Chipset Stats logging
 * 1 - Enable Chipset Stats logging
 *
 * Related: None
 *
 * Usage: External
 *
 * </ini>
 */
#define CHIPSET_STATS_ENABLE CFG_INI_BOOL(\
		"chipset_stats_enable", false,\
		"Enable Chipset stats logging feature")

/*
 * <ini>
 * chipset_stats_debug_logging_enable - Enable/Disable chipset stats logging
 * debug prints
 * @Min: 0
 * @Max: 1
 * @Default: 0
 *
 * Related: Chipset Stats logging
 *
 * Usage: External
 *
 * </ini>
 */
#define CHIPSET_STATS_DEBUG_LOGGING_ENABLE CFG_INI_BOOL(\
		"chipset_stats_debug_logging_enable", false,\
		"enable debug logging for chipset statistics")

#define CFG_CP_STATS_CSTATS CFG(CHIPSET_STATS_ENABLE)
#define CFG_CP_STATS_DEBUG_LOGGING CFG(CHIPSET_STATS_DEBUG_LOGGING_ENABLE)
#else
#define CFG_CP_STATS_CSTATS
#define CFG_CP_STATS_DEBUG_LOGGING
#endif /* WLAN_CHIPSET_STATS */

/*
 * <ini>
 * enable_bcn_rssi_history_report - Enable/Disable beacon rssi history report
 * @Min: 0
 * @Max: 1
 * @Default: 0
 *
 * This ini is used to enable/disable beacon rssi history report feature.
 * Configurations are as follows:
 * 0 - Disable beacon rssi history report feature
 * 1 - Enable beacon rssi history report feature
 *
 * Related: None
 *
 * Usage: External
 *
 * </ini>
 */
#define CFG_ENABLE_BCN_RSSI_HISTORY_REPORT CFG_INI_BOOL(\
		"enable_bcn_rssi_history_report", false, \
		"enable bcn rssi history report")

#define CFG_CP_STATS_ALL \
	CFG_CP_STATS_CSTATS \
	CFG_CP_STATS_DEBUG_LOGGING \
	CFG(CFG_ENABLE_BCN_RSSI_HISTORY_REPORT)

#endif /* __CONFIG_CP_STATS_H */
