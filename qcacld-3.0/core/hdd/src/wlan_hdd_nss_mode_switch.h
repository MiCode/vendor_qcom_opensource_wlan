// MIUI ADD: WIFI_PowerSave
#ifndef _WLAN_HDD_NSS_MODE_SWITCH_H
#define _WLAN_HDD_NSS_MODE_SWITCH_H
/**
 * DOC: wlan_hdd_nss_switch.h
 *
 * This module describes nss switch strategy for power saving.
 */

/*
 * Include Files
 */
#include "qdf_mc_timer.h"
#include "wlan_hdd_main.h"

/*
 * Preprocessor Definitions and Constants
 */

/*
 * Type Declarations
 */
struct nss_mode_context {
    char   intf_name[IFNAMSIZ];
	struct nss_mode_context *next;
	bool   is_nss_2x2;
};

int wlan_hdd_set_nss_and_antenna_mode(struct wlan_hdd_link_info *link_info, int nss, int mode);

void wlan_hdd_stop_nss_mode_switch(struct hdd_adapter *adapter);

#endif /* #ifndef _WLAN_HDD_NSS_MODE_SWITCH_H */
// END WIFI_PowerSave