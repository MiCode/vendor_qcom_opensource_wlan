// MIUI ADD: WIFI_PowerSave
#include <linux/string.h>
#include "wlan_hdd_ioctl.h"
#include "wlan_hdd_cm_api.h"
#include "wlan_hdd_nss_mode_switch.h"

enum {
	NSS_MODE_DEFAULT,  // Default mode
	NSS_MODE_1x1,      // 1x1 mode
	NSS_MODE_2x2       // 2x2 mode
} nss_mode_type;

static int g_nss_mode_type = NSS_MODE_DEFAULT;

int wlan_hdd_set_nss_and_antenna_mode(struct wlan_hdd_link_info *link_info, int nss, int mode)
{
	QDF_STATUS status;
	hdd_debug("NSS = %d, antenna mode = %d", nss, mode);

	if ((nss > 2) || (nss <= 0)) {
		hdd_err("Invalid NSS: %d", nss);
		return -EINVAL;
	}

	if ((mode > HDD_ANTENNA_MODE_2X2) || (mode < HDD_ANTENNA_MODE_1X1)) {
		hdd_err("Invalid antenna mode: %d", mode);
		return -EINVAL;
	}

	if (((nss == NSS_1x1_MODE) && (mode == HDD_ANTENNA_MODE_2X2))
		|| ((nss == NSS_2x2_MODE) && (mode == HDD_ANTENNA_MODE_1X1))) {
		hdd_err("nss and antenna mode is not match: nss = %d, mode = %d", nss, mode);
		return -EINVAL;
	}

	// iwpriv wlan0 nss 1/2
	status = hdd_update_nss(link_info, nss, nss);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("cfg set nss failed, value %d status %d", nss, status);
		return qdf_status_to_os_return(status);
	}

	// wpa_cli -i wlan0 driver SET ANTENNAMODE 1/2
	status = hdd_set_antenna_mode(link_info, mode);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("cfg set antenna mode failed, value %d status %d", mode, status);
		return qdf_status_to_os_return(status);
	}

	if (nss == NSS_1x1_MODE) {
		g_nss_mode_type = NSS_MODE_1x1;
		hdd_err("change NSS mode to 1x1 successfully");
	}

	if (nss == NSS_2x2_MODE) {
		g_nss_mode_type = NSS_MODE_2x2;
		hdd_err("change NSS mode to 2x2 successfully");
	}

	hdd_exit();

	return 0;
}

void wlan_hdd_stop_nss_mode_switch(struct hdd_adapter *adapter)
{
	if(!adapter || hdd_validate_adapter(adapter)){
		hdd_debug("wlan_hdd_stop_nss_mode_switch: adapter is not valid, return.");
		return ;
	}

	hdd_enter_dev(adapter->dev);

	if (adapter->device_mode == QDF_STA_MODE) {
		if (g_nss_mode_type == NSS_MODE_2x2 || g_nss_mode_type == NSS_MODE_DEFAULT) {
			g_nss_mode_type = NSS_MODE_DEFAULT;
			goto exit;
		} else {
			wlan_hdd_set_nss_and_antenna_mode(adapter->deflink, NSS_2x2_MODE, HDD_ANTENNA_MODE_2X2);
			g_nss_mode_type = NSS_MODE_DEFAULT;
		}
	}

exit:
	hdd_exit();
}
// END WIFI_PowerSave