// MIUI ADD: WIFI_P2PHC
#ifndef _P2PHC_SWITCH_H_
#define _P2PHC_SWITCH_H_

int hdd_sysfs_p2phc_switch_create(struct kobject *p2phc_kobject);
void hdd_sysfs_p2phc_switch_destroy(struct kobject *p2phc_kobject);

extern volatile int sysctl_p2phc_enable;

extern int sysctl_p2phc_debug;

extern int sysctl_p2phc_interval;

#endif
// END WIFI_P2PHC
