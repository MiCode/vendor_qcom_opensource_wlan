// MIUI ADD: WIFI_P2PHC
#include <wlan_hdd_includes.h>
#include "osif_psoc_sync.h"
#include <wlan_hdd_sysfs.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include "qdf_trace.h"

#include "p2phc.h"

volatile int sysctl_p2phc_enable = 0;
int sysctl_p2phc_debug = 0;
int sysctl_p2phc_interval = 10;

#ifdef STAT_DUMP
static int p2phc_thread(void *data)
{
	p2phc_t *p2phc = (p2phc_t *)data;
	struct dlhc *dlc;
	p2phc_info("%s", __func__);
	while (!kthread_should_stop()) {
		schedule_timeout_interruptible(HZ * sysctl_p2phc_interval);

		p2phc_info("###### TCP stat ######");
		dlc = p2phc->dlc;
		spin_lock(&p2phc->tcp_rx_lock);
		p2phc_info("i_uncompressed: %d", dlc->stat_i_uncompressed);
		p2phc_info("i_compressed:   %d", dlc->stat_i_compressed);
		p2phc_info("i_error:        %d", dlc->stat_i_error);
		p2phc_info("i_tossed:       %d", dlc->stat_i_tossed);
		p2phc_info("i_runt:         %d", dlc->stat_i_runt);
		p2phc_info("i_badcheck:     %d", dlc->stat_i_badcheck);
		spin_unlock(&p2phc->tcp_rx_lock);

		spin_lock(&p2phc->tcp_tx_lock);
		p2phc_info("o_uncompressed: %d", dlc->stat_o_uncompressed);
		p2phc_info("o_compressed:   %d", dlc->stat_o_compressed);
		p2phc_info("o_tcp:          %d", dlc->stat_o_tcp);
		p2phc_info("o_searches:     %d", dlc->stat_o_searches);
		p2phc_info("o_misses:       %d", dlc->stat_o_misses);
		spin_unlock(&p2phc->tcp_tx_lock);

		p2phc_info("###### UDP stat ######");
		dlc = dlc + 1;
		spin_lock(&p2phc->udp_rx_lock);
		p2phc_info("i_uncompressed: %d", dlc->stat_i_uncompressed);
		p2phc_info("i_compressed:   %d", dlc->stat_i_compressed);
		p2phc_info("i_error:        %d", dlc->stat_i_error);
		p2phc_info("i_tossed:       %d", dlc->stat_i_tossed);
		p2phc_info("i_runt:         %d", dlc->stat_i_runt);
		p2phc_info("i_badcheck:     %d", dlc->stat_i_badcheck);
		spin_unlock(&p2phc->udp_rx_lock);

		spin_lock(&p2phc->udp_tx_lock);
		p2phc_info("o_uncompressed: %d", dlc->stat_o_uncompressed);
		p2phc_info("o_compressed:   %d", dlc->stat_o_compressed);
		p2phc_info("o_searches:     %d", dlc->stat_o_searches);
		p2phc_info("o_misses:       %d", dlc->stat_o_misses);
		spin_unlock(&p2phc->udp_tx_lock);

		p2phc_info("###### stat end ######");
	}
	return 0;
}
#endif

static ssize_t __hdd_sysfs_p2phc_debug_store(struct hdd_context *hdd_ctx,
				struct kobj_attribute *attr,
				char const *buf, size_t count)
{
#ifdef STAT_DUMP
	char buf_local[MAX_SYSFS_USER_COMMAND_SIZE_LENGTH + 1];
	char *sptr, *token;
	int value, ret;
	if (!wlan_hdd_validate_modules_state(hdd_ctx))
		return -EINVAL;

	ret = hdd_sysfs_validate_and_copy_buf(buf_local, sizeof(buf_local),
					      buf, count);
	if (ret) {
		hdd_err_rl("invalid input");
		return ret;
	}

	sptr = buf_local;
	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &value))
		return -EINVAL;
	if (sysctl_p2phc_enable !=0) {
		sysctl_p2phc_debug = value;
        }

	switch (sysctl_p2phc_debug) {
	case 0:
		if (g_p2phc.task) {
			kthread_stop(g_p2phc.task);
			g_p2phc.task = NULL;
		}
		break;
	case 1:
		if (g_p2phc.task != NULL) {
			break;
		}
		g_p2phc.task = kthread_run(p2phc_thread, (void *)&g_p2phc, "p2phc_thread");
		if (IS_ERR_OR_NULL(g_p2phc.task)) {
				p2phc_err("%s kthread_run err", __func__);
				unregister_netdevice_notifier(&p2phc_nb);
		}
		break;
	default:
		hdd_err_rl("invalid input");
		break;
	}
#endif
	return count;
}

static ssize_t hdd_sysfs_p2phc_debug_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char const *buf, size_t count)
{
	struct osif_psoc_sync *psoc_sync;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	ssize_t errno_size;
	int ret;

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret != 0)
		return ret;

	errno_size = osif_psoc_sync_op_start(wiphy_dev(hdd_ctx->wiphy),
					     &psoc_sync);
	if (errno_size)
		return errno_size;

	errno_size = __hdd_sysfs_p2phc_debug_store(hdd_ctx, attr,
						     buf, count);

	osif_psoc_sync_op_stop(psoc_sync);

	return errno_size;
}

static ssize_t __hdd_sysfs_p2phc_debug_show(struct hdd_context *hdd_ctx,
			       struct kobj_attribute *attr, char *buf)
{
	if (!wlan_hdd_validate_modules_state(hdd_ctx))
		return -EINVAL;

	return scnprintf(buf, sizeof(buf), "%d\n", sysctl_p2phc_debug);
}

static ssize_t hdd_sysfs_p2phc_debug_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	struct osif_psoc_sync *psoc_sync;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	ssize_t errno_size;
	int ret;

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret != 0)
		return ret;

	errno_size = osif_psoc_sync_op_start(wiphy_dev(hdd_ctx->wiphy),
					     &psoc_sync);
	if (errno_size)
		return errno_size;

	errno_size = __hdd_sysfs_p2phc_debug_show(hdd_ctx, attr, buf);

	osif_psoc_sync_op_stop(psoc_sync);

	return errno_size;
}

static ssize_t __hdd_sysfs_p2phc_interval_store(struct hdd_context *hdd_ctx,
				struct kobj_attribute *attr,
				char const *buf, size_t count)
{
#ifdef STAT_DUMP
	char buf_local[MAX_SYSFS_USER_COMMAND_SIZE_LENGTH + 1];
	char *sptr, *token;
	int value, ret;
	if (!wlan_hdd_validate_modules_state(hdd_ctx))
		return -EINVAL;
	ret = hdd_sysfs_validate_and_copy_buf(buf_local, sizeof(buf_local),
					      buf, count);
	if (ret) {
		hdd_err_rl("invalid input");
		return ret;
	}
	sptr = buf_local;
	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &value))
		return -EINVAL;
	if (value >= 1 && value <= 20) {
		sysctl_p2phc_interval = value;
	} else {
		p2phc_info("Time interval does not meet the range");
	}
#endif
	return count;
}
static ssize_t hdd_sysfs_p2phc_interval_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char const *buf, size_t count)
{
	struct osif_psoc_sync *psoc_sync;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	ssize_t errno_size;
	int ret;

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret != 0)
		return ret;
	errno_size = osif_psoc_sync_op_start(wiphy_dev(hdd_ctx->wiphy),
					     &psoc_sync);
	if (errno_size)
		return errno_size;
	errno_size = __hdd_sysfs_p2phc_interval_store(hdd_ctx, attr,
						     buf, count);
	osif_psoc_sync_op_stop(psoc_sync);
	return errno_size;
}
static ssize_t __hdd_sysfs_p2phc_interval_show(struct hdd_context *hdd_ctx,
			       struct kobj_attribute *attr, char *buf)
{
	if (!wlan_hdd_validate_modules_state(hdd_ctx))
		return -EINVAL;
	return scnprintf(buf, sizeof(buf), "%d\n", sysctl_p2phc_interval);
}
static ssize_t hdd_sysfs_p2phc_interval_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	struct osif_psoc_sync *psoc_sync;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	ssize_t errno_size;
	int ret;

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret != 0)
		return ret;
	errno_size = osif_psoc_sync_op_start(wiphy_dev(hdd_ctx->wiphy),
					     &psoc_sync);
	if (errno_size)
		return errno_size;
	errno_size = __hdd_sysfs_p2phc_interval_show(hdd_ctx, attr, buf);
	osif_psoc_sync_op_stop(psoc_sync);
	return errno_size;
}

static ssize_t __hdd_sysfs_p2phc_enable_store(struct hdd_context *hdd_ctx,
				struct kobj_attribute *attr,
				char const *buf, size_t count)
{
#ifdef STAT_DUMP
	char buf_local[MAX_SYSFS_USER_COMMAND_SIZE_LENGTH + 1];
	char *sptr, *token;
	int value, ret;
	if (!wlan_hdd_validate_modules_state(hdd_ctx))
		return -EINVAL;
	ret = hdd_sysfs_validate_and_copy_buf(buf_local, sizeof(buf_local),
					      buf, count);
	if (ret) {
		hdd_err_rl("invalid input");
		return ret;
	}
	sptr = buf_local;
	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &value))
		return -EINVAL;
	if (sysctl_p2phc_enable != value) {
		if (value) {
			if(0 == p2phc_init()) {
				sysctl_p2phc_enable = value;
			}
		} else {
			sysctl_p2phc_enable = value;
			p2phc_cleanup();
		}
	}
#endif
	return count;
}
static ssize_t hdd_sysfs_p2phc_enable_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char const *buf, size_t count)
{
	struct osif_psoc_sync *psoc_sync;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	ssize_t errno_size;
	int ret;

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret != 0)
		return ret;
	errno_size = osif_psoc_sync_op_start(wiphy_dev(hdd_ctx->wiphy),
					     &psoc_sync);
	if (errno_size)
		return errno_size;
	errno_size = __hdd_sysfs_p2phc_enable_store(hdd_ctx, attr,
						     buf, count);
	osif_psoc_sync_op_stop(psoc_sync);
	return errno_size;
}
static ssize_t __hdd_sysfs_p2phc_enable_show(struct hdd_context *hdd_ctx,
			       struct kobj_attribute *attr, char *buf)
{
	if (!wlan_hdd_validate_modules_state(hdd_ctx))
		return -EINVAL;
	return scnprintf(buf, sizeof(buf), "%d\n", sysctl_p2phc_enable);
}
static ssize_t hdd_sysfs_p2phc_enable_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	struct osif_psoc_sync *psoc_sync;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	ssize_t errno_size;
	int ret;

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret != 0)
		return ret;
	errno_size = osif_psoc_sync_op_start(wiphy_dev(hdd_ctx->wiphy),
					     &psoc_sync);
	if (errno_size)
		return errno_size;
	errno_size = __hdd_sysfs_p2phc_enable_show(hdd_ctx, attr, buf);
	osif_psoc_sync_op_stop(psoc_sync);
	return errno_size;
}

/* warning! need write-all permission so overriding check */
#undef VERIFY_OCTAL_PERMISSIONS
#define VERIFY_OCTAL_PERMISSIONS(perms) (perms)

static struct kobj_attribute sysfs_sysctl_p2phc_debug =
	__ATTR(p2phc_debug, 0660, hdd_sysfs_p2phc_debug_show,
	       hdd_sysfs_p2phc_debug_store);
static struct kobj_attribute sysfs_sysctl_p2phc_interval =
	__ATTR(p2phc_interval, 0660, hdd_sysfs_p2phc_interval_show,
	       hdd_sysfs_p2phc_interval_store);
static struct kobj_attribute sysfs_sysctl_p2phc_enable =
	__ATTR(p2phc_enable, 0666, hdd_sysfs_p2phc_enable_show,
	       hdd_sysfs_p2phc_enable_store);

int hdd_sysfs_p2phc_switch_create(struct kobject *p2phc_kobject)
{
	int error;
	if (!p2phc_kobject) {
		hdd_err("could not get driver kobject!");
		return -EINVAL;
	}
	error = sysfs_create_file(p2phc_kobject,
				  &sysfs_sysctl_p2phc_debug.attr);
	if (error) {
		hdd_err("Failed to create sysfs file p2phc_debug");
		return -EINVAL;
	}
	error = sysfs_create_file(p2phc_kobject,
				  &sysfs_sysctl_p2phc_interval.attr);
	if (error) {
		hdd_err("Failed to create sysfs file p2phc_interval");
		sysfs_remove_file(p2phc_kobject, &sysfs_sysctl_p2phc_debug.attr);
		return -EINVAL;
        }
	error = sysfs_create_file(p2phc_kobject,
				  &sysfs_sysctl_p2phc_enable.attr);
	if (error) {
		hdd_err("Failed to create sysfs file p2phc_enable");
		sysfs_remove_file(p2phc_kobject, &sysfs_sysctl_p2phc_debug.attr);
		sysfs_remove_file(p2phc_kobject, &sysfs_sysctl_p2phc_interval.attr);
		return -EINVAL;
        }
	return error;
}
void hdd_sysfs_p2phc_switch_destroy(struct kobject *p2phc_kobject)
{
	if (!p2phc_kobject) {
		hdd_err("could not get p2phc kobject!");
		return;
	}
	sysfs_remove_file(p2phc_kobject, &sysfs_sysctl_p2phc_enable.attr);
	sysfs_remove_file(p2phc_kobject, &sysfs_sysctl_p2phc_interval.attr);
	sysfs_remove_file(p2phc_kobject, &sysfs_sysctl_p2phc_debug.attr);
}
// END WIFI_P2PHC
