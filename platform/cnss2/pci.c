// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/completion.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/memblock.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/pm_runtime.h>
#include <linux/suspend.h>
#include <linux/version.h>
#include <linux/sched.h>
#include "main.h"
#include "bus.h"
#include "debug.h"
#include "pci.h"
#include "pci_platform.h"
#include "reg.h"

#define PCI_LINK_UP			1
#define PCI_LINK_DOWN			0

#define SAVE_PCI_CONFIG_SPACE		1
#define RESTORE_PCI_CONFIG_SPACE	0

#define PCI_BAR_NUM			0
#define PCI_INVALID_READ(val)		((val) == U32_MAX)

#define PCI_DMA_MASK_32_BIT		DMA_BIT_MASK(32)
#define PCI_DMA_MASK_36_BIT		DMA_BIT_MASK(36)
#define PCI_DMA_MASK_64_BIT		DMA_BIT_MASK(64)

#define MHI_NODE_NAME			"qcom,mhi"
#define MHI_MSI_NAME			"MHI"

#define QCA6390_PATH_PREFIX		"qca6390/"
#define QCA6490_PATH_PREFIX		"qca6490/"
#define QCN7605_PATH_PREFIX             "qcn7605/"
#define KIWI_PATH_PREFIX		"kiwi/"
#define MANGO_PATH_PREFIX		"mango/"
#define PEACH_PATH_PREFIX		"peach/"
#define DEFAULT_PHY_M3_FILE_NAME	"m3.bin"
#define DEFAULT_AUX_FILE_NAME		"aux_ucode.elf"
#define DEFAULT_PHY_UCODE_FILE_NAME	"phy_ucode.elf"
#define TME_PATCH_FILE_NAME		"tmel_patch.elf"
#define PHY_UCODE_V2_FILE_NAME		"phy_ucode20.elf"
#define DEFAULT_FW_FILE_NAME		"amss.bin"
#define FW_V2_FILE_NAME			"amss20.bin"
#define FW_V2_FTM_FILE_NAME		"amss20_ftm.bin"
#define DEVICE_MAJOR_VERSION_MASK	0xF

#define WAKE_MSI_NAME			"WAKE"

#define DEV_RDDM_TIMEOUT		5000
#define WAKE_EVENT_TIMEOUT		5000

#ifdef CONFIG_CNSS_EMULATION
#define EMULATION_HW			1
#else
#define EMULATION_HW			0
#endif

#define RAMDUMP_SIZE_DEFAULT		0x420000
#define CNSS_256KB_SIZE			0x40000
#define DEVICE_RDDM_COOKIE		0xCAFECACE

static bool cnss_driver_registered;

static DEFINE_SPINLOCK(pci_link_down_lock);
static DEFINE_SPINLOCK(pci_reg_window_lock);
static DEFINE_SPINLOCK(time_sync_lock);

#define MHI_TIMEOUT_OVERWRITE_MS	(plat_priv->ctrl_params.mhi_timeout)
#define MHI_M2_TIMEOUT_MS		(plat_priv->ctrl_params.mhi_m2_timeout)

#define WLAON_PWR_CTRL_SHUTDOWN_DELAY_MIN_US	1000
#define WLAON_PWR_CTRL_SHUTDOWN_DELAY_MAX_US	2000

#define RDDM_LINK_RECOVERY_RETRY		20
#define RDDM_LINK_RECOVERY_RETRY_DELAY_MS	20

#define FORCE_WAKE_DELAY_MIN_US			4000
#define FORCE_WAKE_DELAY_MAX_US			6000
#define FORCE_WAKE_DELAY_TIMEOUT_US		60000

#define REG_RETRY_MAX_TIMES		3

#define MHI_SUSPEND_RETRY_MAX_TIMES		3
#define MHI_SUSPEND_RETRY_DELAY_US		5000

#define BOOT_DEBUG_TIMEOUT_MS			7000

#define HANG_DATA_LENGTH		384
#define HST_HANG_DATA_OFFSET		((3 * 1024 * 1024) - HANG_DATA_LENGTH)
#define HSP_HANG_DATA_OFFSET		((2 * 1024 * 1024) - HANG_DATA_LENGTH)

#define AFC_SLOT_SIZE                   0x1000
#define AFC_MAX_SLOT                    2
#define AFC_MEM_SIZE                    (AFC_SLOT_SIZE * AFC_MAX_SLOT)
#define AFC_AUTH_STATUS_OFFSET          1
#define AFC_AUTH_SUCCESS                1
#define AFC_AUTH_ERROR                  0

static const struct mhi_channel_config cnss_mhi_channels[] = {
	{
		.num = 0,
		.name = "LOOPBACK",
		.num_elements = 32,
		.event_ring = 1,
		.dir = DMA_TO_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 1,
		.name = "LOOPBACK",
		.num_elements = 32,
		.event_ring = 1,
		.dir = DMA_FROM_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 4,
		.name = "DIAG",
		.num_elements = 64,
		.event_ring = 1,
		.dir = DMA_TO_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 5,
		.name = "DIAG",
		.num_elements = 64,
		.event_ring = 1,
		.dir = DMA_FROM_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 20,
		.name = "IPCR",
		.num_elements = 64,
		.event_ring = 1,
		.dir = DMA_TO_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 21,
		.name = "IPCR",
		.num_elements = 64,
		.event_ring = 1,
		.dir = DMA_FROM_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = true,
	},
/* All MHI satellite config to be at the end of data struct */
#if IS_ENABLED(CONFIG_MHI_SATELLITE)
	{
		.num = 50,
		.name = "ADSP_0",
		.num_elements = 64,
		.event_ring = 3,
		.dir = DMA_BIDIRECTIONAL,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = true,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 51,
		.name = "ADSP_1",
		.num_elements = 64,
		.event_ring = 3,
		.dir = DMA_BIDIRECTIONAL,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = true,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 70,
		.name = "ADSP_2",
		.num_elements = 64,
		.event_ring = 3,
		.dir = DMA_BIDIRECTIONAL,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = true,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 71,
		.name = "ADSP_3",
		.num_elements = 64,
		.event_ring = 3,
		.dir = DMA_BIDIRECTIONAL,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = true,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
#endif
};

static const struct mhi_channel_config cnss_mhi_channels_genoa[] = {
	{
		.num = 0,
		.name = "LOOPBACK",
		.num_elements = 32,
		.event_ring = 1,
		.dir = DMA_TO_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 1,
		.name = "LOOPBACK",
		.num_elements = 32,
		.event_ring = 1,
		.dir = DMA_FROM_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 4,
		.name = "DIAG",
		.num_elements = 64,
		.event_ring = 1,
		.dir = DMA_TO_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 5,
		.name = "DIAG",
		.num_elements = 64,
		.event_ring = 1,
		.dir = DMA_FROM_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 16,
		.name = "IPCR",
		.num_elements = 64,
		.event_ring = 1,
		.dir = DMA_TO_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
	},
	{
		.num = 17,
		.name = "IPCR",
		.num_elements = 64,
		.event_ring = 1,
		.dir = DMA_FROM_DEVICE,
		.ee_mask = 0x4,
		.pollcfg = 0,
		.doorbell = MHI_DB_BRST_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = true,
	},
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
static struct mhi_event_config cnss_mhi_events[] = {
#else
static const struct mhi_event_config cnss_mhi_events[] = {
#endif
	{
		.num_elements = 32,
		.irq_moderation_ms = 0,
		.irq = 1,
		.mode = MHI_DB_BRST_DISABLE,
		.data_type = MHI_ER_CTRL,
		.priority = 0,
		.hardware_event = false,
		.client_managed = false,
		.offload_channel = false,
	},
	{
		.num_elements = 256,
		.irq_moderation_ms = 0,
		.irq = 2,
		.mode = MHI_DB_BRST_DISABLE,
		.priority = 1,
		.hardware_event = false,
		.client_managed = false,
		.offload_channel = false,
	},
#if IS_ENABLED(CONFIG_MHI_BUS_MISC)
	{
		.num_elements = 32,
		.irq_moderation_ms = 0,
		.irq = 1,
		.mode = MHI_DB_BRST_DISABLE,
		.data_type = MHI_ER_BW_SCALE,
		.priority = 2,
		.hardware_event = false,
		.client_managed = false,
		.offload_channel = false,
	},
#endif
#if IS_ENABLED(CONFIG_MHI_SATELLITE)
	{
		.num_elements = 256,
		.irq_moderation_ms = 0,
		.irq = 2,
		.mode = MHI_DB_BRST_DISABLE,
		.data_type = MHI_ER_DATA,
		.priority = 1,
		.hardware_event = false,
		.client_managed = true,
		.offload_channel = true,
	},
#endif
};

#if IS_ENABLED(CONFIG_MHI_SATELLITE)
#define CNSS_MHI_SATELLITE_CH_CFG_COUNT 4
#define CNSS_MHI_SATELLITE_EVT_COUNT 1
#else
#define CNSS_MHI_SATELLITE_CH_CFG_COUNT 0
#define CNSS_MHI_SATELLITE_EVT_COUNT 0
#endif

static const struct mhi_controller_config cnss_mhi_config_default = {
#if IS_ENABLED(CONFIG_MHI_SATELLITE)
	.max_channels = 72,
#else
	.max_channels = 32,
#endif
	.timeout_ms = 10000,
	.use_bounce_buf = false,
	.buf_len = 0x8000,
	.num_channels = ARRAY_SIZE(cnss_mhi_channels),
	.ch_cfg = cnss_mhi_channels,
	.num_events = ARRAY_SIZE(cnss_mhi_events),
	.event_cfg = cnss_mhi_events,
	.m2_no_db = true,
};

static const struct mhi_controller_config cnss_mhi_config_genoa = {
	.max_channels = 32,
	.timeout_ms = 10000,
	.use_bounce_buf = false,
	.buf_len = 0x8000,
	.num_channels = ARRAY_SIZE(cnss_mhi_channels_genoa),
	.ch_cfg = cnss_mhi_channels_genoa,
	.num_events = ARRAY_SIZE(cnss_mhi_events) -
		CNSS_MHI_SATELLITE_EVT_COUNT,
	.event_cfg = cnss_mhi_events,
	.m2_no_db = true,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0))
	.bhie_offset = 0x0324,
#endif
};

static const struct mhi_controller_config cnss_mhi_config_no_satellite = {
	.max_channels = 32,
	.timeout_ms = 10000,
	.use_bounce_buf = false,
	.buf_len = 0x8000,
	.num_channels = ARRAY_SIZE(cnss_mhi_channels) -
			CNSS_MHI_SATELLITE_CH_CFG_COUNT,
	.ch_cfg = cnss_mhi_channels,
	.num_events = ARRAY_SIZE(cnss_mhi_events) -
			CNSS_MHI_SATELLITE_EVT_COUNT,
	.event_cfg = cnss_mhi_events,
	.m2_no_db = true,
};

static struct cnss_pci_reg ce_src[] = {
	{ "SRC_RING_BASE_LSB", CE_SRC_RING_BASE_LSB_OFFSET },
	{ "SRC_RING_BASE_MSB", CE_SRC_RING_BASE_MSB_OFFSET },
	{ "SRC_RING_ID", CE_SRC_RING_ID_OFFSET },
	{ "SRC_RING_MISC", CE_SRC_RING_MISC_OFFSET },
	{ "SRC_CTRL", CE_SRC_CTRL_OFFSET },
	{ "SRC_R0_CE_CH_SRC_IS", CE_SRC_R0_CE_CH_SRC_IS_OFFSET },
	{ "SRC_RING_HP", CE_SRC_RING_HP_OFFSET },
	{ "SRC_RING_TP", CE_SRC_RING_TP_OFFSET },
	{ NULL },
};

static struct cnss_pci_reg ce_dst[] = {
	{ "DEST_RING_BASE_LSB", CE_DEST_RING_BASE_LSB_OFFSET },
	{ "DEST_RING_BASE_MSB", CE_DEST_RING_BASE_MSB_OFFSET },
	{ "DEST_RING_ID", CE_DEST_RING_ID_OFFSET },
	{ "DEST_RING_MISC", CE_DEST_RING_MISC_OFFSET },
	{ "DEST_CTRL", CE_DEST_CTRL_OFFSET },
	{ "CE_CH_DST_IS", CE_CH_DST_IS_OFFSET },
	{ "CE_CH_DEST_CTRL2", CE_CH_DEST_CTRL2_OFFSET },
	{ "DEST_RING_HP", CE_DEST_RING_HP_OFFSET },
	{ "DEST_RING_TP", CE_DEST_RING_TP_OFFSET },
	{ "STATUS_RING_BASE_LSB", CE_STATUS_RING_BASE_LSB_OFFSET },
	{ "STATUS_RING_BASE_MSB", CE_STATUS_RING_BASE_MSB_OFFSET },
	{ "STATUS_RING_ID", CE_STATUS_RING_ID_OFFSET },
	{ "STATUS_RING_MISC", CE_STATUS_RING_MISC_OFFSET },
	{ "STATUS_RING_HP", CE_STATUS_RING_HP_OFFSET },
	{ "STATUS_RING_TP", CE_STATUS_RING_TP_OFFSET },
	{ NULL },
};

static struct cnss_pci_reg ce_cmn[] = {
	{ "GXI_ERR_INTS", CE_COMMON_GXI_ERR_INTS },
	{ "GXI_ERR_STATS", CE_COMMON_GXI_ERR_STATS },
	{ "GXI_WDOG_STATUS", CE_COMMON_GXI_WDOG_STATUS },
	{ "TARGET_IE_0", CE_COMMON_TARGET_IE_0 },
	{ "TARGET_IE_1", CE_COMMON_TARGET_IE_1 },
	{ NULL },
};

static struct cnss_pci_reg qdss_csr[] = {
	{ "QDSSCSR_ETRIRQCTRL", QDSS_APB_DEC_CSR_ETRIRQCTRL_OFFSET },
	{ "QDSSCSR_PRESERVEETF", QDSS_APB_DEC_CSR_PRESERVEETF_OFFSET },
	{ "QDSSCSR_PRESERVEETR0", QDSS_APB_DEC_CSR_PRESERVEETR0_OFFSET },
	{ "QDSSCSR_PRESERVEETR1", QDSS_APB_DEC_CSR_PRESERVEETR1_OFFSET },
	{ NULL },
};

static struct cnss_pci_reg pci_scratch[] = {
	{ "PCIE_SCRATCH_0", PCIE_SCRATCH_0_SOC_PCIE_REG },
	{ "PCIE_SCRATCH_1", PCIE_SCRATCH_1_SOC_PCIE_REG },
	{ "PCIE_SCRATCH_2", PCIE_SCRATCH_2_SOC_PCIE_REG },
	{ NULL },
};

/* First field of the structure is the device bit mask. Use
 * enum cnss_pci_reg_mask as reference for the value.
 */
static struct cnss_misc_reg wcss_reg_access_seq[] = {
	{1, 0, QCA6390_GCC_DEBUG_CLK_CTL, 0},
	{1, 1, QCA6390_GCC_DEBUG_CLK_CTL, 0x802},
	{1, 0, QCA6390_GCC_DEBUG_CLK_CTL, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_PLL_MODE, 0},
	{1, 1, QCA6390_GCC_DEBUG_CLK_CTL, 0x805},
	{1, 0, QCA6390_GCC_DEBUG_CLK_CTL, 0},
	{1, 0, QCA6390_WCSS_WFSS_PMM_WFSS_PMM_R0_PMM_CTRL, 0},
	{1, 0, QCA6390_WCSS_PMM_TOP_PMU_CX_CSR, 0},
	{1, 0, QCA6390_WCSS_PMM_TOP_AON_INT_RAW_STAT, 0},
	{1, 0, QCA6390_WCSS_PMM_TOP_AON_INT_EN, 0},
	{1, 0, QCA6390_WCSS_PMM_TOP_PMU_TESTBUS_STS, 0},
	{1, 1, QCA6390_WCSS_PMM_TOP_PMU_TESTBUS_CTL, 0xD},
	{1, 0, QCA6390_WCSS_PMM_TOP_TESTBUS_STS, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_SAW2_CFG, 0},
	{1, 1, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_SAW2_CFG, 0},
	{1, 1, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_CTL, 0x8},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_SAW2_SPM_STS, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_SAW2_SPM_CTL, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_SAW2_SPM_SLP_SEQ_ENTRY_0, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_SAW2_SPM_SLP_SEQ_ENTRY_9, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_STATUS0, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_STATUS1, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_STATUS2, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_STATUS3, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_STATUS4, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_STATUS5, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_STATUS6, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_ENABLE0, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_ENABLE1, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_ENABLE2, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_ENABLE3, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_ENABLE4, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_ENABLE5, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_ENABLE6, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_PENDING0, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_PENDING1, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_PENDING2, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_PENDING3, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_PENDING4, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_PENDING5, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_L2VIC_INT_PENDING6, 0},
	{1, 1, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_CTL, 0x30040},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_CTL, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 1, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_CTL, 0x30105},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_CTL, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_VALUE, 0},
	{1, 0, QCA6390_WCSS_Q6SS_PUBCSR_QDSP6SS_TEST_BUS_CTL, 0},
	{1, 0, QCA6390_WCSS_CC_WCSS_UMAC_NOC_CBCR, 0},
	{1, 0, QCA6390_WCSS_CC_WCSS_UMAC_AHB_CBCR, 0},
	{1, 0, QCA6390_WCSS_CC_WCSS_UMAC_GDSCR, 0},
	{1, 0, QCA6390_WCSS_CC_WCSS_WLAN1_GDSCR, 0},
	{1, 0, QCA6390_WCSS_CC_WCSS_WLAN2_GDSCR, 0},
	{1, 0, QCA6390_WCSS_PMM_TOP_PMM_INT_CLR, 0},
	{1, 0, QCA6390_WCSS_PMM_TOP_AON_INT_STICKY_EN, 0},
};

static struct cnss_misc_reg pcie_reg_access_seq[] = {
	{1, 0, QCA6390_PCIE_PCIE_WCSS_STATUS_FOR_DEBUG_LOW_PCIE_LOCAL_REG, 0},
	{1, 0, QCA6390_PCIE_SOC_PCIE_WRAP_INTR_MASK_SOC_PCIE_REG, 0},
	{1, 1, QCA6390_PCIE_SOC_PCIE_WRAP_INTR_MASK_SOC_PCIE_REG, 0x18},
	{1, 0, QCA6390_PCIE_SOC_PCIE_WRAP_INTR_MASK_SOC_PCIE_REG, 0},
	{1, 0, QCA6390_PCIE_SOC_PCIE_WRAP_INTR_MASK_SOC_PCIE_REG, 0},
	{1, 0, QCA6390_PCIE_SOC_PCIE_WRAP_INTR_STATUS_SOC_PCIE_REG, 0},
	{1, 0, QCA6390_PCIE_SOC_COMMIT_REPLAY_SOC_PCIE_REG, 0},
	{1, 0, QCA6390_TLMM_GPIO_IN_OUT57, 0},
	{1, 0, QCA6390_TLMM_GPIO_INTR_CFG57, 0},
	{1, 0, QCA6390_TLMM_GPIO_INTR_STATUS57, 0},
	{1, 0, QCA6390_TLMM_GPIO_IN_OUT59, 0},
	{1, 0, QCA6390_TLMM_GPIO_INTR_CFG59, 0},
	{1, 0, QCA6390_TLMM_GPIO_INTR_STATUS59, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_LTSSM, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_PM_STTS, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_PM_STTS_1, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_INT_STATUS, 0},
	{1, 0, QCA6390_PCIE_PCIE_INT_ALL_STATUS, 0},
	{1, 0, QCA6390_PCIE_PCIE_INT_ALL_MASK, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_BDF_TO_SID_CFG, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_L1SS_SLEEP_NO_MHI_ACCESS_HANDLER_RD_4, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_L1SS_SLEEP_NO_MHI_ACCESS_HANDLER_RD_3, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_MHI_CLOCK_RESET_CTRL, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_MHI_BASE_ADDR_LOWER, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_L1SS_SLEEP_MODE_HANDLER_STATUS, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_L1SS_SLEEP_MODE_HANDLER_CFG, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_DEBUG_CNT_AUX_CLK_IN_L1SUB_L2, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_DEBUG_CNT_PM_LINKST_IN_L1SUB, 0},
	{1, 0, QCA6390_PCIE_PCIE_CORE_CONFIG, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_L1SS_SLEEP_NO_MHI_ACCESS_HANDLER_RD_4, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_DEBUG_CNT_PM_LINKST_IN_L2, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_DEBUG_CNT_PM_LINKST_IN_L1, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_DEBUG_CNT_AUX_CLK_IN_L1SUB_L1, 0},
	{1, 0, QCA6390_PCIE_PCIE_PARF_DEBUG_CNT_AUX_CLK_IN_L1SUB_L2, 0},
	{1, 0, QCA6390_PCIE_PCIE_LOCAL_REG_WCSSAON_PCIE_SR_STATUS_HIGH, 0},
	{1, 0, QCA6390_PCIE_PCIE_LOCAL_REG_WCSSAON_PCIE_SR_STATUS_LOW, 0},
	{1, 0, QCA6390_PCIE_PCIE_LOCAL_REG_WCSS_STATUS_FOR_DEBUG_HIGH, 0},
	{1, 0, QCA6390_PCIE_PCIE_LOCAL_REG_WCSS_STATUS_FOR_DEBUG_LOW, 0},
	{1, 0, QCA6390_WFSS_PMM_WFSS_PMM_R0_WLAN1_STATUS_REG2, 0},
	{1, 0, QCA6390_WFSS_PMM_WFSS_PMM_R0_WLAN2_STATUS_REG2, 0},
	{1, 0, QCA6390_WFSS_PMM_WFSS_PMM_R0_PMM_WLAN2_CFG_REG1, 0},
	{1, 0, QCA6390_WFSS_PMM_WFSS_PMM_R0_PMM_WLAN1_CFG_REG1, 0},
	{1, 0, QCA6390_WFSS_PMM_WFSS_PMM_R0_WLAN2_APS_STATUS_REG1, 0},
	{1, 0, QCA6390_WFSS_PMM_WFSS_PMM_R0_WLAN1_APS_STATUS_REG1, 0},
	{1, 0, QCA6390_PCIE_PCIE_BHI_EXECENV_REG, 0},
};

static struct cnss_misc_reg wlaon_reg_access_seq[] = {
	{3, 0, WLAON_SOC_POWER_CTRL, 0},
	{3, 0, WLAON_SOC_PWR_WDG_BARK_THRSHD, 0},
	{3, 0, WLAON_SOC_PWR_WDG_BITE_THRSHD, 0},
	{3, 0, WLAON_SW_COLD_RESET, 0},
	{3, 0, WLAON_RFA_MEM_SLP_NRET_N_OVERRIDE, 0},
	{3, 0, WLAON_GDSC_DELAY_SETTING, 0},
	{3, 0, WLAON_GDSC_DELAY_SETTING2, 0},
	{3, 0, WLAON_WL_PWR_STATUS_REG, 0},
	{3, 0, WLAON_WL_AON_DBG_CFG_REG, 0},
	{2, 0, WLAON_WL_AON_DBG_ENABLE_GRP0_REG, 0},
	{2, 0, WLAON_WL_AON_DBG_ENABLE_GRP1_REG, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL0, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL1, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL2, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL3, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL4, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL5, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL5_1, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL6, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL6_1, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL7, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL8, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL8_1, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL9, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL9_1, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL10, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL11, 0},
	{2, 0, WLAON_WL_AON_APM_CFG_CTRL12, 0},
	{2, 0, WLAON_WL_AON_APM_OVERRIDE_REG, 0},
	{2, 0, WLAON_WL_AON_CXPC_REG, 0},
	{2, 0, WLAON_WL_AON_APM_STATUS0, 0},
	{2, 0, WLAON_WL_AON_APM_STATUS1, 0},
	{2, 0, WLAON_WL_AON_APM_STATUS2, 0},
	{2, 0, WLAON_WL_AON_APM_STATUS3, 0},
	{2, 0, WLAON_WL_AON_APM_STATUS4, 0},
	{2, 0, WLAON_WL_AON_APM_STATUS5, 0},
	{2, 0, WLAON_WL_AON_APM_STATUS6, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL1, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL6, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL7, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL3, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL4, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL5, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL8, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL2, 0},
	{3, 0, WLAON_GLOBAL_COUNTER_CTRL9, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL1, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL2, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL3, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL4, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL5, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL6, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL7, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL8, 0},
	{3, 0, WLAON_RTC_CLK_CAL_CTRL9, 0},
	{3, 0, WLAON_WCSSAON_CONFIG_REG, 0},
	{3, 0, WLAON_WLAN_OEM_DEBUG_REG, 0},
	{3, 0, WLAON_WLAN_RAM_DUMP_REG, 0},
	{3, 0, WLAON_QDSS_WCSS_REG, 0},
	{3, 0, WLAON_QDSS_WCSS_ACK, 0},
	{3, 0, WLAON_WL_CLK_CNTL_KDF_REG, 0},
	{3, 0, WLAON_WL_CLK_CNTL_PMU_HFRC_REG, 0},
	{3, 0, WLAON_QFPROM_PWR_CTRL_REG, 0},
	{3, 0, WLAON_DLY_CONFIG, 0},
	{3, 0, WLAON_WLAON_Q6_IRQ_REG, 0},
	{3, 0, WLAON_PCIE_INTF_SW_CFG_REG, 0},
	{3, 0, WLAON_PCIE_INTF_STICKY_SW_CFG_REG, 0},
	{3, 0, WLAON_PCIE_INTF_PHY_SW_CFG_REG, 0},
	{3, 0, WLAON_PCIE_INTF_PHY_NOCSR_SW_CFG_REG, 0},
	{3, 0, WLAON_Q6_COOKIE_BIT, 0},
	{3, 0, WLAON_WARM_SW_ENTRY, 0},
	{3, 0, WLAON_RESET_DBG_SW_ENTRY, 0},
	{3, 0, WLAON_WL_PMUNOC_CFG_REG, 0},
	{3, 0, WLAON_RESET_CAUSE_CFG_REG, 0},
	{3, 0, WLAON_SOC_WCSSAON_WAKEUP_IRQ_7_EN_REG, 0},
	{3, 0, WLAON_DEBUG, 0},
	{3, 0, WLAON_SOC_PARAMETERS, 0},
	{3, 0, WLAON_WLPM_SIGNAL, 0},
	{3, 0, WLAON_SOC_RESET_CAUSE_REG, 0},
	{3, 0, WLAON_WAKEUP_PCIE_SOC_REG, 0},
	{3, 0, WLAON_PBL_STACK_CANARY, 0},
	{3, 0, WLAON_MEM_TOT_NUM_GRP_REG, 0},
	{3, 0, WLAON_MEM_TOT_BANKS_IN_GRP0_REG, 0},
	{3, 0, WLAON_MEM_TOT_BANKS_IN_GRP1_REG, 0},
	{3, 0, WLAON_MEM_TOT_BANKS_IN_GRP2_REG, 0},
	{3, 0, WLAON_MEM_TOT_BANKS_IN_GRP3_REG, 0},
	{3, 0, WLAON_MEM_TOT_SIZE_IN_GRP0_REG, 0},
	{3, 0, WLAON_MEM_TOT_SIZE_IN_GRP1_REG, 0},
	{3, 0, WLAON_MEM_TOT_SIZE_IN_GRP2_REG, 0},
	{3, 0, WLAON_MEM_TOT_SIZE_IN_GRP3_REG, 0},
	{3, 0, WLAON_MEM_SLP_NRET_OVERRIDE_GRP0_REG, 0},
	{3, 0, WLAON_MEM_SLP_NRET_OVERRIDE_GRP1_REG, 0},
	{3, 0, WLAON_MEM_SLP_NRET_OVERRIDE_GRP2_REG, 0},
	{3, 0, WLAON_MEM_SLP_NRET_OVERRIDE_GRP3_REG, 0},
	{3, 0, WLAON_MEM_SLP_RET_OVERRIDE_GRP0_REG, 0},
	{3, 0, WLAON_MEM_SLP_RET_OVERRIDE_GRP1_REG, 0},
	{3, 0, WLAON_MEM_SLP_RET_OVERRIDE_GRP2_REG, 0},
	{3, 0, WLAON_MEM_SLP_RET_OVERRIDE_GRP3_REG, 0},
	{3, 0, WLAON_MEM_CNT_SEL_REG, 0},
	{3, 0, WLAON_MEM_NO_EXTBHS_REG, 0},
	{3, 0, WLAON_MEM_DEBUG_REG, 0},
	{3, 0, WLAON_MEM_DEBUG_BUS_REG, 0},
	{3, 0, WLAON_MEM_REDUN_CFG_REG, 0},
	{3, 0, WLAON_WL_AON_SPARE2, 0},
	{3, 0, WLAON_VSEL_CFG_FOR_WL_RET_DISABLE_REG, 0},
	{3, 0, WLAON_BTFM_WLAN_IPC_STATUS_REG, 0},
	{3, 0, WLAON_MPM_COUNTER_CHICKEN_BITS, 0},
	{3, 0, WLAON_WLPM_CHICKEN_BITS, 0},
	{3, 0, WLAON_PCIE_PHY_PWR_REG, 0},
	{3, 0, WLAON_WL_CLK_CNTL_PMU_LPO2M_REG, 0},
	{3, 0, WLAON_WL_SS_ROOT_CLK_SWITCH_REG, 0},
	{3, 0, WLAON_POWERCTRL_PMU_REG, 0},
	{3, 0, WLAON_POWERCTRL_MEM_REG, 0},
	{3, 0, WLAON_PCIE_PWR_CTRL_REG, 0},
	{3, 0, WLAON_SOC_PWR_PROFILE_REG, 0},
	{3, 0, WLAON_WCSSAON_PCIE_SR_STATUS_HI_REG, 0},
	{3, 0, WLAON_WCSSAON_PCIE_SR_STATUS_LO_REG, 0},
	{3, 0, WLAON_WCSS_TCSR_PMM_SR_STATUS_HI_REG, 0},
	{3, 0, WLAON_WCSS_TCSR_PMM_SR_STATUS_LO_REG, 0},
	{3, 0, WLAON_MEM_SVS_CFG_REG, 0},
	{3, 0, WLAON_CMN_AON_MISC_REG, 0},
	{3, 0, WLAON_INTR_STATUS, 0},
	{2, 0, WLAON_INTR_ENABLE, 0},
	{2, 0, WLAON_NOC_DBG_BUS_SEL_REG, 0},
	{2, 0, WLAON_NOC_DBG_BUS_REG, 0},
	{2, 0, WLAON_WL_CTRL_MISC_REG, 0},
	{2, 0, WLAON_DBG_STATUS0, 0},
	{2, 0, WLAON_DBG_STATUS1, 0},
	{2, 0, WLAON_TIMERSYNC_OFFSET_L, 0},
	{2, 0, WLAON_TIMERSYNC_OFFSET_H, 0},
	{2, 0, WLAON_PMU_LDO_SETTLE_REG, 0},
};

static struct cnss_misc_reg syspm_reg_access_seq[] = {
	{1, 0, QCA6390_SYSPM_SYSPM_PWR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_DBG_BTFM_AON_REG, 0},
	{1, 0, QCA6390_SYSPM_DBG_BUS_SEL_REG, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
	{1, 0, QCA6390_SYSPM_WCSSAON_SR_STATUS, 0},
};

static struct cnss_print_optimize print_optimize;

#define WCSS_REG_SIZE ARRAY_SIZE(wcss_reg_access_seq)
#define PCIE_REG_SIZE ARRAY_SIZE(pcie_reg_access_seq)
#define WLAON_REG_SIZE ARRAY_SIZE(wlaon_reg_access_seq)
#define SYSPM_REG_SIZE ARRAY_SIZE(syspm_reg_access_seq)

static int cnss_pci_update_fw_name(struct cnss_pci_data *pci_priv);
static void cnss_pci_suspend_pwroff(struct pci_dev *pci_dev);
static bool cnss_should_suspend_pwroff(struct pci_dev *pci_dev);


#if IS_ENABLED(CONFIG_MHI_BUS_MISC)
static void cnss_mhi_debug_reg_dump(struct cnss_pci_data *pci_priv)
{
	mhi_debug_reg_dump(pci_priv->mhi_ctrl);
}

static void cnss_mhi_dump_sfr(struct cnss_pci_data *pci_priv)
{
	mhi_dump_sfr(pci_priv->mhi_ctrl);
}

static bool cnss_mhi_scan_rddm_cookie(struct cnss_pci_data *pci_priv,
				      u32 cookie)
{
	return mhi_scan_rddm_cookie(pci_priv->mhi_ctrl, cookie);
}

static int cnss_mhi_pm_fast_suspend(struct cnss_pci_data *pci_priv,
				    bool notify_clients)
{
	return mhi_pm_fast_suspend(pci_priv->mhi_ctrl, notify_clients);
}

static int cnss_mhi_pm_fast_resume(struct cnss_pci_data *pci_priv,
				   bool notify_clients)
{
	return mhi_pm_fast_resume(pci_priv->mhi_ctrl, notify_clients);
}

static void cnss_mhi_set_m2_timeout_ms(struct cnss_pci_data *pci_priv,
				       u32 timeout)
{
	return mhi_set_m2_timeout_ms(pci_priv->mhi_ctrl, timeout);
}

static int cnss_mhi_device_get_sync_atomic(struct cnss_pci_data *pci_priv,
					   int timeout_us, bool in_panic)
{
	return mhi_device_get_sync_atomic(pci_priv->mhi_ctrl->mhi_dev,
					  timeout_us, in_panic);
}

#ifdef CONFIG_CNSS2_SMMU_DB_SUPPORT
static int cnss_mhi_host_notify_db_disable_trace(struct cnss_pci_data *pci_priv)
{
	return mhi_host_notify_db_disable_trace(pci_priv->mhi_ctrl);
}
#endif

static void
cnss_mhi_controller_set_bw_scale_cb(struct cnss_pci_data *pci_priv,
				    int (*cb)(struct mhi_controller *mhi_ctrl,
					      struct mhi_link_info *link_info))
{
	mhi_controller_set_bw_scale_cb(pci_priv->mhi_ctrl, cb);
}

static int cnss_mhi_force_reset(struct cnss_pci_data *pci_priv)
{
	return mhi_force_reset(pci_priv->mhi_ctrl);
}

void cnss_mhi_controller_set_base(struct cnss_pci_data *pci_priv,
				  phys_addr_t base)
{
	return mhi_controller_set_base(pci_priv->mhi_ctrl, base);
}
#else
static void cnss_mhi_debug_reg_dump(struct cnss_pci_data *pci_priv)
{
}

static void cnss_mhi_dump_sfr(struct cnss_pci_data *pci_priv)
{
}

static bool cnss_mhi_scan_rddm_cookie(struct cnss_pci_data *pci_priv,
				      u32 cookie)
{
	return false;
}

static int cnss_mhi_pm_fast_suspend(struct cnss_pci_data *pci_priv,
				    bool notify_clients)
{
	return -EOPNOTSUPP;
}

static int cnss_mhi_pm_fast_resume(struct cnss_pci_data *pci_priv,
				   bool notify_clients)
{
	return -EOPNOTSUPP;
}

static void cnss_mhi_set_m2_timeout_ms(struct cnss_pci_data *pci_priv,
				       u32 timeout)
{
}

static int cnss_mhi_device_get_sync_atomic(struct cnss_pci_data *pci_priv,
					   int timeout_us, bool in_panic)
{
	return -EOPNOTSUPP;
}

#ifdef CONFIG_CNSS2_SMMU_DB_SUPPORT
static int cnss_mhi_host_notify_db_disable_trace(struct cnss_pci_data *pci_priv)
{
	return -EOPNOTSUPP;
}
#endif

static void
cnss_mhi_controller_set_bw_scale_cb(struct cnss_pci_data *pci_priv,
				    int (*cb)(struct mhi_controller *mhi_ctrl,
					      struct mhi_link_info *link_info))
{
}

static int cnss_mhi_force_reset(struct cnss_pci_data *pci_priv)
{
	return -EOPNOTSUPP;
}

void cnss_mhi_controller_set_base(struct cnss_pci_data *pci_priv,
				  phys_addr_t base)
{
}
#endif /* CONFIG_MHI_BUS_MISC */

#ifdef CONFIG_CNSS2_SMMU_DB_SUPPORT
#define CNSS_MHI_WAKE_TIMEOUT		500000

static void cnss_record_smmu_fault_timestamp(struct cnss_pci_data *pci_priv,
					     enum cnss_smmu_fault_time id)
{
	if (id >= SMMU_CB_MAX)
		return;

	pci_priv->smmu_fault_timestamp[id] = sched_clock();
}

static void cnss_pci_smmu_fault_handler_irq(struct iommu_domain *domain,
					    void *handler_token)
{
	struct cnss_pci_data *pci_priv = handler_token;
	int ret = 0;

	cnss_record_smmu_fault_timestamp(pci_priv, SMMU_CB_ENTRY);
	ret = cnss_mhi_device_get_sync_atomic(pci_priv,
					      CNSS_MHI_WAKE_TIMEOUT, true);
	if (ret < 0) {
		cnss_pr_err("Failed to bring mhi in M0 state, ret %d\n", ret);
		return;
	}

	cnss_record_smmu_fault_timestamp(pci_priv, SMMU_CB_DOORBELL_RING);
	ret = cnss_mhi_host_notify_db_disable_trace(pci_priv);
	if (ret < 0)
		cnss_pr_err("Fail to notify wlan fw to stop trace collection, ret %d\n", ret);

	cnss_record_smmu_fault_timestamp(pci_priv, SMMU_CB_EXIT);
}

void cnss_register_iommu_fault_handler_irq(struct cnss_pci_data *pci_priv)
{
	qcom_iommu_set_fault_handler_irq(pci_priv->iommu_domain,
					 cnss_pci_smmu_fault_handler_irq, pci_priv);
}
#else
void cnss_register_iommu_fault_handler_irq(struct cnss_pci_data *pci_priv)
{
}
#endif

int cnss_pci_check_link_status(struct cnss_pci_data *pci_priv)
{
	u16 device_id;

	if (pci_priv->pci_link_state == PCI_LINK_DOWN) {
		cnss_pr_dbg("%ps: PCIe link is in suspend state\n",
			    (void *)_RET_IP_);
		return -EACCES;
	}

	if (pci_priv->pci_link_down_ind) {
		cnss_pr_err("%ps: PCIe link is down\n", (void *)_RET_IP_);
		return -EIO;
	}

	pci_read_config_word(pci_priv->pci_dev, PCI_DEVICE_ID, &device_id);
	if (device_id != pci_priv->device_id)  {
		cnss_fatal_err("%ps: PCI device ID mismatch, link possibly down, current read ID: 0x%x, record ID: 0x%x\n",
			       (void *)_RET_IP_, device_id,
			       pci_priv->device_id);
		return -EIO;
	}

	return 0;
}

static void cnss_pci_select_window(struct cnss_pci_data *pci_priv, u32 offset)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	u32 window = (offset >> WINDOW_SHIFT) & WINDOW_VALUE_MASK;
	u32 window_enable = WINDOW_ENABLE_BIT | window;
	u32 val;

	if (plat_priv->device_id == PEACH_DEVICE_ID) {
		writel_relaxed(window_enable, pci_priv->bar +
			       PEACH_PCIE_REMAP_BAR_CTRL_OFFSET);
	} else {
		writel_relaxed(window_enable, pci_priv->bar +
			       QCA6390_PCIE_REMAP_BAR_CTRL_OFFSET);
	}

	if (plat_priv->device_id == QCN7605_DEVICE_ID)
		window_enable = QCN7605_WINDOW_ENABLE_BIT | window;

	if (window != pci_priv->remap_window) {
		pci_priv->remap_window = window;
		cnss_pr_dbg("Config PCIe remap window register to 0x%x\n",
			    window_enable);
	}

	/* Read it back to make sure the write has taken effect */
	if (plat_priv->device_id == PEACH_DEVICE_ID) {
		val = readl_relaxed(pci_priv->bar +
			PEACH_PCIE_REMAP_BAR_CTRL_OFFSET);
	} else {
		val = readl_relaxed(pci_priv->bar +
			QCA6390_PCIE_REMAP_BAR_CTRL_OFFSET);
	}
	if (val != window_enable) {
		cnss_pr_err("Failed to config window register to 0x%x, current value: 0x%x\n",
			    window_enable, val);
		if (!cnss_pci_check_link_status(pci_priv) &&
		    !test_bit(CNSS_IN_PANIC, &plat_priv->driver_state))
			CNSS_ASSERT(0);
	}
}

static int cnss_pci_reg_read(struct cnss_pci_data *pci_priv,
			     u32 offset, u32 *val)
{
	int ret;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	if (!in_interrupt() && !irqs_disabled()) {
		ret = cnss_pci_check_link_status(pci_priv);
		if (ret)
			return ret;
	}

	if (pci_priv->pci_dev->device == QCA6174_DEVICE_ID ||
	    offset < MAX_UNWINDOWED_ADDRESS) {
		*val = readl_relaxed(pci_priv->bar + offset);
		return 0;
	}

	/* If in panic, assumption is kernel panic handler will hold all threads
	 * and interrupts. Further pci_reg_window_lock could be held before
	 * panic. So only lock during normal operation.
	 */
	if (test_bit(CNSS_IN_PANIC, &plat_priv->driver_state)) {
		cnss_pci_select_window(pci_priv, offset);
		*val = readl_relaxed(pci_priv->bar + WINDOW_START +
				     (offset & WINDOW_RANGE_MASK));
	} else {
		spin_lock_bh(&pci_reg_window_lock);
		cnss_pci_select_window(pci_priv, offset);
		*val = readl_relaxed(pci_priv->bar + WINDOW_START +
				     (offset & WINDOW_RANGE_MASK));
		spin_unlock_bh(&pci_reg_window_lock);
	}

	return 0;
}

static int cnss_pci_reg_write(struct cnss_pci_data *pci_priv, u32 offset,
			      u32 val)
{
	int ret;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	if (!in_interrupt() && !irqs_disabled()) {
		ret = cnss_pci_check_link_status(pci_priv);
		if (ret)
			return ret;
	}

	if (pci_priv->pci_dev->device == QCA6174_DEVICE_ID ||
	    offset < MAX_UNWINDOWED_ADDRESS) {
		writel_relaxed(val, pci_priv->bar + offset);
		return 0;
	}

	/* Same constraint as PCI register read in panic */
	if (test_bit(CNSS_IN_PANIC, &plat_priv->driver_state)) {
		cnss_pci_select_window(pci_priv, offset);
		writel_relaxed(val, pci_priv->bar + WINDOW_START +
			  (offset & WINDOW_RANGE_MASK));
	} else {
		spin_lock_bh(&pci_reg_window_lock);
		cnss_pci_select_window(pci_priv, offset);
		writel_relaxed(val, pci_priv->bar + WINDOW_START +
			  (offset & WINDOW_RANGE_MASK));
		spin_unlock_bh(&pci_reg_window_lock);
	}

	return 0;
}

static int cnss_pci_force_wake_get(struct cnss_pci_data *pci_priv)
{
	struct device *dev = &pci_priv->pci_dev->dev;
	int ret;

	ret = cnss_pci_force_wake_request_sync(dev,
					       FORCE_WAKE_DELAY_TIMEOUT_US);
	if (ret) {
		if (ret != -EAGAIN)
			cnss_pr_err("Failed to request force wake\n");
		return ret;
	}

	/* If device's M1 state-change event races here, it can be ignored,
	 * as the device is expected to immediately move from M2 to M0
	 * without entering low power state.
	 */
	if (cnss_pci_is_device_awake(dev) != true)
		cnss_pr_warn("MHI not in M0, while reg still accessible\n");

	return 0;
}

static int cnss_pci_force_wake_put(struct cnss_pci_data *pci_priv)
{
	struct device *dev = &pci_priv->pci_dev->dev;
	int ret;

	ret = cnss_pci_force_wake_release(dev);
	if (ret && ret != -EAGAIN)
		cnss_pr_err("Failed to release force wake\n");

	return ret;
}

#if IS_ENABLED(CONFIG_INTERCONNECT)
/**
 * cnss_setup_bus_bandwidth() - Setup interconnect vote for given bandwidth
 * @plat_priv: Platform private data struct
 * @bw: bandwidth
 * @save: toggle flag to save bandwidth to current_bw_vote
 *
 * Setup bandwidth votes for configured interconnect paths
 *
 * Return: 0 for success
 */
static int cnss_setup_bus_bandwidth(struct cnss_plat_data *plat_priv,
				    u32 bw, bool save)
{
	int ret = 0;
	struct cnss_bus_bw_info *bus_bw_info;

	if (!plat_priv->icc.path_count)
		return -EOPNOTSUPP;

	if (bw >= plat_priv->icc.bus_bw_cfg_count) {
		cnss_pr_err("Invalid bus bandwidth Type: %d", bw);
		return -EINVAL;
	}

	cnss_pr_buf("Bandwidth vote to %d, save %d\n", bw, save);

	list_for_each_entry(bus_bw_info, &plat_priv->icc.list_head, list) {
		ret = icc_set_bw(bus_bw_info->icc_path,
				 bus_bw_info->cfg_table[bw].avg_bw,
				 bus_bw_info->cfg_table[bw].peak_bw);
		if (ret) {
			cnss_pr_err("Could not set BW Cfg: %d, err = %d ICC Path: %s Val: %d %d\n",
				    bw, ret, bus_bw_info->icc_name,
				    bus_bw_info->cfg_table[bw].avg_bw,
				    bus_bw_info->cfg_table[bw].peak_bw);
			break;
		}
	}
	if (ret == 0 && save)
		plat_priv->icc.current_bw_vote = bw;
	return ret;
}

int cnss_request_bus_bandwidth(struct device *dev, int bandwidth)
{
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(dev);

	if (!plat_priv)
		return -ENODEV;

	if (bandwidth < 0)
		return -EINVAL;

	return cnss_setup_bus_bandwidth(plat_priv, (u32)bandwidth, true);
}
#else
static int cnss_setup_bus_bandwidth(struct cnss_plat_data *plat_priv,
				    u32 bw, bool save)
{
	return 0;
}

int cnss_request_bus_bandwidth(struct device *dev, int bandwidth)
{
	return 0;
}
#endif
EXPORT_SYMBOL(cnss_request_bus_bandwidth);

int cnss_pci_debug_reg_read(struct cnss_pci_data *pci_priv, u32 offset,
			    u32 *val, bool raw_access)
{
	int ret = 0;
	bool do_force_wake_put = true;

	if (raw_access) {
		ret = cnss_pci_reg_read(pci_priv, offset, val);
		goto out;
	}

	ret = cnss_pci_is_device_down(&pci_priv->pci_dev->dev);
	if (ret)
		goto out;

	ret = cnss_pci_pm_runtime_get_sync(pci_priv, RTPM_ID_CNSS);
	if (ret < 0)
		goto runtime_pm_put;

	ret = cnss_pci_force_wake_get(pci_priv);
	if (ret)
		do_force_wake_put = false;

	ret = cnss_pci_reg_read(pci_priv, offset, val);
	if (ret) {
		cnss_pr_err("Failed to read register offset 0x%x, err = %d\n",
			    offset, ret);
		goto force_wake_put;
	}

force_wake_put:
	if (do_force_wake_put)
		cnss_pci_force_wake_put(pci_priv);
runtime_pm_put:
	cnss_pci_pm_runtime_mark_last_busy(pci_priv);
	cnss_pci_pm_runtime_put_autosuspend(pci_priv, RTPM_ID_CNSS);
out:
	return ret;
}

int cnss_pci_debug_reg_write(struct cnss_pci_data *pci_priv, u32 offset,
			     u32 val, bool raw_access)
{
	int ret = 0;
	bool do_force_wake_put = true;

	if (raw_access) {
		ret = cnss_pci_reg_write(pci_priv, offset, val);
		goto out;
	}

	ret = cnss_pci_is_device_down(&pci_priv->pci_dev->dev);
	if (ret)
		goto out;

	ret = cnss_pci_pm_runtime_get_sync(pci_priv, RTPM_ID_CNSS);
	if (ret < 0)
		goto runtime_pm_put;

	ret = cnss_pci_force_wake_get(pci_priv);
	if (ret)
		do_force_wake_put = false;

	ret = cnss_pci_reg_write(pci_priv, offset, val);
	if (ret) {
		cnss_pr_err("Failed to write 0x%x to register offset 0x%x, err = %d\n",
			    val, offset, ret);
		goto force_wake_put;
	}

force_wake_put:
	if (do_force_wake_put)
		cnss_pci_force_wake_put(pci_priv);
runtime_pm_put:
	cnss_pci_pm_runtime_mark_last_busy(pci_priv);
	cnss_pci_pm_runtime_put_autosuspend(pci_priv, RTPM_ID_CNSS);
out:
	return ret;
}

static int cnss_set_pci_config_space(struct cnss_pci_data *pci_priv, bool save)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	bool link_down_or_recovery;

	if (!plat_priv)
		return -ENODEV;

	link_down_or_recovery = pci_priv->pci_link_down_ind ||
		(test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state));

	if (save) {
		if (link_down_or_recovery) {
			pci_priv->saved_state = NULL;
		} else {
			pci_save_state(pci_dev);
			pci_priv->saved_state = pci_store_saved_state(pci_dev);
		}
	} else {
		if (link_down_or_recovery) {
			pci_load_saved_state(pci_dev, pci_priv->default_state);
			pci_restore_state(pci_dev);
		} else if (pci_priv->saved_state) {
			pci_load_and_free_saved_state(pci_dev,
						      &pci_priv->saved_state);
			pci_restore_state(pci_dev);
		}
	}

	return 0;
}

static int cnss_update_supported_link_info(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct pci_dev *root_port;
	struct device_node *root_of_node;
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -EINVAL;

	if (pci_priv->device_id != KIWI_DEVICE_ID)
		return ret;

	plat_priv = pci_priv->plat_priv;
	root_port = pcie_find_root_port(pci_priv->pci_dev);

	if (!root_port) {
		cnss_pr_err("PCIe root port is null\n");
		return -EINVAL;
	}

	root_of_node = root_port->dev.of_node;
	if (root_of_node && root_of_node->parent) {
		ret = of_property_read_u32(root_of_node->parent,
					   "qcom,target-link-speed",
					   &plat_priv->supported_link_speed);
		if (!ret)
			cnss_pr_dbg("Supported PCIe Link Speed: %d\n",
				    plat_priv->supported_link_speed);
		else
			plat_priv->supported_link_speed = 0;
	}

	return ret;
}

static int cnss_pci_get_link_status(struct cnss_pci_data *pci_priv)
{
	u16 link_status;
	int ret;

	ret = pcie_capability_read_word(pci_priv->pci_dev, PCI_EXP_LNKSTA,
					&link_status);
	if (ret)
		return ret;

	cnss_pr_dbg("Get PCI link status register: %u\n", link_status);

	pci_priv->def_link_speed = link_status & PCI_EXP_LNKSTA_CLS;
	pci_priv->def_link_width =
		(link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
	pci_priv->cur_link_speed = pci_priv->def_link_speed;

	cnss_pr_dbg("Default PCI link speed is 0x%x, link width is 0x%x\n",
		    pci_priv->def_link_speed, pci_priv->def_link_width);

	return 0;
}

static void cnss_pci_soc_scratch_reg_dump(struct cnss_pci_data *pci_priv)
{
	u32 reg_offset, val;
	int i;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		break;
	default:
		return;
	}

	if (in_interrupt() || irqs_disabled())
		return;

	if (cnss_pci_check_link_status(pci_priv))
		return;

	cnss_pr_dbg("Start to dump SOC Scratch registers\n");

	for (i = 0; pci_scratch[i].name; i++) {
		reg_offset = pci_scratch[i].offset;
		if (cnss_pci_reg_read(pci_priv, reg_offset, &val))
			return;
		cnss_pr_dbg("PCIE_SOC_REG_%s = 0x%x\n",
			    pci_scratch[i].name, val);
	}
}

int cnss_suspend_pci_link(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv)
		return -ENODEV;

	if (pci_priv->pci_link_state == PCI_LINK_DOWN) {
		cnss_pr_info("PCI link is already suspended\n");
		goto out;
	}

	pci_clear_master(pci_priv->pci_dev);

	ret = cnss_set_pci_config_space(pci_priv, SAVE_PCI_CONFIG_SPACE);
	if (ret)
		goto out;

	pci_disable_device(pci_priv->pci_dev);

	if (pci_priv->pci_dev->device != QCA6174_DEVICE_ID) {
		ret = pci_set_power_state(pci_priv->pci_dev, PCI_D3hot);
		if (ret)
			cnss_pr_err("Failed to set D3Hot, err =  %d\n", ret);
	}

	/* Always do PCIe L2 suspend during power off/PCIe link recovery */
	pci_priv->drv_connected_last = 0;

	ret = cnss_set_pci_link(pci_priv, PCI_LINK_DOWN);
	if (ret)
		goto out;

	pci_priv->pci_link_state = PCI_LINK_DOWN;

	return 0;
out:
	return ret;
}

int cnss_resume_pci_link(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv)
		return -ENODEV;

	if (pci_priv->pci_link_state == PCI_LINK_UP) {
		cnss_pr_info("PCI link is already resumed\n");
		goto out;
	}

	ret = cnss_set_pci_link(pci_priv, PCI_LINK_UP);
	if (ret) {
		ret = -EAGAIN;
		goto out;
	}

	pci_priv->pci_link_state = PCI_LINK_UP;

	if (pci_priv->pci_dev->device != QCA6174_DEVICE_ID) {
		ret = pci_set_power_state(pci_priv->pci_dev, PCI_D0);
		if (ret) {
			cnss_pr_err("Failed to set D0, err = %d\n", ret);
			goto out;
		}
	}

	ret = cnss_set_pci_config_space(pci_priv, RESTORE_PCI_CONFIG_SPACE);
	if (ret)
		goto out;

	ret = pci_enable_device(pci_priv->pci_dev);
	if (ret) {
		cnss_pr_err("Failed to enable PCI device, err = %d\n", ret);
		goto out;
	}

	pci_set_master(pci_priv->pci_dev);

	if (pci_priv->pci_link_down_ind)
		pci_priv->pci_link_down_ind = false;

	return 0;
out:
	return ret;
}

static void cnss_pci_update_link_event(struct cnss_pci_data *pci_priv,
				       enum cnss_bus_event_type type,
				       void *data)
{
	struct cnss_bus_event bus_event;

	bus_event.etype = type;
	bus_event.event_data = data;
	cnss_pci_call_driver_uevent(pci_priv, CNSS_BUS_EVENT, &bus_event);
}

void cnss_pci_handle_linkdown(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	unsigned long flags;

	if (test_bit(ENABLE_PCI_LINK_DOWN_PANIC,
		     &plat_priv->ctrl_params.quirks))
		panic("cnss: PCI link is down\n");

	spin_lock_irqsave(&pci_link_down_lock, flags);
	if (pci_priv->pci_link_down_ind) {
		cnss_pr_dbg("PCI link down recovery is in progress, ignore\n");
		spin_unlock_irqrestore(&pci_link_down_lock, flags);
		return;
	}
	pci_priv->pci_link_down_ind = true;
	spin_unlock_irqrestore(&pci_link_down_lock, flags);

	if (pci_priv->mhi_ctrl) {
		/* Notify MHI about link down*/
		mhi_report_error(pci_priv->mhi_ctrl);
	}

	if (pci_dev->device == QCA6174_DEVICE_ID)
		disable_irq_nosync(pci_dev->irq);

	/* Notify bus related event. Now for all supported chips.
	 * Here PCIe LINK_DOWN notification taken care.
	 * uevent buffer can be extended later, to cover more bus info.
	 */
	cnss_pci_update_link_event(pci_priv, BUS_EVENT_PCI_LINK_DOWN, NULL);

	cnss_fatal_err("PCI link down, schedule recovery\n");
	reinit_completion(&pci_priv->wake_event_complete);
	cnss_schedule_recovery(&pci_dev->dev, CNSS_REASON_LINK_DOWN);
}

int cnss_pci_link_down(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv = NULL;
	int ret;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -EINVAL;
	}

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return -ENODEV;
	}

	if (pci_priv->pci_link_down_ind) {
		cnss_pr_dbg("PCI link down recovery is already in progress\n");
		return -EBUSY;
	}

	if (pci_priv->drv_connected_last &&
	    of_property_read_bool(plat_priv->plat_dev->dev.of_node,
				  "cnss-enable-self-recovery"))
		plat_priv->ctrl_params.quirks |= BIT(LINK_DOWN_SELF_RECOVERY);

	cnss_pr_err("PCI link down is detected by drivers\n");

	ret = cnss_pci_assert_perst(pci_priv);
	if (ret)
		cnss_pci_handle_linkdown(pci_priv);

	return ret;
}
EXPORT_SYMBOL(cnss_pci_link_down);

int cnss_pci_get_reg_dump(struct device *dev, uint8_t *buffer, uint32_t len)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	if (pci_priv->pci_link_state == PCI_LINK_DOWN) {
		cnss_pr_dbg("No PCIe reg dump since PCIe is suspended(D3)\n");
		return -EACCES;
	}

	cnss_pr_dbg("Start to get PCIe reg dump\n");

	return _cnss_pci_get_reg_dump(pci_priv, buffer, len);
}
EXPORT_SYMBOL(cnss_pci_get_reg_dump);

int cnss_pcie_is_device_down(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return -ENODEV;
	}

	return test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state) |
		pci_priv->pci_link_down_ind;
}

int cnss_pci_is_device_down(struct device *dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));

	return cnss_pcie_is_device_down(pci_priv);
}
EXPORT_SYMBOL(cnss_pci_is_device_down);

void cnss_pci_lock_reg_window(struct device *dev, unsigned long *flags)
{
	spin_lock_bh(&pci_reg_window_lock);
}
EXPORT_SYMBOL(cnss_pci_lock_reg_window);

void cnss_pci_unlock_reg_window(struct device *dev, unsigned long *flags)
{
	spin_unlock_bh(&pci_reg_window_lock);
}
EXPORT_SYMBOL(cnss_pci_unlock_reg_window);

int cnss_get_pci_slot(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv = NULL;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -EINVAL;
	}

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return -ENODEV;
	}

	return plat_priv->rc_num;
}
EXPORT_SYMBOL(cnss_get_pci_slot);

/**
 * cnss_pci_dump_bl_sram_mem - Dump WLAN device bootloader debug log
 * @pci_priv: driver PCI bus context pointer
 *
 * Dump primary and secondary bootloader debug log data. For SBL check the
 * log struct address and size for validity.
 *
 * Return: None
 */
static void cnss_pci_dump_bl_sram_mem(struct cnss_pci_data *pci_priv)
{
	enum mhi_ee_type ee;
	u32 mem_addr, val, pbl_log_max_size, sbl_log_max_size;
	u32 pbl_log_sram_start;
	u32 pbl_stage, sbl_log_start, sbl_log_size;
	u32 pbl_wlan_boot_cfg, pbl_bootstrap_status;
	u32 pbl_bootstrap_status_reg = PBL_BOOTSTRAP_STATUS;
	u32 sbl_log_def_start = SRAM_START;
	u32 sbl_log_def_end = SRAM_END;
	int i;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
		pbl_log_sram_start = QCA6390_DEBUG_PBL_LOG_SRAM_START;
		pbl_log_max_size = QCA6390_DEBUG_PBL_LOG_SRAM_MAX_SIZE;
		sbl_log_max_size = QCA6390_DEBUG_SBL_LOG_SRAM_MAX_SIZE;
		break;
	case QCA6490_DEVICE_ID:
		pbl_log_sram_start = QCA6490_DEBUG_PBL_LOG_SRAM_START;
		pbl_log_max_size = QCA6490_DEBUG_PBL_LOG_SRAM_MAX_SIZE;
		sbl_log_max_size = QCA6490_DEBUG_SBL_LOG_SRAM_MAX_SIZE;
		break;
	case KIWI_DEVICE_ID:
		pbl_bootstrap_status_reg = KIWI_PBL_BOOTSTRAP_STATUS;
		pbl_log_sram_start = KIWI_DEBUG_PBL_LOG_SRAM_START;
		pbl_log_max_size = KIWI_DEBUG_PBL_LOG_SRAM_MAX_SIZE;
		sbl_log_max_size = KIWI_DEBUG_SBL_LOG_SRAM_MAX_SIZE;
		break;
	case MANGO_DEVICE_ID:
		pbl_bootstrap_status_reg = MANGO_PBL_BOOTSTRAP_STATUS;
		pbl_log_sram_start = MANGO_DEBUG_PBL_LOG_SRAM_START;
		pbl_log_max_size = MANGO_DEBUG_PBL_LOG_SRAM_MAX_SIZE;
		sbl_log_max_size = MANGO_DEBUG_SBL_LOG_SRAM_MAX_SIZE;
		break;
	case PEACH_DEVICE_ID:
		pbl_bootstrap_status_reg = PEACH_PBL_BOOTSTRAP_STATUS;
		pbl_log_sram_start = PEACH_DEBUG_PBL_LOG_SRAM_START;
		pbl_log_max_size = PEACH_DEBUG_PBL_LOG_SRAM_MAX_SIZE;
		sbl_log_max_size = PEACH_DEBUG_SBL_LOG_SRAM_MAX_SIZE;
		break;
	default:
		return;
	}

	if (cnss_pci_check_link_status(pci_priv))
		return;

	cnss_pci_reg_read(pci_priv, TCSR_PBL_LOGGING_REG, &pbl_stage);
	cnss_pci_reg_read(pci_priv, PCIE_BHI_ERRDBG2_REG, &sbl_log_start);
	cnss_pci_reg_read(pci_priv, PCIE_BHI_ERRDBG3_REG, &sbl_log_size);
	cnss_pci_reg_read(pci_priv, PBL_WLAN_BOOT_CFG, &pbl_wlan_boot_cfg);
	cnss_pci_reg_read(pci_priv, pbl_bootstrap_status_reg,
			  &pbl_bootstrap_status);
	cnss_pr_dbg("TCSR_PBL_LOGGING: 0x%08x PCIE_BHI_ERRDBG: Start: 0x%08x Size:0x%08x\n",
		    pbl_stage, sbl_log_start, sbl_log_size);
	cnss_pr_dbg("PBL_WLAN_BOOT_CFG: 0x%08x PBL_BOOTSTRAP_STATUS: 0x%08x\n",
		    pbl_wlan_boot_cfg, pbl_bootstrap_status);

	ee = mhi_get_exec_env(pci_priv->mhi_ctrl);
	if (CNSS_MHI_IN_MISSION_MODE(ee)) {
		cnss_pr_dbg("Avoid Dumping PBL log data in Mission mode\n");
		return;
	}

	cnss_pr_dbg("Dumping PBL log data\n");
	for (i = 0; i < pbl_log_max_size; i += sizeof(val)) {
		mem_addr = pbl_log_sram_start + i;
		if (cnss_pci_reg_read(pci_priv, mem_addr, &val))
			break;
		cnss_pr_dbg("SRAM[0x%x] = 0x%x\n", mem_addr, val);
	}

	sbl_log_size = (sbl_log_size > sbl_log_max_size ?
			sbl_log_max_size : sbl_log_size);
	if (sbl_log_start < sbl_log_def_start ||
	    sbl_log_start > sbl_log_def_end ||
	    (sbl_log_start + sbl_log_size) > sbl_log_def_end) {
		cnss_pr_err("Invalid SBL log data\n");
		return;
	}

	ee = mhi_get_exec_env(pci_priv->mhi_ctrl);
	if (CNSS_MHI_IN_MISSION_MODE(ee)) {
		cnss_pr_dbg("Avoid Dumping SBL log data in Mission mode\n");
		return;
	}

	cnss_pr_dbg("Dumping SBL log data\n");
	for (i = 0; i < sbl_log_size; i += sizeof(val)) {
		mem_addr = sbl_log_start + i;
		if (cnss_pci_reg_read(pci_priv, mem_addr, &val))
			break;
		cnss_pr_dbg("SRAM[0x%x] = 0x%x\n", mem_addr, val);
	}
}

#ifdef CONFIG_DISABLE_CNSS_SRAM_DUMP
static void cnss_pci_dump_sram(struct cnss_pci_data *pci_priv)
{
}
#else
static void cnss_pci_dump_sram(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;
	u32 i, mem_addr;
	u32 *dump_ptr;

	plat_priv = pci_priv->plat_priv;

	if (plat_priv->device_id != QCA6490_DEVICE_ID ||
	    cnss_get_host_build_type() != QMI_HOST_BUILD_TYPE_PRIMARY_V01)
		return;

	if (!plat_priv->sram_dump) {
		cnss_pr_err("SRAM dump memory is not allocated\n");
		return;
	}

	if (cnss_pci_check_link_status(pci_priv))
		return;

	cnss_pr_dbg("Dumping SRAM at 0x%lx\n", plat_priv->sram_dump);

	for (i = 0; i < SRAM_DUMP_SIZE; i += sizeof(u32)) {
		mem_addr = SRAM_START + i;
		dump_ptr = (u32 *)(plat_priv->sram_dump + i);
		if (cnss_pci_reg_read(pci_priv, mem_addr, dump_ptr)) {
			cnss_pr_err("SRAM Dump failed at 0x%x\n", mem_addr);
			break;
		}
		/* Relinquish CPU after dumping 256KB chunks*/
		if (!(i % CNSS_256KB_SIZE))
			cond_resched();
	}
}
#endif

static int cnss_pci_handle_mhi_poweron_timeout(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	cnss_fatal_err("MHI power up returns timeout\n");

	if (cnss_mhi_scan_rddm_cookie(pci_priv, DEVICE_RDDM_COOKIE) ||
	    cnss_get_dev_sol_value(plat_priv) > 0) {
		/* Wait for RDDM if RDDM cookie is set or device SOL GPIO is
		 * high. If RDDM times out, PBL/SBL error region may have been
		 * erased so no need to dump them either.
		 */
		if (!test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state) &&
		    !pci_priv->pci_link_down_ind) {
			mod_timer(&pci_priv->dev_rddm_timer,
				  jiffies + msecs_to_jiffies(DEV_RDDM_TIMEOUT));
		}
	} else {
		cnss_pr_dbg("RDDM cookie is not set and device SOL is low\n");
		cnss_mhi_debug_reg_dump(pci_priv);
		cnss_pci_soc_scratch_reg_dump(pci_priv);
		/* Dump PBL/SBL error log if RDDM cookie is not set */
		cnss_pci_dump_bl_sram_mem(pci_priv);
		cnss_pci_dump_sram(pci_priv);
		return -ETIMEDOUT;
	}

	return 0;
}

static char *cnss_mhi_state_to_str(enum cnss_mhi_state mhi_state)
{
	switch (mhi_state) {
	case CNSS_MHI_INIT:
		return "INIT";
	case CNSS_MHI_DEINIT:
		return "DEINIT";
	case CNSS_MHI_POWER_ON:
		return "POWER_ON";
	case CNSS_MHI_POWERING_OFF:
		return "POWERING_OFF";
	case CNSS_MHI_POWER_OFF:
		return "POWER_OFF";
	case CNSS_MHI_FORCE_POWER_OFF:
		return "FORCE_POWER_OFF";
	case CNSS_MHI_SUSPEND:
		return "SUSPEND";
	case CNSS_MHI_RESUME:
		return "RESUME";
	case CNSS_MHI_TRIGGER_RDDM:
		return "TRIGGER_RDDM";
	case CNSS_MHI_RDDM_DONE:
		return "RDDM_DONE";
	default:
		return "UNKNOWN";
	}
};

static int cnss_pci_check_mhi_state_bit(struct cnss_pci_data *pci_priv,
					enum cnss_mhi_state mhi_state)
{
	switch (mhi_state) {
	case CNSS_MHI_INIT:
		if (!test_bit(CNSS_MHI_INIT, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_DEINIT:
	case CNSS_MHI_POWER_ON:
		if (test_bit(CNSS_MHI_INIT, &pci_priv->mhi_state) &&
		    !test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_FORCE_POWER_OFF:
		if (test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_POWER_OFF:
	case CNSS_MHI_SUSPEND:
		if (test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state) &&
		    !test_bit(CNSS_MHI_SUSPEND, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_RESUME:
		if (test_bit(CNSS_MHI_SUSPEND, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_TRIGGER_RDDM:
		if (test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state) &&
		    !test_bit(CNSS_MHI_TRIGGER_RDDM, &pci_priv->mhi_state))
			return 0;
		break;
	case CNSS_MHI_RDDM_DONE:
		return 0;
	default:
		cnss_pr_err("Unhandled MHI state: %s(%d)\n",
			    cnss_mhi_state_to_str(mhi_state), mhi_state);
	}

	cnss_pr_err("Cannot set MHI state %s(%d) in current MHI state (0x%lx)\n",
		    cnss_mhi_state_to_str(mhi_state), mhi_state,
		    pci_priv->mhi_state);
	if (mhi_state != CNSS_MHI_TRIGGER_RDDM)
		CNSS_ASSERT(0);

	return -EINVAL;
}

static int cnss_rddm_trigger_debug(struct cnss_pci_data *pci_priv)
{
	int read_val, ret;

	if (!pci_priv || pci_priv->device_id != QCA6490_DEVICE_ID)
		return -EOPNOTSUPP;

	if (cnss_pci_check_link_status(pci_priv))
		return -EINVAL;

	cnss_pr_err("Write GCC Spare with ACE55 Pattern");
	cnss_pci_reg_write(pci_priv, GCC_GCC_SPARE_REG_1, 0xACE55);
	ret = cnss_pci_reg_read(pci_priv, GCC_GCC_SPARE_REG_1, &read_val);
	cnss_pr_err("Read back GCC Spare: 0x%x, ret: %d", read_val, ret);
	ret = cnss_pci_reg_read(pci_priv, GCC_PRE_ARES_DEBUG_TIMER_VAL,
				&read_val);
	cnss_pr_err("Warm reset allowed check: 0x%x, ret: %d", read_val, ret);
	return ret;
}

static int cnss_rddm_trigger_check(struct cnss_pci_data *pci_priv)
{
	int read_val, ret;
	u32 pbl_stage, sbl_log_start, sbl_log_size, pbl_wlan_boot_cfg;

	if (!pci_priv || pci_priv->device_id != QCA6490_DEVICE_ID)
		return -EOPNOTSUPP;

	if (cnss_pci_check_link_status(pci_priv))
		return -EINVAL;

	ret = cnss_pci_reg_read(pci_priv, GCC_GCC_SPARE_REG_1, &read_val);
	cnss_pr_err("Read GCC spare to check reset status: 0x%x, ret: %d",
		    read_val, ret);

	cnss_pci_reg_read(pci_priv, TCSR_PBL_LOGGING_REG, &pbl_stage);
	cnss_pci_reg_read(pci_priv, PCIE_BHI_ERRDBG2_REG, &sbl_log_start);
	cnss_pci_reg_read(pci_priv, PCIE_BHI_ERRDBG3_REG, &sbl_log_size);
	cnss_pci_reg_read(pci_priv, PBL_WLAN_BOOT_CFG, &pbl_wlan_boot_cfg);
	cnss_pr_dbg("TCSR_PBL_LOGGING: 0x%08x PCIE_BHI_ERRDBG: Start: 0x%08x Size:0x%08x \n",
		    pbl_stage, sbl_log_start, sbl_log_size);
	cnss_pr_dbg("PBL_WLAN_BOOT_CFG: 0x%08x\n", pbl_wlan_boot_cfg);

	return ret;
}

static void cnss_pci_set_mhi_state_bit(struct cnss_pci_data *pci_priv,
				       enum cnss_mhi_state mhi_state)
{
	switch (mhi_state) {
	case CNSS_MHI_INIT:
		set_bit(CNSS_MHI_INIT, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_DEINIT:
		clear_bit(CNSS_MHI_INIT, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_POWER_ON:
		set_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_POWERING_OFF:
		set_bit(CNSS_MHI_POWERING_OFF, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_POWER_OFF:
	case CNSS_MHI_FORCE_POWER_OFF:
		clear_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state);
		clear_bit(CNSS_MHI_POWERING_OFF, &pci_priv->mhi_state);
		clear_bit(CNSS_MHI_TRIGGER_RDDM, &pci_priv->mhi_state);
		clear_bit(CNSS_MHI_RDDM_DONE, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_SUSPEND:
		set_bit(CNSS_MHI_SUSPEND, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_RESUME:
		clear_bit(CNSS_MHI_SUSPEND, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_TRIGGER_RDDM:
		set_bit(CNSS_MHI_TRIGGER_RDDM, &pci_priv->mhi_state);
		break;
	case CNSS_MHI_RDDM_DONE:
		set_bit(CNSS_MHI_RDDM_DONE, &pci_priv->mhi_state);
		break;
	default:
		cnss_pr_err("Unhandled MHI state (%d)\n", mhi_state);
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
static int cnss_mhi_pm_force_resume(struct cnss_pci_data *pci_priv)
{
	return mhi_pm_resume_force(pci_priv->mhi_ctrl);
}
#else
static int cnss_mhi_pm_force_resume(struct cnss_pci_data *pci_priv)
{
	return mhi_pm_resume(pci_priv->mhi_ctrl);
}
#endif

static int cnss_pci_set_mhi_state(struct cnss_pci_data *pci_priv,
				  enum cnss_mhi_state mhi_state)
{
	int ret = 0, retry = 0;

	if (pci_priv->device_id == QCA6174_DEVICE_ID)
		return 0;

	if (mhi_state < 0) {
		cnss_pr_err("Invalid MHI state (%d)\n", mhi_state);
		return -EINVAL;
	}

	ret = cnss_pci_check_mhi_state_bit(pci_priv, mhi_state);
	if (ret)
		goto out;

	cnss_pr_vdbg("Setting MHI state: %s(%d)\n",
		     cnss_mhi_state_to_str(mhi_state), mhi_state);

	switch (mhi_state) {
	case CNSS_MHI_INIT:
		ret = mhi_prepare_for_power_up(pci_priv->mhi_ctrl);
		break;
	case CNSS_MHI_DEINIT:
		mhi_unprepare_after_power_down(pci_priv->mhi_ctrl);
		ret = 0;
		break;
	case CNSS_MHI_POWER_ON:
		ret = mhi_sync_power_up(pci_priv->mhi_ctrl);
#if IS_ENABLED(CONFIG_MHI_BUS_MISC)
		/* Only set img_pre_alloc when power up succeeds */
		if (!ret && !pci_priv->mhi_ctrl->img_pre_alloc) {
			cnss_pr_dbg("Notify MHI to use already allocated images\n");
			pci_priv->mhi_ctrl->img_pre_alloc = true;
		}
#endif
		break;
	case CNSS_MHI_POWER_OFF:
		mhi_power_down(pci_priv->mhi_ctrl, true);
		ret = 0;
		break;
	case CNSS_MHI_FORCE_POWER_OFF:
		mhi_power_down(pci_priv->mhi_ctrl, false);
		ret = 0;
		break;
	case CNSS_MHI_SUSPEND:
retry_mhi_suspend:
		mutex_lock(&pci_priv->mhi_ctrl->pm_mutex);
		if (pci_priv->drv_connected_last)
			ret = cnss_mhi_pm_fast_suspend(pci_priv, true);
		else
			ret = mhi_pm_suspend(pci_priv->mhi_ctrl);
		mutex_unlock(&pci_priv->mhi_ctrl->pm_mutex);
		if (ret == -EBUSY && retry++ < MHI_SUSPEND_RETRY_MAX_TIMES) {
			cnss_pr_vdbg("Retry MHI suspend #%d\n", retry);
			usleep_range(MHI_SUSPEND_RETRY_DELAY_US,
				     MHI_SUSPEND_RETRY_DELAY_US + 1000);
			goto retry_mhi_suspend;
		}
		break;
	case CNSS_MHI_RESUME:
		mutex_lock(&pci_priv->mhi_ctrl->pm_mutex);
		if (pci_priv->drv_connected_last) {
			ret = cnss_pci_prevent_l1(&pci_priv->pci_dev->dev);
			if (ret) {
				mutex_unlock(&pci_priv->mhi_ctrl->pm_mutex);
				break;
			}
			ret = cnss_mhi_pm_fast_resume(pci_priv, true);
			cnss_pci_allow_l1(&pci_priv->pci_dev->dev);
		} else {
			if (pci_priv->device_id == QCA6390_DEVICE_ID)
				ret = cnss_mhi_pm_force_resume(pci_priv);
			else
				ret = mhi_pm_resume(pci_priv->mhi_ctrl);
		}
		mutex_unlock(&pci_priv->mhi_ctrl->pm_mutex);
		break;
	case CNSS_MHI_TRIGGER_RDDM:
		cnss_rddm_trigger_debug(pci_priv);
		ret = mhi_force_rddm_mode(pci_priv->mhi_ctrl);
		if (ret) {
			cnss_pr_err("Failed to trigger RDDM, err = %d\n", ret);

			cnss_pr_dbg("Sending host reset req\n");
			ret = cnss_mhi_force_reset(pci_priv);
			cnss_rddm_trigger_check(pci_priv);
		}
		break;
	case CNSS_MHI_RDDM_DONE:
		break;
	default:
		cnss_pr_err("Unhandled MHI state (%d)\n", mhi_state);
		ret = -EINVAL;
	}

	if (ret)
		goto out;

	cnss_pci_set_mhi_state_bit(pci_priv, mhi_state);

	return 0;

out:
	cnss_pr_err("Failed to set MHI state: %s(%d), err = %d\n",
		    cnss_mhi_state_to_str(mhi_state), mhi_state, ret);
	return ret;
}

static int cnss_pci_config_msi_addr(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct cnss_plat_data *plat_priv;

	if (!pci_dev)
		return -ENODEV;

	if (!pci_dev->msix_enabled)
		return ret;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return -ENODEV;
	}

	ret = of_property_read_u32(plat_priv->plat_dev->dev.of_node,
				   "msix-match-addr",
				   &pci_priv->msix_addr);
	cnss_pr_dbg("MSI-X Match address is 0x%X\n",
		    pci_priv->msix_addr);

	return ret;
}

static int cnss_pci_config_msi_data(struct cnss_pci_data *pci_priv)
{
	struct msi_desc *msi_desc;
	struct cnss_msi_config *msi_config;
	struct pci_dev *pci_dev = pci_priv->pci_dev;

	msi_config = pci_priv->msi_config;

	if (pci_dev->msix_enabled) {
		pci_priv->msi_ep_base_data = msi_config->users[0].base_vector;
		cnss_pr_dbg("MSI-X base data is %d\n",
			    pci_priv->msi_ep_base_data);
		return 0;
	}

	msi_desc = irq_get_msi_desc(pci_dev->irq);
	if (!msi_desc) {
		cnss_pr_err("msi_desc is NULL!\n");
		return -EINVAL;
	}

	pci_priv->msi_ep_base_data = msi_desc->msg.data;
	cnss_pr_dbg("MSI base data is %d\n", pci_priv->msi_ep_base_data);

	return 0;
}

#ifdef CONFIG_CNSS_SUPPORT_DUAL_DEV
#define PLC_PCIE_NAME_LEN		14

static struct cnss_plat_data *
cnss_get_plat_priv_by_driver_ops(struct cnss_wlan_driver *driver_ops)
{
	int plat_env_count = cnss_get_plat_env_count();
	struct cnss_plat_data *plat_env;
	struct cnss_pci_data *pci_priv;
	int i = 0;

	if (!driver_ops) {
		cnss_pr_err("No cnss driver\n");
		return NULL;
	}

	for (i = 0; i < plat_env_count; i++) {
		plat_env = cnss_get_plat_env(i);
		if (!plat_env)
			continue;
		if (driver_ops->name && plat_env->pld_bus_ops_name) {
			/* driver_ops->name = PLD_PCIE_OPS_NAME
			 * #ifdef MULTI_IF_NAME
			 * #define PLD_PCIE_OPS_NAME "pld_pcie_" MULTI_IF_NAME
			 * #else
			 * #define PLD_PCIE_OPS_NAME "pld_pcie"
			 * #endif
			 */
			if (memcmp(driver_ops->name,
				   plat_env->pld_bus_ops_name,
				   PLC_PCIE_NAME_LEN) == 0)
				return plat_env;
		}
	}

	cnss_pr_vdbg("Invalid cnss driver name from ko %s\n", driver_ops->name);
	/* in the dual wlan card case, the pld_bus_ops_name from dts
	 * and driver_ops-> name from ko should match, otherwise
	 * wlanhost driver don't know which plat_env it can use;
	 * if doesn't find the match one, then get first available
	 * instance insteadly.
	 */

	for (i = 0; i < plat_env_count; i++) {
		plat_env = cnss_get_plat_env(i);

		if (!plat_env)
			continue;

		pci_priv = plat_env->bus_priv;
		if (!pci_priv) {
			cnss_pr_err("pci_priv is NULL\n");
			continue;
		}

		if (driver_ops == pci_priv->driver_ops)
			return plat_env;
	}
	/* Doesn't find the existing instance,
	 * so return the fist empty instance
	 */
	for (i = 0; i < plat_env_count; i++) {
		plat_env = cnss_get_plat_env(i);

		if (!plat_env)
			continue;
		pci_priv = plat_env->bus_priv;
		if (!pci_priv) {
			cnss_pr_err("pci_priv is NULL\n");
			continue;
		}

		if (!pci_priv->driver_ops)
			return plat_env;
	}

	return NULL;
}

static int cnss_pci_store_qrtr_node_id(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	u32 scratch = QCA6390_PCIE_SOC_PCIE_REG_PCIE_SCRATCH_2_SOC_PCIE_REG;
	struct cnss_plat_data *plat_priv;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	plat_priv = pci_priv->plat_priv;
	/**
	 * in the single wlan chipset case, plat_priv->qrtr_node_id always is 0,
	 * wlan fw will use the hardcode 7 as the qrtr node id.
	 * in the dual Hastings case, we will read qrtr node id
	 * from device tree and pass to get plat_priv->qrtr_node_id,
	 * which always is not zero. And then store this new value
	 * to pcie register, wlan fw will read out this qrtr node id
	 * from this register and overwrite to the hardcode one
	 * while do initialization for ipc router.
	 * without this change, two Hastings will use the same
	 * qrtr node instance id, which will mess up qmi message
	 * exchange. According to qrtr spec, every node should
	 * have unique qrtr node id
	 */
	if (plat_priv->device_id == QCA6390_DEVICE_ID &&
	    plat_priv->qrtr_node_id) {
		u32 val;

		cnss_pr_dbg("write 0x%x to SCRATCH REG\n",
			    plat_priv->qrtr_node_id);
		ret = cnss_pci_reg_write(pci_priv, scratch,
					 plat_priv->qrtr_node_id);
		if (ret) {
			cnss_pr_err("Failed to write register offset 0x%x, err = %d\n",
				    scratch, ret);
			goto out;
		}

		ret = cnss_pci_reg_read(pci_priv, scratch, &val);
		if (ret) {
			cnss_pr_err("Failed to read SCRATCH REG");
			goto out;
		}

		if (val != plat_priv->qrtr_node_id) {
			cnss_pr_err("qrtr node id write to register doesn't match with readout value");
			return -ERANGE;
		}
	}
out:
	return ret;
}
#else
static struct cnss_plat_data *
cnss_get_plat_priv_by_driver_ops(struct cnss_wlan_driver *driver_ops)
{
	return cnss_bus_dev_to_plat_priv(NULL);
}

static int cnss_pci_store_qrtr_node_id(struct cnss_pci_data *pci_priv)
{
	return 0;
}
#endif

int cnss_pci_start_mhi(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv;
	unsigned int timeout = 0;
	int retry = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	plat_priv = pci_priv->plat_priv;
	if (test_bit(FBC_BYPASS, &plat_priv->ctrl_params.quirks))
		return 0;

	if (MHI_TIMEOUT_OVERWRITE_MS)
		pci_priv->mhi_ctrl->timeout_ms = MHI_TIMEOUT_OVERWRITE_MS;
	cnss_mhi_set_m2_timeout_ms(pci_priv, MHI_M2_TIMEOUT_MS);

	ret = cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_INIT);
	if (ret)
		return ret;

	timeout = pci_priv->mhi_ctrl->timeout_ms;
	/* For non-perf builds the timeout is 10 (default) * 6 seconds */
	if (cnss_get_host_build_type() == QMI_HOST_BUILD_TYPE_PRIMARY_V01)
		pci_priv->mhi_ctrl->timeout_ms *= 6;
	else /* For perf builds the timeout is 10 (default) * 3 seconds */
		pci_priv->mhi_ctrl->timeout_ms *= 3;

retry:
	ret = cnss_pci_store_qrtr_node_id(pci_priv);
	if (ret) {
		if (retry++ < REG_RETRY_MAX_TIMES)
			goto retry;
		else
			return ret;
	}

	/* Start the timer to dump MHI/PBL/SBL debug data periodically */
	mod_timer(&pci_priv->boot_debug_timer,
		  jiffies + msecs_to_jiffies(BOOT_DEBUG_TIMEOUT_MS));

	ret = cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_POWER_ON);
	del_timer_sync(&pci_priv->boot_debug_timer);
	if (ret == 0)
		cnss_wlan_adsp_pc_enable(pci_priv, false);

	pci_priv->mhi_ctrl->timeout_ms = timeout;

	if (ret == -ETIMEDOUT) {
		/* This is a special case needs to be handled that if MHI
		 * power on returns -ETIMEDOUT, controller needs to take care
		 * the cleanup by calling MHI power down. Force to set the bit
		 * for driver internal MHI state to make sure it can be handled
		 * properly later.
		 */
		set_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state);
		ret = cnss_pci_handle_mhi_poweron_timeout(pci_priv);
	} else if (!ret) {
		/* kernel may allocate a dummy vector before request_irq and
		 * then allocate a real vector when request_irq is called.
		 * So get msi_data here again to avoid spurious interrupt
		 * as msi_data will configured to srngs.
		 */
		if (cnss_pci_is_one_msi(pci_priv))
			ret = cnss_pci_config_msi_data(pci_priv);
	}

	return ret;
}

static void cnss_pci_power_off_mhi(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	if (test_bit(FBC_BYPASS, &plat_priv->ctrl_params.quirks))
		return;

	if (!test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state)) {
		cnss_pr_dbg("MHI is already powered off\n");
		return;
	}
	cnss_wlan_adsp_pc_enable(pci_priv, true);
	cnss_pci_set_mhi_state_bit(pci_priv, CNSS_MHI_RESUME);
	cnss_pci_set_mhi_state_bit(pci_priv, CNSS_MHI_POWERING_OFF);

	if (!pci_priv->pci_link_down_ind)
		cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_POWER_OFF);
	else
		cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_FORCE_POWER_OFF);
}

static void cnss_pci_deinit_mhi(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	if (test_bit(FBC_BYPASS, &plat_priv->ctrl_params.quirks))
		return;

	if (!test_bit(CNSS_MHI_INIT, &pci_priv->mhi_state)) {
		cnss_pr_dbg("MHI is already deinited\n");
		return;
	}

	cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_DEINIT);
}

static void cnss_pci_set_wlaon_pwr_ctrl(struct cnss_pci_data *pci_priv,
					bool set_vddd4blow, bool set_shutdown,
					bool do_force_wake)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	int ret;
	u32 val;

	if (!plat_priv->set_wlaon_pwr_ctrl)
		return;

	if (pci_priv->pci_link_state == PCI_LINK_DOWN ||
	    pci_priv->pci_link_down_ind)
		return;

	if (do_force_wake)
		if (cnss_pci_force_wake_get(pci_priv))
			return;

	ret = cnss_pci_reg_read(pci_priv, WLAON_QFPROM_PWR_CTRL_REG, &val);
	if (ret) {
		cnss_pr_err("Failed to read register offset 0x%x, err = %d\n",
			    WLAON_QFPROM_PWR_CTRL_REG, ret);
		goto force_wake_put;
	}

	cnss_pr_dbg("Read register offset 0x%x, val = 0x%x\n",
		    WLAON_QFPROM_PWR_CTRL_REG, val);

	if (set_vddd4blow)
		val |= QFPROM_PWR_CTRL_VDD4BLOW_SW_EN_MASK;
	else
		val &= ~QFPROM_PWR_CTRL_VDD4BLOW_SW_EN_MASK;

	if (set_shutdown)
		val |= QFPROM_PWR_CTRL_SHUTDOWN_EN_MASK;
	else
		val &= ~QFPROM_PWR_CTRL_SHUTDOWN_EN_MASK;

	ret = cnss_pci_reg_write(pci_priv, WLAON_QFPROM_PWR_CTRL_REG, val);
	if (ret) {
		cnss_pr_err("Failed to write register offset 0x%x, err = %d\n",
			    WLAON_QFPROM_PWR_CTRL_REG, ret);
		goto force_wake_put;
	}

	cnss_pr_dbg("Write val 0x%x to register offset 0x%x\n", val,
		    WLAON_QFPROM_PWR_CTRL_REG);

	if (set_shutdown)
		usleep_range(WLAON_PWR_CTRL_SHUTDOWN_DELAY_MIN_US,
			     WLAON_PWR_CTRL_SHUTDOWN_DELAY_MAX_US);

force_wake_put:
	if (do_force_wake)
		cnss_pci_force_wake_put(pci_priv);
}

static int cnss_pci_get_device_timestamp(struct cnss_pci_data *pci_priv,
					 u64 *time_us)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	u32 low, high;
	u64 device_ticks;

	if (!plat_priv->device_freq_hz) {
		cnss_pr_err("Device time clock frequency is not valid\n");
		return -EINVAL;
	}

	switch (pci_priv->device_id) {
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		cnss_pci_reg_read(pci_priv, PCIE_MHI_TIME_LOW, &low);
		cnss_pci_reg_read(pci_priv, PCIE_MHI_TIME_HIGH, &high);
		break;
	default:
		cnss_pci_reg_read(pci_priv, WLAON_GLOBAL_COUNTER_CTRL3, &low);
		cnss_pci_reg_read(pci_priv, WLAON_GLOBAL_COUNTER_CTRL4, &high);
		break;
	}

	device_ticks = (u64)high << 32 | low;
	do_div(device_ticks, plat_priv->device_freq_hz / 100000);
	*time_us = device_ticks * 10;

	return 0;
}

static void cnss_pci_enable_time_sync_counter(struct cnss_pci_data *pci_priv)
{
	switch (pci_priv->device_id) {
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		return;
	default:
		break;
	}

	cnss_pci_reg_write(pci_priv, WLAON_GLOBAL_COUNTER_CTRL5,
			   TIME_SYNC_ENABLE);
}

static void cnss_pci_clear_time_sync_counter(struct cnss_pci_data *pci_priv)
{
	switch (pci_priv->device_id) {
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		return;
	default:
		break;
	}

	cnss_pci_reg_write(pci_priv, WLAON_GLOBAL_COUNTER_CTRL5,
			   TIME_SYNC_CLEAR);
}


static void cnss_pci_time_sync_reg_update(struct cnss_pci_data *pci_priv,
					  u32 low, u32 high)
{
	u32 time_reg_low;
	u32 time_reg_high;

	switch (pci_priv->device_id) {
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		/* Use the next two shadow registers after host's usage */
		time_reg_low = PCIE_SHADOW_REG_VALUE_0 +
				(pci_priv->plat_priv->num_shadow_regs_v3 *
				 SHADOW_REG_LEN_BYTES);
		time_reg_high = time_reg_low + SHADOW_REG_LEN_BYTES;
		break;
	default:
		time_reg_low = PCIE_SHADOW_REG_VALUE_34;
		time_reg_high = PCIE_SHADOW_REG_VALUE_35;
		break;
	}

	cnss_pci_reg_write(pci_priv, time_reg_low, low);
	cnss_pci_reg_write(pci_priv, time_reg_high, high);

	cnss_pci_reg_read(pci_priv, time_reg_low, &low);
	cnss_pci_reg_read(pci_priv, time_reg_high, &high);

	cnss_pr_dbg("Updated time sync regs [0x%x] = 0x%x, [0x%x] = 0x%x\n",
		    time_reg_low, low, time_reg_high, high);
}

static int cnss_pci_update_timestamp(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct device *dev = &pci_priv->pci_dev->dev;
	unsigned long flags = 0;
	u64 host_time_us, device_time_us, offset;
	u32 low, high;
	int ret;

	ret = cnss_pci_prevent_l1(dev);
	if (ret)
		goto out;

	ret = cnss_pci_force_wake_get(pci_priv);
	if (ret)
		goto allow_l1;

	spin_lock_irqsave(&time_sync_lock, flags);
	cnss_pci_clear_time_sync_counter(pci_priv);
	cnss_pci_enable_time_sync_counter(pci_priv);
	host_time_us = cnss_get_host_timestamp(plat_priv);
	ret = cnss_pci_get_device_timestamp(pci_priv, &device_time_us);
	cnss_pci_clear_time_sync_counter(pci_priv);
	spin_unlock_irqrestore(&time_sync_lock, flags);
	if (ret)
		goto force_wake_put;

	if (host_time_us < device_time_us) {
		cnss_pr_err("Host time (%llu us) is smaller than device time (%llu us), stop\n",
			    host_time_us, device_time_us);
		ret = -EINVAL;
		goto force_wake_put;
	}

	offset = host_time_us - device_time_us;
	cnss_pr_dbg("Host time = %llu us, device time = %llu us, offset = %llu us\n",
		    host_time_us, device_time_us, offset);

	low = offset & 0xFFFFFFFF;
	high = offset >> 32;

	cnss_pci_time_sync_reg_update(pci_priv, low, high);

force_wake_put:
	cnss_pci_force_wake_put(pci_priv);
allow_l1:
	cnss_pci_allow_l1(dev);
out:
	return ret;
}

static void cnss_pci_time_sync_work_hdlr(struct work_struct *work)
{
	struct cnss_pci_data *pci_priv =
		container_of(work, struct cnss_pci_data, time_sync_work.work);
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	unsigned int time_sync_period_ms =
		plat_priv->ctrl_params.time_sync_period;

	if (test_bit(DISABLE_TIME_SYNC, &plat_priv->ctrl_params.quirks)) {
		cnss_pr_dbg("Time sync is disabled\n");
		return;
	}

	if (!time_sync_period_ms) {
		cnss_pr_dbg("Skip time sync as time period is 0\n");
		return;
	}

	if (cnss_pci_is_device_down(&pci_priv->pci_dev->dev))
		return;

	if (cnss_pci_pm_runtime_get_sync(pci_priv, RTPM_ID_CNSS) < 0)
		goto runtime_pm_put;

	mutex_lock(&pci_priv->bus_lock);
	cnss_pci_update_timestamp(pci_priv);
	mutex_unlock(&pci_priv->bus_lock);
	schedule_delayed_work(&pci_priv->time_sync_work,
			      msecs_to_jiffies(time_sync_period_ms));

runtime_pm_put:
	cnss_pci_pm_runtime_mark_last_busy(pci_priv);
	cnss_pci_pm_runtime_put_autosuspend(pci_priv, RTPM_ID_CNSS);
}

static int cnss_pci_start_time_sync_update(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!plat_priv->device_freq_hz) {
		cnss_pr_dbg("Device time clock frequency is not valid, skip time sync\n");
		return -EINVAL;
	}

	cnss_pci_time_sync_work_hdlr(&pci_priv->time_sync_work.work);

	return 0;
}

static void cnss_pci_stop_time_sync_update(struct cnss_pci_data *pci_priv)
{
	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		break;
	default:
		return;
	}

	cancel_delayed_work_sync(&pci_priv->time_sync_work);
}

int cnss_pci_set_therm_cdev_state(struct cnss_pci_data *pci_priv,
				  unsigned long thermal_state,
				  int tcdev_id)
{
	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL!\n");
		return -ENODEV;
	}

	if (!pci_priv->driver_ops || !pci_priv->driver_ops->set_therm_cdev_state) {
		cnss_pr_err("driver_ops or set_therm_cdev_state is NULL\n");
		return -EINVAL;
	}

	return pci_priv->driver_ops->set_therm_cdev_state(pci_priv->pci_dev,
							 thermal_state,
							 tcdev_id);
}

int cnss_pci_update_time_sync_period(struct cnss_pci_data *pci_priv,
				     unsigned int time_sync_period)
{
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;

	cnss_pci_stop_time_sync_update(pci_priv);
	plat_priv->ctrl_params.time_sync_period = time_sync_period;
	cnss_pci_start_time_sync_update(pci_priv);
	cnss_pr_dbg("WLAN time sync period %u ms\n",
		    plat_priv->ctrl_params.time_sync_period);

	return 0;
}

int cnss_pci_call_driver_probe(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;
	if (test_bit(CNSS_IN_REBOOT, &plat_priv->driver_state)) {
		cnss_pr_err("Reboot is in progress, skip driver probe\n");
		return -EINVAL;
	}

	if (test_bit(CNSS_DRIVER_DEBUG, &plat_priv->driver_state)) {
		clear_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state);
		cnss_pr_dbg("Skip driver probe\n");
		goto out;
	}

	if (!pci_priv->driver_ops) {
		cnss_pr_err("driver_ops is NULL\n");
		ret = -EINVAL;
		goto out;
	}

	if (test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state) &&
	    test_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state)) {
		ret = pci_priv->driver_ops->reinit(pci_priv->pci_dev,
						   pci_priv->pci_device_id);
		if (ret) {
			cnss_pr_err("Failed to reinit host driver, err = %d\n",
				    ret);
			goto out;
		}
		complete(&plat_priv->recovery_complete);
	} else if (test_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state)) {
		ret = pci_priv->driver_ops->probe(pci_priv->pci_dev,
						  pci_priv->pci_device_id);
		if (ret) {
			cnss_pr_err("Failed to probe host driver, err = %d\n",
				    ret);
			complete_all(&plat_priv->power_up_complete);
			goto out;
		}
		clear_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state);
		set_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state);
		cnss_pci_free_blob_mem(pci_priv);
		complete_all(&plat_priv->power_up_complete);
	} else if (test_bit(CNSS_DRIVER_IDLE_RESTART,
			    &plat_priv->driver_state)) {
		ret = pci_priv->driver_ops->idle_restart(pci_priv->pci_dev,
			pci_priv->pci_device_id);
		if (ret) {
			cnss_pr_err("Failed to idle restart host driver, err = %d\n",
				    ret);
			plat_priv->power_up_error = ret;
			complete_all(&plat_priv->power_up_complete);
			goto out;
		}
		clear_bit(CNSS_DRIVER_IDLE_RESTART, &plat_priv->driver_state);
		complete_all(&plat_priv->power_up_complete);
	} else {
		complete(&plat_priv->power_up_complete);
	}

	if (test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state)) {
		clear_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state);
		__pm_relax(plat_priv->recovery_ws);
	}

	cnss_pci_start_time_sync_update(pci_priv);

	return 0;

out:
	return ret;
}

int cnss_pci_call_driver_remove(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;
	int ret;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;

	if (test_bit(CNSS_IN_COLD_BOOT_CAL, &plat_priv->driver_state) ||
	    test_bit(CNSS_FW_BOOT_RECOVERY, &plat_priv->driver_state) ||
	    test_bit(CNSS_DRIVER_DEBUG, &plat_priv->driver_state)) {
		cnss_pr_dbg("Skip driver remove\n");
		return 0;
	}

	if (!pci_priv->driver_ops) {
		cnss_pr_err("driver_ops is NULL\n");
		return -EINVAL;
	}

	cnss_pci_stop_time_sync_update(pci_priv);

	if (test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state) &&
	    test_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state)) {
		complete(&plat_priv->rddm_complete);
		pci_priv->driver_ops->shutdown(pci_priv->pci_dev);
	} else if (test_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state)) {
		pci_priv->driver_ops->remove(pci_priv->pci_dev);
		clear_bit(CNSS_DRIVER_PROBED, &plat_priv->driver_state);
	} else if (test_bit(CNSS_DRIVER_IDLE_SHUTDOWN,
			    &plat_priv->driver_state)) {
		ret = pci_priv->driver_ops->idle_shutdown(pci_priv->pci_dev);
		if (ret == -EAGAIN) {
			clear_bit(CNSS_DRIVER_IDLE_SHUTDOWN,
				  &plat_priv->driver_state);
			return ret;
		}
	}

	plat_priv->get_info_cb_ctx = NULL;
	plat_priv->get_info_cb = NULL;

	return 0;
}

int cnss_pci_call_driver_modem_status(struct cnss_pci_data *pci_priv,
				      int modem_current_status)
{
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		return -ENODEV;

	driver_ops = pci_priv->driver_ops;
	if (!driver_ops || !driver_ops->modem_status)
		return -EINVAL;

	driver_ops->modem_status(pci_priv->pci_dev, modem_current_status);

	return 0;
}

int cnss_pci_update_status(struct cnss_pci_data *pci_priv,
			   enum cnss_driver_status status)
{
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		return -ENODEV;

	driver_ops = pci_priv->driver_ops;
	if (!driver_ops || !driver_ops->update_status)
		return -EINVAL;

	cnss_pr_dbg("Update driver status: %d\n", status);

	driver_ops->update_status(pci_priv->pci_dev, status);

	return 0;
}

static void cnss_pci_misc_reg_dump(struct cnss_pci_data *pci_priv,
				   struct cnss_misc_reg *misc_reg,
				   u32 misc_reg_size,
				   char *reg_name)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	bool do_force_wake_put = true;
	int i;

	if (!misc_reg)
		return;

	if (in_interrupt() || irqs_disabled())
		return;

	if (cnss_pci_check_link_status(pci_priv))
		return;

	if (cnss_pci_force_wake_get(pci_priv)) {
		/* Continue to dump when device has entered RDDM already */
		if (!test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state))
			return;
		do_force_wake_put = false;
	}

	cnss_pr_dbg("Start to dump %s registers\n", reg_name);

	for (i = 0; i < misc_reg_size; i++) {
		if (!test_bit(pci_priv->misc_reg_dev_mask,
			      &misc_reg[i].dev_mask))
			continue;

		if (misc_reg[i].wr) {
			if (misc_reg[i].offset ==
			    QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_SAW2_CFG &&
			    i >= 1)
				misc_reg[i].val =
				QCA6390_WCSS_Q6SS_PRIVCSR_QDSP6SS_SAW2_CFG_MSK |
				misc_reg[i - 1].val;
			if (cnss_pci_reg_write(pci_priv,
					       misc_reg[i].offset,
					       misc_reg[i].val))
				goto force_wake_put;
			cnss_pr_vdbg("Write 0x%X to 0x%X\n",
				     misc_reg[i].val,
				     misc_reg[i].offset);

		} else {
			if (cnss_pci_reg_read(pci_priv,
					      misc_reg[i].offset,
					      &misc_reg[i].val))
				goto force_wake_put;
		}
	}

force_wake_put:
	if (do_force_wake_put)
		cnss_pci_force_wake_put(pci_priv);
}

static void cnss_pci_dump_misc_reg(struct cnss_pci_data *pci_priv)
{
	if (in_interrupt() || irqs_disabled())
		return;

	if (cnss_pci_check_link_status(pci_priv))
		return;

	cnss_pci_misc_reg_dump(pci_priv, pci_priv->wcss_reg,
			       WCSS_REG_SIZE, "wcss");
	cnss_pci_misc_reg_dump(pci_priv, pci_priv->pcie_reg,
			       PCIE_REG_SIZE, "pcie");
	cnss_pci_misc_reg_dump(pci_priv, pci_priv->wlaon_reg,
			       WLAON_REG_SIZE, "wlaon");
	cnss_pci_misc_reg_dump(pci_priv, pci_priv->syspm_reg,
			       SYSPM_REG_SIZE, "syspm");
}

static void cnss_pci_dump_shadow_reg(struct cnss_pci_data *pci_priv)
{
	int i, j = 0, array_size = SHADOW_REG_COUNT + SHADOW_REG_INTER_COUNT;
	u32 reg_offset;
	bool do_force_wake_put = true;

	if (in_interrupt() || irqs_disabled())
		return;

	if (cnss_pci_check_link_status(pci_priv))
		return;

	if (!pci_priv->debug_reg) {
		pci_priv->debug_reg = devm_kzalloc(&pci_priv->pci_dev->dev,
						   sizeof(*pci_priv->debug_reg)
						   * array_size, GFP_KERNEL);
		if (!pci_priv->debug_reg)
			return;
	}

	if (cnss_pci_force_wake_get(pci_priv))
		do_force_wake_put = false;

	cnss_pr_dbg("Start to dump shadow registers\n");

	for (i = 0; i < SHADOW_REG_COUNT; i++, j++) {
		reg_offset = PCIE_SHADOW_REG_VALUE_0 + i * 4;
		pci_priv->debug_reg[j].offset = reg_offset;
		if (cnss_pci_reg_read(pci_priv, reg_offset,
				      &pci_priv->debug_reg[j].val))
			goto force_wake_put;
	}

	for (i = 0; i < SHADOW_REG_INTER_COUNT; i++, j++) {
		reg_offset = PCIE_SHADOW_REG_INTER_0 + i * 4;
		pci_priv->debug_reg[j].offset = reg_offset;
		if (cnss_pci_reg_read(pci_priv, reg_offset,
				      &pci_priv->debug_reg[j].val))
			goto force_wake_put;
	}

force_wake_put:
	if (do_force_wake_put)
		cnss_pci_force_wake_put(pci_priv);
}

static int cnss_qca6174_powerup(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	ret = cnss_power_on_device(plat_priv, false);
	if (ret) {
		cnss_pr_err("Failed to power on device, err = %d\n", ret);
		goto out;
	}

	ret = cnss_resume_pci_link(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to resume PCI link, err = %d\n", ret);
		goto power_off;
	}

	ret = cnss_pci_call_driver_probe(pci_priv);
	if (ret)
		goto suspend_link;

	return 0;
suspend_link:
	cnss_suspend_pci_link(pci_priv);
power_off:
	cnss_power_off_device(plat_priv);
out:
	return ret;
}

static int cnss_qca6174_shutdown(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	cnss_pci_pm_runtime_resume(pci_priv);

	ret = cnss_pci_call_driver_remove(pci_priv);
	if (ret == -EAGAIN)
		goto out;

	cnss_request_bus_bandwidth(&plat_priv->plat_dev->dev,
				   CNSS_BUS_WIDTH_NONE);
	cnss_pci_set_monitor_wake_intr(pci_priv, false);
	cnss_pci_set_auto_suspended(pci_priv, 0);

	ret = cnss_suspend_pci_link(pci_priv);
	if (ret)
		cnss_pr_err("Failed to suspend PCI link, err = %d\n", ret);

	cnss_power_off_device(plat_priv);

	clear_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state);
	clear_bit(CNSS_DRIVER_IDLE_SHUTDOWN, &plat_priv->driver_state);

out:
	return ret;
}

static void cnss_qca6174_crash_shutdown(struct cnss_pci_data *pci_priv)
{
	if (pci_priv->driver_ops && pci_priv->driver_ops->crash_shutdown)
		pci_priv->driver_ops->crash_shutdown(pci_priv->pci_dev);
}

static int cnss_qca6174_ramdump(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_ramdump_info *ramdump_info;

	ramdump_info = &plat_priv->ramdump_info;
	if (!ramdump_info->ramdump_size)
		return -EINVAL;

	return cnss_do_ramdump(plat_priv);
}

static void cnss_get_driver_mode_update_fw_name(struct cnss_plat_data *plat_priv)
{
	struct cnss_pci_data *pci_priv;
	struct cnss_wlan_driver *driver_ops;

	pci_priv = plat_priv->bus_priv;
	driver_ops = pci_priv->driver_ops;

	if (driver_ops && driver_ops->get_driver_mode) {
		plat_priv->driver_mode = driver_ops->get_driver_mode();
		cnss_pci_update_fw_name(pci_priv);
		cnss_pr_dbg("New driver mode is %d", plat_priv->driver_mode);
	}
}

static int cnss_qca6290_powerup(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	unsigned int timeout;
	int retry = 0, bt_en_gpio = plat_priv->pinctrl_info.bt_en_gpio;
	int sw_ctrl_gpio = plat_priv->pinctrl_info.sw_ctrl_gpio;

	if (plat_priv->ramdump_info_v2.dump_data_valid) {
		cnss_pci_clear_dump_info(pci_priv);
		cnss_pci_power_off_mhi(pci_priv);
		cnss_suspend_pci_link(pci_priv);
		cnss_pci_deinit_mhi(pci_priv);
		cnss_power_off_device(plat_priv);
	}

	/* Clear QMI send usage count during every power up */
	pci_priv->qmi_send_usage_count = 0;

	plat_priv->power_up_error = 0;

	cnss_get_driver_mode_update_fw_name(plat_priv);
retry:
	ret = cnss_power_on_device(plat_priv, false);
	if (ret) {
		cnss_pr_err("Failed to power on device, err = %d\n", ret);
		goto out;
	}

	ret = cnss_resume_pci_link(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to resume PCI link, err = %d\n", ret);
		cnss_pr_dbg("Value of SW_CTRL GPIO: %d\n",
			    cnss_get_input_gpio_value(plat_priv, sw_ctrl_gpio));
		if (test_bit(IGNORE_PCI_LINK_FAILURE,
			     &plat_priv->ctrl_params.quirks)) {
			cnss_pr_dbg("Ignore PCI link resume failure\n");
			ret = 0;
			goto out;
		}
		if (ret == -EAGAIN && retry++ < POWER_ON_RETRY_MAX_TIMES) {
			cnss_power_off_device(plat_priv);
			/* Force toggle BT_EN GPIO low */
			if (retry == POWER_ON_RETRY_MAX_TIMES) {
				cnss_pr_dbg("Retry #%d. Set BT_EN GPIO(%u) low\n",
					    retry, bt_en_gpio);
				if (bt_en_gpio >= 0)
					gpio_direction_output(bt_en_gpio, 0);
				cnss_pr_dbg("BT_EN GPIO val: %d\n",
					    gpio_get_value(bt_en_gpio));
			}
			cnss_pr_dbg("Retry to resume PCI link #%d\n", retry);
			cnss_pr_dbg("Value of SW_CTRL GPIO: %d\n",
				    cnss_get_input_gpio_value(plat_priv,
							      sw_ctrl_gpio));
			msleep(POWER_ON_RETRY_DELAY_MS * retry);
			goto retry;
		}
		/* Assert when it reaches maximum retries */
		CNSS_ASSERT(0);
		goto power_off;
	}

	cnss_pci_set_wlaon_pwr_ctrl(pci_priv, false, false, false);
	timeout = cnss_get_timeout(plat_priv, CNSS_TIMEOUT_QMI);

	ret = cnss_pci_start_mhi(pci_priv);
	if (ret) {
		cnss_fatal_err("Failed to start MHI, err = %d\n", ret);
		if (!test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state) &&
		    !pci_priv->pci_link_down_ind && timeout) {
			/* Start recovery directly for MHI start failures */
			cnss_schedule_recovery(&pci_priv->pci_dev->dev,
					       CNSS_REASON_DEFAULT);
		}
		return 0;
	}

	if (test_bit(USE_CORE_ONLY_FW, &plat_priv->ctrl_params.quirks)) {
		clear_bit(CNSS_FW_BOOT_RECOVERY, &plat_priv->driver_state);
		clear_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state);
		return 0;
	}

	cnss_set_pin_connect_status(plat_priv);

	if (test_bit(QMI_BYPASS, &plat_priv->ctrl_params.quirks)) {
		ret = cnss_pci_call_driver_probe(pci_priv);
		if (ret)
			goto stop_mhi;
	} else if (timeout) {
		if (test_bit(CNSS_IN_COLD_BOOT_CAL, &plat_priv->driver_state))
			timeout += WLAN_COLD_BOOT_CAL_TIMEOUT;
		else
			timeout += WLAN_MISSION_MODE_TIMEOUT;
		mod_timer(&plat_priv->fw_boot_timer,
			  jiffies + msecs_to_jiffies(timeout));
	}

	return 0;

stop_mhi:
	cnss_pci_set_wlaon_pwr_ctrl(pci_priv, false, true, true);
	cnss_pci_power_off_mhi(pci_priv);
	cnss_suspend_pci_link(pci_priv);
	cnss_pci_deinit_mhi(pci_priv);
power_off:
	cnss_power_off_device(plat_priv);
out:
	return ret;
}

static int cnss_qca6290_shutdown(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	int do_force_wake = true;

	cnss_pci_pm_runtime_resume(pci_priv);

	ret = cnss_pci_call_driver_remove(pci_priv);
	if (ret == -EAGAIN)
		goto out;

	cnss_request_bus_bandwidth(&plat_priv->plat_dev->dev,
				   CNSS_BUS_WIDTH_NONE);
	cnss_pci_set_monitor_wake_intr(pci_priv, false);
	cnss_pci_set_auto_suspended(pci_priv, 0);

	if ((test_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state) ||
	     test_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state) ||
	     test_bit(CNSS_DRIVER_IDLE_RESTART, &plat_priv->driver_state) ||
	     test_bit(CNSS_DRIVER_IDLE_SHUTDOWN, &plat_priv->driver_state) ||
	     test_bit(CNSS_IN_COLD_BOOT_CAL, &plat_priv->driver_state)) &&
	    test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state)) {
		del_timer(&pci_priv->dev_rddm_timer);
		cnss_pci_collect_dump_info(pci_priv, false);

		if (!plat_priv->recovery_enabled)
			CNSS_ASSERT(0);
	}

	if (!cnss_is_device_powered_on(plat_priv)) {
		cnss_pr_dbg("Device is already powered off, ignore\n");
		goto skip_power_off;
	}

	if (test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state))
		do_force_wake = false;
	cnss_pci_set_wlaon_pwr_ctrl(pci_priv, false, true, do_force_wake);

	/* FBC image will be freed after powering off MHI, so skip
	 * if RAM dump data is still valid.
	 */
	if (plat_priv->ramdump_info_v2.dump_data_valid)
		goto skip_power_off;

	cnss_pci_power_off_mhi(pci_priv);
	ret = cnss_suspend_pci_link(pci_priv);
	if (ret)
		cnss_pr_err("Failed to suspend PCI link, err = %d\n", ret);
	cnss_pci_deinit_mhi(pci_priv);
	cnss_power_off_device(plat_priv);

skip_power_off:
	pci_priv->remap_window = 0;

	clear_bit(CNSS_FW_READY, &plat_priv->driver_state);
	clear_bit(CNSS_FW_MEM_READY, &plat_priv->driver_state);
	if (test_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state) ||
	    test_bit(CNSS_DRIVER_IDLE_SHUTDOWN, &plat_priv->driver_state)) {
		clear_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state);
		pci_priv->pci_link_down_ind = false;
	}
	clear_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state);
	clear_bit(CNSS_DRIVER_IDLE_SHUTDOWN, &plat_priv->driver_state);
	memset(&print_optimize, 0, sizeof(print_optimize));

out:
	return ret;
}

static void cnss_qca6290_crash_shutdown(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	set_bit(CNSS_IN_PANIC, &plat_priv->driver_state);
	cnss_pr_dbg("Crash shutdown with driver_state 0x%lx\n",
		    plat_priv->driver_state);

	cnss_pci_collect_dump_info(pci_priv, true);
	clear_bit(CNSS_IN_PANIC, &plat_priv->driver_state);
}

static int cnss_qca6290_ramdump(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_ramdump_info_v2 *info_v2 = &plat_priv->ramdump_info_v2;
	struct cnss_dump_data *dump_data = &info_v2->dump_data;
	struct cnss_dump_seg *dump_seg = info_v2->dump_data_vaddr;
	int ret = 0;

	if (!info_v2->dump_data_valid || !dump_seg ||
	    dump_data->nentries == 0)
		return 0;

	ret = cnss_do_elf_ramdump(plat_priv);

	cnss_pci_clear_dump_info(pci_priv);
	cnss_pci_power_off_mhi(pci_priv);
	cnss_suspend_pci_link(pci_priv);
	cnss_pci_deinit_mhi(pci_priv);
	cnss_power_off_device(plat_priv);

	return ret;
}

int cnss_pci_dev_powerup(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		ret = cnss_qca6174_powerup(pci_priv);
		break;
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCN7605_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		ret = cnss_qca6290_powerup(pci_priv);
		break;
	default:
		cnss_pr_err("Unknown device_id found: 0x%x\n",
			    pci_priv->device_id);
		ret = -ENODEV;
	}

	return ret;
}

int cnss_pci_dev_shutdown(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		ret = cnss_qca6174_shutdown(pci_priv);
		break;
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCN7605_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		ret = cnss_qca6290_shutdown(pci_priv);
		break;
	default:
		cnss_pr_err("Unknown device_id found: 0x%x\n",
			    pci_priv->device_id);
		ret = -ENODEV;
	}

	return ret;
}

int cnss_pci_dev_crash_shutdown(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		cnss_qca6174_crash_shutdown(pci_priv);
		break;
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCN7605_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		cnss_qca6290_crash_shutdown(pci_priv);
		break;
	default:
		cnss_pr_err("Unknown device_id found: 0x%x\n",
			    pci_priv->device_id);
		ret = -ENODEV;
	}

	return ret;
}

int cnss_pci_dev_ramdump(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		ret = cnss_qca6174_ramdump(pci_priv);
		break;
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCN7605_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		ret = cnss_qca6290_ramdump(pci_priv);
		break;
	default:
		cnss_pr_err("Unknown device_id found: 0x%x\n",
			    pci_priv->device_id);
		ret = -ENODEV;
	}

	return ret;
}

int cnss_pci_is_drv_connected(struct device *dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));

	if (!pci_priv)
		return -ENODEV;

	return pci_priv->drv_connected_last;
}
EXPORT_SYMBOL(cnss_pci_is_drv_connected);

static void cnss_wlan_reg_driver_work(struct work_struct *work)
{
	struct cnss_plat_data *plat_priv =
	container_of(work, struct cnss_plat_data, wlan_reg_driver_work.work);
	struct cnss_pci_data *pci_priv = plat_priv->bus_priv;
	struct cnss_cal_info *cal_info;
	unsigned int timeout;

	if (test_bit(CNSS_WLAN_HW_DISABLED, &plat_priv->driver_state))
		return;

	if (test_bit(CNSS_COLD_BOOT_CAL_DONE, &plat_priv->driver_state)) {
		goto reg_driver;
	} else {
		if (plat_priv->charger_mode) {
			cnss_pr_err("Ignore calibration timeout in charger mode\n");
			return;
		}
		if (!test_bit(CNSS_IN_COLD_BOOT_CAL,
			      &plat_priv->driver_state)) {
			timeout = cnss_get_timeout(plat_priv,
						   CNSS_TIMEOUT_CALIBRATION);
			cnss_pr_dbg("File system not ready to start calibration. Wait for %ds..\n",
				    timeout / 1000);
			schedule_delayed_work(&plat_priv->wlan_reg_driver_work,
					      msecs_to_jiffies(timeout));
			return;
		}

		del_timer(&plat_priv->fw_boot_timer);
		if (test_bit(CNSS_IN_COLD_BOOT_CAL, &plat_priv->driver_state) &&
		    !test_bit(CNSS_IN_REBOOT, &plat_priv->driver_state)) {
			cnss_pr_err("Timeout waiting for calibration to complete\n");
			CNSS_ASSERT(0);
		}
		cal_info = kzalloc(sizeof(*cal_info), GFP_KERNEL);
		if (!cal_info)
			return;
		cal_info->cal_status = CNSS_CAL_TIMEOUT;
		cnss_driver_event_post(plat_priv,
				       CNSS_DRIVER_EVENT_COLD_BOOT_CAL_DONE,
				       0, cal_info);
	}
reg_driver:
	if (test_bit(CNSS_IN_REBOOT, &plat_priv->driver_state)) {
		cnss_pr_dbg("Reboot/Shutdown is in progress, ignore register driver\n");
		return;
	}
	reinit_completion(&plat_priv->power_up_complete);
	cnss_driver_event_post(plat_priv,
			       CNSS_DRIVER_EVENT_REGISTER_DRIVER,
			       CNSS_EVENT_SYNC_UNKILLABLE,
			       pci_priv->driver_ops);
}

int cnss_wlan_register_driver(struct cnss_wlan_driver *driver_ops)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv;
	struct cnss_pci_data *pci_priv;
	const struct pci_device_id *id_table = driver_ops->id_table;
	unsigned int timeout;

	if (!cnss_check_driver_loading_allowed()) {
		cnss_pr_info("No cnss2 dtsi entry present");
		return -ENODEV;
	}

	plat_priv = cnss_get_plat_priv_by_driver_ops(driver_ops);

	if (!plat_priv) {
		cnss_pr_buf("plat_priv is not ready for register driver\n");
		return -EAGAIN;
	}

	pci_priv = plat_priv->bus_priv;
	if (test_bit(CNSS_WLAN_HW_DISABLED, &plat_priv->driver_state)) {
		while (id_table && id_table->device) {
			if (plat_priv->device_id == id_table->device) {
				if (plat_priv->device_id == KIWI_DEVICE_ID &&
				    driver_ops->chip_version != 2) {
					cnss_pr_err("WLAN HW disabled. kiwi_v2 only supported\n");
					return -ENODEV;
				}
				cnss_pr_info("WLAN register driver deferred for device ID: 0x%x due to HW disable\n",
					     id_table->device);
				plat_priv->driver_ops = driver_ops;
				return 0;
			}
			id_table++;
		}
		return -ENODEV;
	}

	if (!test_bit(CNSS_PCI_PROBE_DONE, &plat_priv->driver_state)) {
		cnss_pr_info("pci probe not yet done for register driver\n");
		return -EAGAIN;
	}

	if (test_bit(CNSS_DRIVER_REGISTERED, &plat_priv->driver_state)) {
		cnss_pr_err("Driver has already registered\n");
		return -EEXIST;
	}

	if (test_bit(CNSS_IN_REBOOT, &plat_priv->driver_state)) {
		cnss_pr_dbg("Reboot/Shutdown is in progress, ignore register driver\n");
		return -EINVAL;
	}

	if (!id_table || !pci_dev_present(id_table)) {
		/* id_table pointer will move from pci_dev_present(),
		 * so check again using local pointer.
		 */
		id_table = driver_ops->id_table;
		while (id_table && id_table->vendor) {
			cnss_pr_info("Host driver is built for PCIe device ID 0x%x\n",
				     id_table->device);
			id_table++;
		}
		cnss_pr_err("Enumerated PCIe device id is 0x%x, reject unsupported driver\n",
			    pci_priv->device_id);
		return -ENODEV;
	}

	if (driver_ops->chip_version != CNSS_CHIP_VER_ANY &&
	    driver_ops->chip_version != plat_priv->device_version.major_version) {
		cnss_pr_err("Driver built for chip ver 0x%x, enumerated ver 0x%x, reject unsupported driver\n",
			    driver_ops->chip_version,
			    plat_priv->device_version.major_version);
		return -ENODEV;
	}

	cnss_get_driver_mode_update_fw_name(plat_priv);
	set_bit(CNSS_DRIVER_REGISTER, &plat_priv->driver_state);

	if (!plat_priv->cbc_enabled ||
	    test_bit(CNSS_COLD_BOOT_CAL_DONE, &plat_priv->driver_state))
		goto register_driver;

	pci_priv->driver_ops = driver_ops;
	/* If Cold Boot Calibration is enabled, it is the 1st step in init
	 * sequence.CBC is done on file system_ready trigger. Qcacld will be
	 * loaded from vendor_modprobe.sh at early boot and must be deferred
	 * until CBC is complete
	 */
	timeout = cnss_get_timeout(plat_priv, CNSS_TIMEOUT_CALIBRATION);
	INIT_DELAYED_WORK(&plat_priv->wlan_reg_driver_work,
			  cnss_wlan_reg_driver_work);
	schedule_delayed_work(&plat_priv->wlan_reg_driver_work,
			      msecs_to_jiffies(timeout));
	cnss_pr_info("WLAN register driver deferred for Calibration\n");
	return 0;
register_driver:
	reinit_completion(&plat_priv->power_up_complete);
	ret = cnss_driver_event_post(plat_priv,
				     CNSS_DRIVER_EVENT_REGISTER_DRIVER,
				     CNSS_EVENT_SYNC_UNKILLABLE,
				     driver_ops);

	return ret;
}
EXPORT_SYMBOL(cnss_wlan_register_driver);

void cnss_wlan_unregister_driver(struct cnss_wlan_driver *driver_ops)
{
	struct cnss_plat_data *plat_priv;
	int ret = 0;
	unsigned int timeout;

	plat_priv = cnss_get_plat_priv_by_driver_ops(driver_ops);
	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return;
	}

	mutex_lock(&plat_priv->driver_ops_lock);

	if (plat_priv->device_id == QCA6174_DEVICE_ID)
		goto skip_wait_power_up;

	timeout = cnss_get_timeout(plat_priv, CNSS_TIMEOUT_WLAN_WATCHDOG);
	ret = wait_for_completion_timeout(&plat_priv->power_up_complete,
					  msecs_to_jiffies(timeout));
	if (!ret) {
		cnss_pr_err("Timeout (%ums) waiting for driver power up to complete\n",
			    timeout);
		CNSS_ASSERT(0);
	}

skip_wait_power_up:
	if (!test_bit(CNSS_DRIVER_RECOVERY, &plat_priv->driver_state) &&
	    !test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state))
		goto skip_wait_recovery;

	reinit_completion(&plat_priv->recovery_complete);
	timeout = cnss_get_timeout(plat_priv, CNSS_TIMEOUT_RECOVERY);
	ret = wait_for_completion_timeout(&plat_priv->recovery_complete,
					  msecs_to_jiffies(timeout));
	if (!ret) {
		cnss_pr_err("Timeout (%ums) waiting for recovery to complete\n",
			    timeout);
		CNSS_ASSERT(0);
	}

skip_wait_recovery:
	cnss_driver_event_post(plat_priv,
			       CNSS_DRIVER_EVENT_UNREGISTER_DRIVER,
			       CNSS_EVENT_SYNC_UNKILLABLE, NULL);

	mutex_unlock(&plat_priv->driver_ops_lock);
}
EXPORT_SYMBOL(cnss_wlan_unregister_driver);

int cnss_pci_register_driver_hdlr(struct cnss_pci_data *pci_priv,
				  void *data)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	if (test_bit(CNSS_IN_REBOOT, &plat_priv->driver_state)) {
		cnss_pr_dbg("Reboot or shutdown is in progress, ignore register driver\n");
		return -EINVAL;
	}

	set_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state);
	pci_priv->driver_ops = data;

	ret = cnss_pci_dev_powerup(pci_priv);
	if (ret) {
		clear_bit(CNSS_DRIVER_LOADING, &plat_priv->driver_state);
		pci_priv->driver_ops = NULL;
	} else {
		set_bit(CNSS_DRIVER_REGISTERED, &plat_priv->driver_state);
	}

	return ret;
}

int cnss_pci_unregister_driver_hdlr(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -EINVAL;

	plat_priv = pci_priv->plat_priv;
	set_bit(CNSS_DRIVER_UNLOADING, &plat_priv->driver_state);
	cnss_pci_dev_shutdown(pci_priv);
	pci_priv->driver_ops = NULL;
	clear_bit(CNSS_DRIVER_REGISTERED, &plat_priv->driver_state);

	return 0;
}

static int cnss_pci_suspend_driver(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct cnss_wlan_driver *driver_ops = pci_priv->driver_ops;
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	pm_message_t state = { .event = PM_EVENT_SUSPEND };

	if (test_bit(CNSS_DRIVER_REGISTERED, &plat_priv->driver_state) &&
	    driver_ops && driver_ops->suspend) {
		ret = driver_ops->suspend(pci_dev, state);
		if (ret) {
			cnss_pr_err("Failed to suspend host driver, err = %d\n",
				    ret);
			ret = -EAGAIN;
		}
	}

	return ret;
}

static int cnss_pci_resume_driver(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct cnss_wlan_driver *driver_ops = pci_priv->driver_ops;
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	if (test_bit(CNSS_DRIVER_REGISTERED, &plat_priv->driver_state) &&
	    driver_ops && driver_ops->resume) {
		ret = driver_ops->resume(pci_dev);
		if (ret)
			cnss_pr_err("Failed to resume host driver, err = %d\n",
				    ret);
	}

	return ret;
}

int cnss_pci_suspend_bus(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	int ret = 0;

	if (pci_priv->pci_link_state == PCI_LINK_DOWN)
		goto out;

	if (cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_SUSPEND)) {
		ret = -EAGAIN;
		goto out;
	}

	if (pci_priv->drv_connected_last)
		goto skip_disable_pci;

	pci_clear_master(pci_dev);
	cnss_set_pci_config_space(pci_priv, SAVE_PCI_CONFIG_SPACE);
	pci_disable_device(pci_dev);

	ret = pci_set_power_state(pci_dev, PCI_D3hot);
	if (ret)
		cnss_pr_err("Failed to set D3Hot, err = %d\n", ret);

skip_disable_pci:
	if (cnss_set_pci_link(pci_priv, PCI_LINK_DOWN)) {
		ret = -EAGAIN;
		goto resume_mhi;
	}
	pci_priv->pci_link_state = PCI_LINK_DOWN;

	return 0;

resume_mhi:
	if (!pci_is_enabled(pci_dev))
		if (pci_enable_device(pci_dev))
			cnss_pr_err("Failed to enable PCI device\n");
	if (pci_priv->saved_state)
		cnss_set_pci_config_space(pci_priv, RESTORE_PCI_CONFIG_SPACE);
	pci_set_master(pci_dev);
	cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_RESUME);
out:
	return ret;
}

int cnss_pci_resume_bus(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	int ret = 0;

	if (pci_priv->pci_link_state == PCI_LINK_UP)
		goto out;

	if (cnss_set_pci_link(pci_priv, PCI_LINK_UP)) {
		cnss_fatal_err("Failed to resume PCI link from suspend\n");
		cnss_pci_link_down(&pci_dev->dev);
		ret = -EAGAIN;
		goto out;
	}

	pci_priv->pci_link_state = PCI_LINK_UP;

	if (pci_priv->drv_connected_last)
		goto skip_enable_pci;

	ret = pci_enable_device(pci_dev);
	if (ret) {
		cnss_pr_err("Failed to enable PCI device, err = %d\n",
			    ret);
		goto out;
	}

	if (pci_priv->saved_state)
		cnss_set_pci_config_space(pci_priv,
					  RESTORE_PCI_CONFIG_SPACE);
	pci_set_master(pci_dev);

skip_enable_pci:
	cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_RESUME);
out:
	return ret;
}

static int cnss_pci_suspend(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		goto out;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		goto out;

	if (!cnss_is_device_powered_on(plat_priv))
		goto out;

	/* No mhi state bit set if only finish pcie enumeration,
	 * so test_bit is not applicable to check if it is INIT state.
	 */
	if (pci_priv->mhi_state == CNSS_MHI_INIT) {
		bool suspend = cnss_should_suspend_pwroff(pci_dev);

		/* Do PCI link suspend and power off in the LPM case
		 * if chipset didn't do that after pcie enumeration.
		 */
		if (!suspend) {
			ret = cnss_suspend_pci_link(pci_priv);
			if (ret)
				cnss_pr_err("Failed to suspend PCI link, err = %d\n",
					    ret);
			cnss_power_off_device(plat_priv);
			goto out;
		}
	}

	if (!test_bit(DISABLE_DRV, &plat_priv->ctrl_params.quirks) &&
	    pci_priv->drv_supported) {
		pci_priv->drv_connected_last =
			cnss_pci_get_drv_connected(pci_priv);
		if (!pci_priv->drv_connected_last) {
			cnss_pr_dbg("Firmware does not support non-DRV suspend, reject\n");
			ret = -EAGAIN;
			goto out;
		}
	}

	set_bit(CNSS_IN_SUSPEND_RESUME, &plat_priv->driver_state);

	ret = cnss_pci_suspend_driver(pci_priv);
	if (ret)
		goto clear_flag;

	if (!pci_priv->disable_pc) {
		mutex_lock(&pci_priv->bus_lock);
		ret = cnss_pci_suspend_bus(pci_priv);
		mutex_unlock(&pci_priv->bus_lock);
		if (ret)
			goto resume_driver;
	}

	cnss_pci_set_monitor_wake_intr(pci_priv, false);

	return 0;

resume_driver:
	cnss_pci_resume_driver(pci_priv);
clear_flag:
	pci_priv->drv_connected_last = 0;
	clear_bit(CNSS_IN_SUSPEND_RESUME, &plat_priv->driver_state);
out:
	return ret;
}

static int cnss_pci_resume(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		goto out;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		goto out;

	if (pci_priv->pci_link_down_ind)
		goto out;

	if (!cnss_is_device_powered_on(pci_priv->plat_priv))
		goto out;

	if (!pci_priv->disable_pc) {
		mutex_lock(&pci_priv->bus_lock);
		ret = cnss_pci_resume_bus(pci_priv);
		mutex_unlock(&pci_priv->bus_lock);
		if (ret)
			goto out;
	}

	ret = cnss_pci_resume_driver(pci_priv);

	pci_priv->drv_connected_last = 0;
	clear_bit(CNSS_IN_SUSPEND_RESUME, &plat_priv->driver_state);

out:
	return ret;
}

static int cnss_pci_suspend_noirq(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_wlan_driver *driver_ops;
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		goto out;

	if (!cnss_is_device_powered_on(pci_priv->plat_priv))
		goto out;

	driver_ops = pci_priv->driver_ops;
	plat_priv = pci_priv->plat_priv;
	if (test_bit(CNSS_DRIVER_REGISTERED, &plat_priv->driver_state) &&
	    driver_ops && driver_ops->suspend_noirq)
		ret = driver_ops->suspend_noirq(pci_dev);

	if (pci_priv->disable_pc && !pci_dev->state_saved &&
	    !pci_priv->plat_priv->use_pm_domain)
		pci_save_state(pci_dev);

out:
	return ret;
}

static int cnss_pci_resume_noirq(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_wlan_driver *driver_ops;
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		goto out;

	if (!cnss_is_device_powered_on(pci_priv->plat_priv))
		goto out;

	plat_priv = pci_priv->plat_priv;
	driver_ops = pci_priv->driver_ops;
	if (test_bit(CNSS_DRIVER_REGISTERED, &plat_priv->driver_state) &&
	    driver_ops && driver_ops->resume_noirq &&
	    !pci_priv->pci_link_down_ind)
		ret = driver_ops->resume_noirq(pci_dev);

out:
	return ret;
}

static int cnss_pci_runtime_suspend(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		return -EAGAIN;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -EAGAIN;

	if (!cnss_is_device_powered_on(pci_priv->plat_priv))
		return -EAGAIN;

	if (pci_priv->pci_link_down_ind) {
		cnss_pr_dbg("PCI link down recovery is in progress!\n");
		return -EAGAIN;
	}

	if (!test_bit(DISABLE_DRV, &plat_priv->ctrl_params.quirks) &&
	    pci_priv->drv_supported) {
		pci_priv->drv_connected_last =
			cnss_pci_get_drv_connected(pci_priv);
		if (!pci_priv->drv_connected_last) {
			cnss_pr_dbg("Firmware does not support non-DRV suspend, reject\n");
			return -EAGAIN;
		}
	}

	cnss_pr_vdbg("Runtime suspend start\n");

	driver_ops = pci_priv->driver_ops;
	if (driver_ops && driver_ops->runtime_ops &&
	    driver_ops->runtime_ops->runtime_suspend)
		ret = driver_ops->runtime_ops->runtime_suspend(pci_dev);
	else
		ret = cnss_auto_suspend(dev);

	if (ret)
		pci_priv->drv_connected_last = 0;

	cnss_pr_vdbg("Runtime suspend status: %d\n", ret);

	return ret;
}

static int cnss_pci_runtime_resume(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_wlan_driver *driver_ops;

	if (!pci_priv)
		return -EAGAIN;

	if (!cnss_is_device_powered_on(pci_priv->plat_priv))
		return -EAGAIN;

	if (pci_priv->pci_link_down_ind) {
		cnss_pr_dbg("PCI link down recovery is in progress!\n");
		return -EAGAIN;
	}

	cnss_pr_vdbg("Runtime resume start\n");

	driver_ops = pci_priv->driver_ops;
	if (driver_ops && driver_ops->runtime_ops &&
	    driver_ops->runtime_ops->runtime_resume)
		ret = driver_ops->runtime_ops->runtime_resume(pci_dev);
	else
		ret = cnss_auto_resume(dev);

	if (!ret)
		pci_priv->drv_connected_last = 0;

	cnss_pr_vdbg("Runtime resume status: %d\n", ret);

	return ret;
}

static int cnss_pci_runtime_idle(struct device *dev)
{
	cnss_pr_vdbg("Runtime idle\n");

	pm_request_autosuspend(dev);

	return -EBUSY;
}

int cnss_wlan_pm_control(struct device *dev, bool vote)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	int ret = 0;

	if (!pci_priv)
		return -ENODEV;

	ret = cnss_pci_disable_pc(pci_priv, vote);
	if (ret)
		return ret;

	pci_priv->disable_pc = vote;
	cnss_pr_dbg("%s PCIe power collapse\n", vote ? "disable" : "enable");

	return 0;
}
EXPORT_SYMBOL(cnss_wlan_pm_control);

static void cnss_pci_pm_runtime_get_record(struct cnss_pci_data *pci_priv,
					   enum cnss_rtpm_id id)
{
	if (id >= RTPM_ID_MAX)
		return;

	atomic_inc(&pci_priv->pm_stats.runtime_get);
	atomic_inc(&pci_priv->pm_stats.runtime_get_id[id]);
	pci_priv->pm_stats.runtime_get_timestamp_id[id] =
		cnss_get_host_timestamp(pci_priv->plat_priv);
}

static void cnss_pci_pm_runtime_put_record(struct cnss_pci_data *pci_priv,
					   enum cnss_rtpm_id id)
{
	if (id >= RTPM_ID_MAX)
		return;

	atomic_inc(&pci_priv->pm_stats.runtime_put);
	atomic_inc(&pci_priv->pm_stats.runtime_put_id[id]);
	pci_priv->pm_stats.runtime_put_timestamp_id[id] =
		cnss_get_host_timestamp(pci_priv->plat_priv);
}

void cnss_pci_pm_runtime_show_usage_count(struct cnss_pci_data *pci_priv)
{
	struct device *dev;

	if (!pci_priv)
		return;

	dev = &pci_priv->pci_dev->dev;

	cnss_pr_dbg("Runtime PM usage count: %d\n",
		    atomic_read(&dev->power.usage_count));
}

int cnss_pci_pm_request_resume(struct cnss_pci_data *pci_priv)
{
	struct device *dev;
	enum rpm_status status;

	if (!pci_priv)
		return -ENODEV;

	dev = &pci_priv->pci_dev->dev;

	status = dev->power.runtime_status;
	if (status == RPM_SUSPENDING || status == RPM_SUSPENDED)
		cnss_pr_vdbg("Runtime PM resume is requested by %ps\n",
			     (void *)_RET_IP_);

	return pm_request_resume(dev);
}

int cnss_pci_pm_runtime_resume(struct cnss_pci_data *pci_priv)
{
	struct device *dev;
	enum rpm_status status;

	if (!pci_priv)
		return -ENODEV;

	dev = &pci_priv->pci_dev->dev;

	status = dev->power.runtime_status;
	if (status == RPM_SUSPENDING || status == RPM_SUSPENDED)
		cnss_pr_vdbg("Runtime PM resume is requested by %ps\n",
			     (void *)_RET_IP_);

	return pm_runtime_resume(dev);
}

int cnss_pci_pm_runtime_get(struct cnss_pci_data *pci_priv,
			    enum cnss_rtpm_id id)
{
	struct device *dev;
	enum rpm_status status;

	if (!pci_priv)
		return -ENODEV;

	dev = &pci_priv->pci_dev->dev;

	status = dev->power.runtime_status;
	if (status == RPM_SUSPENDING || status == RPM_SUSPENDED)
		cnss_pr_vdbg("Runtime PM resume is requested by %ps\n",
			     (void *)_RET_IP_);

	cnss_pci_pm_runtime_get_record(pci_priv, id);

	return pm_runtime_get(dev);
}

int cnss_pci_pm_runtime_get_sync(struct cnss_pci_data *pci_priv,
				 enum cnss_rtpm_id id)
{
	struct device *dev;
	enum rpm_status status;

	if (!pci_priv)
		return -ENODEV;

	dev = &pci_priv->pci_dev->dev;

	status = dev->power.runtime_status;
	if (status == RPM_SUSPENDING || status == RPM_SUSPENDED)
		cnss_pr_vdbg("Runtime PM resume is requested by %ps\n",
			     (void *)_RET_IP_);

	cnss_pci_pm_runtime_get_record(pci_priv, id);

	return pm_runtime_get_sync(dev);
}

void cnss_pci_pm_runtime_get_noresume(struct cnss_pci_data *pci_priv,
				      enum cnss_rtpm_id id)
{
	if (!pci_priv)
		return;

	cnss_pci_pm_runtime_get_record(pci_priv, id);
	pm_runtime_get_noresume(&pci_priv->pci_dev->dev);
}

int cnss_pci_pm_runtime_put_autosuspend(struct cnss_pci_data *pci_priv,
					enum cnss_rtpm_id id)
{
	struct device *dev;

	if (!pci_priv)
		return -ENODEV;

	dev = &pci_priv->pci_dev->dev;

	if (atomic_read(&dev->power.usage_count) == 0) {
		cnss_pr_dbg("Ignore excessive runtime PM put operation\n");
		return -EINVAL;
	}

	cnss_pci_pm_runtime_put_record(pci_priv, id);

	return pm_runtime_put_autosuspend(&pci_priv->pci_dev->dev);
}

void cnss_pci_pm_runtime_put_noidle(struct cnss_pci_data *pci_priv,
				    enum cnss_rtpm_id id)
{
	struct device *dev;

	if (!pci_priv)
		return;

	dev = &pci_priv->pci_dev->dev;

	if (atomic_read(&dev->power.usage_count) == 0) {
		cnss_pr_dbg("Ignore excessive runtime PM put operation\n");
		return;
	}

	cnss_pci_pm_runtime_put_record(pci_priv, id);
	pm_runtime_put_noidle(&pci_priv->pci_dev->dev);
}

void cnss_pci_pm_runtime_mark_last_busy(struct cnss_pci_data *pci_priv)
{
	if (!pci_priv)
		return;

	pm_runtime_mark_last_busy(&pci_priv->pci_dev->dev);
}

int cnss_auto_suspend(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -ENODEV;

	mutex_lock(&pci_priv->bus_lock);
	if (!pci_priv->qmi_send_usage_count) {
		ret = cnss_pci_suspend_bus(pci_priv);
		if (ret) {
			mutex_unlock(&pci_priv->bus_lock);
			return ret;
		}
	}

	cnss_pci_set_auto_suspended(pci_priv, 1);
	mutex_unlock(&pci_priv->bus_lock);

	cnss_pci_set_monitor_wake_intr(pci_priv, true);

	/* For suspend temporarily set bandwidth vote to NONE and dont save in
	 * current_bw_vote as in resume path we should vote for last used
	 * bandwidth vote. Also ignore error if bw voting is not setup.
	 */
	cnss_setup_bus_bandwidth(plat_priv, CNSS_BUS_WIDTH_NONE, false);
	return 0;
}
EXPORT_SYMBOL(cnss_auto_suspend);

int cnss_auto_resume(struct device *dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -ENODEV;

	mutex_lock(&pci_priv->bus_lock);
	ret = cnss_pci_resume_bus(pci_priv);
	if (ret) {
		mutex_unlock(&pci_priv->bus_lock);
		return ret;
	}

	cnss_pci_set_auto_suspended(pci_priv, 0);
	mutex_unlock(&pci_priv->bus_lock);

	cnss_request_bus_bandwidth(dev, plat_priv->icc.current_bw_vote);

	return 0;
}
EXPORT_SYMBOL(cnss_auto_resume);

int cnss_pci_force_wake_request_sync(struct device *dev, int timeout_us)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct mhi_controller *mhi_ctrl;

	if (!pci_priv)
		return -ENODEV;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		break;
	default:
		return 0;
	}

	mhi_ctrl = pci_priv->mhi_ctrl;
	if (!mhi_ctrl)
		return -EINVAL;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -ENODEV;

	if (test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state))
		return -EAGAIN;

	if (timeout_us) {
		/* Busy wait for timeout_us */
		return cnss_mhi_device_get_sync_atomic(pci_priv,
						       timeout_us, false);
	} else {
		/* Sleep wait for mhi_ctrl->timeout_ms */
		return mhi_device_get_sync(mhi_ctrl->mhi_dev);
	}
}
EXPORT_SYMBOL(cnss_pci_force_wake_request_sync);

int cnss_pci_force_wake_request(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct mhi_controller *mhi_ctrl;

	if (!pci_priv)
		return -ENODEV;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		break;
	default:
		return 0;
	}

	mhi_ctrl = pci_priv->mhi_ctrl;
	if (!mhi_ctrl)
		return -EINVAL;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -ENODEV;

	if (test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state))
		return -EAGAIN;

	mhi_device_get(mhi_ctrl->mhi_dev);

	return 0;
}
EXPORT_SYMBOL(cnss_pci_force_wake_request);

int cnss_pci_is_device_awake(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct mhi_controller *mhi_ctrl;

	if (!pci_priv)
		return -ENODEV;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		break;
	default:
		return 0;
	}

	mhi_ctrl = pci_priv->mhi_ctrl;
	if (!mhi_ctrl)
		return -EINVAL;

	return (mhi_ctrl->dev_state == MHI_STATE_M0);
}
EXPORT_SYMBOL(cnss_pci_is_device_awake);

int cnss_pci_force_wake_release(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv;
	struct mhi_controller *mhi_ctrl;

	if (!pci_priv)
		return -ENODEV;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		break;
	default:
		return 0;
	}

	mhi_ctrl = pci_priv->mhi_ctrl;
	if (!mhi_ctrl)
		return -EINVAL;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -ENODEV;

	if (test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state))
		return -EAGAIN;

	mhi_device_put(mhi_ctrl->mhi_dev);

	return 0;
}
EXPORT_SYMBOL(cnss_pci_force_wake_release);

int cnss_pci_qmi_send_get(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv)
		return -ENODEV;

	mutex_lock(&pci_priv->bus_lock);
	if (cnss_pci_get_auto_suspended(pci_priv) &&
	    !pci_priv->qmi_send_usage_count)
		ret = cnss_pci_resume_bus(pci_priv);
	pci_priv->qmi_send_usage_count++;
	cnss_pr_buf("Increased QMI send usage count to %d\n",
		    pci_priv->qmi_send_usage_count);
	mutex_unlock(&pci_priv->bus_lock);

	return ret;
}

int cnss_pci_qmi_send_put(struct cnss_pci_data *pci_priv)
{
	int ret = 0;

	if (!pci_priv)
		return -ENODEV;

	mutex_lock(&pci_priv->bus_lock);
	if (pci_priv->qmi_send_usage_count)
		pci_priv->qmi_send_usage_count--;
	cnss_pr_buf("Decreased QMI send usage count to %d\n",
		    pci_priv->qmi_send_usage_count);
	if (cnss_pci_get_auto_suspended(pci_priv) &&
	    !pci_priv->qmi_send_usage_count &&
	    !cnss_pcie_is_device_down(pci_priv))
		ret = cnss_pci_suspend_bus(pci_priv);
	mutex_unlock(&pci_priv->bus_lock);

	return ret;
}

int cnss_send_buffer_to_afcmem(struct device *dev, const uint8_t *afcdb,
			       uint32_t len, uint8_t slotid)
{
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(dev);
	struct cnss_fw_mem *fw_mem;
	void *mem = NULL;
	int i, ret;
	u32 *status;

	if (!plat_priv)
		return -EINVAL;

	fw_mem = plat_priv->fw_mem;
	if (slotid >= AFC_MAX_SLOT) {
		cnss_pr_err("Invalid slot id %d\n", slotid);
		ret = -EINVAL;
		goto err;
	}
	if (len > AFC_SLOT_SIZE) {
		cnss_pr_err("len %d greater than slot size", len);
		ret = -EINVAL;
		goto err;
	}

	for (i = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (fw_mem[i].type == QMI_WLFW_AFC_MEM_V01) {
			mem = fw_mem[i].va;
			status = mem + (slotid * AFC_SLOT_SIZE);
			break;
		}
	}

	if (!mem) {
		cnss_pr_err("AFC mem is not available\n");
		ret = -ENOMEM;
		goto err;
	}

	memcpy(mem + (slotid * AFC_SLOT_SIZE), afcdb, len);
	if (len < AFC_SLOT_SIZE)
		memset(mem + (slotid * AFC_SLOT_SIZE) + len,
		       0, AFC_SLOT_SIZE - len);
	status[AFC_AUTH_STATUS_OFFSET] = cpu_to_le32(AFC_AUTH_SUCCESS);

	return 0;
err:
	return ret;
}
EXPORT_SYMBOL(cnss_send_buffer_to_afcmem);

int cnss_reset_afcmem(struct device *dev, uint8_t slotid)
{
	struct cnss_plat_data *plat_priv = cnss_bus_dev_to_plat_priv(dev);
	struct cnss_fw_mem *fw_mem;
	void *mem = NULL;
	int i, ret;

	if (!plat_priv)
		return -EINVAL;

	fw_mem = plat_priv->fw_mem;
	if (slotid >= AFC_MAX_SLOT) {
		cnss_pr_err("Invalid slot id %d\n", slotid);
		ret = -EINVAL;
		goto err;
	}

	for (i = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (fw_mem[i].type == QMI_WLFW_AFC_MEM_V01) {
			mem = fw_mem[i].va;
			break;
		}
	}

	if (!mem) {
		cnss_pr_err("AFC mem is not available\n");
		ret = -ENOMEM;
		goto err;
	}

	memset(mem + (slotid * AFC_SLOT_SIZE), 0, AFC_SLOT_SIZE);
	return 0;

err:
	return ret;
}
EXPORT_SYMBOL(cnss_reset_afcmem);

int cnss_pci_alloc_fw_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *fw_mem = plat_priv->fw_mem;
	struct device *dev = &pci_priv->pci_dev->dev;
	int i;

	for (i = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (!fw_mem[i].va && fw_mem[i].size) {
retry:
			fw_mem[i].va =
				dma_alloc_attrs(dev, fw_mem[i].size,
						&fw_mem[i].pa, GFP_KERNEL,
						fw_mem[i].attrs);

			if (!fw_mem[i].va) {
				if ((fw_mem[i].attrs &
				    DMA_ATTR_FORCE_CONTIGUOUS)) {
					fw_mem[i].attrs &=
						~DMA_ATTR_FORCE_CONTIGUOUS;

					cnss_pr_dbg("Fallback to non-contiguous memory for FW, Mem type: %u\n",
						    fw_mem[i].type);
					goto retry;
				}
				cnss_pr_err("Failed to allocate memory for FW, size: 0x%zx, type: %u\n",
					    fw_mem[i].size, fw_mem[i].type);
				CNSS_ASSERT(0);
				return -ENOMEM;
			}
		}
	}

	return 0;
}

static void cnss_pci_free_fw_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *fw_mem = plat_priv->fw_mem;
	struct device *dev = &pci_priv->pci_dev->dev;
	int i;

	for (i = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (fw_mem[i].va && fw_mem[i].size) {
			cnss_pr_dbg("Freeing memory for FW, va: 0x%pK, pa: %pa, size: 0x%zx, type: %u\n",
				    fw_mem[i].va, &fw_mem[i].pa,
				    fw_mem[i].size, fw_mem[i].type);
			dma_free_attrs(dev, fw_mem[i].size,
				       fw_mem[i].va, fw_mem[i].pa,
				       fw_mem[i].attrs);
			fw_mem[i].va = NULL;
			fw_mem[i].pa = 0;
			fw_mem[i].size = 0;
			fw_mem[i].type = 0;
		}
	}

	plat_priv->fw_mem_seg_len = 0;
}

int cnss_pci_alloc_qdss_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *qdss_mem = plat_priv->qdss_mem;
	int i, j;

	for (i = 0; i < plat_priv->qdss_mem_seg_len; i++) {
		if (!qdss_mem[i].va && qdss_mem[i].size) {
			qdss_mem[i].va =
				dma_alloc_coherent(&pci_priv->pci_dev->dev,
						   qdss_mem[i].size,
						   &qdss_mem[i].pa,
						   GFP_KERNEL);
			if (!qdss_mem[i].va) {
				cnss_pr_err("Failed to allocate QDSS memory for FW, size: 0x%zx, type: %u, chuck-ID: %d\n",
					    qdss_mem[i].size,
					    qdss_mem[i].type, i);
				break;
			}
		}
	}

	/* Best-effort allocation for QDSS trace */
	if (i < plat_priv->qdss_mem_seg_len) {
		for (j = i; j < plat_priv->qdss_mem_seg_len; j++) {
			qdss_mem[j].type = 0;
			qdss_mem[j].size = 0;
		}
		plat_priv->qdss_mem_seg_len = i;
	}

	return 0;
}

void cnss_pci_free_qdss_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *qdss_mem = plat_priv->qdss_mem;
	int i;

	for (i = 0; i < plat_priv->qdss_mem_seg_len; i++) {
		if (qdss_mem[i].va && qdss_mem[i].size) {
			cnss_pr_dbg("Freeing memory for QDSS: pa: %pa, size: 0x%zx, type: %u\n",
				    &qdss_mem[i].pa, qdss_mem[i].size,
				    qdss_mem[i].type);
			dma_free_coherent(&pci_priv->pci_dev->dev,
					  qdss_mem[i].size, qdss_mem[i].va,
					  qdss_mem[i].pa);
			qdss_mem[i].va = NULL;
			qdss_mem[i].pa = 0;
			qdss_mem[i].size = 0;
			qdss_mem[i].type = 0;
		}
	}
	plat_priv->qdss_mem_seg_len = 0;
}

int cnss_pci_load_tme_patch(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *tme_lite_mem = &plat_priv->tme_lite_mem;
	char filename[MAX_FIRMWARE_NAME_LEN];
	char *tme_patch_filename = NULL;
	const struct firmware *fw_entry;
	int ret = 0;

	switch (pci_priv->device_id) {
	case PEACH_DEVICE_ID:
		tme_patch_filename = TME_PATCH_FILE_NAME;
		break;
	case QCA6174_DEVICE_ID:
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	default:
		cnss_pr_dbg("TME-L not supported for device ID: (0x%x)\n",
			    pci_priv->device_id);
		return 0;
	}

	if (!tme_lite_mem->va && !tme_lite_mem->size) {
		cnss_pci_add_fw_prefix_name(pci_priv, filename,
					    tme_patch_filename);

		ret = firmware_request_nowarn(&fw_entry, filename,
					      &pci_priv->pci_dev->dev);
		if (ret) {
			cnss_pr_err("Failed to load TME-L patch: %s, ret: %d\n",
				    filename, ret);
			return ret;
		}

		tme_lite_mem->va = dma_alloc_coherent(&pci_priv->pci_dev->dev,
						fw_entry->size, &tme_lite_mem->pa,
						GFP_KERNEL);
		if (!tme_lite_mem->va) {
			cnss_pr_err("Failed to allocate memory for M3, size: 0x%zx\n",
				    fw_entry->size);
			release_firmware(fw_entry);
			return -ENOMEM;
		}

		memcpy(tme_lite_mem->va, fw_entry->data, fw_entry->size);
		tme_lite_mem->size = fw_entry->size;
		release_firmware(fw_entry);
	}

	return 0;
}

static void cnss_pci_free_tme_lite_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *tme_lite_mem = &plat_priv->tme_lite_mem;

	if (tme_lite_mem->va && tme_lite_mem->size) {
		cnss_pr_dbg("Freeing memory for TME patch, va: 0x%pK, pa: %pa, size: 0x%zx\n",
			    tme_lite_mem->va, &tme_lite_mem->pa, tme_lite_mem->size);
		dma_free_coherent(&pci_priv->pci_dev->dev, tme_lite_mem->size,
				  tme_lite_mem->va, tme_lite_mem->pa);
	}

	tme_lite_mem->va = NULL;
	tme_lite_mem->pa = 0;
	tme_lite_mem->size = 0;
}

int cnss_pci_load_m3(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *m3_mem = &plat_priv->m3_mem;
	char filename[MAX_FIRMWARE_NAME_LEN];
	char *phy_filename = DEFAULT_PHY_UCODE_FILE_NAME;
	const struct firmware *fw_entry;
	int ret = 0;

	/* Use forward compatibility here since for any recent device
	 * it should use DEFAULT_PHY_UCODE_FILE_NAME.
	 */
	switch (pci_priv->device_id) {
	case QCA6174_DEVICE_ID:
		cnss_pr_err("Invalid device ID (0x%x) to load phy image\n",
			    pci_priv->device_id);
		return -EINVAL;
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
		phy_filename = DEFAULT_PHY_M3_FILE_NAME;
		break;
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		switch (plat_priv->device_version.major_version) {
		case FW_V2_NUMBER:
			phy_filename = PHY_UCODE_V2_FILE_NAME;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (!m3_mem->va && !m3_mem->size) {
		cnss_pci_add_fw_prefix_name(pci_priv, filename,
					    phy_filename);

		ret = firmware_request_nowarn(&fw_entry, filename,
					      &pci_priv->pci_dev->dev);
		if (ret) {
			cnss_pr_err("Failed to load M3 image: %s\n", filename);
			return ret;
		}

		m3_mem->va = dma_alloc_coherent(&pci_priv->pci_dev->dev,
						fw_entry->size, &m3_mem->pa,
						GFP_KERNEL);
		if (!m3_mem->va) {
			cnss_pr_err("Failed to allocate memory for M3, size: 0x%zx\n",
				    fw_entry->size);
			release_firmware(fw_entry);
			return -ENOMEM;
		}

		memcpy(m3_mem->va, fw_entry->data, fw_entry->size);
		m3_mem->size = fw_entry->size;
		release_firmware(fw_entry);
	}

	return 0;
}

static void cnss_pci_free_m3_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *m3_mem = &plat_priv->m3_mem;

	if (m3_mem->va && m3_mem->size) {
		cnss_pr_dbg("Freeing memory for M3, va: 0x%pK, pa: %pa, size: 0x%zx\n",
			    m3_mem->va, &m3_mem->pa, m3_mem->size);
		dma_free_coherent(&pci_priv->pci_dev->dev, m3_mem->size,
				  m3_mem->va, m3_mem->pa);
	}

	m3_mem->va = NULL;
	m3_mem->pa = 0;
	m3_mem->size = 0;
}

#ifdef CONFIG_FREE_M3_BLOB_MEM
void cnss_pci_free_blob_mem(struct cnss_pci_data *pci_priv)
{
	cnss_pci_free_m3_mem(pci_priv);
}
#else
void cnss_pci_free_blob_mem(struct cnss_pci_data *pci_priv)
{
}
#endif

int cnss_pci_load_aux(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *aux_mem = &plat_priv->aux_mem;
	char filename[MAX_FIRMWARE_NAME_LEN];
	char *aux_filename = DEFAULT_AUX_FILE_NAME;
	const struct firmware *fw_entry;
	int ret = 0;

	if (!aux_mem->va && !aux_mem->size) {
		cnss_pci_add_fw_prefix_name(pci_priv, filename,
					    aux_filename);

		ret = firmware_request_nowarn(&fw_entry, filename,
					      &pci_priv->pci_dev->dev);
		if (ret) {
			cnss_pr_err("Failed to load AUX image: %s\n", filename);
			return ret;
		}

		aux_mem->va = dma_alloc_coherent(&pci_priv->pci_dev->dev,
						fw_entry->size, &aux_mem->pa,
						GFP_KERNEL);
		if (!aux_mem->va) {
			cnss_pr_err("Failed to allocate memory for AUX, size: 0x%zx\n",
				    fw_entry->size);
			release_firmware(fw_entry);
			return -ENOMEM;
		}

		memcpy(aux_mem->va, fw_entry->data, fw_entry->size);
		aux_mem->size = fw_entry->size;
		release_firmware(fw_entry);
	}

	return 0;
}

static void cnss_pci_free_aux_mem(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *aux_mem = &plat_priv->aux_mem;

	if (aux_mem->va && aux_mem->size) {
		cnss_pr_dbg("Freeing memory for AUX, va: 0x%pK, pa: %pa, size: 0x%zx\n",
			    aux_mem->va, &aux_mem->pa, aux_mem->size);
		dma_free_coherent(&pci_priv->pci_dev->dev, aux_mem->size,
				  aux_mem->va, aux_mem->pa);
	}

	aux_mem->va = NULL;
	aux_mem->pa = 0;
	aux_mem->size = 0;
}

void cnss_pci_fw_boot_timeout_hdlr(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return;

	cnss_fatal_err("Timeout waiting for FW ready indication\n");

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return;

	if (test_bit(CNSS_IN_COLD_BOOT_CAL, &plat_priv->driver_state)) {
		cnss_pr_dbg("Ignore FW ready timeout for calibration mode\n");
		return;
	}

	cnss_schedule_recovery(&pci_priv->pci_dev->dev,
			       CNSS_REASON_TIMEOUT);
}

static void cnss_pci_deinit_smmu(struct cnss_pci_data *pci_priv)
{
	pci_priv->iommu_domain = NULL;
}

int cnss_pci_get_iova(struct cnss_pci_data *pci_priv, u64 *addr, u64 *size)
{
	if (!pci_priv)
		return -ENODEV;

	if (!pci_priv->smmu_iova_len)
		return -EINVAL;

	*addr = pci_priv->smmu_iova_start;
	*size = pci_priv->smmu_iova_len;

	return 0;
}

int cnss_pci_get_iova_ipa(struct cnss_pci_data *pci_priv, u64 *addr, u64 *size)
{
	if (!pci_priv)
		return -ENODEV;

	if (!pci_priv->smmu_iova_ipa_len)
		return -EINVAL;

	*addr = pci_priv->smmu_iova_ipa_start;
	*size = pci_priv->smmu_iova_ipa_len;

	return 0;
}

bool cnss_pci_is_smmu_s1_enabled(struct cnss_pci_data *pci_priv)
{
	if (pci_priv)
		return pci_priv->smmu_s1_enable;

	return false;
}
struct iommu_domain *cnss_smmu_get_domain(struct device *dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));

	if (!pci_priv)
		return NULL;

	return pci_priv->iommu_domain;
}
EXPORT_SYMBOL(cnss_smmu_get_domain);

int cnss_smmu_map(struct device *dev,
		  phys_addr_t paddr, uint32_t *iova_addr, size_t size)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));
	struct cnss_plat_data *plat_priv;
	unsigned long iova;
	size_t len;
	int ret = 0;
	int flag = IOMMU_READ | IOMMU_WRITE;
	struct pci_dev *root_port;
	struct device_node *root_of_node;
	bool dma_coherent = false;

	if (!pci_priv)
		return -ENODEV;

	if (!iova_addr) {
		cnss_pr_err("iova_addr is NULL, paddr %pa, size %zu\n",
			    &paddr, size);
		return -EINVAL;
	}

	plat_priv = pci_priv->plat_priv;

	len = roundup(size + paddr - rounddown(paddr, PAGE_SIZE), PAGE_SIZE);
	iova = roundup(pci_priv->smmu_iova_ipa_current, PAGE_SIZE);

	if (pci_priv->iommu_geometry &&
	    iova >= pci_priv->smmu_iova_ipa_start +
		    pci_priv->smmu_iova_ipa_len) {
		cnss_pr_err("No IOVA space to map, iova %lx, smmu_iova_ipa_start %pad, smmu_iova_ipa_len %zu\n",
			    iova,
			    &pci_priv->smmu_iova_ipa_start,
			    pci_priv->smmu_iova_ipa_len);
		return -ENOMEM;
	}

	if (!test_bit(DISABLE_IO_COHERENCY,
		      &plat_priv->ctrl_params.quirks)) {
		root_port = pcie_find_root_port(pci_priv->pci_dev);
		if (!root_port) {
			cnss_pr_err("Root port is null, so dma_coherent is disabled\n");
		} else {
			root_of_node = root_port->dev.of_node;
			if (root_of_node && root_of_node->parent) {
				dma_coherent =
				    of_property_read_bool(root_of_node->parent,
							  "dma-coherent");
			cnss_pr_dbg("dma-coherent is %s\n",
				    dma_coherent ? "enabled" : "disabled");
			if (dma_coherent)
				flag |= IOMMU_CACHE;
			}
		}
	}

	cnss_pr_dbg("IOMMU map: iova %lx, len %zu\n", iova, len);

	ret = cnss_iommu_map(pci_priv->iommu_domain, iova,
			     rounddown(paddr, PAGE_SIZE), len, flag);
	if (ret) {
		cnss_pr_err("PA to IOVA mapping failed, ret %d\n", ret);
		return ret;
	}

	pci_priv->smmu_iova_ipa_current = iova + len;
	*iova_addr = (uint32_t)(iova + paddr - rounddown(paddr, PAGE_SIZE));
	cnss_pr_dbg("IOMMU map: iova_addr %lx\n", *iova_addr);

	return 0;
}
EXPORT_SYMBOL(cnss_smmu_map);

int cnss_smmu_unmap(struct device *dev, uint32_t iova_addr, size_t size)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));
	unsigned long iova;
	size_t unmapped;
	size_t len;

	if (!pci_priv)
		return -ENODEV;

	iova = rounddown(iova_addr, PAGE_SIZE);
	len = roundup(size + iova_addr - iova, PAGE_SIZE);

	if (iova >= pci_priv->smmu_iova_ipa_start +
		    pci_priv->smmu_iova_ipa_len) {
		cnss_pr_err("Out of IOVA space to unmap, iova %lx, smmu_iova_ipa_start %pad, smmu_iova_ipa_len %zu\n",
			    iova,
			    &pci_priv->smmu_iova_ipa_start,
			    pci_priv->smmu_iova_ipa_len);
		return -ENOMEM;
	}

	cnss_pr_dbg("IOMMU unmap: iova %lx, len %zu\n", iova, len);

	unmapped = iommu_unmap(pci_priv->iommu_domain, iova, len);
	if (unmapped != len) {
		cnss_pr_err("IOMMU unmap failed, unmapped = %zu, requested = %zu\n",
			    unmapped, len);
		return -EINVAL;
	}

	pci_priv->smmu_iova_ipa_current = iova;
	return 0;
}
EXPORT_SYMBOL(cnss_smmu_unmap);

int cnss_get_soc_info(struct device *dev, struct cnss_soc_info *info)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -ENODEV;

	info->va = pci_priv->bar;
	info->pa = pci_resource_start(pci_priv->pci_dev, PCI_BAR_NUM);
	info->chip_id = plat_priv->chip_info.chip_id;
	info->chip_family = plat_priv->chip_info.chip_family;
	info->board_id = plat_priv->board_info.board_id;
	info->soc_id = plat_priv->soc_info.soc_id;
	info->fw_version = plat_priv->fw_version_info.fw_version;
	strlcpy(info->fw_build_timestamp,
		plat_priv->fw_version_info.fw_build_timestamp,
		sizeof(info->fw_build_timestamp));
	memcpy(&info->device_version, &plat_priv->device_version,
	       sizeof(info->device_version));
	memcpy(&info->dev_mem_info, &plat_priv->dev_mem_info,
	       sizeof(info->dev_mem_info));
	memcpy(&info->fw_build_id, &plat_priv->fw_build_id,
	       sizeof(info->fw_build_id));

	return 0;
}
EXPORT_SYMBOL(cnss_get_soc_info);

int cnss_pci_get_user_msi_assignment(struct cnss_pci_data *pci_priv,
				     char *user_name,
				     int *num_vectors,
				     u32 *user_base_data,
				     u32 *base_vector)
{
	return cnss_get_user_msi_assignment(&pci_priv->pci_dev->dev,
					    user_name,
					    num_vectors,
					    user_base_data,
					    base_vector);
}

static int cnss_pci_irq_set_affinity_hint(struct cnss_pci_data *pci_priv,
					  unsigned int vec,
					  const struct cpumask *cpumask)
{
	int ret;
	struct pci_dev *pci_dev = pci_priv->pci_dev;

	ret = irq_set_affinity_hint(pci_irq_vector(pci_dev, vec),
				    cpumask);

	return ret;
}

static int cnss_pci_enable_msi(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	int num_vectors;
	struct cnss_msi_config *msi_config;

	if (pci_priv->device_id == QCA6174_DEVICE_ID)
		return 0;

	if (cnss_pci_is_force_one_msi(pci_priv)) {
		ret = cnss_pci_get_one_msi_assignment(pci_priv);
		cnss_pr_dbg("force one msi\n");
	} else {
		ret = cnss_pci_get_msi_assignment(pci_priv);
	}
	if (ret) {
		cnss_pr_err("Failed to get MSI assignment, err = %d\n", ret);
		goto out;
	}

	msi_config = pci_priv->msi_config;
	if (!msi_config) {
		cnss_pr_err("msi_config is NULL!\n");
		ret = -EINVAL;
		goto out;
	}

	num_vectors = pci_alloc_irq_vectors(pci_dev,
					    msi_config->total_vectors,
					    msi_config->total_vectors,
					    PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if ((num_vectors != msi_config->total_vectors) &&
	    !cnss_pci_fallback_one_msi(pci_priv, &num_vectors)) {
		cnss_pr_err("Failed to get enough MSI vectors (%d), available vectors = %d",
			    msi_config->total_vectors, num_vectors);
		if (num_vectors >= 0)
			ret = -EINVAL;
		goto reset_msi_config;
	}

	/* With VT-d disabled on x86 platform, only one pci irq vector is
	 * allocated. Once suspend the irq may be migrated to CPU0 if it was
	 * affine to other CPU with one new msi vector re-allocated.
	 * The observation cause the issue about no irq handler for vector
	 * once resume.
	 * The fix is to set irq vector affinity to CPU0 before calling
	 * request_irq to avoid the irq migration.
	 */
	if (cnss_pci_is_one_msi(pci_priv)) {
		ret = cnss_pci_irq_set_affinity_hint(pci_priv,
						     0,
						     cpumask_of(0));
		if (ret) {
			cnss_pr_err("Failed to affinize irq vector to CPU0\n");
			goto free_msi_vector;
		}
	}

	if (cnss_pci_config_msi_addr(pci_priv)) {
		ret = -EINVAL;
		goto free_msi_vector;
	}

	if (cnss_pci_config_msi_data(pci_priv)) {
		ret = -EINVAL;
		goto free_msi_vector;
	}

	return 0;

free_msi_vector:
	if (cnss_pci_is_one_msi(pci_priv))
		cnss_pci_irq_set_affinity_hint(pci_priv, 0, NULL);
	pci_free_irq_vectors(pci_priv->pci_dev);
reset_msi_config:
	pci_priv->msi_config = NULL;
out:
	return ret;
}

static void cnss_pci_disable_msi(struct cnss_pci_data *pci_priv)
{
	if (pci_priv->device_id == QCA6174_DEVICE_ID)
		return;

	if (cnss_pci_is_one_msi(pci_priv))
		cnss_pci_irq_set_affinity_hint(pci_priv, 0, NULL);

	pci_free_irq_vectors(pci_priv->pci_dev);
}

int cnss_get_user_msi_assignment(struct device *dev, char *user_name,
				 int *num_vectors, u32 *user_base_data,
				 u32 *base_vector)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));
	struct cnss_msi_config *msi_config;
	int idx;

	if (!pci_priv)
		return -ENODEV;

	msi_config = pci_priv->msi_config;
	if (!msi_config) {
		cnss_pr_err("MSI is not supported.\n");
		return -EINVAL;
	}

	for (idx = 0; idx < msi_config->total_users; idx++) {
		if (strcmp(user_name, msi_config->users[idx].name) == 0) {
			*num_vectors = msi_config->users[idx].num_vectors;
			*user_base_data = msi_config->users[idx].base_vector
				+ pci_priv->msi_ep_base_data;
			*base_vector = msi_config->users[idx].base_vector;
			/*Add only single print for each user*/
			if (print_optimize.msi_log_chk[idx]++)
				goto skip_print;

			cnss_pr_dbg("Assign MSI to user: %s, num_vectors: %d, user_base_data: %u, base_vector: %u\n",
				    user_name, *num_vectors, *user_base_data,
				    *base_vector);
skip_print:
			return 0;
		}
	}

	cnss_pr_err("Failed to find MSI assignment for %s!\n", user_name);

	return -EINVAL;
}
EXPORT_SYMBOL(cnss_get_user_msi_assignment);

int cnss_get_msi_irq(struct device *dev, unsigned int vector)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	int irq_num;

	irq_num = pci_irq_vector(pci_dev, vector);
	cnss_pr_dbg("Get IRQ number %d for vector index %d\n", irq_num, vector);

	return irq_num;
}
EXPORT_SYMBOL(cnss_get_msi_irq);

bool cnss_is_one_msi(struct device *dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(to_pci_dev(dev));

	if (!pci_priv)
		return false;

	return cnss_pci_is_one_msi(pci_priv);
}
EXPORT_SYMBOL(cnss_is_one_msi);

void cnss_get_msi_address(struct device *dev, u32 *msi_addr_low,
			  u32 *msi_addr_high)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct cnss_pci_data *pci_priv;
	u16 control;

	if (!pci_dev)
		return;

	pci_priv = cnss_get_pci_priv(pci_dev);
	if (!pci_priv)
		return;

	if (pci_dev->msix_enabled) {
		*msi_addr_low = pci_priv->msix_addr;
		*msi_addr_high = 0;
		if (!print_optimize.msi_addr_chk++)
			cnss_pr_dbg("Get MSI low addr = 0x%x, high addr = 0x%x\n",
				    *msi_addr_low, *msi_addr_high);
		return;
	}

	pci_read_config_word(pci_dev, pci_dev->msi_cap + PCI_MSI_FLAGS,
			     &control);
	pci_read_config_dword(pci_dev, pci_dev->msi_cap + PCI_MSI_ADDRESS_LO,
			      msi_addr_low);
	/* Return MSI high address only when device supports 64-bit MSI */
	if (control & PCI_MSI_FLAGS_64BIT)
		pci_read_config_dword(pci_dev,
				      pci_dev->msi_cap + PCI_MSI_ADDRESS_HI,
				      msi_addr_high);
	else
		*msi_addr_high = 0;
	 /*Add only single print as the address is constant*/
	 if (!print_optimize.msi_addr_chk++)
		cnss_pr_dbg("Get MSI low addr = 0x%x, high addr = 0x%x\n",
			    *msi_addr_low, *msi_addr_high);
}
EXPORT_SYMBOL(cnss_get_msi_address);

u32 cnss_pci_get_wake_msi(struct cnss_pci_data *pci_priv)
{
	int ret, num_vectors;
	u32 user_base_data, base_vector;

	if (!pci_priv)
		return -ENODEV;

	ret = cnss_get_user_msi_assignment(&pci_priv->pci_dev->dev,
					   WAKE_MSI_NAME, &num_vectors,
					   &user_base_data, &base_vector);
	if (ret) {
		cnss_pr_err("WAKE MSI is not valid\n");
		return 0;
	}

	return user_base_data;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0))
static inline int cnss_pci_set_dma_mask(struct pci_dev *pci_dev, u64 mask)
{
	return dma_set_mask(&pci_dev->dev, mask);
}

static inline int cnss_pci_set_coherent_dma_mask(struct pci_dev *pci_dev,
	u64 mask)
{
	return dma_set_coherent_mask(&pci_dev->dev, mask);
}
#else /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)) */
static inline int cnss_pci_set_dma_mask(struct pci_dev *pci_dev, u64 mask)
{
	return pci_set_dma_mask(pci_dev, mask);
}

static inline int cnss_pci_set_coherent_dma_mask(struct pci_dev *pci_dev,
	u64 mask)
{
	return pci_set_consistent_dma_mask(pci_dev, mask);
}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)) */

static int cnss_pci_enable_bus(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	u16 device_id;

	pci_read_config_word(pci_dev, PCI_DEVICE_ID, &device_id);
	if (device_id != pci_priv->pci_device_id->device)  {
		cnss_pr_err("PCI device ID mismatch, config ID: 0x%x, probe ID: 0x%x\n",
			    device_id, pci_priv->pci_device_id->device);
		ret = -EIO;
		goto out;
	}

	ret = pci_assign_resource(pci_dev, PCI_BAR_NUM);
	if (ret) {
		pr_err("Failed to assign PCI resource, err = %d\n", ret);
		goto out;
	}

	ret = pci_enable_device(pci_dev);
	if (ret) {
		cnss_pr_err("Failed to enable PCI device, err = %d\n", ret);
		goto out;
	}

	ret = pci_request_region(pci_dev, PCI_BAR_NUM, "cnss");
	if (ret) {
		cnss_pr_err("Failed to request PCI region, err = %d\n", ret);
		goto disable_device;
	}

	switch (device_id) {
	case QCA6174_DEVICE_ID:
	case QCN7605_DEVICE_ID:
		pci_priv->dma_bit_mask = PCI_DMA_MASK_32_BIT;
		break;
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		pci_priv->dma_bit_mask = PCI_DMA_MASK_36_BIT;
		break;
	default:
		pci_priv->dma_bit_mask = PCI_DMA_MASK_32_BIT;
		break;
	}

	cnss_pr_dbg("Set PCI DMA MASK (0x%llx)\n", pci_priv->dma_bit_mask);

	ret = cnss_pci_set_dma_mask(pci_dev, pci_priv->dma_bit_mask);
	if (ret) {
		cnss_pr_err("Failed to set PCI DMA mask, err = %d\n", ret);
		goto release_region;
	}

	ret = cnss_pci_set_coherent_dma_mask(pci_dev, pci_priv->dma_bit_mask);
	if (ret) {
		cnss_pr_err("Failed to set PCI coherent DMA mask, err = %d\n",
			    ret);
		goto release_region;
	}

	pci_priv->bar = pci_iomap(pci_dev, PCI_BAR_NUM, 0);
	if (!pci_priv->bar) {
		cnss_pr_err("Failed to do PCI IO map!\n");
		ret = -EIO;
		goto release_region;
	}

	/* Save default config space without BME enabled */
	pci_save_state(pci_dev);
	pci_priv->default_state = pci_store_saved_state(pci_dev);

	pci_set_master(pci_dev);

	return 0;

release_region:
	pci_release_region(pci_dev, PCI_BAR_NUM);
disable_device:
	pci_disable_device(pci_dev);
out:
	return ret;
}

static void cnss_pci_disable_bus(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;

	pci_clear_master(pci_dev);
	pci_load_and_free_saved_state(pci_dev, &pci_priv->saved_state);
	pci_load_and_free_saved_state(pci_dev, &pci_priv->default_state);

	if (pci_priv->bar) {
		pci_iounmap(pci_dev, pci_priv->bar);
		pci_priv->bar = NULL;
	}

	pci_release_region(pci_dev, PCI_BAR_NUM);
	if (pci_is_enabled(pci_dev))
		pci_disable_device(pci_dev);
}

static void cnss_pci_dump_qdss_reg(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	int i, array_size = ARRAY_SIZE(qdss_csr) - 1;
	gfp_t gfp = GFP_KERNEL;
	u32 reg_offset;

	if (in_interrupt() || irqs_disabled())
		gfp = GFP_ATOMIC;

	if (!plat_priv->qdss_reg) {
		plat_priv->qdss_reg = devm_kzalloc(&pci_priv->pci_dev->dev,
						   sizeof(*plat_priv->qdss_reg)
						   * array_size, gfp);
		if (!plat_priv->qdss_reg)
			return;
	}

	cnss_pr_dbg("Start to dump qdss registers\n");

	for (i = 0; qdss_csr[i].name; i++) {
		reg_offset = QDSS_APB_DEC_CSR_BASE + qdss_csr[i].offset;
		if (cnss_pci_reg_read(pci_priv, reg_offset,
				      &plat_priv->qdss_reg[i]))
			return;
		cnss_pr_dbg("%s[0x%x] = 0x%x\n", qdss_csr[i].name, reg_offset,
			    plat_priv->qdss_reg[i]);
	}
}

static void cnss_pci_dump_ce_reg(struct cnss_pci_data *pci_priv,
				 enum cnss_ce_index ce)
{
	int i;
	u32 ce_base = ce * CE_REG_INTERVAL;
	u32 reg_offset, src_ring_base, dst_ring_base, cmn_base, val;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
		src_ring_base = QCA6390_CE_SRC_RING_REG_BASE;
		dst_ring_base = QCA6390_CE_DST_RING_REG_BASE;
		cmn_base = QCA6390_CE_COMMON_REG_BASE;
		break;
	case QCA6490_DEVICE_ID:
		src_ring_base = QCA6490_CE_SRC_RING_REG_BASE;
		dst_ring_base = QCA6490_CE_DST_RING_REG_BASE;
		cmn_base = QCA6490_CE_COMMON_REG_BASE;
		break;
	default:
		return;
	}

	switch (ce) {
	case CNSS_CE_09:
	case CNSS_CE_10:
		for (i = 0; ce_src[i].name; i++) {
			reg_offset = src_ring_base + ce_base + ce_src[i].offset;
			if (cnss_pci_reg_read(pci_priv, reg_offset, &val))
				return;
			cnss_pr_dbg("CE_%02d_%s[0x%x] = 0x%x\n",
				    ce, ce_src[i].name, reg_offset, val);
		}

		for (i = 0; ce_dst[i].name; i++) {
			reg_offset = dst_ring_base + ce_base + ce_dst[i].offset;
			if (cnss_pci_reg_read(pci_priv, reg_offset, &val))
				return;
			cnss_pr_dbg("CE_%02d_%s[0x%x] = 0x%x\n",
				    ce, ce_dst[i].name, reg_offset, val);
		}
		break;
	case CNSS_CE_COMMON:
		for (i = 0; ce_cmn[i].name; i++) {
			reg_offset = cmn_base  + ce_cmn[i].offset;
			if (cnss_pci_reg_read(pci_priv, reg_offset, &val))
				return;
			cnss_pr_dbg("CE_COMMON_%s[0x%x] = 0x%x\n",
				    ce_cmn[i].name, reg_offset, val);
		}
		break;
	default:
		cnss_pr_err("Unsupported CE[%d] registers dump\n", ce);
	}
}

static void cnss_pci_dump_debug_reg(struct cnss_pci_data *pci_priv)
{
	if (cnss_pci_check_link_status(pci_priv))
		return;

	cnss_pr_dbg("Start to dump debug registers\n");

	cnss_mhi_debug_reg_dump(pci_priv);
	cnss_pci_soc_scratch_reg_dump(pci_priv);
	cnss_pci_dump_ce_reg(pci_priv, CNSS_CE_COMMON);
	cnss_pci_dump_ce_reg(pci_priv, CNSS_CE_09);
	cnss_pci_dump_ce_reg(pci_priv, CNSS_CE_10);
}

static int cnss_pci_assert_host_sol(struct cnss_pci_data *pci_priv)
{
	if (cnss_get_host_sol_value(pci_priv->plat_priv))
		return -EINVAL;

	cnss_pr_dbg("Assert host SOL GPIO to retry RDDM, expecting link down\n");
	cnss_set_host_sol_value(pci_priv->plat_priv, 1);

	return 0;
}

static void cnss_pci_mhi_reg_dump(struct cnss_pci_data *pci_priv)
{
	if (!cnss_pci_check_link_status(pci_priv))
		cnss_mhi_debug_reg_dump(pci_priv);

	cnss_pci_soc_scratch_reg_dump(pci_priv);
	cnss_pci_dump_misc_reg(pci_priv);
	cnss_pci_dump_shadow_reg(pci_priv);
}

int cnss_pci_recover_link_down(struct cnss_pci_data *pci_priv)
{
	int ret;
	int retry = 0;
	enum mhi_ee_type mhi_ee;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		break;
	default:
		return -EOPNOTSUPP;
	}

	/* Always wait here to avoid missing WAKE assert for RDDM
	 * before link recovery
	 */
	ret = wait_for_completion_timeout(&pci_priv->wake_event_complete,
					  msecs_to_jiffies(WAKE_EVENT_TIMEOUT));
	if (!ret)
		cnss_pr_err("Timeout waiting for wake event after link down\n");

	ret = cnss_suspend_pci_link(pci_priv);
	if (ret)
		cnss_pr_err("Failed to suspend PCI link, err = %d\n", ret);

	ret = cnss_resume_pci_link(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to resume PCI link, err = %d\n", ret);
		del_timer(&pci_priv->dev_rddm_timer);
		return ret;
	}

retry:
	/*
	 * After PCIe link resumes, 20 to 400 ms delay is observerved
	 * before device moves to RDDM.
	 */
	msleep(RDDM_LINK_RECOVERY_RETRY_DELAY_MS);
	mhi_ee = mhi_get_exec_env(pci_priv->mhi_ctrl);
	if (mhi_ee == MHI_EE_RDDM) {
		del_timer(&pci_priv->dev_rddm_timer);
		cnss_pr_info("Device in RDDM after link recovery, try to collect dump\n");
		cnss_schedule_recovery(&pci_priv->pci_dev->dev,
				       CNSS_REASON_RDDM);
		return 0;
	} else if (retry++ < RDDM_LINK_RECOVERY_RETRY) {
		cnss_pr_dbg("Wait for RDDM after link recovery, retry #%d, Device EE: %d\n",
			    retry, mhi_ee);
		goto retry;
	}

	if (!cnss_pci_assert_host_sol(pci_priv))
		return 0;
	cnss_mhi_debug_reg_dump(pci_priv);
	cnss_pci_soc_scratch_reg_dump(pci_priv);
	cnss_schedule_recovery(&pci_priv->pci_dev->dev,
			       CNSS_REASON_TIMEOUT);
	return 0;
}

int cnss_pci_force_fw_assert_hdlr(struct cnss_pci_data *pci_priv)
{
	int ret;
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return -ENODEV;

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv)
		return -ENODEV;

	if (!test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state) ||
	    test_bit(CNSS_MHI_POWERING_OFF, &pci_priv->mhi_state))
		return -EINVAL;
	/*
	 * Call pm_runtime_get_sync insteat of auto_resume to get
	 * reference and make sure runtime_suspend wont get called.
	 */
	ret = cnss_pci_pm_runtime_get_sync(pci_priv, RTPM_ID_CNSS);
	if (ret < 0)
		goto runtime_pm_put;
	/*
	 * In some scenarios, cnss_pci_pm_runtime_get_sync
	 * might not resume PCI bus. For those cases do auto resume.
	 */
	cnss_auto_resume(&pci_priv->pci_dev->dev);

	if (!pci_priv->is_smmu_fault)
		cnss_pci_mhi_reg_dump(pci_priv);

	/* If link is still down here, directly trigger link down recovery */
	ret = cnss_pci_check_link_status(pci_priv);
	if (ret) {
		cnss_pci_link_down(&pci_priv->pci_dev->dev);
		cnss_pci_pm_runtime_mark_last_busy(pci_priv);
		cnss_pci_pm_runtime_put_autosuspend(pci_priv, RTPM_ID_CNSS);
		return 0;
	}

	ret = cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_TRIGGER_RDDM);
	if (ret) {
		if (pci_priv->is_smmu_fault) {
			cnss_pci_mhi_reg_dump(pci_priv);
			pci_priv->is_smmu_fault = false;
		}
		if (!test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state) ||
		    test_bit(CNSS_MHI_POWERING_OFF, &pci_priv->mhi_state)) {
			cnss_pr_dbg("MHI is not powered on, ignore RDDM failure\n");
			cnss_pci_pm_runtime_mark_last_busy(pci_priv);
			cnss_pci_pm_runtime_put_autosuspend(pci_priv, RTPM_ID_CNSS);
			return 0;
		}
		cnss_fatal_err("Failed to trigger RDDM, err = %d\n", ret);
		if (!cnss_pci_assert_host_sol(pci_priv)) {
			cnss_pci_pm_runtime_mark_last_busy(pci_priv);
			cnss_pci_pm_runtime_put_autosuspend(pci_priv, RTPM_ID_CNSS);
			return 0;
		}
		cnss_pci_dump_debug_reg(pci_priv);
		cnss_schedule_recovery(&pci_priv->pci_dev->dev,
				       CNSS_REASON_DEFAULT);
		ret = 0;
		goto runtime_pm_put;
	}

	if (pci_priv->is_smmu_fault) {
		cnss_pci_mhi_reg_dump(pci_priv);
		pci_priv->is_smmu_fault = false;
	}

	if (!test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state)) {
		mod_timer(&pci_priv->dev_rddm_timer,
			  jiffies + msecs_to_jiffies(DEV_RDDM_TIMEOUT));
	}

runtime_pm_put:
	cnss_pci_pm_runtime_mark_last_busy(pci_priv);
	cnss_pci_pm_runtime_put_autosuspend(pci_priv, RTPM_ID_CNSS);
	return ret;
}

static void cnss_pci_add_dump_seg(struct cnss_pci_data *pci_priv,
				  struct cnss_dump_seg *dump_seg,
				  enum cnss_fw_dump_type type, int seg_no,
				  void *va, dma_addr_t dma, size_t size)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct device *dev = &pci_priv->pci_dev->dev;
	phys_addr_t pa;

	dump_seg->address = dma;
	dump_seg->v_address = va;
	dump_seg->size = size;
	dump_seg->type = type;

	cnss_pr_dbg("Seg: %x, va: %pK, dma: %pa, size: 0x%zx\n",
		    seg_no, va, &dma, size);

	if (cnss_va_to_pa(dev, size, va, dma, &pa, DMA_ATTR_FORCE_CONTIGUOUS))
		return;

	cnss_minidump_add_region(plat_priv, type, seg_no, va, pa, size);
}

static void cnss_pci_remove_dump_seg(struct cnss_pci_data *pci_priv,
				     struct cnss_dump_seg *dump_seg,
				     enum cnss_fw_dump_type type, int seg_no,
				     void *va, dma_addr_t dma, size_t size)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct device *dev = &pci_priv->pci_dev->dev;
	phys_addr_t pa;

	cnss_va_to_pa(dev, size, va, dma, &pa, DMA_ATTR_FORCE_CONTIGUOUS);
	cnss_minidump_remove_region(plat_priv, type, seg_no, va, pa, size);
}

int cnss_pci_call_driver_uevent(struct cnss_pci_data *pci_priv,
				enum cnss_driver_status status, void *data)
{
	struct cnss_uevent_data uevent_data;
	struct cnss_wlan_driver *driver_ops;

	driver_ops = pci_priv->driver_ops;
	if (!driver_ops || !driver_ops->update_event) {
		cnss_pr_dbg("Hang event driver ops is NULL\n");
		return -EINVAL;
	}

	cnss_pr_dbg("Calling driver uevent: %d\n", status);

	uevent_data.status = status;
	uevent_data.data = data;

	return driver_ops->update_event(pci_priv->pci_dev, &uevent_data);
}

static void cnss_pci_send_hang_event(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_fw_mem *fw_mem = plat_priv->fw_mem;
	struct cnss_hang_event hang_event;
	void *hang_data_va = NULL;
	u64 offset = 0;
	u16 length = 0;
	int i = 0;

	if (!fw_mem || !plat_priv->fw_mem_seg_len)
		return;

	memset(&hang_event, 0, sizeof(hang_event));
	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
		offset = HST_HANG_DATA_OFFSET;
		length = HANG_DATA_LENGTH;
		break;
	case QCA6490_DEVICE_ID:
		/* Fallback to hard-coded values if hang event params not
		 * present in QMI. Once all the firmware branches have the
		 * fix to send params over QMI, this can be removed.
		 */
		if (plat_priv->hang_event_data_len) {
			offset = plat_priv->hang_data_addr_offset;
			length = plat_priv->hang_event_data_len;
		} else {
			offset = HSP_HANG_DATA_OFFSET;
			length = HANG_DATA_LENGTH;
		}
		break;
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		offset = plat_priv->hang_data_addr_offset;
		length = plat_priv->hang_event_data_len;
		break;
	default:
		cnss_pr_err("Skip Hang Event Data as unsupported Device ID received: %d\n",
			    pci_priv->device_id);
		return;
	}

	for (i = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (fw_mem[i].type == QMI_WLFW_MEM_TYPE_DDR_V01 &&
		    fw_mem[i].va) {
			/* The offset must be < (fw_mem size- hangdata length) */
			if (!(offset <= fw_mem[i].size - length))
				goto exit;

			hang_data_va = fw_mem[i].va + offset;
			hang_event.hang_event_data = kmemdup(hang_data_va,
							     length,
							     GFP_ATOMIC);
			if (!hang_event.hang_event_data) {
				cnss_pr_dbg("Hang data memory alloc failed\n");
				return;
			}
			hang_event.hang_event_data_len = length;
			break;
		}
	}

	cnss_pci_call_driver_uevent(pci_priv, CNSS_HANG_EVENT, &hang_event);

	kfree(hang_event.hang_event_data);
	hang_event.hang_event_data = NULL;
	return;
exit:
	cnss_pr_dbg("Invalid hang event params, offset:0x%x, length:0x%x\n",
		    plat_priv->hang_data_addr_offset,
		    plat_priv->hang_event_data_len);
}

#ifdef CONFIG_CNSS2_SSR_DRIVER_DUMP
void cnss_pci_collect_host_dump_info(struct cnss_pci_data *pci_priv)
{
	struct cnss_ssr_driver_dump_entry *ssr_entry;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	size_t num_entries_loaded = 0;
	int x;
	int ret = -1;

	ssr_entry = kmalloc(sizeof(*ssr_entry) * CNSS_HOST_DUMP_TYPE_MAX, GFP_KERNEL);
	if (!ssr_entry) {
		cnss_pr_err("ssr_entry malloc failed");
		return;
	}

	if (pci_priv->driver_ops &&
	    pci_priv->driver_ops->collect_driver_dump) {
		ret = pci_priv->driver_ops->collect_driver_dump(pci_priv->pci_dev,
								ssr_entry,
								&num_entries_loaded);
	}

	if (!ret) {
		for (x = 0; x < num_entries_loaded; x++) {
			cnss_pr_info("Idx:%d, ptr: %p, name: %s, size: %d\n",
				     x, ssr_entry[x].buffer_pointer,
				     ssr_entry[x].region_name,
				     ssr_entry[x].buffer_size);
		}

		cnss_do_host_ramdump(plat_priv, ssr_entry, num_entries_loaded);
	} else {
		cnss_pr_info("Host SSR elf dump collection feature disabled\n");
	}

	kfree(ssr_entry);
}
#endif

void cnss_pci_collect_dump_info(struct cnss_pci_data *pci_priv, bool in_panic)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_dump_data *dump_data =
		&plat_priv->ramdump_info_v2.dump_data;
	struct cnss_dump_seg *dump_seg =
		plat_priv->ramdump_info_v2.dump_data_vaddr;
	struct image_info *fw_image, *rddm_image;
	struct cnss_fw_mem *fw_mem = plat_priv->fw_mem;
	int ret, i, j;

	if (test_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state) &&
	    !test_bit(CNSS_IN_PANIC, &plat_priv->driver_state))
		cnss_pci_send_hang_event(pci_priv);

	if (test_bit(CNSS_MHI_RDDM_DONE, &pci_priv->mhi_state)) {
		cnss_pr_dbg("RAM dump is already collected, skip\n");
		return;
	}

	if (!cnss_is_device_powered_on(plat_priv)) {
		cnss_pr_dbg("Device is already powered off, skip\n");
		return;
	}

	if (!in_panic) {
		mutex_lock(&pci_priv->bus_lock);
		ret = cnss_pci_check_link_status(pci_priv);
		if (ret) {
			if (ret != -EACCES) {
				mutex_unlock(&pci_priv->bus_lock);
				return;
			}
			if (cnss_pci_resume_bus(pci_priv)) {
				mutex_unlock(&pci_priv->bus_lock);
				return;
			}
		}
		mutex_unlock(&pci_priv->bus_lock);
	} else {
		if (cnss_pci_check_link_status(pci_priv))
			return;
		/* Inside panic handler, reduce timeout for RDDM to avoid
		 * unnecessary hypervisor watchdog bite.
		 */
		pci_priv->mhi_ctrl->timeout_ms /= 2;
	}

	cnss_mhi_debug_reg_dump(pci_priv);
	cnss_pci_soc_scratch_reg_dump(pci_priv);
	cnss_pci_dump_misc_reg(pci_priv);

	cnss_rddm_trigger_debug(pci_priv);
	ret = mhi_download_rddm_image(pci_priv->mhi_ctrl, in_panic);
	if (ret) {
		cnss_fatal_err("Failed to download RDDM image, err = %d\n",
			       ret);
		if (!cnss_pci_assert_host_sol(pci_priv))
			return;
		cnss_rddm_trigger_check(pci_priv);
		cnss_pci_dump_debug_reg(pci_priv);
		return;
	}
	cnss_rddm_trigger_check(pci_priv);
	fw_image = pci_priv->mhi_ctrl->fbc_image;
	rddm_image = pci_priv->mhi_ctrl->rddm_image;
	dump_data->nentries = 0;

	if (plat_priv->qdss_mem_seg_len)
		cnss_pci_dump_qdss_reg(pci_priv);
	cnss_mhi_dump_sfr(pci_priv);

	if (!dump_seg) {
		cnss_pr_warn("FW image dump collection not setup");
		goto skip_dump;
	}

	cnss_pr_dbg("Collect FW image dump segment, nentries %d\n",
		    fw_image->entries);

	for (i = 0; i < fw_image->entries; i++) {
		cnss_pci_add_dump_seg(pci_priv, dump_seg, CNSS_FW_IMAGE, i,
				      fw_image->mhi_buf[i].buf,
				      fw_image->mhi_buf[i].dma_addr,
				      fw_image->mhi_buf[i].len);
		dump_seg++;
	}

	dump_data->nentries += fw_image->entries;

	cnss_pr_dbg("Collect RDDM image dump segment, nentries %d\n",
		    rddm_image->entries);

	for (i = 0; i < rddm_image->entries; i++) {
		cnss_pci_add_dump_seg(pci_priv, dump_seg, CNSS_FW_RDDM, i,
				      rddm_image->mhi_buf[i].buf,
				      rddm_image->mhi_buf[i].dma_addr,
				      rddm_image->mhi_buf[i].len);
		dump_seg++;
	}

	dump_data->nentries += rddm_image->entries;

	for (i = 0, j = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (fw_mem[i].type == CNSS_MEM_TYPE_DDR) {
			if (fw_mem[i].attrs & DMA_ATTR_FORCE_CONTIGUOUS) {
				cnss_pr_dbg("Collect remote heap dump segment\n");
				cnss_pci_add_dump_seg(pci_priv, dump_seg,
						      CNSS_FW_REMOTE_HEAP, j,
						      fw_mem[i].va,
						      fw_mem[i].pa,
						      fw_mem[i].size);
				dump_seg++;
				dump_data->nentries++;
				j++;
			} else {
				cnss_pr_dbg("Skip remote heap dumps as it is non-contiguous\n");
			}
		}
	}

	if (dump_data->nentries > 0)
		plat_priv->ramdump_info_v2.dump_data_valid = true;

	cnss_pci_set_mhi_state(pci_priv, CNSS_MHI_RDDM_DONE);

skip_dump:
	complete(&plat_priv->rddm_complete);
}

void cnss_pci_clear_dump_info(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct cnss_dump_seg *dump_seg =
		plat_priv->ramdump_info_v2.dump_data_vaddr;
	struct image_info *fw_image, *rddm_image;
	struct cnss_fw_mem *fw_mem = plat_priv->fw_mem;
	int i, j;

	if (!dump_seg)
		return;

	fw_image = pci_priv->mhi_ctrl->fbc_image;
	rddm_image = pci_priv->mhi_ctrl->rddm_image;

	for (i = 0; i < fw_image->entries; i++) {
		cnss_pci_remove_dump_seg(pci_priv, dump_seg, CNSS_FW_IMAGE, i,
					 fw_image->mhi_buf[i].buf,
					 fw_image->mhi_buf[i].dma_addr,
					 fw_image->mhi_buf[i].len);
		dump_seg++;
	}

	for (i = 0; i < rddm_image->entries; i++) {
		cnss_pci_remove_dump_seg(pci_priv, dump_seg, CNSS_FW_RDDM, i,
					 rddm_image->mhi_buf[i].buf,
					 rddm_image->mhi_buf[i].dma_addr,
					 rddm_image->mhi_buf[i].len);
		dump_seg++;
	}

	for (i = 0, j = 0; i < plat_priv->fw_mem_seg_len; i++) {
		if (fw_mem[i].type == CNSS_MEM_TYPE_DDR &&
		    (fw_mem[i].attrs & DMA_ATTR_FORCE_CONTIGUOUS)) {
			cnss_pci_remove_dump_seg(pci_priv, dump_seg,
						 CNSS_FW_REMOTE_HEAP, j,
						 fw_mem[i].va, fw_mem[i].pa,
						 fw_mem[i].size);
			dump_seg++;
			j++;
		}
	}

	plat_priv->ramdump_info_v2.dump_data.nentries = 0;
	plat_priv->ramdump_info_v2.dump_data_valid = false;
}

void cnss_pci_device_crashed(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return;
	}

	plat_priv = pci_priv->plat_priv;
	if (!plat_priv) {
		cnss_pr_err("plat_priv is NULL\n");
		return;
	}

	if (plat_priv->recovery_enabled)
		cnss_pci_collect_host_dump_info(pci_priv);

	/* Call recovery handler in the DRIVER_RECOVERY event context
	 * instead of scheduling work. In that way complete recovery
	 * will be done as part of DRIVER_RECOVERY event and get
	 * serialized with other events.
	 */
	cnss_recovery_handler(plat_priv);
}

static int cnss_mhi_pm_runtime_get(struct mhi_controller *mhi_ctrl)
{
	struct cnss_pci_data *pci_priv = dev_get_drvdata(mhi_ctrl->cntrl_dev);

	return cnss_pci_pm_runtime_get(pci_priv, RTPM_ID_MHI);
}

static void cnss_mhi_pm_runtime_put_noidle(struct mhi_controller *mhi_ctrl)
{
	struct cnss_pci_data *pci_priv = dev_get_drvdata(mhi_ctrl->cntrl_dev);

	cnss_pci_pm_runtime_put_noidle(pci_priv, RTPM_ID_MHI);
}

void cnss_pci_add_fw_prefix_name(struct cnss_pci_data *pci_priv,
				 char *prefix_name, char *name)
{
	struct cnss_plat_data *plat_priv;

	if (!pci_priv)
		return;

	plat_priv = pci_priv->plat_priv;

	if (!plat_priv->use_fw_path_with_prefix) {
		scnprintf(prefix_name, MAX_FIRMWARE_NAME_LEN, "%s", name);
		return;
	}

	switch (pci_priv->device_id) {
	case QCN7605_DEVICE_ID:
		scnprintf(prefix_name, MAX_FIRMWARE_NAME_LEN,
			  QCN7605_PATH_PREFIX "%s", name);
		break;
	case QCA6390_DEVICE_ID:
		scnprintf(prefix_name, MAX_FIRMWARE_NAME_LEN,
			  QCA6390_PATH_PREFIX "%s", name);
		break;
	case QCA6490_DEVICE_ID:
		scnprintf(prefix_name, MAX_FIRMWARE_NAME_LEN,
			  QCA6490_PATH_PREFIX "%s", name);
		break;
	case KIWI_DEVICE_ID:
		scnprintf(prefix_name, MAX_FIRMWARE_NAME_LEN,
			  KIWI_PATH_PREFIX "%s", name);
		break;
	case MANGO_DEVICE_ID:
		scnprintf(prefix_name, MAX_FIRMWARE_NAME_LEN,
			  MANGO_PATH_PREFIX "%s", name);
		break;
	case PEACH_DEVICE_ID:
		scnprintf(prefix_name, MAX_FIRMWARE_NAME_LEN,
			  PEACH_PATH_PREFIX "%s", name);
		break;
	default:
		scnprintf(prefix_name, MAX_FIRMWARE_NAME_LEN, "%s", name);
		break;
	}

	cnss_pr_dbg("FW name added with prefix: %s\n", prefix_name);
}

static int cnss_pci_update_fw_name(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
		if (plat_priv->device_version.major_version < FW_V2_NUMBER) {
			cnss_pr_dbg("Device ID:version (0x%lx:%d) is not supported\n",
				    pci_priv->device_id,
				    plat_priv->device_version.major_version);
			return -EINVAL;
		}
		cnss_pci_add_fw_prefix_name(pci_priv, plat_priv->firmware_name,
					    FW_V2_FILE_NAME);
		snprintf(plat_priv->fw_fallback_name, MAX_FIRMWARE_NAME_LEN,
			 FW_V2_FILE_NAME);
		break;
	case QCA6490_DEVICE_ID:
		switch (plat_priv->device_version.major_version) {
		case FW_V2_NUMBER:
				cnss_pci_add_fw_prefix_name(pci_priv,
							    plat_priv->firmware_name,
							    FW_V2_FILE_NAME);
				snprintf(plat_priv->fw_fallback_name,
					 MAX_FIRMWARE_NAME_LEN,
					 FW_V2_FILE_NAME);
			break;
		default:
			cnss_pci_add_fw_prefix_name(pci_priv,
						    plat_priv->firmware_name,
						    DEFAULT_FW_FILE_NAME);
			snprintf(plat_priv->fw_fallback_name,
				 MAX_FIRMWARE_NAME_LEN,
				 DEFAULT_FW_FILE_NAME);
			break;
		}
		break;
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		switch (plat_priv->device_version.major_version) {
		case FW_V2_NUMBER:
			/*
			 * kiwiv2 using seprate fw binary for MM and FTM mode,
			 * platform driver loads corresponding binary according
			 * to current mode indicated by wlan driver. Otherwise
			 * use default binary.
			 * Mission mode using same binary name as before,
			 * if seprate binary is not there, fall back to default.
			 */
			if (plat_priv->driver_mode == CNSS_MISSION) {
				cnss_pci_add_fw_prefix_name(pci_priv,
							    plat_priv->firmware_name,
							    FW_V2_FILE_NAME);
				cnss_pci_add_fw_prefix_name(pci_priv,
							    plat_priv->fw_fallback_name,
							    FW_V2_FILE_NAME);
			} else if (plat_priv->driver_mode == CNSS_FTM) {
				cnss_pci_add_fw_prefix_name(pci_priv,
							    plat_priv->firmware_name,
							    FW_V2_FTM_FILE_NAME);
				cnss_pci_add_fw_prefix_name(pci_priv,
							    plat_priv->fw_fallback_name,
							    FW_V2_FILE_NAME);
			} else {
				/*
				 * Since during cold boot calibration phase,
				 * wlan driver has not registered, so default
				 * fw binary will be used.
				 */
				cnss_pci_add_fw_prefix_name(pci_priv,
							    plat_priv->firmware_name,
							    FW_V2_FILE_NAME);
				snprintf(plat_priv->fw_fallback_name,
					 MAX_FIRMWARE_NAME_LEN,
					 FW_V2_FILE_NAME);
			}
			break;
		default:
			cnss_pci_add_fw_prefix_name(pci_priv,
						    plat_priv->firmware_name,
						    DEFAULT_FW_FILE_NAME);
			snprintf(plat_priv->fw_fallback_name,
				 MAX_FIRMWARE_NAME_LEN,
				 DEFAULT_FW_FILE_NAME);
			break;
		}
		break;
	default:
		cnss_pci_add_fw_prefix_name(pci_priv, plat_priv->firmware_name,
					    DEFAULT_FW_FILE_NAME);
		snprintf(plat_priv->fw_fallback_name, MAX_FIRMWARE_NAME_LEN,
			 DEFAULT_FW_FILE_NAME);
		break;
	}

	cnss_pr_dbg("FW name is %s, FW fallback name is %s\n",
		    plat_priv->firmware_name, plat_priv->fw_fallback_name);

	return 0;
}

static char *cnss_mhi_notify_status_to_str(enum mhi_callback status)
{
	switch (status) {
	case MHI_CB_IDLE:
		return "IDLE";
	case MHI_CB_EE_RDDM:
		return "RDDM";
	case MHI_CB_SYS_ERROR:
		return "SYS_ERROR";
	case MHI_CB_FATAL_ERROR:
		return "FATAL_ERROR";
	case MHI_CB_EE_MISSION_MODE:
		return "MISSION_MODE";
#if IS_ENABLED(CONFIG_MHI_BUS_MISC) && \
(LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0))
	case MHI_CB_FALLBACK_IMG:
		return "FW_FALLBACK";
#endif
	default:
		return "UNKNOWN";
	}
};

static void cnss_dev_rddm_timeout_hdlr(struct timer_list *t)
{
	struct cnss_pci_data *pci_priv =
		from_timer(pci_priv, t, dev_rddm_timer);
	enum mhi_ee_type mhi_ee;

	if (!pci_priv)
		return;

	cnss_fatal_err("Timeout waiting for RDDM notification\n");

	if (!cnss_pci_assert_host_sol(pci_priv))
		return;

	mhi_ee = mhi_get_exec_env(pci_priv->mhi_ctrl);
	if (mhi_ee == MHI_EE_PBL)
		cnss_pr_err("Device MHI EE is PBL, unable to collect dump\n");

	if (mhi_ee == MHI_EE_RDDM) {
		cnss_pr_info("Device MHI EE is RDDM, try to collect dump\n");
		cnss_schedule_recovery(&pci_priv->pci_dev->dev,
				       CNSS_REASON_RDDM);
	} else {
		cnss_mhi_debug_reg_dump(pci_priv);
		cnss_pci_soc_scratch_reg_dump(pci_priv);
		cnss_schedule_recovery(&pci_priv->pci_dev->dev,
				       CNSS_REASON_TIMEOUT);
	}
}

static void cnss_boot_debug_timeout_hdlr(struct timer_list *t)
{
	struct cnss_pci_data *pci_priv =
		from_timer(pci_priv, t, boot_debug_timer);

	if (!pci_priv)
		return;

	if (cnss_pci_check_link_status(pci_priv))
		return;

	if (cnss_pci_is_device_down(&pci_priv->pci_dev->dev))
		return;

	if (test_bit(CNSS_MHI_POWER_ON, &pci_priv->mhi_state))
		return;

	if (cnss_mhi_scan_rddm_cookie(pci_priv, DEVICE_RDDM_COOKIE))
		return;

	cnss_pr_dbg("Dump MHI/PBL/SBL debug data every %ds during MHI power on\n",
		    BOOT_DEBUG_TIMEOUT_MS / 1000);
	cnss_mhi_debug_reg_dump(pci_priv);
	cnss_pci_soc_scratch_reg_dump(pci_priv);
	cnss_pci_dump_bl_sram_mem(pci_priv);

	mod_timer(&pci_priv->boot_debug_timer,
		  jiffies + msecs_to_jiffies(BOOT_DEBUG_TIMEOUT_MS));
}

static int cnss_pci_handle_mhi_sys_err(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	cnss_ignore_qmi_failure(true);
	set_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state);
	del_timer(&plat_priv->fw_boot_timer);
	reinit_completion(&pci_priv->wake_event_complete);
	mod_timer(&pci_priv->dev_rddm_timer,
		  jiffies + msecs_to_jiffies(DEV_RDDM_TIMEOUT));
	cnss_pci_update_status(pci_priv, CNSS_FW_DOWN);

	return 0;
}

int cnss_pci_handle_dev_sol_irq(struct cnss_pci_data *pci_priv)
{
	return cnss_pci_handle_mhi_sys_err(pci_priv);
}

static void cnss_mhi_notify_status(struct mhi_controller *mhi_ctrl,
				   enum mhi_callback reason)
{
	struct cnss_pci_data *pci_priv = dev_get_drvdata(mhi_ctrl->cntrl_dev);
	struct cnss_plat_data *plat_priv;
	enum cnss_recovery_reason cnss_reason;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL");
		return;
	}

	plat_priv = pci_priv->plat_priv;

	if (reason != MHI_CB_IDLE)
		cnss_pr_dbg("MHI status cb is called with reason %s(%d)\n",
			    cnss_mhi_notify_status_to_str(reason), reason);

	switch (reason) {
	case MHI_CB_IDLE:
	case MHI_CB_EE_MISSION_MODE:
		return;
	case MHI_CB_FATAL_ERROR:
		cnss_ignore_qmi_failure(true);
		set_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state);
		del_timer(&plat_priv->fw_boot_timer);
		cnss_pci_update_status(pci_priv, CNSS_FW_DOWN);
		cnss_reason = CNSS_REASON_DEFAULT;
		break;
	case MHI_CB_SYS_ERROR:
		cnss_pci_handle_mhi_sys_err(pci_priv);
		return;
	case MHI_CB_EE_RDDM:
		cnss_ignore_qmi_failure(true);
		set_bit(CNSS_DEV_ERR_NOTIFY, &plat_priv->driver_state);
		del_timer(&plat_priv->fw_boot_timer);
		del_timer(&pci_priv->dev_rddm_timer);
		cnss_pci_update_status(pci_priv, CNSS_FW_DOWN);
		cnss_reason = CNSS_REASON_RDDM;
		break;
#if IS_ENABLED(CONFIG_MHI_BUS_MISC) && \
(LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0))
	case MHI_CB_FALLBACK_IMG:
		/* for kiwi_v2 binary fallback is used, skip path fallback here */
		if (!(pci_priv->device_id == KIWI_DEVICE_ID &&
		      plat_priv->device_version.major_version == FW_V2_NUMBER)) {
			plat_priv->use_fw_path_with_prefix = false;
			cnss_pci_update_fw_name(pci_priv);
		}
		return;
#endif

	default:
		cnss_pr_err("Unsupported MHI status cb reason: %d\n", reason);
		return;
	}

	cnss_schedule_recovery(&pci_priv->pci_dev->dev, cnss_reason);
}

static int cnss_pci_get_mhi_msi(struct cnss_pci_data *pci_priv)
{
	int ret, num_vectors, i;
	u32 user_base_data, base_vector;
	int *irq;
	unsigned int msi_data;
	bool is_one_msi = false;

	ret = cnss_get_user_msi_assignment(&pci_priv->pci_dev->dev,
					   MHI_MSI_NAME, &num_vectors,
					   &user_base_data, &base_vector);
	if (ret)
		return ret;

	if (cnss_pci_is_one_msi(pci_priv)) {
		is_one_msi = true;
		num_vectors = cnss_pci_get_one_msi_mhi_irq_array_size(pci_priv);
	}
	cnss_pr_dbg("Number of assigned MSI for MHI is %d, base vector is %d\n",
		    num_vectors, base_vector);

	irq = kcalloc(num_vectors, sizeof(int), GFP_KERNEL);
	if (!irq)
		return -ENOMEM;

	for (i = 0; i < num_vectors; i++) {
		msi_data = base_vector;
		if (!is_one_msi)
			msi_data += i;
		irq[i] = cnss_get_msi_irq(&pci_priv->pci_dev->dev, msi_data);
	}

	pci_priv->mhi_ctrl->irq = irq;
	pci_priv->mhi_ctrl->nr_irqs = num_vectors;

	return 0;
}

static int cnss_mhi_bw_scale(struct mhi_controller *mhi_ctrl,
			     struct mhi_link_info *link_info)
{
	struct cnss_pci_data *pci_priv = dev_get_drvdata(mhi_ctrl->cntrl_dev);
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	int ret = 0;

	cnss_pr_dbg("Setting link speed:0x%x, width:0x%x\n",
		    link_info->target_link_speed,
		    link_info->target_link_width);

	/* It has to set target link speed here before setting link bandwidth
	 * when device requests link speed change. This can avoid setting link
	 * bandwidth getting rejected if requested link speed is higher than
	 * current one.
	 */
	ret = cnss_pci_set_max_link_speed(pci_priv, plat_priv->rc_num,
					  link_info->target_link_speed);
	if (ret)
		cnss_pr_err("Failed to set target link speed to 0x%x, err = %d\n",
			    link_info->target_link_speed, ret);

	ret = cnss_pci_set_link_bandwidth(pci_priv,
					  link_info->target_link_speed,
					  link_info->target_link_width);

	if (ret) {
		cnss_pr_err("Failed to set link bandwidth, err = %d\n", ret);
		return ret;
	}

	pci_priv->def_link_speed = link_info->target_link_speed;
	pci_priv->def_link_width = link_info->target_link_width;

	return 0;
}

static int cnss_mhi_read_reg(struct mhi_controller *mhi_ctrl,
			     void __iomem *addr, u32 *out)
{
	struct cnss_pci_data *pci_priv = dev_get_drvdata(mhi_ctrl->cntrl_dev);

	u32 tmp = readl_relaxed(addr);

	/* Unexpected value, query the link status */
	if (PCI_INVALID_READ(tmp) &&
	    cnss_pci_check_link_status(pci_priv))
		return -EIO;

	*out = tmp;

	return 0;
}

static void cnss_mhi_write_reg(struct mhi_controller *mhi_ctrl,
			       void __iomem *addr, u32 val)
{
	writel_relaxed(val, addr);
}

static int cnss_get_mhi_soc_info(struct cnss_plat_data *plat_priv,
				 struct mhi_controller *mhi_ctrl)
{
	int ret = 0;

	ret = mhi_get_soc_info(mhi_ctrl);
	if (ret)
		goto exit;

	plat_priv->device_version.family_number = mhi_ctrl->family_number;
	plat_priv->device_version.device_number = mhi_ctrl->device_number;
	plat_priv->device_version.major_version = mhi_ctrl->major_version;
	plat_priv->device_version.minor_version = mhi_ctrl->minor_version;

	cnss_pr_dbg("Get device version info, family number: 0x%x, device number: 0x%x, major version: 0x%x, minor version: 0x%x\n",
		    plat_priv->device_version.family_number,
		    plat_priv->device_version.device_number,
		    plat_priv->device_version.major_version,
		    plat_priv->device_version.minor_version);

	/* Only keep lower 4 bits as real device major version */
	plat_priv->device_version.major_version &= DEVICE_MAJOR_VERSION_MASK;

exit:
	return ret;
}

static bool cnss_is_tme_supported(struct cnss_pci_data *pci_priv)
{
	if (!pci_priv) {
		cnss_pr_dbg("pci_priv is NULL");
		return false;
	}

	switch (pci_priv->device_id) {
	case PEACH_DEVICE_ID:
		return true;
	default:
		return false;
	}
}

static int cnss_pci_register_mhi(struct cnss_pci_data *pci_priv)
{
	int ret = 0;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct mhi_controller *mhi_ctrl;
	phys_addr_t bar_start;
	const struct mhi_controller_config *cnss_mhi_config =
						&cnss_mhi_config_default;

	ret = cnss_qmi_init(plat_priv);
	if (ret)
		return -EINVAL;

	if (pci_priv->device_id == QCA6174_DEVICE_ID)
		return 0;

	mhi_ctrl = mhi_alloc_controller();
	if (!mhi_ctrl) {
		cnss_pr_err("Invalid MHI controller context\n");
		return -EINVAL;
	}

	pci_priv->mhi_ctrl = mhi_ctrl;
	mhi_ctrl->cntrl_dev = &pci_dev->dev;

	mhi_ctrl->fw_image = plat_priv->firmware_name;
#if IS_ENABLED(CONFIG_MHI_BUS_MISC) && \
(LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0))
	mhi_ctrl->fallback_fw_image = plat_priv->fw_fallback_name;
#endif

	mhi_ctrl->regs = pci_priv->bar;
	mhi_ctrl->reg_len = pci_resource_len(pci_priv->pci_dev, PCI_BAR_NUM);
	bar_start = pci_resource_start(pci_priv->pci_dev, PCI_BAR_NUM);
	cnss_pr_dbg("BAR starts at %pa, length is %x\n",
		    &bar_start, mhi_ctrl->reg_len);

	ret = cnss_pci_get_mhi_msi(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to get MSI for MHI, err = %d\n", ret);
		goto free_mhi_ctrl;
	}

	if (cnss_pci_is_one_msi(pci_priv))
		mhi_ctrl->irq_flags = IRQF_SHARED | IRQF_NOBALANCING;

	if (pci_priv->smmu_s1_enable) {
		mhi_ctrl->iova_start = pci_priv->smmu_iova_start;
		mhi_ctrl->iova_stop = pci_priv->smmu_iova_start +
					pci_priv->smmu_iova_len;
	} else {
		mhi_ctrl->iova_start = 0;
		mhi_ctrl->iova_stop = pci_priv->dma_bit_mask;
	}

	mhi_ctrl->status_cb = cnss_mhi_notify_status;
	mhi_ctrl->runtime_get = cnss_mhi_pm_runtime_get;
	mhi_ctrl->runtime_put = cnss_mhi_pm_runtime_put_noidle;
	mhi_ctrl->read_reg = cnss_mhi_read_reg;
	mhi_ctrl->write_reg = cnss_mhi_write_reg;

	mhi_ctrl->rddm_size = pci_priv->plat_priv->ramdump_info_v2.ramdump_size;
	if (!mhi_ctrl->rddm_size)
		mhi_ctrl->rddm_size = RAMDUMP_SIZE_DEFAULT;

	if (plat_priv->device_id == QCN7605_DEVICE_ID)
		mhi_ctrl->sbl_size = SZ_256K;
	else
		mhi_ctrl->sbl_size = SZ_512K;

	mhi_ctrl->seg_len = SZ_512K;
	mhi_ctrl->fbc_download = true;

	ret = cnss_get_mhi_soc_info(plat_priv, mhi_ctrl);
	if (ret)
		goto free_mhi_irq;

	/* Satellite config only supported on KIWI V2 and later chipset */
	if (plat_priv->device_id <= QCA6490_DEVICE_ID ||
			(plat_priv->device_id == KIWI_DEVICE_ID &&
			 plat_priv->device_version.major_version == 1)) {
		if (plat_priv->device_id == QCN7605_DEVICE_ID)
			cnss_mhi_config = &cnss_mhi_config_genoa;
		else
			cnss_mhi_config = &cnss_mhi_config_no_satellite;
	}

	mhi_ctrl->tme_supported_image = cnss_is_tme_supported(pci_priv);

	ret = mhi_register_controller(mhi_ctrl, cnss_mhi_config);
	if (ret) {
		cnss_pr_err("Failed to register to MHI bus, err = %d\n", ret);
		goto free_mhi_irq;
	}

	/* MHI satellite driver only needs to connect when DRV is supported */
	if (cnss_pci_get_drv_supported(pci_priv))
		cnss_mhi_controller_set_base(pci_priv, bar_start);

	cnss_get_bwscal_info(plat_priv);
	cnss_pr_dbg("no_bwscale: %d\n", plat_priv->no_bwscale);

	/* BW scale CB needs to be set after registering MHI per requirement */
	if (!plat_priv->no_bwscale)
		cnss_mhi_controller_set_bw_scale_cb(pci_priv,
						    cnss_mhi_bw_scale);

	ret = cnss_pci_update_fw_name(pci_priv);
	if (ret)
		goto unreg_mhi;

	return 0;

unreg_mhi:
	mhi_unregister_controller(mhi_ctrl);
free_mhi_irq:
	kfree(mhi_ctrl->irq);
free_mhi_ctrl:
	mhi_free_controller(mhi_ctrl);

	return ret;
}

static void cnss_pci_unregister_mhi(struct cnss_pci_data *pci_priv)
{
	struct mhi_controller *mhi_ctrl = pci_priv->mhi_ctrl;

	if (pci_priv->device_id == QCA6174_DEVICE_ID)
		return;

	mhi_unregister_controller(mhi_ctrl);
	kfree(mhi_ctrl->irq);
	mhi_ctrl->irq = NULL;
	mhi_free_controller(mhi_ctrl);
	pci_priv->mhi_ctrl = NULL;
}

static void cnss_pci_config_regs(struct cnss_pci_data *pci_priv)
{
	switch (pci_priv->device_id) {
	case QCA6390_DEVICE_ID:
		pci_priv->misc_reg_dev_mask = REG_MASK_QCA6390;
		pci_priv->wcss_reg = wcss_reg_access_seq;
		pci_priv->pcie_reg = pcie_reg_access_seq;
		pci_priv->wlaon_reg = wlaon_reg_access_seq;
		pci_priv->syspm_reg = syspm_reg_access_seq;

		/* Configure WDOG register with specific value so that we can
		 * know if HW is in the process of WDOG reset recovery or not
		 * when reading the registers.
		 */
		cnss_pci_reg_write
		(pci_priv,
		QCA6390_PCIE_SOC_WDOG_DISC_BAD_DATA_LOW_CFG_SOC_PCIE_REG,
		QCA6390_PCIE_SOC_WDOG_DISC_BAD_DATA_LOW_CFG_SOC_PCIE_REG_VAL);
		break;
	case QCA6490_DEVICE_ID:
		pci_priv->misc_reg_dev_mask = REG_MASK_QCA6490;
		pci_priv->wlaon_reg = wlaon_reg_access_seq;
		break;
	default:
		return;
	}
}

#if !IS_ENABLED(CONFIG_ARCH_QCOM)
static int cnss_pci_of_reserved_mem_device_init(struct cnss_pci_data *pci_priv)
{
	return 0;
}

static irqreturn_t cnss_pci_wake_handler(int irq, void *data)
{
	struct cnss_pci_data *pci_priv = data;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	enum rpm_status status;
	struct device *dev;

	pci_priv->wake_counter++;
	cnss_pr_dbg("WLAN PCI wake IRQ (%u) is asserted #%u\n",
		    pci_priv->wake_irq, pci_priv->wake_counter);

	/* Make sure abort current suspend */
	cnss_pm_stay_awake(plat_priv);
	cnss_pm_relax(plat_priv);
	/* Above two pm* API calls will abort system suspend only when
	 * plat_dev->dev->ws is initiated by device_init_wakeup() API, and
	 * calling pm_system_wakeup() is just to guarantee system suspend
	 * can be aborted if it is not initiated in any case.
	 */
	pm_system_wakeup();

	dev = &pci_priv->pci_dev->dev;
	status = dev->power.runtime_status;

	if ((cnss_pci_get_monitor_wake_intr(pci_priv) &&
	     cnss_pci_get_auto_suspended(pci_priv)) ||
	    (status == RPM_SUSPENDING || status == RPM_SUSPENDED)) {
		cnss_pci_set_monitor_wake_intr(pci_priv, false);
		cnss_pci_pm_request_resume(pci_priv);
	}

	return IRQ_HANDLED;
}

/**
 * cnss_pci_wake_gpio_init() - Setup PCI wake GPIO for WLAN
 * @pci_priv: driver PCI bus context pointer
 *
 * This function initializes WLAN PCI wake GPIO and corresponding
 * interrupt. It should be used in non-MSM platforms whose PCIe
 * root complex driver doesn't handle the GPIO.
 *
 * Return: 0 for success or skip, negative value for error
 */
static int cnss_pci_wake_gpio_init(struct cnss_pci_data *pci_priv)
{
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct device *dev = &plat_priv->plat_dev->dev;
	int ret = 0;

	pci_priv->wake_gpio = of_get_named_gpio(dev->of_node,
						"wlan-pci-wake-gpio", 0);
	if (pci_priv->wake_gpio < 0)
		goto out;

	cnss_pr_dbg("Get PCI wake GPIO (%d) from device node\n",
		    pci_priv->wake_gpio);

	ret = gpio_request(pci_priv->wake_gpio, "wlan_pci_wake_gpio");
	if (ret) {
		cnss_pr_err("Failed to request PCI wake GPIO, err = %d\n",
			    ret);
		goto out;
	}

	gpio_direction_input(pci_priv->wake_gpio);
	pci_priv->wake_irq = gpio_to_irq(pci_priv->wake_gpio);

	ret = request_irq(pci_priv->wake_irq, cnss_pci_wake_handler,
			  IRQF_TRIGGER_FALLING, "wlan_pci_wake_irq", pci_priv);
	if (ret) {
		cnss_pr_err("Failed to request PCI wake IRQ, err = %d\n", ret);
		goto free_gpio;
	}

	ret = enable_irq_wake(pci_priv->wake_irq);
	if (ret) {
		cnss_pr_err("Failed to enable PCI wake IRQ, err = %d\n", ret);
		goto free_irq;
	}

	return 0;

free_irq:
	free_irq(pci_priv->wake_irq, pci_priv);
free_gpio:
	gpio_free(pci_priv->wake_gpio);
out:
	return ret;
}

static void cnss_pci_wake_gpio_deinit(struct cnss_pci_data *pci_priv)
{
	if (pci_priv->wake_gpio < 0)
		return;

	disable_irq_wake(pci_priv->wake_irq);
	free_irq(pci_priv->wake_irq, pci_priv);
	gpio_free(pci_priv->wake_gpio);
}
#endif

#ifdef CONFIG_CNSS_SUPPORT_DUAL_DEV
static int cnss_try_suspend(struct cnss_plat_data *plat_priv)
{
	int ret = 0;

	/* in the dual wlan card case, if call pci_register_driver after
	 * finishing the first pcie device enumeration, it will cause
	 * the cnss_pci_probe called in advance with the second wlan card,
	 * and the sequence like this:
	 * enter msm_pcie_enumerate -> pci_bus_add_devices -> cnss_pci_probe
	 * -> exit msm_pcie_enumerate.
	 * But the correct sequence we expected is like this:
	 * enter msm_pcie_enumerate -> pci_bus_add_devices  ->
	 * exit msm_pcie_enumerate -> cnss_pci_probe.
	 * And this unexpected sequence will make the second wlan card do
	 * pcie link suspend while the pcie enumeration not finished.
	 * So need to add below logical to avoid doing pcie link suspend
	 * if the enumeration has not finish.
	 */
	plat_priv->enumerate_done = true;

	/* Now enumeration is finished, try to suspend PCIe link */
	if (plat_priv->bus_priv) {
		struct cnss_pci_data *pci_priv = plat_priv->bus_priv;
		struct pci_dev *pci_dev = pci_priv->pci_dev;

		switch (pci_dev->device) {
		case QCA6390_DEVICE_ID:
			cnss_pci_set_wlaon_pwr_ctrl(pci_priv,
						    false,
						    true,
						    false);

			cnss_pci_suspend_pwroff(pci_dev);
			break;
		default:
			cnss_pr_err("Unknown PCI device found: 0x%x\n",
				    pci_dev->device);
			ret = -ENODEV;
		}
	}

	return ret;
}
#else
static int cnss_try_suspend(struct cnss_plat_data *plat_priv)
{
	return 0;
}
#endif

/* Setting to use this cnss_pm_domain ops will let PM framework override the
 * ops from dev->bus->pm which is pci_dev_pm_ops from pci-driver.c. This ops
 * has to take care everything device driver needed which is currently done
 * from pci_dev_pm_ops.
 */
static struct dev_pm_domain cnss_pm_domain = {
	.ops = {
		SET_SYSTEM_SLEEP_PM_OPS(cnss_pci_suspend, cnss_pci_resume)
		SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(cnss_pci_suspend_noirq,
					      cnss_pci_resume_noirq)
		SET_RUNTIME_PM_OPS(cnss_pci_runtime_suspend,
				   cnss_pci_runtime_resume,
				   cnss_pci_runtime_idle)
	}
};

static int cnss_pci_get_dev_cfg_node(struct cnss_plat_data *plat_priv)
{
	struct device_node *child;
	u32 id, i;
	int id_n, ret;

	if (plat_priv->dt_type != CNSS_DTT_MULTIEXCHG)
		return 0;

	if (!plat_priv->device_id) {
		cnss_pr_err("Invalid device id\n");
		return -EINVAL;
	}

	for_each_available_child_of_node(plat_priv->plat_dev->dev.of_node,
					 child) {
		if (strcmp(child->name, "chip_cfg"))
			continue;

		id_n = of_property_count_u32_elems(child, "supported-ids");
		if (id_n <= 0) {
			cnss_pr_err("Device id is NOT set\n");
			return -EINVAL;
		}

		for (i = 0; i < id_n; i++) {
			ret = of_property_read_u32_index(child,
							 "supported-ids",
							 i, &id);
			if (ret) {
				cnss_pr_err("Failed to read supported ids\n");
				return -EINVAL;
			}

			if (id == plat_priv->device_id) {
				plat_priv->dev_node = child;
				cnss_pr_dbg("got node[%s@%d] for device[0x%x]\n",
					    child->name, i, id);
				return 0;
			}
		}
	}

	return -EINVAL;
}

#ifdef CONFIG_CNSS2_CONDITIONAL_POWEROFF
static bool cnss_should_suspend_pwroff(struct pci_dev *pci_dev)
{
	bool suspend_pwroff;

	switch (pci_dev->device) {
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
		suspend_pwroff = false;
		break;
	default:
		suspend_pwroff = true;
	}

	return suspend_pwroff;
}
#else
static bool cnss_should_suspend_pwroff(struct pci_dev *pci_dev)
{
	return true;
}
#endif

static int cnss_pci_set_gen2_speed(struct cnss_plat_data *plat_priv, u32 rc_num)
{
	int ret;

	/* Always set initial target PCIe link speed to Gen2 for QCA6490 device
	 * since there may be link issues if it boots up with Gen3 link speed.
	 * Device is able to change it later at any time. It will be rejected
	 * if requested speed is higher than the one specified in PCIe DT.
	 */
	ret = cnss_pci_set_max_link_speed(plat_priv->bus_priv, rc_num,
					  PCI_EXP_LNKSTA_CLS_5_0GB);
	if (ret && ret != -EPROBE_DEFER)
		cnss_pr_err("Failed to set max PCIe RC%x link speed to Gen2, err = %d\n",
				rc_num, ret);

	return ret;
}

#ifdef CONFIG_CNSS2_ENUM_WITH_LOW_SPEED
static void
cnss_pci_downgrade_rc_speed(struct cnss_plat_data *plat_priv, u32 rc_num)
{
	int ret;

	ret = cnss_pci_set_max_link_speed(plat_priv->bus_priv, rc_num,
					  PCI_EXP_LNKSTA_CLS_2_5GB);
	if (ret)
		cnss_pr_err("Failed to set max PCIe RC%x link speed to Gen1, err = %d\n",
			     rc_num, ret);
}

static void
cnss_pci_restore_rc_speed(struct cnss_pci_data *pci_priv)
{
	int ret;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;

	/* if not Genoa, do not restore rc speed */
	if (pci_priv->device_id == QCA6490_DEVICE_ID) {
		cnss_pci_set_gen2_speed(plat_priv, plat_priv->rc_num);
	} else if (pci_priv->device_id != QCN7605_DEVICE_ID) {
		/* The request 0 will reset maximum GEN speed to default */
		ret = cnss_pci_set_max_link_speed(pci_priv, plat_priv->rc_num, 0);
		if (ret)
			cnss_pr_err("Failed to reset max PCIe RC%x link speed to default, err = %d\n",
				     plat_priv->rc_num, ret);
	}
}

static void
cnss_pci_link_retrain_trigger(struct cnss_pci_data *pci_priv)
{
	int ret;

	/* suspend/resume will trigger retain to re-establish link speed */
	ret = cnss_suspend_pci_link(pci_priv);
	if (ret)
		cnss_pr_err("Failed to suspend PCI link, err = %d\n", ret);

	ret = cnss_resume_pci_link(pci_priv);
	if (ret)
		cnss_pr_err("Failed to resume PCI link, err = %d\n", ret);

	cnss_pci_get_link_status(pci_priv);
}
#else
static void
cnss_pci_downgrade_rc_speed(struct cnss_plat_data *plat_priv, u32 rc_num)
{
}

static void
cnss_pci_restore_rc_speed(struct cnss_pci_data *pci_priv)
{
}

static void
cnss_pci_link_retrain_trigger(struct cnss_pci_data *pci_priv)
{
}
#endif

static void cnss_pci_suspend_pwroff(struct pci_dev *pci_dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	int rc_num = pci_dev->bus->domain_nr;
	struct cnss_plat_data *plat_priv;
	int ret = 0;
	bool suspend_pwroff = cnss_should_suspend_pwroff(pci_dev);

	plat_priv = cnss_get_plat_priv_by_rc_num(rc_num);

	if (suspend_pwroff) {
		ret = cnss_suspend_pci_link(pci_priv);
		if (ret)
			cnss_pr_err("Failed to suspend PCI link, err = %d\n",
				    ret);
		cnss_power_off_device(plat_priv);
	} else {
		cnss_pr_dbg("bus suspend and dev power off disabled for device [0x%x]\n",
			    pci_dev->device);
		cnss_pci_link_retrain_trigger(pci_priv);
	}
}

static int cnss_pci_probe(struct pci_dev *pci_dev,
			  const struct pci_device_id *id)
{
	int ret = 0;
	struct cnss_pci_data *pci_priv;
	struct device *dev = &pci_dev->dev;
	int rc_num = pci_dev->bus->domain_nr;
	struct cnss_plat_data *plat_priv = cnss_get_plat_priv_by_rc_num(rc_num);

	cnss_pr_dbg("PCI is probing, vendor ID: 0x%x, device ID: 0x%x rc_num %d\n",
		    id->vendor, pci_dev->device, rc_num);
	if (!plat_priv) {
		cnss_pr_err("Find match plat_priv with rc number failure\n");
		ret = -ENODEV;
		goto out;
	}

	pci_priv = devm_kzalloc(dev, sizeof(*pci_priv), GFP_KERNEL);
	if (!pci_priv) {
		ret = -ENOMEM;
		goto out;
	}

	pci_priv->pci_link_state = PCI_LINK_UP;
	pci_priv->plat_priv = plat_priv;
	pci_priv->pci_dev = pci_dev;
	pci_priv->pci_device_id = id;
	pci_priv->device_id = pci_dev->device;
	cnss_set_pci_priv(pci_dev, pci_priv);
	plat_priv->device_id = pci_dev->device;
	plat_priv->bus_priv = pci_priv;
	mutex_init(&pci_priv->bus_lock);
	if (plat_priv->use_pm_domain)
		dev->pm_domain = &cnss_pm_domain;

	cnss_pci_restore_rc_speed(pci_priv);

	ret = cnss_pci_get_dev_cfg_node(plat_priv);
	if (ret) {
		cnss_pr_err("Failed to get device cfg node, err = %d\n", ret);
		goto reset_ctx;
	}

	cnss_get_sleep_clk_supported(plat_priv);

	ret = cnss_dev_specific_power_on(plat_priv);
	if (ret < 0)
		goto reset_ctx;

	cnss_pci_of_reserved_mem_device_init(pci_priv);

	ret = cnss_register_subsys(plat_priv);
	if (ret)
		goto reset_ctx;

	ret = cnss_register_ramdump(plat_priv);
	if (ret)
		goto unregister_subsys;

	ret = cnss_pci_init_smmu(pci_priv);
	if (ret)
		goto unregister_ramdump;

	/* update drv support flag */
	cnss_pci_update_drv_supported(pci_priv);

	cnss_update_supported_link_info(pci_priv);

	ret = cnss_reg_pci_event(pci_priv);
	if (ret) {
		cnss_pr_err("Failed to register PCI event, err = %d\n", ret);
		goto deinit_smmu;
	}

	ret = cnss_pci_enable_bus(pci_priv);
	if (ret)
		goto dereg_pci_event;

	ret = cnss_pci_enable_msi(pci_priv);
	if (ret)
		goto disable_bus;

	ret = cnss_pci_register_mhi(pci_priv);
	if (ret)
		goto disable_msi;

	switch (pci_dev->device) {
	case QCA6174_DEVICE_ID:
		pci_read_config_word(pci_dev, QCA6174_REV_ID_OFFSET,
				     &pci_priv->revision_id);
		break;
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCN7605_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		if ((cnss_is_dual_wlan_enabled() &&
		     plat_priv->enumerate_done) || !cnss_is_dual_wlan_enabled())
			cnss_pci_set_wlaon_pwr_ctrl(pci_priv, false, false,
						    false);

		timer_setup(&pci_priv->dev_rddm_timer,
			    cnss_dev_rddm_timeout_hdlr, 0);
		timer_setup(&pci_priv->boot_debug_timer,
			    cnss_boot_debug_timeout_hdlr, 0);
		INIT_DELAYED_WORK(&pci_priv->time_sync_work,
				  cnss_pci_time_sync_work_hdlr);
		cnss_pci_get_link_status(pci_priv);
		cnss_pci_set_wlaon_pwr_ctrl(pci_priv, false, true, false);
		cnss_pci_wake_gpio_init(pci_priv);
		init_completion(&pci_priv->wake_event_complete);
		break;
	default:
		cnss_pr_err("Unknown PCI device found: 0x%x\n",
			    pci_dev->device);
		ret = -ENODEV;
		goto unreg_mhi;
	}

	cnss_pci_config_regs(pci_priv);
	if (EMULATION_HW)
		goto out;
	if (cnss_is_dual_wlan_enabled() && !plat_priv->enumerate_done)
		goto probe_done;
	cnss_pci_suspend_pwroff(pci_dev);

probe_done:
	set_bit(CNSS_PCI_PROBE_DONE, &plat_priv->driver_state);

	return 0;

unreg_mhi:
	cnss_pci_unregister_mhi(pci_priv);
disable_msi:
	cnss_pci_disable_msi(pci_priv);
disable_bus:
	cnss_pci_disable_bus(pci_priv);
dereg_pci_event:
	cnss_dereg_pci_event(pci_priv);
deinit_smmu:
	cnss_pci_deinit_smmu(pci_priv);
unregister_ramdump:
	cnss_unregister_ramdump(plat_priv);
unregister_subsys:
	cnss_unregister_subsys(plat_priv);
reset_ctx:
	plat_priv->bus_priv = NULL;
out:
	return ret;
}

static void cnss_pci_remove(struct pci_dev *pci_dev)
{
	struct cnss_pci_data *pci_priv = cnss_get_pci_priv(pci_dev);
	struct cnss_plat_data *plat_priv =
		cnss_bus_dev_to_plat_priv(&pci_dev->dev);

	clear_bit(CNSS_PCI_PROBE_DONE, &plat_priv->driver_state);
	cnss_pci_unregister_driver_hdlr(pci_priv);
	cnss_pci_free_aux_mem(pci_priv);
	cnss_pci_free_tme_lite_mem(pci_priv);
	cnss_pci_free_m3_mem(pci_priv);
	cnss_pci_free_fw_mem(pci_priv);
	cnss_pci_free_qdss_mem(pci_priv);

	switch (pci_dev->device) {
	case QCA6290_DEVICE_ID:
	case QCA6390_DEVICE_ID:
	case QCN7605_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
		cnss_pci_wake_gpio_deinit(pci_priv);
		del_timer(&pci_priv->boot_debug_timer);
		del_timer(&pci_priv->dev_rddm_timer);
		break;
	default:
		break;
	}

	cnss_pci_unregister_mhi(pci_priv);
	cnss_pci_disable_msi(pci_priv);
	cnss_pci_disable_bus(pci_priv);
	cnss_dereg_pci_event(pci_priv);
	cnss_pci_deinit_smmu(pci_priv);
	if (plat_priv) {
		cnss_unregister_ramdump(plat_priv);
		cnss_unregister_subsys(plat_priv);
		plat_priv->bus_priv = NULL;
	} else {
		cnss_pr_err("Plat_priv is null, Unable to unregister ramdump,subsys\n");
	}
}

static const struct pci_device_id cnss_pci_id_table[] = {
	{ QCA6174_VENDOR_ID, QCA6174_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ QCA6290_VENDOR_ID, QCA6290_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ QCA6390_VENDOR_ID, QCA6390_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ QCN7605_VENDOR_ID, QCN7605_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ QCA6490_VENDOR_ID, QCA6490_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ KIWI_VENDOR_ID, KIWI_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ MANGO_VENDOR_ID, MANGO_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ PEACH_VENDOR_ID, PEACH_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID },
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, cnss_pci_id_table);

static const struct dev_pm_ops cnss_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(cnss_pci_suspend, cnss_pci_resume)
	SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(cnss_pci_suspend_noirq,
				      cnss_pci_resume_noirq)
	SET_RUNTIME_PM_OPS(cnss_pci_runtime_suspend, cnss_pci_runtime_resume,
			   cnss_pci_runtime_idle)
};

static struct pci_driver cnss_pci_driver = {
	.name     = "cnss_pci",
	.id_table = cnss_pci_id_table,
	.probe    = cnss_pci_probe,
	.remove   = cnss_pci_remove,
	.driver = {
		.pm = &cnss_pm_ops,
	},
};

static int cnss_pci_enumerate(struct cnss_plat_data *plat_priv, u32 rc_num)
{
	int ret, retry = 0;

	if (plat_priv->device_id == QCA6490_DEVICE_ID) {
		cnss_pci_set_gen2_speed(plat_priv, rc_num);
	} else {
		cnss_pci_downgrade_rc_speed(plat_priv, rc_num);
	}

	cnss_pr_dbg("Trying to enumerate with PCIe RC%x\n", rc_num);
retry:
	ret = _cnss_pci_enumerate(plat_priv, rc_num);
	if (ret) {
		if (ret == -EPROBE_DEFER) {
			cnss_pr_dbg("PCIe RC driver is not ready, defer probe\n");
			goto out;
		}
		cnss_pr_err("Failed to enable PCIe RC%x, err = %d\n",
			    rc_num, ret);
		if (retry++ < LINK_TRAINING_RETRY_MAX_TIMES) {
			cnss_pr_dbg("Retry PCI link training #%d\n", retry);
			goto retry;
		} else {
			goto out;
		}
	}

	plat_priv->rc_num = rc_num;

out:
	return ret;
}

int cnss_pci_init(struct cnss_plat_data *plat_priv)
{
	struct device *dev = &plat_priv->plat_dev->dev;
	const __be32 *prop;
	int ret = 0, prop_len = 0, rc_count, i;

	prop = of_get_property(dev->of_node, "qcom,wlan-rc-num", &prop_len);
	if (!prop || !prop_len) {
		cnss_pr_err("Failed to get PCIe RC number from DT\n");
		goto out;
	}

	rc_count = prop_len / sizeof(__be32);
	for (i = 0; i < rc_count; i++) {
		ret = cnss_pci_enumerate(plat_priv, be32_to_cpup(&prop[i]));
		if (!ret)
			break;
		else if (ret == -EPROBE_DEFER || (ret && i == rc_count - 1))
			goto out;
	}

	ret = cnss_try_suspend(plat_priv);
	if (ret) {
		cnss_pr_err("Failed to suspend, ret: %d\n", ret);
		goto out;
	}

	if (!cnss_driver_registered) {
		ret = pci_register_driver(&cnss_pci_driver);
		if (ret) {
			cnss_pr_err("Failed to register to PCI framework, err = %d\n",
				    ret);
			goto out;
		}
		if (!plat_priv->bus_priv) {
			cnss_pr_err("Failed to probe PCI driver\n");
			ret = -ENODEV;
			goto unreg_pci;
		}
		cnss_driver_registered = true;
	}

	return 0;

unreg_pci:
	pci_unregister_driver(&cnss_pci_driver);
out:
	return ret;
}

void cnss_pci_deinit(struct cnss_plat_data *plat_priv)
{
	if (cnss_driver_registered) {
		pci_unregister_driver(&cnss_pci_driver);
		cnss_driver_registered = false;
	}
}
