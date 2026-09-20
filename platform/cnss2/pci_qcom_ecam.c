// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved. */

#include "pci_platform.h"
#include "debug.h"
#include <linux/pm.h>
#include <linux/of_address.h>

static struct cnss_msi_config msi_config = {
	.total_vectors = 32,
	.total_users = MSI_USERS,
	.users = (struct cnss_msi_user[]) {
		{ .name = "MHI", .num_vectors = 3, .base_vector = 0 },
		{ .name = "CE", .num_vectors = 10, .base_vector = 3 },
		{ .name = "WAKE", .num_vectors = 1, .base_vector = 13 },
		{ .name = "DP", .num_vectors = 18, .base_vector = 14 },
	},
};

int _cnss_pci_enumerate(struct cnss_plat_data *plat_priv, u32 rc_num)
{
	return 0;
}

bool cnss_pci_is_sync_probe(void)
{
	return false;
}

int cnss_pci_assert_perst(struct cnss_pci_data *pci_priv)
{
	return -EOPNOTSUPP;
}

int cnss_pci_disable_pc(struct cnss_pci_data *pci_priv, bool vote)
{
	return 0;
}

int cnss_pci_set_link_bandwidth(struct cnss_pci_data *pci_priv,
				u16 link_speed, u16 link_width)
{
	return 0;
}

int cnss_pci_set_max_link_speed(struct cnss_pci_data *pci_priv,
				u32 rc_num, u16 link_speed)
{
	return 0;
}

int cnss_reg_pci_event(struct cnss_pci_data *pci_priv)
{
	return 0;
}

void cnss_dereg_pci_event(struct cnss_pci_data *pci_priv) {}

int cnss_wlan_adsp_pc_enable(struct cnss_pci_data *pci_priv, bool control)
{
	return 0;
}

int cnss_set_pci_link(struct cnss_pci_data *pci_priv, bool link_up)
{
	int ret = 0;
	struct device *dev, *host_bridge_dev;
	struct pci_dev *root_port;

	if (!pci_priv) {
		cnss_pr_err("pci_priv is null\n");
		return -EINVAL;
	}

	root_port = pcie_find_root_port(pci_priv->pci_dev);
	if (!root_port) {
		cnss_pr_err("PCIe root port is null\n");
		return -EINVAL;
	}

	host_bridge_dev = root_port->dev.parent;
	if (!host_bridge_dev) {
		cnss_pr_err("host_bridge_dev is null\n");
		return -EINVAL;
	}

	dev = host_bridge_dev->parent;
	if (!dev) {
		cnss_pr_err("PCIe platform device is null\n");
		return -EINVAL;
	}

	cnss_pr_info("%s PCI link, \n", link_up ? "Resuming" : "Suspending");

	cnss_pr_info("PCIe PM: usage_count:%d, runtime_status:%d\n",
		     atomic_read(&dev->power.usage_count),
		     dev->power.runtime_status);

	if (link_up) {
		pm_suspend_ignore_children(dev, false);
		ret = pm_runtime_resume(dev);
		pm_runtime_barrier(dev);
		cnss_pr_info("PCIe resume: ret:%d, usage_count:%d, runtime_status:%d\n",
			     ret, atomic_read(&dev->power.usage_count),
			     dev->power.runtime_status);

		if (ret ||
		    dev->power.runtime_status != RPM_ACTIVE) {
			cnss_pr_info("Faile to resume PCIe link\n");
			return ret;
		}
	} else {
		pm_suspend_ignore_children(dev, true);
		ret = pm_runtime_suspend(dev);
		pm_runtime_barrier(dev);
		cnss_pr_info("PCIe suspend: ret:%d, usage_count:%d, runtime_status:%d\n",
			     ret, atomic_read(&dev->power.usage_count),
			     dev->power.runtime_status);

		if (ret ||
		    dev->power.runtime_status != RPM_SUSPENDED) {
			dev->power.ignore_children = false;
			cnss_pr_info("Faile to suspend PCIe link\n");
			return ret;
		}
	}

	return ret;
}

int cnss_pci_prevent_l1(struct device *dev)
{
	return 0;
}
EXPORT_SYMBOL(cnss_pci_prevent_l1);

int __cnss_pci_prevent_l1(struct device *dev)
{
	return 0;
}

void cnss_pci_allow_l1(struct device *dev)
{
}
EXPORT_SYMBOL(cnss_pci_allow_l1);

void __cnss_pci_allow_l1(struct device *dev)
{
}

int cnss_pci_fmd_enable(struct cnss_pci_data *pci_priv)
{
	return -EOPNOTSUPP;
}

int _cnss_pci_get_reg_dump(struct cnss_pci_data *pci_priv,
			   u8 *buf, u32 len)
{
	return 0;
}

void cnss_pci_update_drv_supported(struct cnss_pci_data *pci_priv)
{
	pci_priv->drv_supported = false;
}

int cnss_pci_get_msi_assignment(struct cnss_pci_data *pci_priv)
{
	pci_priv->msi_config = &msi_config;

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)) && \
    (LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0))
static int
cnss_pci_smmu_dev_fault_handler(struct iommu_fault *fault,  void *data)
{
	struct cnss_pci_data *pci_priv = data;

	cnss_fatal_err("SMMU fault happened with IOVA 0x%llx\n",
		       fault->event.addr);

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	pci_priv->is_smmu_fault = true;
	cnss_pci_update_status(pci_priv, CNSS_FW_DOWN);
	cnss_force_fw_assert(&pci_priv->pci_dev->dev);

	/* IOMMU driver requires -ENOSYS to print debug info. */
	return -ENOSYS;
}

static
void cnss_register_iommu_fault_handler(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;

	iommu_register_device_fault_handler(&pci_dev->dev,
					    cnss_pci_smmu_dev_fault_handler,
					    pci_priv);
}
#else
static int cnss_pci_smmu_fault_handler(struct iommu_domain *domain,
				       struct device *dev, unsigned long iova,
				       int flags, void *handler_token)
{
	struct cnss_pci_data *pci_priv = handler_token;

	cnss_fatal_err("SMMU fault happened with IOVA 0x%lx\n", iova);

	if (!pci_priv) {
		cnss_pr_err("pci_priv is NULL\n");
		return -ENODEV;
	}

	pci_priv->is_smmu_fault = true;
	cnss_pci_update_status(pci_priv, CNSS_FW_DOWN);
	cnss_force_fw_assert(&pci_priv->pci_dev->dev);

	/* IOMMU driver requires -ENOSYS to print debug info. */
	return -ENOSYS;
}

static
void cnss_register_iommu_fault_handler(struct cnss_pci_data *pci_priv)
{
	iommu_set_fault_handler(pci_priv->iommu_domain,
				cnss_pci_smmu_fault_handler, pci_priv);
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0))
int cnss_pci_get_iommu_addr(struct cnss_pci_data *pci_priv,
			    struct device_node *iommu_group_node)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct device_node *of_node;
	const u32 *maps;
	const u32 *end;
	int size;

	of_node = of_find_node_by_name(pci_dev->dev.of_node,
				       "cnss_pci0_iommu_region_partition");
	if (!of_node)
		return -EINVAL;

	maps = of_get_property(of_node, "iommu-addresses", &size);
	if (!maps) {
		of_node_put(of_node);
		return -EINVAL;
	}

	end = maps + size / sizeof(u32);

	pci_priv->smmu_iova_start = 0;

	while (maps < end) {
		phys_addr_t iova;
		size_t length;

		/*
		 * Skip the device phandle and if required later, we can
		 * check if the device phandle matches with pci_dev->dev.of_node
		 */
		maps++;

		maps = of_translate_dma_region(pci_dev->dev.of_node, maps,
					       &iova, &length);

		/*
		 * Assuming a single contiguous DMA address range
		 */
		if (!pci_priv->smmu_iova_start)
			pci_priv->smmu_iova_start = length;
		else
			pci_priv->smmu_iova_len =
					iova - pci_priv->smmu_iova_start;
	}

	of_node_put(of_node);

	return (pci_priv->smmu_iova_start && pci_priv->smmu_iova_len) ?
		0 : -EINVAL;
}
#else
int cnss_pci_get_iommu_addr(struct cnss_pci_data *pci_priv,
			    struct device_node *iommu_group_node)
{
	u32 addr_win[2];
	int ret;

	ret = of_property_read_u32_array(iommu_group_node,
					 "qcom,iommu-dma-addr-pool",
					 addr_win, ARRAY_SIZE(addr_win));

	pci_priv->smmu_iova_start = addr_win[0];
	pci_priv->smmu_iova_len = addr_win[1];

	return ret;
}
#endif

int cnss_pci_init_smmu(struct cnss_pci_data *pci_priv)
{
	struct pci_dev *pci_dev = pci_priv->pci_dev;
	struct cnss_plat_data *plat_priv = pci_priv->plat_priv;
	struct device_node *of_node;
	struct resource *res;
	const char *iommu_dma_type;
	int ret = 0;

	of_node = of_parse_phandle(pci_dev->dev.of_node, "qcom,iommu-group", 0);
	if (!of_node)
		return ret;

	cnss_pr_dbg("Initializing SMMU\n");

	pci_priv->iommu_domain = iommu_get_domain_for_dev(&pci_dev->dev);
	ret = of_property_read_string(of_node, "qcom,iommu-dma",
				      &iommu_dma_type);
	if (!ret && !strcmp("fastmap", iommu_dma_type)) {
		cnss_pr_dbg("Enabling SMMU S1 stage\n");
		pci_priv->smmu_s1_enable = true;
		cnss_register_iommu_fault_handler(pci_priv);
		cnss_register_iommu_fault_handler_irq(pci_priv);
	}

	ret = cnss_pci_get_iommu_addr(pci_priv, of_node);
	if (ret) {
		cnss_pr_err("Invalid SMMU size window, err = %d\n", ret);
		of_node_put(of_node);
		return ret;
	}

	cnss_pr_dbg("smmu_iova_start: %pa, smmu_iova_len: 0x%zx\n",
		    &pci_priv->smmu_iova_start,
		    pci_priv->smmu_iova_len);

	res = platform_get_resource_byname(plat_priv->plat_dev, IORESOURCE_MEM,
					   "smmu_iova_ipa");
	if (res) {
		pci_priv->smmu_iova_ipa_start = res->start;
		pci_priv->smmu_iova_ipa_current = res->start;
		pci_priv->smmu_iova_ipa_len = resource_size(res);
		cnss_pr_dbg("smmu_iova_ipa_start: %pa, smmu_iova_ipa_len: 0x%zx\n",
			    &pci_priv->smmu_iova_ipa_start,
			    pci_priv->smmu_iova_ipa_len);
	}

	pci_priv->iommu_geometry = of_property_read_bool(of_node,
							 "qcom,iommu-geometry");
	cnss_pr_dbg("iommu_geometry: %d\n", pci_priv->iommu_geometry);

	of_node_put(of_node);

	return 0;
}
