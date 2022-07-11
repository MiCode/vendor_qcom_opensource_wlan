/*
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
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
#include <dp_types.h>
#include <wlan_cfg.h>
#include <hif.h>

/**
 * dp_get_umac_reset_intr_ctx() - Get the interrupt context to be used by
 * UMAC reset feature
 * @soc: DP soc object
 * @intr_ctx: Interrupt context variable to be populated by this API
 *
 * Return: QDF_STATUS of operation
 */
static QDF_STATUS dp_get_umac_reset_intr_ctx(struct dp_soc *soc, int *intr_ctx)
{
	int umac_reset_mask, i;

	/**
	 * Go over all the contexts and check which interrupt context has
	 * the UMAC reset mask set.
	 */
	for (i = 0; i < wlan_cfg_get_num_contexts(soc->wlan_cfg_ctx); i++) {
		umac_reset_mask = wlan_cfg_get_umac_reset_intr_mask(
					soc->wlan_cfg_ctx, i);

		if (umac_reset_mask) {
			*intr_ctx = i;
			return QDF_STATUS_SUCCESS;
		}
	}

	*intr_ctx = -1;
	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS dp_soc_umac_reset_init(struct dp_soc *soc)
{
	struct dp_soc_umac_reset_ctx *umac_reset_ctx;
	size_t alloc_size;
	QDF_STATUS status;

	if (!soc) {
		dp_umac_reset_err("DP SOC is null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	umac_reset_ctx = &soc->umac_reset_ctx;
	qdf_mem_zero(umac_reset_ctx, sizeof(*umac_reset_ctx));

	umac_reset_ctx->supported = true;
	umac_reset_ctx->current_state = UMAC_RESET_STATE_WAIT_FOR_PRE_RESET;

	status = dp_get_umac_reset_intr_ctx(soc, &umac_reset_ctx->intr_offset);
	if (QDF_IS_STATUS_ERROR(status)) {
		dp_umac_reset_err("No interrupt assignment");
		return status;
	}

	alloc_size = sizeof(struct umac_reset_shmem) +
			DP_UMAC_RESET_SHMEM_ALIGN - 1;
	umac_reset_ctx->shmem_vaddr_unaligned =
	    qdf_mem_alloc_consistent(soc->osdev, soc->osdev->dev,
				     alloc_size,
				     &umac_reset_ctx->shmem_paddr_unaligned);
	if (!umac_reset_ctx->shmem_vaddr_unaligned) {
		dp_umac_reset_err("shmem allocation failed");
		return QDF_STATUS_E_NOMEM;
	}

	umac_reset_ctx->shmem_vaddr_aligned = (void *)(uintptr_t)qdf_roundup(
		(uint64_t)(uintptr_t)umac_reset_ctx->shmem_vaddr_unaligned,
		DP_UMAC_RESET_SHMEM_ALIGN);
	umac_reset_ctx->shmem_paddr_aligned = qdf_roundup(
		(uint64_t)umac_reset_ctx->shmem_paddr_unaligned,
		DP_UMAC_RESET_SHMEM_ALIGN);

	return QDF_STATUS_SUCCESS;
}

/**
 * dp_umac_reset_rx_event_handler() - Main Rx event handler for UMAC reset
 * @dp_ctx: Interrupt context corresponding to UMAC reset
 *
 * Return: 0 incase of success, else failure
 */
static int dp_umac_reset_rx_event_handler(void *dp_ctx)
{
	/* Note: This will be implemented in an upcoming change */
	return 0;
}

QDF_STATUS dp_umac_reset_interrupt_attach(struct dp_soc *soc)
{
	struct dp_soc_umac_reset_ctx *umac_reset_ctx;
	int msi_vector_count, ret;
	uint32_t msi_base_data, msi_vector_start;
	uint32_t umac_reset_vector, umac_reset_irq;

	if (!soc) {
		dp_umac_reset_err("DP SOC is null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	umac_reset_ctx = &soc->umac_reset_ctx;

	/* return if feature is not supported */
	if (!umac_reset_ctx->supported) {
		dp_umac_reset_info("UMAC reset is not supported on this SOC");
		return QDF_STATUS_SUCCESS;
	}

	if (pld_get_enable_intx(soc->osdev->dev)) {
		dp_umac_reset_err("UMAC reset is not supported in legacy interrupt mode");
		return QDF_STATUS_E_FAILURE;
	}

	ret = pld_get_user_msi_assignment(soc->osdev->dev, "DP",
					  &msi_vector_count, &msi_base_data,
					  &msi_vector_start);
	if (ret) {
		dp_umac_reset_err("UMAC reset is only supported in MSI interrupt mode");
		return QDF_STATUS_E_FAILURE;
	}

	if (umac_reset_ctx->intr_offset < 0 ||
	    umac_reset_ctx->intr_offset >= WLAN_CFG_INT_NUM_CONTEXTS) {
		dp_umac_reset_err("Invalid interrupt offset");
		return QDF_STATUS_E_FAILURE;
	}

	umac_reset_vector = msi_vector_start +
			       (umac_reset_ctx->intr_offset % msi_vector_count);

	/* Get IRQ number */
	umac_reset_irq = pld_get_msi_irq(soc->osdev->dev, umac_reset_vector);

	/* Finally register to this IRQ from HIF layer */
	return hif_register_umac_reset_handler(
				soc->hif_handle,
				dp_umac_reset_rx_event_handler,
				&soc->intr_ctx[umac_reset_ctx->intr_offset],
				umac_reset_irq);
}

QDF_STATUS dp_umac_reset_interrupt_detach(struct dp_soc *soc)
{
	struct dp_soc_umac_reset_ctx *umac_reset_ctx;

	if (!soc) {
		dp_umac_reset_err("DP SOC is null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	umac_reset_ctx = &soc->umac_reset_ctx;

	/* return if feature is not supported */
	if (!umac_reset_ctx->supported) {
		dp_umac_reset_info("UMAC reset is not supported on this SOC");
		return QDF_STATUS_SUCCESS;
	}

	return hif_unregister_umac_reset_handler(soc->hif_handle);
}
