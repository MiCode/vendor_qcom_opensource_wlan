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

