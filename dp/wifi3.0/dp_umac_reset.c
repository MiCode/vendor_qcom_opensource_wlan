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

QDF_STATUS dp_soc_umac_reset_init(struct dp_soc *soc)
{
	struct dp_soc_umac_reset_ctx *umac_reset_ctx;
	size_t alloc_size;

	if (!soc) {
		dp_umac_reset_err("DP SOC is null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	umac_reset_ctx = &soc->umac_reset_ctx;
	qdf_mem_zero(umac_reset_ctx, sizeof(*umac_reset_ctx));

	umac_reset_ctx->current_state = UMAC_RESET_STATE_WAIT_FOR_PRE_RESET;

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

