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

#ifndef _DP_UMAC_RESET_H_
#define _DP_UMAC_RESET_H_

#ifdef DP_UMAC_HW_RESET_SUPPORT

#include <qdf_types.h>

#define dp_umac_reset_alert(params...) \
	QDF_TRACE_FATAL(QDF_MODULE_ID_DP_UMAC_RESET, params)
#define dp_umac_reset_err(params...) \
	QDF_TRACE_ERROR(QDF_MODULE_ID_DP_UMAC_RESET, params)
#define dp_umac_reset_warn(params...) \
	QDF_TRACE_WARN(QDF_MODULE_ID_DP_UMAC_RESET, params)
#define dp_umac_reset_notice(params...) \
	QDF_TRACE_INFO(QDF_MODULE_ID_DP_UMAC_RESET, params)
#define dp_umac_reset_info(params...) \
	QDF_TRACE_INFO(QDF_MODULE_ID_DP_UMAC_RESET, params)
#define dp_umac_reset_debug(params...) \
	QDF_TRACE_DEBUG(QDF_MODULE_ID_DP_UMAC_RESET, params)

#define DP_UMAC_RESET_SHMEM_ALIGN 8

struct dp_soc;
/**
 * enum umac_reset_state - States required for UMAC reset state machine
 * @UMAC_RESET_STATE_WAIT_FOR_PRE_RESET: Waiting for the PRE_RESET event
 * @UMAC_RESET_STATE_PRE_RESET_RECEIVED: Received the PRE_RESET event
 * @UMAC_RESET_STATE_HOST_PRE_RESET_COMPLETED: Host has completed handling the
 * PRE_RESET event
 * @UMAC_RESET_STATE_WAIT_FOR_POST_RESET: Waiting for the POST_RESET event
 * @UMAC_RESET_STATE_POST_RESET_RECEIVED: Received the POST_RESET event
 * @UMAC_RESET_STATE_HOST_POST_RESET_COMPLETED: Host has completed handling the
 * POST_RESET event
 */
enum umac_reset_state {
	UMAC_RESET_STATE_WAIT_FOR_PRE_RESET = 0,
	UMAC_RESET_STATE_PRE_RESET_RECEIVED,
	UMAC_RESET_STATE_HOST_PRE_RESET_COMPLETED,
	UMAC_RESET_STATE_WAIT_FOR_POST_RESET,
	UMAC_RESET_STATE_POST_RESET_RECEIVED,
	UMAC_RESET_STATE_HOST_POST_RESET_COMPLETED,
};

/**
 * struct umac_reset_shmem - Shared memory layout for UMAC reset feature
 * @t2h_indication: target to host communicaton
 * @h2t_indication: host to target communicaton
 */
struct umac_reset_shmem {
	uint32_t t2h_indication;
	uint32_t h2t_indication;
};

/**
 * struct dp_soc_umac_reset_ctx - UMAC reset context at soc level
 * @shmem_paddr_unaligned: Physical address of the shared memory (unaligned)
 * @shmem_vaddr_unaligned: Virtual address of the shared memory (unaligned)
 * @shmem_paddr_aligned: Physical address of the shared memory (aligned)
 * @shmem_vaddr_aligned: Virtual address of the shared memory (aligned)
 * @intr_offset: Offset of the UMAC reset interrupt w.r.t DP base interrupt
 * @current_state: current state of the UMAC reset state machine
 */
struct dp_soc_umac_reset_ctx {
	qdf_dma_addr_t shmem_paddr_unaligned;
	struct umac_reset_shmem *shmem_vaddr_unaligned;
	qdf_dma_addr_t shmem_paddr_aligned;
	struct umac_reset_shmem *shmem_vaddr_aligned;
	uint32_t intr_offset;
	enum umac_reset_state current_state;
};

/**
 * dp_soc_umac_reset_init() - Initialize UMAC reset context
 * @soc: DP soc object
 *
 * Return: QDF status of operation
 */
QDF_STATUS dp_soc_umac_reset_init(struct dp_soc *soc);
#endif /* DP_UMAC_HW_RESET_SUPPORT */
#endif /* _DP_UMAC_RESET_H_ */
