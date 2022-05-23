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
	umac_reset_ctx->current_state = UMAC_RESET_STATE_WAIT_FOR_DO_PRE_RESET;

	status = dp_get_umac_reset_intr_ctx(soc, &umac_reset_ctx->intr_offset);
	if (QDF_IS_STATUS_ERROR(status)) {
		dp_umac_reset_err("No interrupt assignment");
		return status;
	}

	alloc_size = sizeof(htt_umac_hang_recovery_msg_shmem_t) +
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
 * dp_umac_reset_get_rx_event() - Extract the Rx event from the shared memory
 * @umac_reset_ctx: UMAC reset context
 *
 * Return: Extracted Rx event in the form of enumeration umac_reset_rx_event
 */
static enum umac_reset_rx_event
dp_umac_reset_get_rx_event_from_shmem(
	struct dp_soc_umac_reset_ctx *umac_reset_ctx)
{
	htt_umac_hang_recovery_msg_shmem_t *shmem_vaddr;
	uint32_t t2h_msg;
	uint8_t num_events = 0;
	enum umac_reset_rx_event rx_event;

	shmem_vaddr = umac_reset_ctx->shmem_vaddr_aligned;
	if (!shmem_vaddr) {
		dp_umac_reset_err("Shared memory address is NULL");
		goto err;
	}

	if (shmem_vaddr->magic_num != umac_reset_ctx->shmem_exp_magic_num) {
		dp_umac_reset_err("Shared memory got corrupted");
		goto err;
	}

	/* Read the shared memory into a local variable */
	t2h_msg = shmem_vaddr->t2h_msg;

	/* Clear the shared memory right away */
	shmem_vaddr->t2h_msg = 0;

	dp_umac_reset_debug("shmem value - t2h_msg: 0x%x", t2h_msg);

	rx_event = UMAC_RESET_RX_EVENT_NONE;

	if (HTT_UMAC_HANG_RECOVERY_MSG_SHMEM_DO_PRE_RESET_GET(t2h_msg)) {
		rx_event |= UMAC_RESET_RX_EVENT_DO_PRE_RESET;
		num_events++;
	}

	if (HTT_UMAC_HANG_RECOVERY_MSG_SHMEM_DO_POST_RESET_START_GET(t2h_msg)) {
		rx_event |= UMAC_RESET_RX_EVENT_DO_POST_RESET_START;
		num_events++;
	}

	if (HTT_UMAC_HANG_RECOVERY_MSG_SHMEM_DO_POST_RESET_COMPLETE_GET(t2h_msg)) {
		rx_event |= UMAC_RESET_RX_EVENT_DO_POST_RESET_COMPELTE;
		num_events++;
	}

	dp_umac_reset_debug("deduced rx event: 0x%x", rx_event);
	/* There should not be more than 1 event */
	if (num_events > 1) {
		dp_umac_reset_err("Multiple events(0x%x) got posted", rx_event);
		goto err;
	}

	return rx_event;
err:
	qdf_assert_always(0);
	return UMAC_RESET_RX_EVENT_ERROR;
}

/**
 * dp_umac_reset_get_rx_event() - Extract the Rx event
 * @umac_reset_ctx: UMAC reset context
 *
 * Return: Extracted Rx event in the form of enumeration umac_reset_rx_event
 */
static inline enum umac_reset_rx_event
dp_umac_reset_get_rx_event(struct dp_soc_umac_reset_ctx *umac_reset_ctx)
{
	return dp_umac_reset_get_rx_event_from_shmem(umac_reset_ctx);
}

/**
 * dp_umac_reset_validate_n_update_state_machine_on_rx() - Validate the state
 * machine for a given rx event and update the state machine
 * @umac_reset_ctx: UMAC reset context
 * @rx_event: Rx event
 * @current_exp_state: Expected state
 * @next_state: The state to which the state machine needs to be updated
 *
 * Return: QDF_STATUS of operation
 */
static QDF_STATUS
dp_umac_reset_validate_n_update_state_machine_on_rx(
	struct dp_soc_umac_reset_ctx *umac_reset_ctx,
	enum umac_reset_rx_event rx_event,
	enum umac_reset_state current_exp_state,
	enum umac_reset_state next_state)
{
	if (umac_reset_ctx->current_state != current_exp_state) {
		dp_umac_reset_err("state machine validation failed on rx event: %d, current state is %d",
				  rx_event,
				  umac_reset_ctx->current_state);
		qdf_assert_always(0);
		return QDF_STATUS_E_FAILURE;
	}

	/* Update the state */
	umac_reset_ctx->current_state = next_state;
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
	struct dp_intr *int_ctx = (struct dp_intr *)dp_ctx;
	struct dp_soc *soc = int_ctx->soc;
	struct dp_soc_umac_reset_ctx *umac_reset_ctx;
	enum umac_reset_rx_event rx_event;
	QDF_STATUS status = QDF_STATUS_E_INVAL;
	enum umac_reset_action action;

	if (!soc) {
		dp_umac_reset_err("DP SOC is null");
		goto exit;
	}

	umac_reset_ctx = &soc->umac_reset_ctx;

	dp_umac_reset_debug("enter");
	rx_event = dp_umac_reset_get_rx_event(umac_reset_ctx);

	switch (rx_event) {
	case UMAC_RESET_RX_EVENT_NONE:
		/* This interrupt is not meant for us, so exit */
		dp_umac_reset_debug("Not a UMAC reset event");
		status = QDF_STATUS_SUCCESS;
		goto exit;

	case UMAC_RESET_RX_EVENT_DO_PRE_RESET:
		status = dp_umac_reset_validate_n_update_state_machine_on_rx(
			umac_reset_ctx, rx_event,
			UMAC_RESET_STATE_WAIT_FOR_DO_PRE_RESET,
			UMAC_RESET_STATE_DO_PRE_RESET_RECEIVED);

		action = UMAC_RESET_ACTION_DO_PRE_RESET;
		break;

	case UMAC_RESET_RX_EVENT_DO_POST_RESET_START:
		status = dp_umac_reset_validate_n_update_state_machine_on_rx(
			umac_reset_ctx, rx_event,
			UMAC_RESET_STATE_WAIT_FOR_DO_POST_RESET_START,
			UMAC_RESET_STATE_DO_POST_RESET_START_RECEIVED);

		action = UMAC_RESET_ACTION_DO_POST_RESET_START;
		break;

	case UMAC_RESET_RX_EVENT_DO_POST_RESET_COMPELTE:
		status = dp_umac_reset_validate_n_update_state_machine_on_rx(
			umac_reset_ctx, rx_event,
			UMAC_RESET_STATE_WAIT_FOR_DO_POST_RESET_COMPLETE,
			UMAC_RESET_STATE_DO_POST_RESET_COMPLETE_RECEIVED);

		action = UMAC_RESET_ACTION_DO_POST_RESET_COMPLETE;
		break;

	case UMAC_RESET_RX_EVENT_ERROR:
		dp_umac_reset_err("Error Rx event");
		goto exit;

	default:
		dp_umac_reset_err("Invalid value(%u) for Rx event", rx_event);
		goto exit;
	}

	/* Call the handler for this event */
	if (QDF_IS_STATUS_SUCCESS(status)) {
		if (!umac_reset_ctx->rx_actions.cb[action]) {
			dp_umac_reset_err("rx callback is NULL");
			goto exit;
		}

		status = umac_reset_ctx->rx_actions.cb[action](soc);
	}

exit:
	return qdf_status_to_os_return(status);
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

QDF_STATUS dp_umac_reset_register_rx_action_callback(
			struct dp_soc *soc,
			QDF_STATUS (*handler)(struct dp_soc *soc),
			enum umac_reset_action action)
{
	struct dp_soc_umac_reset_ctx *umac_reset_ctx;

	if (!soc) {
		dp_umac_reset_err("DP SOC is null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	if (action >= UMAC_RESET_ACTION_MAX) {
		dp_umac_reset_err("invalid action: %d", action);
		return QDF_STATUS_E_INVAL;
	}

	umac_reset_ctx = &soc->umac_reset_ctx;

	umac_reset_ctx->rx_actions.cb[action] = handler;

	return QDF_STATUS_SUCCESS;
}
