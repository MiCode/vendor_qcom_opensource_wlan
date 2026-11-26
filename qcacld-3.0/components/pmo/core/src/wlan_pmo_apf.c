/*
 * Copyright (c) 2018 The Linux Foundation. All rights reserved.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: PMO implementations for Android Packet Filter (APF) functions
 */

#include "qdf_types.h"
#include "wlan_objmgr_psoc_obj.h"
#include "wlan_pmo_apf.h"
#include "wlan_pmo_main.h"
#include "wlan_pmo_tgt_api.h"


#define PMO_APF_SIZE_AUTO	0
#define PMO_APF_SIZE_DISABLE	0xffffffff

uint32_t pmo_get_apf_instruction_size(struct wlan_objmgr_psoc *psoc)
{
	struct pmo_psoc_priv_obj *psoc_ctx;
	bool apf = false;

	pmo_psoc_with_ctx(psoc, psoc_ctx) {
		apf = pmo_intersect_apf(psoc_ctx);
	}

	return apf ? PMO_APF_SIZE_AUTO : PMO_APF_SIZE_DISABLE;
}

uint32_t pmo_get_apf_mode(struct wlan_objmgr_psoc *psoc)
{
	uint32_t apf_mode = 0;
	struct pmo_psoc_priv_obj *psoc_ctx;

	pmo_psoc_with_ctx(psoc, psoc_ctx) {
		apf_mode = psoc_ctx->psoc_cfg.apf_mode;
	}

	return apf_mode;
}

QDF_STATUS pmo_set_apf_mode(struct wlan_objmgr_psoc *psoc,
			    uint32_t apf_mode,
			    uint32_t vdev_id)
{
	struct pmo_psoc_priv_obj *psoc_ctx;

	pmo_psoc_with_ctx(psoc, psoc_ctx) {
		psoc_ctx->psoc_cfg.apf_mode = apf_mode;
	}

	return pmo_tgt_set_apf_mode_req(psoc, apf_mode, vdev_id);
}

QDF_STATUS pmo_store_apf_mode(struct wlan_objmgr_psoc *psoc,
			      uint32_t apf_mode)
{
	struct pmo_psoc_priv_obj *psoc_ctx;

	pmo_psoc_with_ctx(psoc, psoc_ctx) {
		psoc_ctx->psoc_cfg.apf_mode = apf_mode;
	}

	return QDF_STATUS_SUCCESS;
}
