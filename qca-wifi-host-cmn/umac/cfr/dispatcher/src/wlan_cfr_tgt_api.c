/*
 * Copyright (c) 2019-2021 The Linux Foundation. All rights reserved.
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

/*
 * Layer b/w umac and target_if (ol) txops
 * It contains wrapers for txops
 */

#include <wlan_cfr_tgt_api.h>
#include <wlan_cfr_utils_api.h>
#include <target_type.h>
#include <cfr_defs_i.h>
#include <qca_vendor.h>

uint32_t tgt_cfr_send_stop(struct wlan_objmgr_pdev *pdev, uint32_t reason)
{
	struct pdev_cfr *pcfr;
	uint32_t status = QDF_STATUS_SUCCESS;

	if (!pdev) {
		cfr_err("Invalid pdev pointer");
		return QDF_STATUS_E_INVAL;
	}

	pcfr = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);
	if (!pcfr) {
		cfr_err("pdev_cfr is NULL");
		return QDF_STATUS_E_INVAL;
	}

	if (!pcfr->cfr_stop_cb) {
		cfr_err("No CFR v3 stop callback registered");
		return QDF_STATUS_SUCCESS;
	}

	pcfr->cfr_stop_cb(pcfr->vdev_id, reason);

	return status;
}

static uint64_t cfr_construct_tsf_timestamp(struct cfr_info_v3 info_v3)
{
	uint64_t tsf_timestamp;

	tsf_timestamp = ((uint64_t)info_v3.tsf_timestamp_15_0)        |
			((uint64_t)info_v3.tsf_timestamp_31_16 << 16) |
			((uint64_t)info_v3.tsf_timestamp_47_32 << 32) |
			((uint64_t)info_v3.tsf_timestamp_63_48 << 48);

	cfr_debug("timestamp: 0x%llx from parts [0x%x, 0x%x, 0x%x, 0x%x]",
		  tsf_timestamp, info_v3.tsf_timestamp_15_0,
		  info_v3.tsf_timestamp_31_16, info_v3.tsf_timestamp_47_32,
		  info_v3.tsf_timestamp_63_48);

	return tsf_timestamp;
}

static void
cfr_populate_antenna_info(struct cfr_enhanced_event_data *event_data,
			  struct csi_cfr_header *header)
{
	uint8_t i;

	if (!event_data || !header) {
		cfr_err("Invalid parameters: event_data=%pK, header=%pK",
			event_data, header);
		return;
	}

	event_data->antenna_count = event_data->num_chains + 1;
	cfr_debug("Populating antenna info for %d chains",
		  event_data->antenna_count);

	for (i = 0; i < HOST_MAX_CHAINS && i < event_data->antenna_count;
	    i++) {
		event_data->antenna_info[i].antenna_index = i;
		event_data->antenna_info[i].rssi =
			header->u.meta_enh.chain_rssi[i];
		event_data->antenna_info[i].agc =
			header->u.meta_enh.agc_gain[i];

		cfr_debug("Antenna[%d]: RSSI=%d, AGC=%d", i,
			  event_data->antenna_info[i].rssi,
			  event_data->antenna_info[i].agc);
	}
}

static enum
qca_wlan_vendor_chip_id convert_chip_type_to_chip_id(uint8_t chip_type)
{
	switch (chip_type) {
	case CFR_CAPTURE_RADIO_PEACH:
		return QCA_WLAN_VENDOR_CHIP_ID_WCN7881;
	case CFR_CAPTURE_RADIO_FIG:
		return QCA_WLAN_VENDOR_CHIP_ID_WCN8850;
	default:
		cfr_err("Invalid chip_type %d", chip_type);
		return QCA_WLAN_VENDOR_CHIP_ID_WCN7881;
	}
}

static void cfr_populate_event_data(struct cfr_enhanced_event_data *event_data,
				    struct csi_cfr_header *header,
				    struct cfr_info_v3 *info_v3,
				    struct pdev_cfr *pcfr)
{
	cfr_debug("Populating CFR enhanced event data");

	qdf_mem_copy(&event_data->peer_mac_addr[0],
		     &header->u.meta_enh.peer_addr.su_peer_addr[0],
		     QDF_MAC_ADDR_SIZE);

	cfr_debug("Peer MAC: " QDF_MAC_ADDR_FMT,
		  QDF_MAC_ADDR_REF(event_data->peer_mac_addr));

	event_data->timestamp_us = header->u.meta_enh.timestamp;
	event_data->capture_tsf = cfr_construct_tsf_timestamp(*info_v3);

	cfr_debug("Timing - timestamp_us: %llu, capture_tsf: 0x%llx",
		  event_data->timestamp_us, event_data->capture_tsf);

	event_data->cfo = header->u.meta_enh.rtt_cfo_measurement;
	event_data->bandwidth = header->u.meta_enh.channel_bw;
	event_data->ltf_type = info_v3->preamble;
	event_data->num_spatial_streams = info_v3->nss;
	event_data->frame_sequence_number = info_v3->seq_num;
	event_data->freq = pcfr->freq;
	event_data->num_chains = info_v3->num_chains;

	cfr_debug("CFO: %d, BW: %d, LTF: %d, NSS: %d, Seq: %d, Freq: %d",
		  event_data->cfo, event_data->bandwidth, event_data->ltf_type,
		  event_data->num_spatial_streams,
		  event_data->frame_sequence_number,
		  event_data->freq);

	cfr_populate_antenna_info(event_data, header);

	event_data->oui_length = pcfr->oui_length;
	event_data->format_version = pcfr->format_version;

	if (pcfr->oui_length) {
		if (pcfr->oui_length <= MAX_CFR_OUI_LEN) {
			qdf_mem_copy(&event_data->oui[0], &pcfr->oui[0],
				     pcfr->oui_length);
			cfr_debug("Copied OUI of length %d", pcfr->oui_length);
		} else {
			cfr_err("OUI length %d exceeds maximum %d, truncating",
				pcfr->oui_length, MAX_CFR_OUI_LEN);
			qdf_mem_copy(&event_data->oui[0], &pcfr->oui[0],
				     MAX_CFR_OUI_LEN);
			event_data->oui_length = MAX_CFR_OUI_LEN;
		}
	}

	event_data->chip_id =
		convert_chip_type_to_chip_id(header->cmn.chip_type);
	event_data->frame_type = pcfr->frame_type;
	event_data->frame_sub_type = pcfr->frame_sub_type;
	event_data->cfr_version = ENHANCED_CFR_VERSION_V3;

	cfr_debug("chip_id: %d, frame_type: %d, sub_type: %d, version: %d",
		  event_data->chip_id, event_data->frame_type,
		  event_data->frame_sub_type, event_data->cfr_version);
}

uint32_t tgt_cfr_info_send_v3(struct wlan_objmgr_pdev *pdev,
			      struct csi_cfr_header header,
			      void *data, size_t dlen,
			      struct cfr_info_v3 info_v3)
{
	struct pdev_cfr *pcfr;
	uint8_t *nl_data = NULL;
	struct cfr_enhanced_event_data event_data = {0};
	uint32_t status = QDF_STATUS_SUCCESS;

	cfr_debug("CFR v3 info send: dlen=%zu, preamble=%d, nss=%d, seq=%d",
		  dlen, info_v3.preamble, info_v3.nss, info_v3.seq_num);

	if (!pdev) {
		cfr_err("Invalid pdev pointer");
		return QDF_STATUS_E_INVAL;
	}

	pcfr = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);
	if (!pcfr) {
		cfr_err("pdev_cfr is NULL");
		return QDF_STATUS_E_INVAL;
	}

	cfr_debug("CFR vdev_id=%d, chip_id=%d, oui_length=%d",
		  pcfr->nl_cb.vdev_id, pcfr->chip_id, pcfr->oui_length);

	if (!pcfr->nl_cb.cfr_nl_cb_v3) {
		cfr_debug("No CFR v3 netlink callback registered");
		return QDF_STATUS_SUCCESS;
	}

	if ((dlen > 0 && !data) || (dlen >= WLAN_CFR_DATA_MAX_LEN)) {
		cfr_err("Invalid data: non-zero length %zu", dlen);
		return QDF_STATUS_E_INVAL;
	}

	cfr_populate_event_data(&event_data, &header, &info_v3, pcfr);

	if (!dlen) {
		cfr_err("Invalid data length %zu", dlen);
		return QDF_STATUS_E_INVAL;
	}

	nl_data = qdf_mem_malloc(dlen);
	if (!nl_data) {
		cfr_err("Failed to allocate %zu bytes vdev_id=%d",
			dlen, pcfr->nl_cb.vdev_id);
		return QDF_STATUS_E_NOMEM;
	}

	qdf_mem_copy(nl_data, data, dlen);

	pcfr->nl_cb.cfr_nl_cb_v3(pcfr->nl_cb.vdev_id,
				  event_data,
				  (const void *)nl_data, dlen);

	cfr_info("CFR v3 vdev_id=%d, dlen=%zu, peer=" QDF_MAC_ADDR_FMT,
		 pcfr->nl_cb.vdev_id, dlen,
		 QDF_MAC_ADDR_REF(event_data.peer_mac_addr));

	pcfr->is_cfr_data_present = true;

	qdf_mem_free(nl_data);
	cfr_debug("Freed allocated CFR data memory");

	return status;
}

uint32_t tgt_cfr_info_send(struct wlan_objmgr_pdev *pdev, void *head,
			   size_t hlen, void *data, size_t dlen, void *tail,
			   size_t tlen)
{
	struct pdev_cfr *pa;
	uint32_t status, total_len;
	uint8_t *nl_data = NULL;

	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_CFR);

	if (pa == NULL) {
		cfr_err("pdev_cfr is NULL\n");
		return -1;
	}

	/* If CFR data transport mode is NL event then send single event*/
	if (pa->nl_cb.cfr_nl_cb) {
		total_len = hlen + dlen + tlen;

		nl_data = qdf_mem_malloc(total_len);
		if (!nl_data) {
			cfr_err("failed to alloc memory, len %d, vdev_id %d",
				total_len, pa->nl_cb.vdev_id);
			return QDF_STATUS_E_FAILURE;
		}

		if (hlen)
			qdf_mem_copy(nl_data, head, hlen);

		if (dlen)
			qdf_mem_copy(nl_data + hlen, data, dlen);

		if (tlen)
			qdf_mem_copy(nl_data + hlen + dlen, tail, tlen);

		pa->nl_cb.cfr_nl_cb(pa->nl_cb.vdev_id, pa->nl_cb.pid,
				    (const void *)nl_data, total_len);
		qdf_mem_free(nl_data);

		return QDF_STATUS_SUCCESS;
	}

	if (head)
		status = cfr_streamfs_write(pa, (const void *)head, hlen);

	if (data)
		status = cfr_streamfs_write(pa, (const void *)data, dlen);

	if (tail)
		status = cfr_streamfs_write(pa, (const void *)tail, tlen);


	/* finalise the write */
	status = cfr_streamfs_flush(pa);

	return status;
}

void tgt_cfr_support_set(struct wlan_objmgr_psoc *psoc, uint32_t value)
{
	struct psoc_cfr *cfr_sc;

	if (psoc == NULL)
		return;

	cfr_sc = wlan_objmgr_psoc_get_comp_private_obj(psoc,
					WLAN_UMAC_COMP_CFR);
	if (cfr_sc == NULL)
		return;

	cfr_sc->is_cfr_capable = !!value;
	cfr_debug("CFR: FW support advert=%d", cfr_sc->is_cfr_capable);
}

static inline struct wlan_lmac_if_cfr_tx_ops *
	wlan_psoc_get_cfr_txops(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_tx_ops *tx_ops;

	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	if (!tx_ops) {
		cfr_err("tx_ops is NULL");
		return NULL;
	}
	return &tx_ops->cfr_tx_ops;
}

int tgt_cfr_get_target_type(struct wlan_objmgr_psoc *psoc)
{
	uint32_t target_type = 0;
	struct wlan_lmac_if_target_tx_ops *target_type_tx_ops;
	struct wlan_lmac_if_tx_ops *tx_ops;

	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	if (!tx_ops) {
		cfr_err("tx_ops is NULL");
		return target_type;
	}
	target_type_tx_ops = &tx_ops->target_tx_ops;

	if (target_type_tx_ops->tgt_get_tgt_type)
		target_type = target_type_tx_ops->tgt_get_tgt_type(psoc);

	return target_type;
}

int tgt_cfr_validate_period(struct wlan_objmgr_psoc *psoc, u_int32_t period)
{
	uint32_t target_type = tgt_cfr_get_target_type(psoc);
	int status = 0;

	if (target_type == TARGET_TYPE_UNKNOWN) {
		cfr_err("cfr period validation fail due to invalid target type");
		return status;
	}

	/* Basic check is the period should be between 0 and MAX_CFR_PRD */
	if (period > MAX_CFR_PRD) {
		cfr_err("Invalid period value: %d\n", period);
		return status;
	}

	if (target_type == TARGET_TYPE_QCN9000 ||
	    target_type == TARGET_TYPE_QCA6018 ||
	    target_type == TARGET_TYPE_QCA8074V2 ||
	    target_type == TARGET_TYPE_QCA5018 ||
	    target_type == TARGET_TYPE_QCA5332 ||
	    target_type == TARGET_TYPE_QCA5424 ||
	    target_type == TARGET_TYPE_QCN9224 ||
	    target_type == TARGET_TYPE_QCN6432) {
		/* No additional check required for these targets */
		status = 1;
	} else {
		if (!(period % CFR_MOD_PRD)) {
			status = 1;
		} else {
			cfr_err("Invalid period value. Value must be mod of %d",
				CFR_MOD_PRD);
		}
	}
	return status;
}

QDF_STATUS tgt_cfr_init_pdev(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_init_pdev)
		status = cfr_tx_ops->cfr_init_pdev(psoc, pdev);

	if (QDF_IS_STATUS_ERROR(status))
		cfr_err("Error occurred with exit code %d\n", status);

	return status;
}

QDF_STATUS tgt_cfr_deinit_pdev(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_deinit_pdev)
		status = cfr_tx_ops->cfr_deinit_pdev(psoc, pdev);

	if (QDF_IS_STATUS_ERROR(status))
		cfr_err("Error occurred with exit code %d\n", status);

	return status;
}

int tgt_cfr_start_capture(struct wlan_objmgr_pdev *pdev,
			  struct wlan_objmgr_peer *peer,
			  struct cfr_capture_params *cfr_params)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	int status = 0;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_start_capture)
		status = cfr_tx_ops->cfr_start_capture(pdev, peer, cfr_params);

	if (status != 0)
		cfr_err("Error occurred with exit code %d\n", status);

	return status;
}

int tgt_cfr_stop_capture(struct wlan_objmgr_pdev *pdev,
			 struct wlan_objmgr_peer *peer)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	int status = 0;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_stop_capture)
		status = cfr_tx_ops->cfr_stop_capture(pdev, peer);

	if (status != 0)
		cfr_err("Error occurred with exit code %d\n", status);

	return status;
}

int
tgt_cfr_enable_cfr_timer(struct wlan_objmgr_pdev *pdev, uint32_t cfr_timer)
{
	int status = 0;
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_enable_cfr_timer)
		status = cfr_tx_ops->cfr_enable_cfr_timer(pdev, cfr_timer);

	if (status != 0)
		cfr_err("Error occurred with exit code %d\n", status);

	return status;
}

#ifdef WLAN_ENH_CFR_ENABLE
QDF_STATUS
tgt_cfr_config_rcc(struct wlan_objmgr_pdev *pdev,
		   struct cfr_rcc_param *rcc_param)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_config_rcc)
		status = cfr_tx_ops->cfr_config_rcc(pdev, rcc_param);

	if (status != QDF_STATUS_SUCCESS)
		cfr_err("Error occurred with exit code %d\n", status);

	return status;
}

void tgt_cfr_start_lut_age_timer(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	if (!psoc) {
		cfr_err("Invalid PSOC: Flush LUT Timer cannot be started\n");
		return;
	}

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_start_lut_timer)
		cfr_tx_ops->cfr_start_lut_timer(pdev);
}

void tgt_cfr_stop_lut_age_timer(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	if (!psoc) {
		cfr_err("Invalid PSOC: Flush LUT Timer cannot be stopped\n");
		return;
	}

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_stop_lut_timer)
		cfr_tx_ops->cfr_stop_lut_timer(pdev);
}

void tgt_cfr_start_report_interval_timer(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	if (!psoc) {
		cfr_err("Invalid PSOC: Flush LUT Timer cannot be started\n");
		return;
	}

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops && cfr_tx_ops->cfr_start_report_interval_timer)
		cfr_tx_ops->cfr_start_report_interval_timer(pdev);
}

void tgt_cfr_stop_report_interval_timer(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	if (!psoc) {
		cfr_err("Invalid PSOC: Flush LUT Timer cannot be stopped\n");
		return;
	}

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops && cfr_tx_ops->cfr_stop_report_interval_timer)
		cfr_tx_ops->cfr_stop_report_interval_timer(pdev);
}

void tgt_cfr_default_ta_ra_cfg(struct wlan_objmgr_pdev *pdev,
			       struct cfr_rcc_param *rcc_param,
			       bool allvalid, uint16_t reset_cfg)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_default_ta_ra_cfg)
		cfr_tx_ops->cfr_default_ta_ra_cfg(rcc_param,
						 allvalid, reset_cfg);
}

void tgt_cfr_dump_lut_enh(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_dump_lut_enh)
		cfr_tx_ops->cfr_dump_lut_enh(pdev);
}

void tgt_cfr_rx_tlv_process(struct wlan_objmgr_pdev *pdev, void *nbuf)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_rx_tlv_process)
		cfr_tx_ops->cfr_rx_tlv_process(pdev, nbuf);
}

void tgt_cfr_update_global_cfg(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	if (!psoc) {
		cfr_err("Invalid PSOC:Cannot update global config.\n");
		return;
	}

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_update_global_cfg)
		cfr_tx_ops->cfr_update_global_cfg(pdev);
}

QDF_STATUS tgt_cfr_subscribe_ppdu_desc(struct wlan_objmgr_pdev *pdev,
				       bool is_subscribe)
{
	struct wlan_lmac_if_cfr_tx_ops *cfr_tx_ops = NULL;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	if (!psoc) {
		cfr_err("Invalid psoc\n");
		return QDF_STATUS_E_INVAL;
	}

	cfr_tx_ops = wlan_psoc_get_cfr_txops(psoc);

	if (cfr_tx_ops->cfr_subscribe_ppdu_desc)
		return cfr_tx_ops->cfr_subscribe_ppdu_desc(pdev,
							   is_subscribe);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
tgt_cfr_capture_count_support_set(struct wlan_objmgr_psoc *psoc,
				  uint32_t value)
{
	struct psoc_cfr *cfr_sc;

	if (!psoc) {
		cfr_err("CFR: NULL PSOC!!");
		return QDF_STATUS_E_INVAL;
	}

	cfr_sc = wlan_objmgr_psoc_get_comp_private_obj(psoc,
						       WLAN_UMAC_COMP_CFR);

	if (!cfr_sc) {
		cfr_err("Failed to get CFR component priv obj!!");
		return QDF_STATUS_E_INVAL;
	}

	cfr_sc->is_cap_interval_mode_sel_support = !!value;
	cfr_debug("CFR: cap_interval_mode_sel_support is %s\n",
		  (cfr_sc->is_cap_interval_mode_sel_support) ?
		  "enabled" :
		  "disabled");

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
tgt_cfr_mo_marking_support_set(struct wlan_objmgr_psoc *psoc, uint32_t value)
{
	struct psoc_cfr *cfr_sc;

	if (!psoc) {
		cfr_err("CFR: NULL PSOC!!");
		return QDF_STATUS_E_INVAL;
	}

	cfr_sc = wlan_objmgr_psoc_get_comp_private_obj(psoc,
						       WLAN_UMAC_COMP_CFR);
	if (!cfr_sc) {
		cfr_err("Failed to get CFR component priv obj!!");
		return QDF_STATUS_E_INVAL;
	}

	cfr_sc->is_mo_marking_support = !!value;
	cfr_debug("CFR: mo_marking_support is %s\n",
		  (cfr_sc->is_mo_marking_support) ? "enabled" : "disabled");

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
tgt_cfr_aoa_for_rcc_support_set(struct wlan_objmgr_psoc *psoc, uint32_t value)
{
	struct psoc_cfr *cfr_sc;

	if (!psoc) {
		cfr_err("CFR: NULL PSOC!!");
		return QDF_STATUS_E_INVAL;
	}

	cfr_sc = wlan_objmgr_psoc_get_comp_private_obj(psoc,
						       WLAN_UMAC_COMP_CFR);

	if (!cfr_sc) {
		cfr_err("Failed to get CFR component priv obj!!");
		return QDF_STATUS_E_INVAL;
	}

	cfr_sc->is_aoa_for_rcc_support = !!value;
	cfr_debug("CFR: aoa_for_rcc_support is %s\n",
		  (cfr_sc->is_aoa_for_rcc_support) ? "enabled" : "disabled");

	return QDF_STATUS_SUCCESS;
}
#else
QDF_STATUS
tgt_cfr_capture_count_support_set(struct wlan_objmgr_psoc *psoc,
				  uint32_t value)
{
	return QDF_STATUS_E_NOSUPPORT;
}

QDF_STATUS
tgt_cfr_mo_marking_support_set(struct wlan_objmgr_psoc *psoc,
			       uint32_t value)
{
	return QDF_STATUS_E_NOSUPPORT;
}

QDF_STATUS
tgt_cfr_aoa_for_rcc_support_set(struct wlan_objmgr_psoc *psoc, uint32_t value)
{
	return QDF_STATUS_E_NOSUPPORT;
}
#endif
