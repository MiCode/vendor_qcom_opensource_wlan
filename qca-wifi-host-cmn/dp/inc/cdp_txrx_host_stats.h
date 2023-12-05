/*
 * Copyright (c) 2016-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: cdp_txrx_host_stats.h
 * Define the host data path stats API functions
 * called by the host control SW and the OS interface module
 */
#ifndef _CDP_TXRX_HOST_STATS_H_
#define _CDP_TXRX_HOST_STATS_H_
#include "cdp_txrx_handle.h"
#include <cdp_txrx_cmn.h>
#include <wmi_unified_api.h>
/**
 * cdp_host_stats_get() - cdp call to get host stats
 * @soc: SOC handle
 * @vdev_id: vdev id of vdev
 * @req: Requirement type
 *
 * Return: 0 for Success, Failure returns error message
 */
static inline int cdp_host_stats_get(ol_txrx_soc_handle soc,
		uint8_t vdev_id,
		struct ol_txrx_stats_req *req)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_host_stats_get)
		return 0;

	return soc->ops->host_stats_ops->txrx_host_stats_get(soc, vdev_id, req);
}

/**
 * cdp_host_stats_get_ratekbps() - cdp call to get rate in kbps
 * @soc: SOC handle
 * @preamb: Preamble
 * @mcs: Modulation and Coding scheme index
 * @htflag: Flag to identify HT or VHT
 * @gintval: Guard Interval value
 *
 * Return: 0 for Failure, Returns rate on Success
 */
static inline int cdp_host_stats_get_ratekbps(ol_txrx_soc_handle soc,
					      int preamb, int mcs,
					      int htflag, int gintval)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_ratekbps)
		return 0;

	return soc->ops->host_stats_ops->txrx_get_ratekbps(preamb,
							   mcs, htflag,
							   gintval);
}

/**
 * cdp_host_stats_clr() - cdp call to clear host stats
 * @soc: soc handle
 * @vdev_id: vdev handle id
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_host_stats_clr(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_host_stats_clr)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_host_stats_clr(soc, vdev_id);
}

static inline QDF_STATUS
cdp_host_ce_stats(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_host_ce_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_host_ce_stats(soc, vdev_id);
}

static inline int cdp_stats_publish
	(ol_txrx_soc_handle soc, uint8_t pdev_id,
	struct cdp_stats_extd *buf)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_stats_publish)
		return 0;

	return soc->ops->host_stats_ops->txrx_stats_publish(soc, pdev_id, buf);
}

/**
 * cdp_enable_enhanced_stats() - Enable enhanced stats functionality.
 * @soc: the soc object
 * @pdev_id: id of the physical device object
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_enable_enhanced_stats(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->mon_ops ||
	    !soc->ops->mon_ops->txrx_enable_enhanced_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->mon_ops->txrx_enable_enhanced_stats
			(soc, pdev_id);
}

/**
 * cdp_disable_enhanced_stats() - Disable enhanced stats functionality.
 * @soc: the soc object
 * @pdev_id: id of the physical device object
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_disable_enhanced_stats(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->mon_ops ||
	    !soc->ops->mon_ops->txrx_disable_enhanced_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->mon_ops->txrx_disable_enhanced_stats
			(soc, pdev_id);
}

static inline QDF_STATUS
cdp_tx_print_tso_stats(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->tx_print_tso_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->tx_print_tso_stats(soc, vdev_id);
}

static inline QDF_STATUS
cdp_tx_rst_tso_stats(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->tx_rst_tso_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->tx_rst_tso_stats(soc, vdev_id);
}

static inline QDF_STATUS
cdp_tx_print_sg_stats(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->tx_print_sg_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->tx_print_sg_stats(soc, vdev_id);
}

static inline QDF_STATUS
cdp_tx_rst_sg_stats(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->tx_rst_sg_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->tx_rst_sg_stats(soc, vdev_id);
}

static inline QDF_STATUS
cdp_print_rx_cksum_stats(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->print_rx_cksum_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->print_rx_cksum_stats(soc, vdev_id);
}

static inline QDF_STATUS
cdp_rst_rx_cksum_stats(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->rst_rx_cksum_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->rst_rx_cksum_stats(soc, vdev_id);
}

static inline QDF_STATUS
cdp_host_me_stats(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_host_me_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_host_me_stats(soc, vdev_id);
}

/**
 * cdp_per_peer_stats() - function to print per peer REO Queue stats
 * @soc: soc handle
 * @addr: peer address
 *
 * Return: status
 */
static inline QDF_STATUS cdp_per_peer_stats(ol_txrx_soc_handle soc,
					    uint8_t *addr)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_per_peer_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_per_peer_stats(soc, addr);
}

static inline int cdp_host_msdu_ttl_stats(ol_txrx_soc_handle soc,
	uint8_t vdev_id,
	struct ol_txrx_stats_req *req)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_host_msdu_ttl_stats)
		return 0;

	return soc->ops->host_stats_ops->txrx_host_msdu_ttl_stats
			(soc, vdev_id, req);
}

static inline QDF_STATUS cdp_update_peer_stats(ol_txrx_soc_handle soc,
					       uint8_t vdev_id, uint8_t *mac,
					       void *stats,
					       uint32_t last_tx_rate_mcs,
					       uint32_t stats_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_update_peer_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_update_peer_stats
			(soc, vdev_id, mac, stats, last_tx_rate_mcs, stats_id);
}

static inline QDF_STATUS cdp_get_dp_fw_peer_stats(ol_txrx_soc_handle soc,
						  uint8_t pdev_id,
						  uint8_t *mac, uint32_t caps,
						  uint32_t copy_stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->get_fw_peer_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->get_fw_peer_stats
			(soc, pdev_id, mac, caps, copy_stats);
}

static inline QDF_STATUS cdp_get_dp_htt_stats(ol_txrx_soc_handle soc,
					      uint8_t pdev_id,
					      void *data, uint32_t data_len)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->get_htt_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->get_htt_stats(soc, pdev_id, data,
						       data_len);
}

/**
 * cdp_update_pdev_host_stats() - Update pdev host stats received from firmware
 * (wmi_host_pdev_stats and wmi_host_pdev_ext_stats) into dp
 * @soc: soc handle
 * @pdev_id: id of the physical device object
 * @data: pdev stats
 * @stats_id: statistics to be updated
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_update_pdev_host_stats(ol_txrx_soc_handle soc,
			   uint8_t pdev_id,
			   void *data,
			   uint16_t stats_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_update_pdev_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_update_pdev_stats(soc, pdev_id,
								data,
								stats_id);
}

/**
 * cdp_update_vdev_host_stats() - Update vdev host stats
 * @soc: soc handle
 * @vdev_id: id of the virtual device object
 * @data: pdev stats
 * @stats_id: type of stats
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_update_vdev_host_stats(ol_txrx_soc_handle soc,
			   uint8_t vdev_id,
			   void *data,
			   uint16_t stats_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_update_vdev_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_update_vdev_stats(soc, vdev_id,
								data,
								stats_id);
}

/**
 * cdp_txrx_get_peer_stats_param() - Call to get specified peer stats
 * @soc: soc handle
 * @vdev_id: vdev_id of vdev object
 * @peer_mac: mac address of the peer
 * @type: enum of required stats
 * @buf: buffer to hold the value
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_txrx_get_peer_stats_param(ol_txrx_soc_handle soc, uint8_t vdev_id,
			      uint8_t *peer_mac,
			      enum cdp_peer_stats_type type,
			      cdp_peer_stats_param_t *buf)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_peer_stats_param)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_peer_stats_param(soc,
								   vdev_id,
								   peer_mac,
								   type,
								   buf);
}

/**
 * cdp_host_get_soc_stats() - Call to get soc stats
 * @soc: soc handle
 * @soc_stats: buffer for cdp soc stats
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_host_get_soc_stats(ol_txrx_soc_handle soc, struct cdp_soc_stats *soc_stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_soc_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_soc_stats(soc, soc_stats);
}

/**
 * cdp_host_get_peer_stats() - Call to get peer stats
 * @soc: soc handle
 * @vdev_id: vdev_id of vdev object
 * @peer_mac: mac address of the peer
 * @peer_stats: destination buffer
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_host_get_peer_stats(ol_txrx_soc_handle soc, uint8_t vdev_id,
			uint8_t *peer_mac,
			struct cdp_peer_stats *peer_stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_peer_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_peer_stats(soc, vdev_id,
							     peer_mac,
							     peer_stats);
}

/**
 * cdp_host_get_per_link_peer_stats() - Call to get peer stats
 * @soc: soc handle
 * @vdev_id: vdev_id of vdev object
 * @peer_mac: mac address of the peer
 * @peer_stats: destination buffer
 * @peer_type: Peer type
 * @num_link: Number of ML links
 *
 * NOTE: For peer_type = CDP_MLD_PEER_TYPE peer_stats should point to
 *       buffer of size = (sizeof(*peer_stats) * num_link)
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_host_get_per_link_peer_stats(ol_txrx_soc_handle soc, uint8_t vdev_id,
				 uint8_t *peer_mac,
				 struct cdp_peer_stats *peer_stats,
				 enum cdp_peer_type peer_type,
				 uint8_t num_link)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_per_link_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_per_link_stats(soc, vdev_id,
								 peer_mac,
								 peer_stats,
								 peer_type,
								 num_link);
}

/**
 * cdp_host_reset_peer_ald_stats() - Call to reset ald stats
 * @soc: soc handle
 * @vdev_id: vdev_id of vdev object
 * @peer_mac: mac address of the peer
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_host_reset_peer_ald_stats(ol_txrx_soc_handle soc, uint8_t vdev_id,
			      uint8_t *peer_mac)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_reset_peer_ald_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_reset_peer_ald_stats(soc,
							    vdev_id,
							    peer_mac);
}

/**
 * cdp_host_reset_peer_stats() - Call to reset peer stats
 * @soc: soc handle
 * @vdev_id: vdev_id of vdev object
 * @peer_mac: mac address of the peer
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_host_reset_peer_stats(ol_txrx_soc_handle soc,
			  uint8_t vdev_id, uint8_t *peer_mac)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_reset_peer_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_reset_peer_stats(soc,
							vdev_id,
							peer_mac);
}

/**
 * cdp_host_get_vdev_stats() - Call to get vdev stats
 * @soc: dp soc object
 * @vdev_id: id of dp vdev object
 * @buf: buffer
 * @is_aggregate:
 *
 * Return: int
 */
static inline int
cdp_host_get_vdev_stats(ol_txrx_soc_handle soc,
			uint8_t vdev_id,
			struct cdp_vdev_stats *buf,
			bool is_aggregate)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_vdev_stats)
		return 0;

	return soc->ops->host_stats_ops->txrx_get_vdev_stats(soc, vdev_id,
							     buf,
							     is_aggregate);
}

/**
 * cdp_update_host_vdev_stats() - Call to update vdev stats received from
 * firmware (wmi_host_vdev_stats and wmi_host_vdev_extd_stats) into dp
 * @soc: soc handle
 * @data: stats data to be updated
 * @size: size of stats data
 * @stats_id: stats id
 *
 * Return: int
 */
static inline int
cdp_update_host_vdev_stats(ol_txrx_soc_handle soc,
			   void *data,
			   uint32_t size,
			   uint32_t stats_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_process_wmi_host_vdev_stats)
		return 0;

	return soc->ops->host_stats_ops->txrx_process_wmi_host_vdev_stats
								(soc,
								 data,
								 size,
								 stats_id);
}

/**
 * cdp_get_vdev_extd_stats() - Call to get vdev extd stats
 * @soc: soc handle
 * @vdev_id: id of dp vdev object
 * @buf: buffer
 *
 * Return: int
 */
static inline int
cdp_get_vdev_extd_stats(ol_txrx_soc_handle soc,
			uint8_t vdev_id,
			wmi_host_vdev_extd_stats *buf)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_vdev_extd_stats)
		return 0;

	return soc->ops->host_stats_ops->txrx_get_vdev_extd_stats(soc, vdev_id,
								  buf);
}

/**
 * cdp_host_get_pdev_stats() - Call to get cdp_pdev_stats
 * @soc: soc handle
 * @pdev_id: id of dp pdev object
 * @buf: buffer to hold cdp_pdev_stats
 *
 * Return: success/failure
 */
static inline int
cdp_host_get_pdev_stats(ol_txrx_soc_handle soc,
			uint8_t pdev_id, struct cdp_pdev_stats *buf)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_pdev_stats)
		return 0;

	return soc->ops->host_stats_ops->txrx_get_pdev_stats(soc, pdev_id, buf);
}

/**
 * cdp_host_get_radio_stats() - Call to get radio stats
 * @soc: soc handle
 * @pdev_id: id of dp pdev object
 * @buf: stats buffer
 *
 * Return: int
 */
static inline int
cdp_host_get_radio_stats(ol_txrx_soc_handle soc,
			 uint8_t pdev_id,
			 void *buf)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_radio_stats)
		return 0;

	return soc->ops->host_stats_ops->txrx_get_radio_stats(soc, pdev_id,
							      buf);
}

#ifdef QCA_SUPPORT_SCAN_SPCL_VAP_STATS
static inline int
cdp_get_scan_spcl_vap_stats(ol_txrx_soc_handle soc,
			    uint8_t vdev_id,
			    struct cdp_scan_spcl_vap_stats *stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_scan_spcl_vap_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_scan_spcl_vap_stats(soc,
								      vdev_id,
								      stats);
}
#endif

/**
 * cdp_get_peer_delay_stats() - Call to get per peer delay stats
 * @soc: soc handle
 * @vdev_id: id of dp_vdev handle
 * @peer_mac: peer mac address
 * @delay_stats: user allocated buffer for peer delay stats
 *
 * Return: status Success/Failure
 */
static inline QDF_STATUS
cdp_get_peer_delay_stats(ol_txrx_soc_handle soc,
			 uint8_t vdev_id,
			 uint8_t *peer_mac,
			 struct cdp_delay_tid_stats *delay_stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_peer_delay_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_peer_delay_stats(soc,
								   vdev_id,
								   peer_mac,
								   delay_stats);
}

/**
 * cdp_get_peer_jitter_stats() - Call to get per peer jitter stats
 * @soc: soc handle
 * @pdev_id: id of dp_pdev handle
 * @vdev_id: id of dp_vdev handle
 * @peer_mac: peer mac address
 * @tid_stats: user allocated buffer for tid_stats
 *
 * Return: status Success/Failure
 */
static inline QDF_STATUS
cdp_get_peer_jitter_stats(ol_txrx_soc_handle soc,
			  uint8_t pdev_id,
			  uint8_t vdev_id,
			  uint8_t *peer_mac,
			  struct cdp_peer_tid_stats *tid_stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_peer_jitter_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_peer_jitter_stats(soc,
								    pdev_id,
								    vdev_id,
								    peer_mac,
								    tid_stats);
}

/**
 * cdp_mon_pdev_get_rx_stats() - Call to get monitor pdev rx stats
 * @soc: soc handle
 * @pdev_id: id of dp_pdev handle
 * @stats: user allocated buffer for dp pdev mon stats
 *
 * Return: status Success/Failure
 */
static inline QDF_STATUS
cdp_mon_pdev_get_rx_stats(ol_txrx_soc_handle soc, uint8_t pdev_id,
			  struct cdp_pdev_mon_stats *stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->mon_ops ||
	    !soc->ops->mon_ops->get_mon_pdev_rx_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->mon_ops->get_mon_pdev_rx_stats(soc, pdev_id, stats);
}

#ifdef WLAN_TX_PKT_CAPTURE_ENH
/**
 * cdp_get_peer_tx_capture_stats() - Call to get peer tx capture stats
 * @soc: soc handle
 * @vdev_id: id of dp_vdev handle
 * @peer_mac: peer mac address
 * @stats: pointer to peer tx capture stats
 *
 * Return: status Success/Failure
 */
static inline QDF_STATUS
cdp_get_peer_tx_capture_stats(ol_txrx_soc_handle soc,
			      uint8_t vdev_id,
			      uint8_t *peer_mac,
			      struct cdp_peer_tx_capture_stats *stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->get_peer_tx_capture_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->get_peer_tx_capture_stats(soc, vdev_id,
								   peer_mac,
								   stats);
}

/**
 * cdp_get_pdev_tx_capture_stats() - Call to get pdev tx capture stats
 * @soc: soc handle
 * @pdev_id: id of dp_pdev handle
 * @stats: pointer to pdev tx capture stats
 *
 * Return: status Success/Failure
 */
static inline QDF_STATUS
cdp_get_pdev_tx_capture_stats(ol_txrx_soc_handle soc, uint8_t pdev_id,
			      struct cdp_pdev_tx_capture_stats *stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->get_pdev_tx_capture_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->get_pdev_tx_capture_stats(soc, pdev_id,
								   stats);
}
#endif /* WLAN_TX_PKT_CAPTURE_ENH */

#ifdef HW_TX_DELAY_STATS_ENABLE
/**
 * cdp_enable_disable_vdev_tx_delay_stats() - Start/Stop tx delay stats capture
 * @soc: soc handle
 * @vdev_id: vdev id
 * @value: value to be set
 *
 * Return: None
 */
static inline void
cdp_enable_disable_vdev_tx_delay_stats(ol_txrx_soc_handle soc, uint8_t vdev_id,
				       uint8_t value)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		return;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->enable_disable_vdev_tx_delay_stats)
		return;

	soc->ops->host_stats_ops->enable_disable_vdev_tx_delay_stats(soc,
								     vdev_id,
								     value);
}

/**
 * cdp_vdev_is_tx_delay_stats_enabled() - Check if the Tx delay stats
 *  is enabled or not for the given vdev_id
 * @soc: soc handle
 * @vdev_id: vdev_id
 *
 * Return: 1 if enabled, 0 if disabled
 */
static inline uint8_t
cdp_vdev_is_tx_delay_stats_enabled(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops || !soc->ops->host_stats_ops) {
		dp_cdp_debug("Invalid Instance:");
		return 0;
	}

	if (soc->ops->host_stats_ops->is_tx_delay_stats_enabled)
		return soc->ops->host_stats_ops->is_tx_delay_stats_enabled(soc,
								     vdev_id);

	return 0;
}
#endif

/**
 * cdp_get_pdev_tid_stats() - Get pdev tid stats
 * @soc: soc handle
 * @pdev_id: Pdev id
 * @tid_stats: Pointer to cdp_tid_stats_intf
 *
 * Return: status Success/Failure
 */
static inline QDF_STATUS
cdp_get_pdev_tid_stats(ol_txrx_soc_handle soc, uint8_t pdev_id,
		       struct cdp_tid_stats_intf *tid_stats)
{
	if (!soc || !soc->ops || !soc->ops->host_stats_ops) {
		dp_cdp_debug("Invalid Instance:");
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops->txrx_get_pdev_tid_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_pdev_tid_stats(soc, pdev_id,
								 tid_stats);
}

#ifdef WLAN_CONFIG_TELEMETRY_AGENT
/**
 * cdp_get_pdev_telemetry_stats() - function to get pdev telemetry stats
 * @soc: soc handle
 * @pdev_id: pdev id
 * @stats: pointer to pdev telemetry stats
 *
 * Return: status
 */
static inline QDF_STATUS cdp_get_pdev_telemetry_stats(
				ol_txrx_soc_handle soc,
				uint8_t pdev_id,
				struct cdp_pdev_telemetry_stats *stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_pdev_telemetry_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_pdev_telemetry_stats(
					soc, pdev_id, stats);
}

/**
 * cdp_get_peer_telemetry_stats() - function to get peer telemetry stats
 * @soc: soc handle
 * @addr: peer address
 * @stats: pointer to peer telemetry stats
 *
 * Return: status
 */
static inline QDF_STATUS cdp_get_peer_telemetry_stats(
				ol_txrx_soc_handle soc,
				uint8_t *addr,
				struct cdp_peer_telemetry_stats *stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_peer_telemetry_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_peer_telemetry_stats(
					soc, addr, stats);
}

/**
 * cdp_get_pdev_deter_stats(): function to get pdev deterministic stats
 * @soc: soc handle
 * @pdev_id: pdev id
 * @stats: pointer to pdev deterministic stats
 *
 * return: status
 */
static inline QDF_STATUS cdp_get_pdev_deter_stats(
				ol_txrx_soc_handle soc,
				uint8_t pdev_id,
				struct cdp_pdev_deter_stats *stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_pdev_deter_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_pdev_deter_stats(
					soc, pdev_id, stats);
}

/**
 * cdp_get_peer_deter_stats(): function to get peer deterministic stats
 * @soc: soc handle
 * @vdev_id: id of vdev handle
 * @addr: peer address
 * @stats: pointer to peer telemetry stats
 *
 * return: status
 */
static inline QDF_STATUS cdp_get_peer_deter_stats(
				ol_txrx_soc_handle soc,
				uint8_t vdev_id,
				uint8_t *addr,
				struct cdp_peer_deter_stats *stats)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_peer_deter_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_peer_deter_stats(
					soc, vdev_id, addr, stats);
}

/**
 * cdp_update_pdev_chan_util_stats(): function to update pdev channel util stats
 * @soc: soc handle
 * @pdev_id: pdev id
 * @ch_util: pointer to pdev ch util stats
 *
 * return: status
 */
static inline QDF_STATUS cdp_update_pdev_chan_util_stats(
				ol_txrx_soc_handle soc,
				uint8_t pdev_id,
				struct cdp_pdev_chan_util_stats *ch_util)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_update_pdev_chan_util_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_update_pdev_chan_util_stats(
					soc, pdev_id, ch_util);
}
#endif

/**
 * cdp_get_peer_extd_rate_link_stats() - cdp function to get peer
 *				extended rate and link stats
 * @soc: soc handle
 * @mac_addr: mac address
 *
 * Return: status
 */
static inline QDF_STATUS cdp_get_peer_extd_rate_link_stats(
					ol_txrx_soc_handle soc,
					uint8_t *mac_addr)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_peer_extd_rate_link_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_peer_extd_rate_link_stats(
								soc, mac_addr);
}

/**
 * cdp_get_pdev_obss_pd_stats() - function to get pdev obss stats
 * @soc: soc handle
 * @pdev_id: pdev id
 * @stats: pointer to pdev obss stats
 * @req: Pointer to CDP TxRx stats
 *
 * Return: status
 */
static inline QDF_STATUS cdp_get_pdev_obss_pd_stats(
				ol_txrx_soc_handle soc,
				uint8_t pdev_id,
				struct cdp_pdev_obss_pd_stats_tlv *stats,
				struct cdp_txrx_stats_req *req)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->get_pdev_obss_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->get_pdev_obss_stats(
				     soc, pdev_id, stats, req);
}

/**
 * cdp_clear_pdev_obss_pd_stats() - function to clear pdev obss stats
 * @soc: soc handle
 * @pdev_id: pdev id
 * @req: Pointer to CDP TxRx stats request. mac_id will be pre-filled
 *	 and should not be overwritten
 *
 * Return: status
 */
static inline QDF_STATUS cdp_clear_pdev_obss_pd_stats(
				ol_txrx_soc_handle soc,
				uint8_t pdev_id, struct cdp_txrx_stats_req *req)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->clear_pdev_obss_pd_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->clear_pdev_obss_pd_stats(
					soc, pdev_id, req);
}

/*
 * cdp_host_get_interface_stats - Get vdev stats for ath interface
 * @soc: soc handle
 * @vdev_id: vdev_id
 * @buf: buffer to hold vdev_stats
 *
 * return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_host_get_interface_stats(ol_txrx_soc_handle soc,
			     uint8_t vdev_id,
			     struct cdp_vdev_stats *buf)
{
	if (!soc || !soc->ops) {
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_get_interface_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_get_interface_stats(soc,
								  vdev_id,
								  buf,
								  true);
}
#endif /* _CDP_TXRX_HOST_STATS_H_ */
