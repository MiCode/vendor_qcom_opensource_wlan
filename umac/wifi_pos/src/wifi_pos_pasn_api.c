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
/**
 * DOC: wifi_pos_pasn_api.c
 * This file defines the 11az PASN authentication related APIs for wifi_pos
 * component.
 */

#include <wlan_lmac_if_def.h>
#include "wifi_pos_api.h"
#include "wifi_pos_pasn_api.h"
#include "wifi_pos_utils_i.h"
#include "wifi_pos_main_i.h"
#include "os_if_wifi_pos.h"
#include "os_if_wifi_pos_utils.h"
#include "target_if_wifi_pos.h"
#include "target_if_wifi_pos_rx_ops.h"
#include "wlan_objmgr_cmn.h"
#include "wlan_objmgr_global_obj.h"
#include "wlan_objmgr_psoc_obj.h"
#include "wlan_objmgr_peer_obj.h"
#include "wlan_lmac_if_def.h"

void wifi_pos_set_11az_failed_peers(struct wlan_objmgr_vdev *vdev,
				    struct qdf_mac_addr *mac_addr)
{
	struct wifi_pos_vdev_priv_obj *vdev_pos_obj;
	struct wifi_pos_11az_context *pasn_context;
	uint8_t i;

	vdev_pos_obj = wifi_pos_get_vdev_priv_obj(vdev);
	if (!vdev_pos_obj) {
		wifi_pos_err("Wifi pos vdev priv obj is null");
		return;
	}

	pasn_context = &vdev_pos_obj->pasn_context;
	if (!pasn_context->num_failed_peers)
		goto add_failed_peer;

	for (i = 0; i < WLAN_MAX_11AZ_PEERS; i++) {
		if (qdf_is_macaddr_equal(mac_addr,
					 &pasn_context->failed_peer_list[i])) {
			wifi_pos_debug("Peer: " QDF_MAC_ADDR_FMT " already exists in failed list",
				       QDF_MAC_ADDR_REF(mac_addr->bytes));
			return;
		}
	}

add_failed_peer:
	for (i = 0; i < WLAN_MAX_11AZ_PEERS; i++) {
		if (qdf_is_macaddr_broadcast(
					&pasn_context->failed_peer_list[i])) {
			qdf_copy_macaddr(&pasn_context->failed_peer_list[i],
					 mac_addr);
			pasn_context->num_failed_peers++;
			wifi_pos_debug("Added failed peer: " QDF_MAC_ADDR_FMT " at idx[%d]",
				       QDF_MAC_ADDR_REF(mac_addr->bytes), i);

			return;
		}
	}

	wifi_pos_debug("Not able to set failed peer");
}

void wifi_pos_add_peer_to_list(struct wlan_objmgr_vdev *vdev,
			       struct wlan_pasn_request *req,
			       bool is_peer_create_required)
{
	struct wifi_pos_vdev_priv_obj *vdev_pos_obj;
	struct wifi_pos_11az_context *pasn_context;
	struct wlan_pasn_request *secure_list, *unsecure_list, *dst_entry;
	uint8_t i;

	vdev_pos_obj = wifi_pos_get_vdev_priv_obj(vdev);
	if (!vdev_pos_obj) {
		wifi_pos_err("Wifi pos vdev priv obj is null");
		return;
	}

	pasn_context = &vdev_pos_obj->pasn_context;
	secure_list = pasn_context->secure_peer_list;
	unsecure_list = pasn_context->unsecure_peer_list;

	/* Find the 1st empty slot and copy the entry to peer list */
	for (i = 0; i < WLAN_MAX_11AZ_PEERS; i++) {
		if (req->peer_type == WLAN_WIFI_POS_PASN_SECURE_PEER)
			dst_entry = &secure_list[i];
		else
			dst_entry = &unsecure_list[i];

		/* Current slot is not empty */
		if (!qdf_is_macaddr_broadcast(&dst_entry->peer_mac))
			continue;

		*dst_entry = *req;
		if (is_peer_create_required)
			pasn_context->num_pending_peer_creation++;

		if (req->peer_type == WLAN_WIFI_POS_PASN_SECURE_PEER)
			pasn_context->num_secure_peers++;
		else
			pasn_context->num_unsecure_peers++;

		wifi_pos_debug("Added %s peer: " QDF_MAC_ADDR_FMT " at idx[%d]",
			       (req->peer_type == WLAN_WIFI_POS_PASN_SECURE_PEER) ? "secure" : "unsecure",
			       QDF_MAC_ADDR_REF(mac_addr), i);

		break;
	}
}

/**
 * wifi_pos_move_peers_to_fail_list  - Move the peers in secure/unsecure list
 * to failed peer list
 * @vdev: Vdev pointer
 * @peer_mac: Peer mac address
 * @peer_type: Secure or unsecure PASN peer
 *
 * Return: None
 */
static
void wifi_pos_move_peers_to_fail_list(struct wlan_objmgr_vdev *vdev,
				      struct qdf_mac_addr *peer_mac,
				      enum wifi_pos_pasn_peer_type peer_type)
{
	uint8_t i;
	struct wifi_pos_vdev_priv_obj *vdev_pos_obj;
	struct wifi_pos_11az_context *pasn_context;
	struct wlan_pasn_request *secure_list, *unsecure_list, *list;
	struct qdf_mac_addr entry_to_copy;

	vdev_pos_obj = wifi_pos_get_vdev_priv_obj(vdev);
	if (!vdev_pos_obj) {
		wifi_pos_err("Wifi pos vdev priv obj is null");
		return;
	}

	pasn_context = &vdev_pos_obj->pasn_context;

	/*
	 * Broadcast mac address will be sent by caller when initiate
	 * external auth fails and to move the entire list to failed
	 * peers list
	 */
	if (qdf_is_macaddr_broadcast(peer_mac)) {
		/* Clear the entire list and move it to failed peers list */
		if (peer_type == WLAN_WIFI_POS_PASN_SECURE_PEER)
			list = pasn_context->secure_peer_list;
		else if (peer_type == WLAN_WIFI_POS_PASN_UNSECURE_PEER)
			list = pasn_context->secure_peer_list;

		for (i = 0; i < WLAN_MAX_11AZ_PEERS; i++) {
			/*
			 * if valid entry exist in the list, set that mac
			 * address to failed list and clear that mac from the
			 * secure/unsecure list
			 */
			if (!qdf_is_macaddr_broadcast(&list[i].peer_mac)) {
				wifi_pos_set_11az_failed_peers(
						vdev, &list[i].peer_mac);
				qdf_set_macaddr_broadcast(&list[i].peer_mac);
			}
		}

		return;
	}

	secure_list = pasn_context->secure_peer_list;
	unsecure_list = pasn_context->unsecure_peer_list;
	/*
	 * This condition is hit when peer create confirm for a pasn
	 * peer is received with failure status
	 */
	for (i = 0; i < WLAN_MAX_11AZ_PEERS; i++) {
		/*
		 * Clear the indvidual entry that exist for the given
		 * mac address in secure/unsecure list
		 */
		if (qdf_is_macaddr_equal(peer_mac, &secure_list[i].peer_mac)) {
			entry_to_copy = secure_list[i].peer_mac;
			qdf_set_macaddr_broadcast(&secure_list[i].peer_mac);
			pasn_context->num_secure_peers--;
		} else if (qdf_is_macaddr_equal(peer_mac,
			   &unsecure_list[i].peer_mac)) {
			entry_to_copy = unsecure_list[i].peer_mac;
			qdf_set_macaddr_broadcast(&unsecure_list[i].peer_mac);
			pasn_context->num_unsecure_peers--;
		} else {
			continue;
		}

		wifi_pos_set_11az_failed_peers(vdev, &entry_to_copy);
		break;
	}
}

static QDF_STATUS
wifi_pos_request_external_pasn_auth(struct wlan_objmgr_psoc *psoc,
				    struct wlan_objmgr_vdev *vdev)
{
	struct wifi_pos_vdev_priv_obj *vdev_pos_obj;
	struct wifi_pos_osif_ops *osif_cb;
	struct wifi_pos_11az_context *pasn_context;
	QDF_STATUS status;

	if (wlan_vdev_mlme_get_opmode(vdev) != QDF_STA_MODE)
		return QDF_STATUS_E_INVAL;

	osif_cb = wifi_pos_get_osif_callbacks(psoc);
	if (!osif_cb || !osif_cb->osif_initiate_pasn_cb) {
		wifi_pos_err("OSIF %s cb is NULL",
			     !osif_cb ? "" : "PASN");
		return QDF_STATUS_E_FAILURE;
	}

	vdev_pos_obj = wifi_pos_get_vdev_priv_obj(vdev);
	if (!vdev_pos_obj) {
		wifi_pos_err("Wifi pos vdev priv obj is null");
		return QDF_STATUS_E_FAILURE;
	}

	pasn_context = &vdev_pos_obj->pasn_context;

	status = osif_cb->osif_initiate_pasn_cb(vdev,
						pasn_context->secure_peer_list,
						pasn_context->num_secure_peers,
						true);

	return status;
}

static QDF_STATUS
wifi_pos_check_and_initiate_pasn_authentication(struct wlan_objmgr_psoc *psoc,
						struct wlan_objmgr_vdev *vdev,
						struct wifi_pos_11az_context *pasn_ctx)
{
	struct qdf_mac_addr bcast_mac = QDF_MAC_ADDR_BCAST_INIT;
	QDF_STATUS status;

	if (pasn_ctx->num_pending_peer_creation)
		return QDF_STATUS_SUCCESS;

	status = wifi_pos_request_external_pasn_auth(psoc, vdev);
	if (QDF_IS_STATUS_ERROR(status)) {
		wifi_pos_err("Initiate Pasn Authentication failed");
		wifi_pos_move_peers_to_fail_list(vdev, &bcast_mac,
						 WLAN_WIFI_POS_PASN_SECURE_PEER);
		/* TODO send PASN_STATUS cmd from here */
	}

	return status;
}

QDF_STATUS wifi_pos_handle_ranging_peer_create(struct wlan_objmgr_psoc *psoc,
					       struct wlan_pasn_request *req,
					       uint8_t vdev_id,
					       uint8_t total_entries)
{
	struct wifi_pos_legacy_ops *legacy_cb;
	struct wlan_objmgr_peer *peer;
	struct wlan_objmgr_vdev *vdev;
	struct wifi_pos_vdev_priv_obj *vdev_pos_obj;
	struct wifi_pos_11az_context *pasn_context;
	QDF_STATUS status;
	uint8_t i;

	legacy_cb = wifi_pos_get_legacy_ops(psoc);
	if (!legacy_cb || !legacy_cb->pasn_peer_create_cb) {
		wifi_pos_err("legacy callbacks is not registered");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_WIFI_POS_CORE_ID);
	if (!vdev) {
		wifi_pos_err("Vdev object is null");
		return QDF_STATUS_E_FAILURE;
	}

	wifi_pos_debug("PASN peer create request received. Num peers:%d",
		       total_entries);
	for (i = 0; i < total_entries; i++) {
		peer = wlan_objmgr_get_peer_by_mac(psoc, req[i].peer_mac.bytes,
						   WLAN_WIFI_POS_CORE_ID);
		/*
		 * If already PASN peer is found, then this is a request to
		 * initiate PASN authentication alone and not to send
		 * peer create to fw
		 */
		if (peer &&
		    (wlan_peer_get_peer_type(peer) == WLAN_PEER_RTT_PASN)) {
			wifi_pos_debug("PASN Peer: " QDF_MAC_ADDR_FMT "already exists",
				       QDF_MAC_ADDR_REF(req[i].peer_mac.bytes));
			wifi_pos_add_peer_to_list(vdev, &req[i], false);
			wlan_objmgr_peer_release_ref(peer,
						     WLAN_WIFI_POS_CORE_ID);
			continue;
		} else if (peer) {
			/*
			 * If a peer with given mac address already exists which
			 * is not a PASN peer, then move this peer to failed
			 * list
			 */
			wifi_pos_debug("Peer: " QDF_MAC_ADDR_FMT "of type:%d already exist",
				       QDF_MAC_ADDR_REF(req[i].peer_mac.bytes),
				       wlan_peer_get_peer_type(peer));
			wifi_pos_set_11az_failed_peers(vdev, &req[i].peer_mac);
			wlan_objmgr_peer_release_ref(peer,
						     WLAN_WIFI_POS_CORE_ID);
			continue;
		}

		status = legacy_cb->pasn_peer_create_cb(psoc, &req[i].peer_mac,
							vdev_id);
		if (QDF_IS_STATUS_ERROR(status)) {
			wifi_pos_set_11az_failed_peers(vdev, &req[i].peer_mac);
			continue;
		}
		wifi_pos_add_peer_to_list(vdev, &req[i], true);
	}

	vdev_pos_obj = wifi_pos_get_vdev_priv_obj(vdev);
	if (!vdev_pos_obj) {
		wifi_pos_err("Wifi pos vdev priv obj is null");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_WIFI_POS_CORE_ID);
		return QDF_STATUS_E_FAILURE;
	}

	/*
	 * This condition occurs when firmware requests for PASN peer
	 * create with all PASN peers which are already created.
	 */
	pasn_context = &vdev_pos_obj->pasn_context;
	status = wifi_pos_check_and_initiate_pasn_authentication(psoc, vdev,
								 pasn_context);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_WIFI_POS_CORE_ID);

	return status;
}

QDF_STATUS
wifi_pos_handle_ranging_peer_create_rsp(struct wlan_objmgr_psoc *psoc,
					uint8_t vdev_id,
					struct qdf_mac_addr *peer_mac,
					uint8_t peer_create_status)
{
	struct wlan_objmgr_vdev *vdev;
	struct wifi_pos_vdev_priv_obj *vdev_pos_obj;
	struct wifi_pos_11az_context *pasn_context;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_WIFI_POS_CORE_ID);
	if (!vdev) {
		wifi_pos_err("Vdev object is null");
		return QDF_STATUS_E_FAILURE;
	}

	vdev_pos_obj = wifi_pos_get_vdev_priv_obj(vdev);
	if (!vdev_pos_obj) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_WIFI_POS_CORE_ID);
		wifi_pos_err("Wifi pos vdev priv obj is null");
		return QDF_STATUS_E_FAILURE;
	}

	pasn_context = &vdev_pos_obj->pasn_context;
	if (pasn_context->num_pending_peer_creation)
		pasn_context->num_pending_peer_creation--;

	wifi_pos_debug("Received peer create response for " QDF_MAC_ADDR_FMT " status:%d pending_count:%d",
		       QDF_MAC_ADDR_REF(peer_mac.bytes), peer_create_status,
		       pasn_context->num_pending_peer_creation);
	if (peer_create_status)
		wifi_pos_move_peers_to_fail_list(vdev, peer_mac,
						 WLAN_WIFI_POS_PASN_PEER_TYPE_MAX);

	status = wifi_pos_check_and_initiate_pasn_authentication(psoc, vdev,
								 pasn_context);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_WIFI_POS_CORE_ID);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wifi_pos_handle_ranging_peer_delete(struct wlan_objmgr_psoc *psoc,
					       struct wlan_pasn_request *req,
					       uint8_t vdev_id,
					       uint8_t total_entries)
{
	struct wifi_pos_legacy_ops *legacy_cb;
	struct wlan_objmgr_peer *peer;
	bool no_fw_peer_delete;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	legacy_cb = wifi_pos_get_legacy_ops(psoc);
	if (!legacy_cb || !legacy_cb->pasn_peer_delete_cb) {
		wifi_pos_err("legacy callback is not registered");
		return QDF_STATUS_E_FAILURE;
	}

	for (i = 0; i < total_entries; i++) {
		peer = wlan_objmgr_get_peer_by_mac(psoc, req[i].peer_mac.bytes,
						   WLAN_WIFI_POS_CORE_ID);
		if (peer &&
		    (wlan_peer_get_peer_type(peer) == WLAN_PEER_RTT_PASN)) {
			no_fw_peer_delete = WIFI_POS_IS_PEER_ALREADY_DELETED(
							req[i].control_flags);
			wifi_pos_debug("Delete PASN Peer: " QDF_MAC_ADDR_FMT,
				       QDF_MAC_ADDR_REF(req[i].peer_mac.bytes));
			status = legacy_cb->pasn_peer_delete_cb(
						psoc, &req[i].peer_mac,
						vdev_id, no_fw_peer_delete);

			wlan_objmgr_peer_release_ref(peer,
						     WLAN_WIFI_POS_CORE_ID);
			continue;
		} else {
			wifi_pos_debug("PASN Peer: " QDF_MAC_ADDR_FMT "doesn't exist",
				       QDF_MAC_ADDR_REF(req[i].peer_mac.bytes));
			if (peer)
				wlan_objmgr_peer_release_ref(
						peer, WLAN_WIFI_POS_CORE_ID);

			continue;
		}
	}

	return QDF_STATUS_SUCCESS;
}
