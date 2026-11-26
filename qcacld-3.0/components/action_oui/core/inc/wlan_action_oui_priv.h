/*
 * Copyright (c) 2012-2018 The Linux Foundation. All rights reserved.
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
 * DOC: Declare private API which shall be used internally only
 * in action_oui component. This file shall include prototypes of
 * action_oui parsing and send logic.
 *
 * Note: This API should be never accessed out of action_oui component.
 */

#ifndef _WLAN_ACTION_OUI_PRIV_STRUCT_H_
#define _WLAN_ACTION_OUI_PRIV_STRUCT_H_

#include <qdf_list.h>
#include <qdf_types.h>
#include "wlan_action_oui_public_struct.h"
#include "wlan_action_oui_tgt_api.h"
#include "wlan_action_oui_objmgr.h"

/**
 * struct action_oui_extension_priv - Private contents of extension.
 * @item: list element
 * @extension: Extension contents
 *
 * This structure encapsulates action_oui_extension and list item.
 */
struct action_oui_extension_priv {
	qdf_list_node_t item;
	struct action_oui_extension extension;
};

/**
 * struct action_oui_priv - Each action info.
 * @id: type of action
 * @extension_list: list of extensions
 * @extension_lock: lock to control access to @extension_list
 *
 * All extensions of action specified by action_id are stored
 * at @extension_list as linked list.
 */
struct action_oui_priv {
	enum action_oui_id id;
	qdf_list_t extension_list;
	qdf_mutex_t extension_lock;
};

/**
 * struct action_oui_psoc_priv - Private object to be stored in psoc
 * @psoc: pointer to psoc object
 * @action_oui_enable: action oui enable config
 * @action_oui_str: oui configuration strings
 * @total_extensions: total count of extensions from all actions
 * @host_only_extensions: total host only only extensions from all actions
 * @max_extensions: Max no. of extensions that can be configured to the firmware
 * @oui_priv: array of pointers used to refer each action info
 * @tx_ops: call-back functions to send OUIs to firmware
 * @is_action_oui_v2_enabled: Is action oui v2 enabled
 * @is_action_oui_v2_used: Is action oui v2 used per action id
 */
struct action_oui_psoc_priv {
	struct wlan_objmgr_psoc *psoc;
	uint8_t action_oui_enable;
	uint8_t action_oui_str[ACTION_OUI_MAXIMUM_ID][ACTION_OUI_MAX_STR_LEN];
	uint32_t total_extensions;
	uint32_t host_only_extensions;
	uint32_t max_extensions;
	struct action_oui_priv *oui_priv[ACTION_OUI_MAXIMUM_ID];
	struct action_oui_tx_ops tx_ops;
	bool is_action_oui_v2_enabled;
	bool is_action_oui_v2_used[ACTION_OUI_MAXIMUM_ID];
};

/**
 * action_oui_parse() - Parse action oui string
 * @psoc_priv: pointer to action_oui psoc priv obj
 * @oui_string: string to be parsed
 * @action_id: type of the action to be parsed
 *
 * This function parses the action oui string, extracts extensions and
 * stores them @action_oui_priv using list data structure.
 *
 * Return: QDF_STATUS
 *
 */
QDF_STATUS
action_oui_parse(struct action_oui_psoc_priv *psoc_priv,
		 uint8_t *oui_string, enum action_oui_id action_id);

/**
 * action_oui_parse_string() - Parse action oui string
 * @psoc: psoc object
 * @in_str: string to be parsed
 * @action_id: type of the action to be parsed
 *
 * This function will validate the input string and call action_oui_parse
 * to parse it.
 *
 * Return: QDF_STATUS
 *
 */
QDF_STATUS
action_oui_parse_string(struct wlan_objmgr_psoc *psoc,
			const uint8_t *in_str,
			enum action_oui_id action_id);

/**
 * action_oui_send() - Send action oui extensions to target_if.
 * @psoc_priv: pointer to action_oui psoc priv obj
 * @action_id: type of the action to send
 *
 * This function sends action oui extensions to target_if.
 *
 * Return: QDF_STATUS
 *
 */
QDF_STATUS
action_oui_send(struct action_oui_psoc_priv *psoc_priv,
		enum action_oui_id action_id);

/**
 * action_oui_search() - Check if Vendor OUIs are present in IE buffer
 * @psoc_priv: pointer to action_oui psoc priv obj
 * @attr: pointer to structure containing type of action, beacon IE data etc.,
 * @action_id: type of action to be checked
 *
 * This function parses the IE buffer and finds if any of the vendor OUI
 * and related attributes are present in it.
 *
 * Return: If vendor OUI is present return true else false
 */
bool
action_oui_search(struct action_oui_psoc_priv *psoc_priv,
		  struct action_oui_search_attr *attr,
		  enum action_oui_id action_id);

/**
 * action_oui_is_empty() - Check action oui present or not
 * @psoc_priv: action psoc private object
 * @action_id: action oui id
 *
 * This function will check action oui present or not for specific action type.
 *
 * Return: True if no action oui for the action type.
 */
bool
action_oui_is_empty(struct action_oui_psoc_priv *psoc_priv,
		    enum action_oui_id action_id);

/**
 * action_oui_extension_store() - store action oui extension
 * @psoc_priv: pointer to action_oui priv obj
 * @oui_priv: type of the action
 * @ext: pointer to oui extension to store in psoc
 * @oui_ext_num: number of action oui extension to be stored
 *
 * This function stores oui extension to psoc private object of
 * action oui component.
 *
 * Return: QDF_STATUS
 *
 */
QDF_STATUS
action_oui_extension_store(struct action_oui_psoc_priv *psoc_priv,
			   struct action_oui_priv *oui_priv,
			   struct action_oui_extension *ext,
			   uint8_t oui_ext_num);
#endif /* End  of _WLAN_ACTION_OUI_PRIV_STRUCT_H_ */
