/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2019-2020, The Linux Foundation. All rights reserved. */

#ifndef __CNSS_GENL_H__
#define __CNSS_GENL_H__

#define CNSS_GENL_FAMILY_NAME "cnss-genl"
#define CNSS_GENL_MCAST_GROUP_NAME "cnss-genl-grp"
#define CNSS_GENL_VERSION 1
#define CNSS_GENL_DATA_LEN_MAX (15 * 1024)
#define CNSS_GENL_STR_LEN_MAX 16
#define CNSS_GENL_SEND_RETRY_COUNT 10
#define CNSS_GENL_SEND_RETRY_DELAY 200

enum cnss_genl_msg_type {
	CNSS_GENL_MSG_TYPE_UNSPEC,
	CNSS_GENL_MSG_TYPE_QDSS,
};

enum cnss_genl_msg_attrs {
	CNSS_GENL_ATTR_MSG_UNSPEC,
	CNSS_GENL_ATTR_MSG_TYPE,
	CNSS_GENL_ATTR_MSG_FILE_NAME,
	CNSS_GENL_ATTR_MSG_TOTAL_SIZE,
	CNSS_GENL_ATTR_MSG_SEG_ID,
	CNSS_GENL_ATTR_MSG_END,
	CNSS_GENL_ATTR_MSG_DATA_LEN,
	CNSS_GENL_ATTR_MSG_DATA,
	CNSS_GENL_ATTR_MSG_INSTANCE_ID,
	CNSS_GENL_ATTR_MSG_VALUE,

	/* keep last */
	CNSS_GENL_ATTR_MSG_LAST,
	CNSS_GENL_ATTR_MSG_MAX = CNSS_GENL_ATTR_MSG_LAST - 1,
};

/**
 * enum cnss_genl_xdump_attrs: Attributes used by %CNSS_GENL_CMD_XDUMP command.
 * @CNSS_GENL_ATTR_XDUMP_SUBCMD: u8, sub command for XDUMP command.
 *  Uses values from enum cnss_genl_xdump_subcmds.
 *
 * @CNSS_GENL_ATTR_XDUMP_RESULT: s32, result of XDUMP
 *  Uses values from linux error numbers
 *
 * @CNSS_GENL_ATTR_XDUMP_WL_SRAM_ADDR: u32, Offset from WLAN SRAM start address
 *
 * @CNSS_GENL_ATTR_XDUMP_WL_SRAM_SIZE: u32, size of SRAM to be dumped
 *
 * @CNSS_GENL_ATTR_XDUMP_WL_OVER_BT_SUPPORT: flag
 *  Indicate supportance of dumping WLAN over BT
 *
 * @CNSS_GENL_ATTR_XDUMP_BT_OVER_WL_SUPPORT: flag
 *  Indicate supportance of dumping BT over WLAN
 *
 * !!Important!!
 * This enumeration is defined both in cnss and in userspace.
 * If you need to modify it, ensure that changes are made in all places.
 */
enum cnss_genl_xdump_attrs {
	CNSS_GENL_ATTR_XDUMP_UNSPEC,
	CNSS_GENL_ATTR_XDUMP_SUBCMD,
	CNSS_GENL_ATTR_XDUMP_RESULT,
	CNSS_GENL_ATTR_XDUMP_WL_SRAM_ADDR,
	CNSS_GENL_ATTR_XDUMP_WL_SRAM_SIZE,
	CNSS_GENL_ATTR_XDUMP_WL_OVER_BT_SUPPORT,
	CNSS_GENL_ATTR_XDUMP_BT_OVER_WL_SUPPORT,

	/* keep last */
	CNSS_GENL_ATTR_XDUMP_LAST,
	CNSS_GENL_ATTR_XDUMP_MAX = CNSS_GENL_ATTR_XDUMP_LAST - 1,
};

/**
 * enum cnss_genl_xdump_subcmds: Sub commands for Cross Module Dump
 * @CNSS_GENL_XDUMP_SUBCMD_BT_ARRIVAL: Indicate BT info for dumping
 *  The mandatory attributes used with this sub command:
 *  CNSS_GENL_ATTR_XDUMP_WL_OVER_BT_SUPPORT
 *  CNSS_GENL_ATTR_XDUMP_BT_OVER_WL_SUPPORT
 *
 * @CNSS_GENL_XDUMP_SUBCMD_BT_OVER_WL_REQ: Request for dumping BT over WLAN
 *
 * @CNSS_GENL_XDUMP_SUBCMD_BT_OVER_WL_RESP: Response for dumping BT over WLAN
 *  The mandatory attribute used with this sub command:
 *  CNSS_GENL_ATTR_XDUMP_RESULT
 *
 * @CNSS_GENL_XDUMP_SUBCMD_WL_ARRIVAL: Indicate WLAN info for dumping
 *  The mandatory attributes used with this sub command:
 *  CNSS_GENL_ATTR_XDUMP_WL_SRAM_ADDR,
 *  CNSS_GENL_ATTR_XDUMP_WL_SRAM_SIZE,
 *  CNSS_GENL_ATTR_XDUMP_WL_OVER_BT_SUPPORT
 *  CNSS_GENL_ATTR_XDUMP_BT_OVER_WL_SUPPORT
 *
 * @CNSS_GENL_XDUMP_SUBCMD_WL_OVER_BT_REQ: Request for dumping WLAN over BT
 *
 * @CNSS_GENL_XDUMP_SUBCMD_WL_OVER_BT_RESP:  Response for dumping WLAN over BT
 *  The mandatory attribute used with this sub command:
 *  CNSS_GENL_ATTR_XDUMP_RESULT
 *
 * !!Important!!
 * This enumeration is defined both in cnss and in userspace.
 * If you need to modify it, ensure that changes are made in all places.
 */
enum cnss_genl_xdump_subcmds {
	CNSS_GENL_XDUMP_SUBCMD_UNSPEC,
	CNSS_GENL_XDUMP_SUBCMD_BT_ARRIVAL,
	CNSS_GENL_XDUMP_SUBCMD_BT_OVER_WL_REQ,
	CNSS_GENL_XDUMP_SUBCMD_BT_OVER_WL_RESP,
	CNSS_GENL_XDUMP_SUBCMD_WL_ARRIVAL,
	CNSS_GENL_XDUMP_SUBCMD_WL_OVER_BT_REQ,
	CNSS_GENL_XDUMP_SUBCMD_WL_OVER_BT_RESP,

	/* keep last */
	CNSS_GENL_XDUMP_SUBCMD_LAST,
	CNSS_GENL_XDUMP_SUBCMD_MAX = CNSS_GENL_XDUMP_SUBCMD_LAST - 1,
};

/**
 * enum cnss_genl_cmds: Commands for cnss genl
 *
 * @CNSS_GENL_CMD_MSG: Command for legacy messages
 *  The attributes used with this command are in the enum cnss_genl_msg_attrs.
 *
 * @CNSS_GENL_CMD_XDUMP: Command for WLAN/BT cross-module dump
 *  The attributes used with this command are in the enum cnss_genl_xdump_attrs.
 *
 * !!Important!!
 * This enumeration is defined both in cnss and in userspace.
 * If you need to modify it, ensure that changes are made in all places.
 */
enum cnss_genl_cmds {
	CNSS_GENL_CMD_UNSPEC,
	CNSS_GENL_CMD_MSG,
	CNSS_GENL_CMD_XDUMP,

	/* keep last */
	CNSS_GENL_CMD_LAST,
	CNSS_GENL_CMD_MAX = CNSS_GENL_CMD_LAST - 1,
};

int cnss_genl_init(void);
void cnss_genl_exit(void);
int cnss_genl_send_msg(void *buff, u8 type,
		       char *file_name, u32 total_size);

/**
 * cnss_genl_send_xdump_wlan_arrival - Sends XDUMP WLAN arrival message with
 * provided params
 * @wlan_dump_over_bt: Indicates if collecting WLAN dump over BT is supported
 * @bt_dump_over_wlan: Indicates if collecting BT dump over WLAN is supported
 * @sram_start: Offset from WLAN SRAM start address
 * @sram_size: Size of SRAM to be dumpped
 *
 * Return: 0 on success, errno otherwise
 */
int cnss_genl_send_xdump_wlan_arrival(u8 wlan_dump_over_bt,
				      u8 bt_dump_over_wlan,
				      u32 sram_start,
				      u32 sram_size);

/**
 * cnss_genl_send_xdump_bt_over_wl_resp - Sends response to the request for
 * collecting BT dump over WLAN.
 * @result: The processing result of the request for collecting BT dump over
 * WLAN.
 *
 * Return: 0 on success, errno otherwise
 */
int cnss_genl_send_xdump_bt_over_wl_resp(s32 result);

/**
 * cnss_genl_send_xdump_wl_over_bt_req - Sends request for collecting
 * WLAN dump over BT.
 *
 * Return: 0 on success, errno otherwise
 */
int cnss_genl_send_xdump_wl_over_bt_req(void);
#endif
