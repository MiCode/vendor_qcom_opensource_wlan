// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#define pr_fmt(fmt) "cnss_genl: " fmt

#include <linux/err.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#include "main.h"
#include "debug.h"
#include "genl.h"

static struct nla_policy cnss_genl_msg_policy[CNSS_GENL_ATTR_MSG_MAX + 1] = {
	[CNSS_GENL_ATTR_MSG_TYPE] = { .type = NLA_U8 },
	[CNSS_GENL_ATTR_MSG_FILE_NAME] = { .type = NLA_NUL_STRING,
					   .len = CNSS_GENL_STR_LEN_MAX },
	[CNSS_GENL_ATTR_MSG_TOTAL_SIZE] = { .type = NLA_U32 },
	[CNSS_GENL_ATTR_MSG_SEG_ID] = { .type = NLA_U32 },
	[CNSS_GENL_ATTR_MSG_END] = { .type = NLA_U8 },
	[CNSS_GENL_ATTR_MSG_DATA_LEN] = { .type = NLA_U32 },
	[CNSS_GENL_ATTR_MSG_DATA] = { .type = NLA_BINARY,
				      .len = CNSS_GENL_DATA_LEN_MAX },
};

static struct nla_policy
cnss_genl_xdump_policy[CNSS_GENL_ATTR_XDUMP_MAX + 1] = {
	[CNSS_GENL_ATTR_XDUMP_SUBCMD] = { .type = NLA_U8 },
	[CNSS_GENL_ATTR_XDUMP_RESULT] = { .type = NLA_S32 },
	[CNSS_GENL_ATTR_XDUMP_WL_SRAM_ADDR] = { .type = NLA_U32 },
	[CNSS_GENL_ATTR_XDUMP_WL_SRAM_SIZE] = { .type = NLA_U32 },
	[CNSS_GENL_ATTR_XDUMP_WL_OVER_BT_SUPPORT] = { .type = NLA_FLAG },
	[CNSS_GENL_ATTR_XDUMP_BT_OVER_WL_SUPPORT] = { .type = NLA_FLAG },
};

static int cnss_genl_process_msg(struct sk_buff *skb, struct genl_info *info)
{
	return 0;
}

/**
 * cnss_genl_xdump_bt_arrival_hdl - Handler for XDUMP_SUBCMD_BT_ARRIVAL
 * @plat_priv: pointer to cnss platform data
 * @attrs: Parsed attributes array for XDUMP
 *
 * Return: None
 */
static void cnss_genl_xdump_bt_arrival_hdl(struct cnss_plat_data *plat_priv,
					   struct nlattr **attrs)
{
	struct cnss_xdump_cap *bt_cap;

	bt_cap = kzalloc(sizeof(*bt_cap), GFP_KERNEL);
	if (!bt_cap) {
		cnss_genl_send_xdump_wlan_arrival(0, 0, 0, 0);
		return;
	}

	bt_cap->indicated = true;
	bt_cap->wl_over_bt =
		nla_get_flag(attrs[CNSS_GENL_ATTR_XDUMP_WL_OVER_BT_SUPPORT]);
	bt_cap->bt_over_wl =
		nla_get_flag(attrs[CNSS_GENL_ATTR_XDUMP_BT_OVER_WL_SUPPORT]);
	cnss_pr_info("Received XDUMP_SUBCMD_BT_ARRIVAL: wl_over_bt: %d, bt_over_wl %d\n",
		     bt_cap->wl_over_bt, bt_cap->bt_over_wl);

	cnss_driver_event_post(plat_priv,
			       CNSS_DRIVER_EVENT_XDUMP_BT_ARRIVAL,
			       0, bt_cap);
}

/**
 * cnss_genl_xdump_bt_over_wl_req_hdl - Handler for XDUMP_SUBCMD_BT_OVER_WL_REQ
 * @plat_priv: pointer to cnss platform data
 * @attrs: Parsed attributes array for XDUMP
 *
 * Return: None
 */
static void cnss_genl_xdump_bt_over_wl_req_hdl(struct cnss_plat_data *plat_priv,
					       struct nlattr **attrs)
{
	cnss_pr_info("Received XDUMP_SUBCMD_BT_OVER_WL_REQ\n");
	cnss_driver_event_post(plat_priv,
			       CNSS_DRIVER_EVENT_XDUMP_BT_OVER_WL_REQ,
			       0, NULL);
}

/**
 * cnss_genl_xdump_wl_over_bt_resp_hdl - Handler for
 * XDUMP_SUBCMD_WL_OVER_BT_RESP
 * @plat_priv: pointer to cnss platform data
 * @attrs: Parsed attributes array for XDUMP
 *
 * Return: None
 */
static void
cnss_genl_xdump_wl_over_bt_resp_hdl(struct cnss_plat_data *plat_priv,
				    struct nlattr **attrs)
{
	s32 result;

	result = nla_get_s32(attrs[CNSS_GENL_ATTR_XDUMP_RESULT]);
	cnss_pr_info("Received XDUMP_SUBCMD_WL_OVER_BT_RESP: result %d\n",
		     result);
	cnss_xdump_wl_over_bt_complete(plat_priv, result);
}

/**
 * cnss_genl_process_xdump - Handler for netlink message CNSS_GENL_CMD_XDUMP
 * @skb: socket buffer holding the message
 * @info: receiving information
 *
 * Return: 0 on success, errno otherwise
 */
static int cnss_genl_process_xdump(struct sk_buff *skb, struct genl_info *info)
{
	u8 subcmd;
	struct cnss_plat_data *plat_priv;
	struct nlattr **attrs = info->attrs;

	plat_priv = cnss_get_first_plat_priv();
	if (!plat_priv) {
		cnss_pr_err("cnss not ready\n");
		return -ENODEV;
	}

	if (!attrs[CNSS_GENL_ATTR_XDUMP_SUBCMD]) {
		cnss_pr_err("No CNSS_GENL_ATTR_XDUMP_SUBCMD\n");
		return -EINVAL;
	}

	subcmd = nla_get_u8(attrs[CNSS_GENL_ATTR_XDUMP_SUBCMD]);
	switch (subcmd) {
	case CNSS_GENL_XDUMP_SUBCMD_BT_ARRIVAL:
		cnss_genl_xdump_bt_arrival_hdl(plat_priv, attrs);
		break;
	case CNSS_GENL_XDUMP_SUBCMD_BT_OVER_WL_REQ:
		cnss_genl_xdump_bt_over_wl_req_hdl(plat_priv, attrs);
		break;
	case CNSS_GENL_XDUMP_SUBCMD_WL_OVER_BT_RESP:
		cnss_genl_xdump_wl_over_bt_resp_hdl(plat_priv, attrs);
		break;
	default:
		cnss_pr_err("Unrecognized subcmd: %d\n", subcmd);
		return -EINVAL;
	}

	return 0;
}

static struct genl_ops cnss_genl_ops[] = {
	{
		.cmd = CNSS_GENL_CMD_MSG,
		.doit = cnss_genl_process_msg,
		.policy = cnss_genl_msg_policy,
		.maxattr = CNSS_GENL_ATTR_MSG_MAX,
	},
	{
		.cmd = CNSS_GENL_CMD_XDUMP,
		.doit = cnss_genl_process_xdump,
		.policy = cnss_genl_xdump_policy,
		.maxattr = CNSS_GENL_ATTR_XDUMP_MAX,
	},
};

static struct genl_multicast_group cnss_genl_mcast_grp[] = {
	{
		.name = CNSS_GENL_MCAST_GROUP_NAME,
	},
};

static struct genl_family cnss_genl_family = {
	.id = 0,
	.hdrsize = 0,
	.name = CNSS_GENL_FAMILY_NAME,
	.version = CNSS_GENL_VERSION,
	.module = THIS_MODULE,
	.ops = cnss_genl_ops,
	.n_ops = ARRAY_SIZE(cnss_genl_ops),
	.mcgrps = cnss_genl_mcast_grp,
	.n_mcgrps = ARRAY_SIZE(cnss_genl_mcast_grp),
};

int cnss_genl_send_xdump_wlan_arrival(u8 wlan_dump_over_bt,
				      u8 bt_dump_over_wlan,
				      u32 sram_start,
				      u32 sram_size)
{
	struct sk_buff *skb;
	void *msg_header;
	int ret = 0;
	u8 subcmd = CNSS_GENL_XDUMP_SUBCMD_WL_ARRIVAL;

	skb = genlmsg_new(NLMSG_HDRLEN +
			  nla_total_size(sizeof(subcmd)) +
			  nla_total_size(sizeof(wlan_dump_over_bt)) +
			  nla_total_size(sizeof(bt_dump_over_wlan)) +
			  nla_total_size(sizeof(sram_start)) +
			  nla_total_size(sizeof(sram_size)), GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto fail;
	}

	msg_header = genlmsg_put(skb, 0, 0,
				 &cnss_genl_family, 0,
				 CNSS_GENL_CMD_XDUMP);
	if (!msg_header) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = nla_put_u8(skb, CNSS_GENL_ATTR_XDUMP_SUBCMD, subcmd);
	if (ret < 0)
		goto fail;

	if (wlan_dump_over_bt) {
		ret = nla_put_flag(skb,
				   CNSS_GENL_ATTR_XDUMP_WL_OVER_BT_SUPPORT);
		if (ret < 0)
			goto fail;
	}

	if (bt_dump_over_wlan) {
		ret = nla_put_flag(skb,
				   CNSS_GENL_ATTR_XDUMP_BT_OVER_WL_SUPPORT);
		if (ret < 0)
			goto fail;
	}

	ret = nla_put_u32(skb, CNSS_GENL_ATTR_XDUMP_WL_SRAM_ADDR, sram_start);
	if (ret < 0)
		goto fail;

	ret = nla_put_u32(skb, CNSS_GENL_ATTR_XDUMP_WL_SRAM_SIZE, sram_size);
	if (ret < 0)
		goto fail;

	genlmsg_end(skb, msg_header);
	ret = genlmsg_multicast(&cnss_genl_family, skb, 0, 0, GFP_KERNEL);
	goto out;

fail:
	if (skb)
		nlmsg_free(skb);
out:
	cnss_pr_info("Send XDUMP_SUBCMD_WL_ARRIVAL(wl_over_bt: %d, bt_over_wl: %d, sram_addr: 0x%x, sram_size: 0x%x): %d\n",
		     wlan_dump_over_bt, bt_dump_over_wlan,
		     sram_start, sram_size, ret);
	return ret;
}

int cnss_genl_send_xdump_bt_over_wl_resp(s32 result)
{
	struct sk_buff *skb;
	void *msg_header;
	int ret = 0;
	u8 subcmd = CNSS_GENL_XDUMP_SUBCMD_BT_OVER_WL_RESP;

	skb = genlmsg_new(NLMSG_HDRLEN +
			  nla_total_size(sizeof(subcmd)) +
			  nla_total_size(sizeof(result)), GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto fail;
	}

	msg_header = genlmsg_put(skb, 0, 0,
				 &cnss_genl_family, 0,
				 CNSS_GENL_CMD_XDUMP);
	if (!msg_header) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = nla_put_u8(skb, CNSS_GENL_ATTR_XDUMP_SUBCMD, subcmd);
	if (ret < 0)
		goto fail;

	ret = nla_put_s32(skb, CNSS_GENL_ATTR_XDUMP_RESULT, result);
	if (ret < 0)
		goto fail;

	genlmsg_end(skb, msg_header);
	ret = genlmsg_multicast(&cnss_genl_family, skb, 0, 0, GFP_KERNEL);
	goto out;

fail:
	if (skb)
		nlmsg_free(skb);
out:
	cnss_pr_info("Send XDUMP_SUBCMD_BT_OVER_WL_RESP(%d): %d\n",
		     result, ret);
	return ret;
}

int cnss_genl_send_xdump_wl_over_bt_req(void)
{
	struct sk_buff *skb;
	void *msg_header;
	int ret = 0;
	u8 subcmd = CNSS_GENL_XDUMP_SUBCMD_WL_OVER_BT_REQ;

	skb = genlmsg_new(NLMSG_HDRLEN +
			  nla_total_size(sizeof(subcmd)), GFP_KERNEL);
	if (!skb) {
		ret = -ENOMEM;
		goto fail;
	}

	msg_header = genlmsg_put(skb, 0, 0,
				 &cnss_genl_family, 0,
				 CNSS_GENL_CMD_XDUMP);
	if (!msg_header) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = nla_put_u8(skb, CNSS_GENL_ATTR_XDUMP_SUBCMD, subcmd);
	if (ret < 0)
		goto fail;

	genlmsg_end(skb, msg_header);
	ret = genlmsg_multicast(&cnss_genl_family, skb, 0, 0, GFP_KERNEL);
	goto out;

fail:
	if (skb)
		nlmsg_free(skb);
out:
	cnss_pr_info("Send XDUMP_SUBCMD_WL_OVER_BT_REQ: %d\n", ret);
	return ret;
}

static int cnss_genl_send_data(u8 type, char *file_name, u32 total_size,
			       u32 seg_id, u8 end, u32 data_len, u8 *msg_buff)
{
	struct sk_buff *skb = NULL;
	void *msg_header = NULL;
	int ret = 0;
	char filename[CNSS_GENL_STR_LEN_MAX + 1];

	cnss_pr_dbg_buf("type: %u, file_name %s, total_size: %x, seg_id %u, end %u, data_len %u\n",
			type, file_name, total_size, seg_id, end, data_len);

	if (!file_name)
		strscpy(filename, "default", sizeof(filename));
	else
		strscpy(filename, file_name, sizeof(filename));

	skb = genlmsg_new(NLMSG_HDRLEN +
			  nla_total_size(sizeof(type)) +
			  nla_total_size(strlen(filename) + 1) +
			  nla_total_size(sizeof(total_size)) +
			  nla_total_size(sizeof(seg_id)) +
			  nla_total_size(sizeof(end)) +
			  nla_total_size(sizeof(data_len)) +
			  nla_total_size(data_len), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	msg_header = genlmsg_put(skb, 0, 0,
				 &cnss_genl_family, 0,
				 CNSS_GENL_CMD_MSG);
	if (!msg_header) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = nla_put_u8(skb, CNSS_GENL_ATTR_MSG_TYPE, type);
	if (ret < 0)
		goto fail;
	ret = nla_put_string(skb, CNSS_GENL_ATTR_MSG_FILE_NAME, filename);
	if (ret < 0)
		goto fail;
	ret = nla_put_u32(skb, CNSS_GENL_ATTR_MSG_TOTAL_SIZE, total_size);
	if (ret < 0)
		goto fail;
	ret = nla_put_u32(skb, CNSS_GENL_ATTR_MSG_SEG_ID, seg_id);
	if (ret < 0)
		goto fail;
	ret = nla_put_u8(skb, CNSS_GENL_ATTR_MSG_END, end);
	if (ret < 0)
		goto fail;
	ret = nla_put_u32(skb, CNSS_GENL_ATTR_MSG_DATA_LEN, data_len);
	if (ret < 0)
		goto fail;
	ret = nla_put(skb, CNSS_GENL_ATTR_MSG_DATA, data_len, msg_buff);
	if (ret < 0)
		goto fail;

	genlmsg_end(skb, msg_header);
	ret = genlmsg_multicast(&cnss_genl_family, skb, 0, 0, GFP_KERNEL);

	return ret;
fail:
	cnss_pr_err("Fail to generate genl msg: %d\n", ret);
	if (skb)
		nlmsg_free(skb);
	return ret;
}

int cnss_genl_send_msg(void *buff, u8 type, char *file_name, u32 total_size)
{
	int ret = 0;
	u8 *msg_buff = buff;
	u32 remaining = total_size;
	u32 seg_id = 0;
	u32 data_len = 0;
	u8 end = 0;
	u8 retry;

	cnss_pr_dbg_buf("type: %u, total_size: %x\n", type, total_size);

	while (remaining) {
		if (remaining > CNSS_GENL_DATA_LEN_MAX) {
			data_len = CNSS_GENL_DATA_LEN_MAX;
		} else {
			data_len = remaining;
			end = 1;
		}

		for (retry = 0; retry < CNSS_GENL_SEND_RETRY_COUNT; retry++) {
			ret = cnss_genl_send_data(type, file_name, total_size,
						  seg_id, end, data_len,
						  msg_buff);
			if (ret >= 0)
				break;

			cnss_pr_err("Fail to send genl seg_id %d: %d, try %d\n",
				    seg_id, ret, retry+1);

			msleep(CNSS_GENL_SEND_RETRY_DELAY);
		}

		if (ret < 0) {
			cnss_pr_err("fail to send genl msg, ret %d\n", ret);
			return ret;
		}

		remaining -= data_len;
		msg_buff += data_len;
		seg_id++;
	}

	return ret;
}

int cnss_genl_init(void)
{
	int ret = 0;

	ret = genl_register_family(&cnss_genl_family);
	if (ret != 0)
		cnss_pr_err("genl_register_family fail: %d\n", ret);

	return ret;
}

void cnss_genl_exit(void)
{
	genl_unregister_family(&cnss_genl_family);
}
