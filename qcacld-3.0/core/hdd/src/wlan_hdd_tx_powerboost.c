/*
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
 * DOC: wlan_hdd_tx_powerboost.c
 *
 * WLAN Host Device Driver Tx powerboost API implementation
 */
#ifdef FEATURE_WLAN_TX_POWERBOOST
#include "wlan_hdd_main.h"
#include "cfg_ucfg_api.h"
#include "wlan_hdd_tx_powerboost.h"
#include "osif_vdev_sync.h"
#include "wlan_scan_public_structs.h"
#include <wlan_reg_ucfg_api.h>
#include "reg_services_public_struct.h"
#include "wlan_osif_priv.h"
#include "osif_psoc_sync.h"

#define TX_PB_DMA_SIZE (100 * 1024)
#define TXPB_MAX_REQ_COUNT 5
#define MEMORY_ALIGN      8
#define TX_PB_WAKE_LOCK_DURATION     1000
#define TXPB_DEVICE_NAME      "txpb"

#define ATTR_INFERENCE_MAX    QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MAX
#define CMD_TYPE              QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CMD_TYPE
#define BW                    QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_BW
#define CHANNEL_FREQ          QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CHANNEL_FREQ
#define CENTER_FREQ_1         QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CENTER_FREQ_1
#define CENTER_FREQ_2         QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CENTER_FREQ_2
#define MCS                   QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MCS
#define TEMPERATURE           QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TEMPERATURE
#define STAGE                 QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_STAGE
#define EVM                   QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_EVM
#define MASK_MARGIN           QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MASK_MARGIN
#define PHY_MODE              QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_PHY_MODE
#define SAMPLE_SIZE           QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_SAMPLE_SIZE
#define TX_PWR                QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TX_POWER
#define TX_CHAIN_IDX          QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TX_CHAIN_IDX
#define INFERENCE_STATUS      QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_STATUS
#define COOKIE                QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_COOKIE
#define CMD_APP_START         QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_APP_START
#define CMD_APP_STOP          QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_APP_STOP
#define CMD_RESULT            QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_RESULT
#define CMD_FAILURE           QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_FAILURE
#define STAGE_FIRST_PASS      QCA_WLAN_VENDOR_IQ_INFERENCE_STAGE_FIRST_PASS
#define STAGE_SECOND_PASS     QCA_WLAN_VENDOR_IQ_INFERENCE_STAGE_SECOND_PASS
#define STATUS_INFERENCE      QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_START_INFERENCE
#define STATUS_ABORT          QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_ABORT
#define STATUS_COMPLETE       QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_COMPLETE

const struct nla_policy qca_wlan_vendor_power_boost_policy
[ATTR_INFERENCE_MAX + 1] = {
	[CMD_TYPE] = {.type = NLA_U32},
	[BW] = {.type = NLA_U32},
	[CHANNEL_FREQ] = {.type = NLA_U32},
	[CENTER_FREQ_1] = {.type = NLA_U32},
	[CENTER_FREQ_2] = {.type = NLA_U32},
	[MCS] = {.type = NLA_U32},
	[TEMPERATURE] = {.type = NLA_S32},
	[STAGE] = {.type = NLA_U32},
	[EVM] = {.type = NLA_S32},
	[MASK_MARGIN] = {.type = NLA_S32},
	[PHY_MODE] = {.type = NLA_U32},
	[COOKIE] = {.type = NLA_U64},
};

void hdd_tx_powerboost_target_config(struct hdd_context *hdd_ctx,
				     struct wma_tgt_cfg *tgt_cfg)
{
	bool tx_pb_ini;

	tx_pb_ini = cfg_get(hdd_ctx->psoc, CFG_TX_POWERBOOST);
	hdd_ctx->tx_pb.tx_powerboost_enabled = tx_pb_ini &&
					       tgt_cfg->tx_powerboost;
	hdd_debug("TPB Enable: %d (Host: %d FW: %d)",
		  hdd_ctx->tx_pb.tx_powerboost_enabled, tx_pb_ini,
		  tgt_cfg->tx_powerboost);
}

static QDF_STATUS hdd_tx_powerboost_init_dma(struct hdd_context *hdd_ctx)
{
	qdf_device_t qdf_dev;
	struct reg_pdev_pb_dma_buf dma = {0};
	QDF_STATUS status;

	qdf_dev = wlan_psoc_get_qdf_dev(hdd_ctx->psoc);
	if (!qdf_dev) {
		hdd_err("TPB: Invalid qdf dev");
		return QDF_STATUS_E_FAILURE;
	}

	/*
	 * Set the buffer size to 100KB + 8 bytes for alignment
	 * 1KB = 1024B
	 */
	hdd_ctx->tx_pb.dma.size = TX_PB_DMA_SIZE;
	hdd_ctx->tx_pb.dma.vaddr = qdf_aligned_mem_alloc_consistent(
				qdf_dev, &hdd_ctx->tx_pb.dma.size,
				&hdd_ctx->tx_pb.dma.vaddr_unaligned,
				&hdd_ctx->tx_pb.dma.paddr_unaligned,
				&hdd_ctx->tx_pb.dma.paddr,
				MEMORY_ALIGN);
	if (!hdd_ctx->tx_pb.dma.vaddr) {
		hdd_err("TPB: DMA buffer allocation failed, size: %u",
			hdd_ctx->tx_pb.dma.size);
		return QDF_STATUS_E_NOMEM;
	}

	qdf_mem_set(hdd_ctx->tx_pb.dma.vaddr, hdd_ctx->tx_pb.dma.size, 0);
	dma.size = hdd_ctx->tx_pb.dma.size;
	qdf_dmaaddr_to_32s(hdd_ctx->tx_pb.dma.paddr,
			   &dma.paddr_aligned_lo,
			   &dma.paddr_aligned_hi);
	status = ucfg_reg_txpb_send_dma_addr(hdd_ctx->pdev, &dma);
	if (QDF_IS_STATUS_ERROR(status))
		hdd_err("TPB: ucfg_reg_txpb_send_dma_addr failed: %d", status);

	hdd_debug("TPB: DMA address sent to firmware");
	return status;
}

static void hdd_tx_powerboost_deinit_dma(struct hdd_context *hdd_ctx)
{
	qdf_device_t qdf_dev;

	qdf_dev = wlan_psoc_get_qdf_dev(hdd_ctx->psoc);
	if (!qdf_dev) {
		hdd_err("TPB: Invalid qdf dev");
		return;
	}

	if (!hdd_ctx->tx_pb.dma.vaddr_unaligned)
		return;

	qdf_mem_free_consistent(qdf_dev, qdf_dev->dev,
				hdd_ctx->tx_pb.dma.size,
				hdd_ctx->tx_pb.dma.vaddr_unaligned,
				hdd_ctx->tx_pb.dma.paddr_unaligned,
				0);
	hdd_ctx->tx_pb.dma.vaddr_unaligned = NULL;
	hdd_ctx->tx_pb.dma.vaddr = NULL;
	hdd_ctx->tx_pb.dma.size = 0;
	hdd_debug("TPB: DMA memory freed");
}

static QDF_STATUS
hdd_txpb_req_queue_init(struct hdd_context *hdd_ctx)
{
	qdf_mutex_create(&hdd_ctx->tx_pb.txpb_req_q_lock);
	qdf_list_create(&hdd_ctx->tx_pb.txpb_req_q, TXPB_MAX_REQ_COUNT);

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
hdd_txpb_req_queue_cleanup(struct hdd_context *hdd_ctx)
{
	struct reg_txpb_cmn_params *entry, *next;

	qdf_mutex_acquire(&hdd_ctx->tx_pb.txpb_req_q_lock);

	qdf_list_for_each_del(&hdd_ctx->tx_pb.txpb_req_q, entry, next, node) {
		qdf_list_remove_node(&hdd_ctx->tx_pb.txpb_req_q, &entry->node);
		qdf_mem_free(entry);
		}

	qdf_mutex_release(&hdd_ctx->tx_pb.txpb_req_q_lock);
	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
hdd_txpb_req_queue_deinit(struct hdd_context *hdd_ctx)
{
	hdd_txpb_req_queue_cleanup(hdd_ctx);

	qdf_mutex_destroy(&hdd_ctx->tx_pb.txpb_req_q_lock);
	qdf_list_destroy(&hdd_ctx->tx_pb.txpb_req_q);

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
hdd_txpb_req_enqueue(struct hdd_context *hdd_ctx,
		     struct reg_txpb_cmn_params *params,
		     uint64_t *cookie)
{
	struct reg_txpb_cmn_params *req;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint32_t size;

	req = qdf_mem_malloc(sizeof(*req));
	if (!req)
		return QDF_STATUS_E_NOMEM;

	req->pdev_id = params->pdev_id;
	req->status = params->status;
	req->inference_stage = params->inference_stage;
	req->mcs = params->mcs;
	req->bandwidth = params->bandwidth;
	req->temperature_degreeC = params->temperature_degreeC;
	req->primary_chan_mhz = params->primary_chan_mhz;
	req->center_freq1 = params->center_freq1;
	req->center_freq2 = params->center_freq2;
	req->phy_mode = params->phy_mode;
	req->req_id = params->req_id;

	qdf_mutex_acquire(&hdd_ctx->tx_pb.txpb_req_q_lock);
	size = qdf_list_size(&hdd_ctx->tx_pb.txpb_req_q);
	if (size < TXPB_MAX_REQ_COUNT) {
		qdf_list_insert_back(&hdd_ctx->tx_pb.txpb_req_q,
				     &req->node);
	} else {
		status = QDF_STATUS_E_RESOURCES;
	}
	qdf_mutex_release(&hdd_ctx->tx_pb.txpb_req_q_lock);

	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("TPB: Failed to enqueue req_id: %d, already max %d reached",
			req->req_id, size);
		qdf_mem_free(req);
		return status;
	}

	*cookie = (uintptr_t)req;
	hdd_debug("TPB: enqueue req_id: %u cookie: %llx",
			req->req_id, *cookie);
	return status;
}

static QDF_STATUS
hdd_txpb_req_dequeue(struct hdd_context *hdd_ctx,
		     struct reg_txpb_cmn_params *params,
		     uint64_t cookie)
{
	struct reg_txpb_cmn_params *req;
	qdf_list_node_t *node = NULL, *ptr_node = NULL;
	QDF_STATUS status;

	qdf_mutex_acquire(&hdd_ctx->tx_pb.txpb_req_q_lock);
	if (qdf_list_empty(&hdd_ctx->tx_pb.txpb_req_q)) {
		qdf_mutex_release(&hdd_ctx->tx_pb.txpb_req_q_lock);
		hdd_err("TPB: Failed to find req id");
		return QDF_STATUS_E_INVAL;
	}

	if (QDF_STATUS_SUCCESS !=
		qdf_list_peek_front(&hdd_ctx->tx_pb.txpb_req_q,
					&ptr_node)) {
		qdf_mutex_release(&hdd_ctx->tx_pb.txpb_req_q_lock);
		return QDF_STATUS_E_INVAL;
	}

	do {
		node = ptr_node;
		req = qdf_container_of(node, struct reg_txpb_cmn_params, node);
		if (cookie == (uintptr_t)(req)) {
			status = qdf_list_remove_node(&hdd_ctx->tx_pb.txpb_req_q,
							node);
			if (status == QDF_STATUS_SUCCESS) {
				hdd_debug("TPB: Cookie match, req_id: %d", req->req_id);
				params->pdev_id = req->pdev_id;
				params->req_id = req->req_id;
				params->status = req->status;
				params->inference_stage = req->inference_stage;
				params->mcs = req->mcs;
				params->bandwidth = req->bandwidth;
				params->temperature_degreeC = req->temperature_degreeC;
				params->primary_chan_mhz = req->primary_chan_mhz;
				params->center_freq1 = req->center_freq1;
				params->center_freq2 = req->center_freq2;
				params->phy_mode = req->phy_mode;

				qdf_mem_free(req);

				qdf_mutex_release(&hdd_ctx->tx_pb.txpb_req_q_lock);
				hdd_err("Removed req_id: %d pending_reqs: %d",
					params->req_id,
					qdf_list_size(&hdd_ctx->tx_pb.txpb_req_q));
				return status;
			} else {
				qdf_mutex_release(&hdd_ctx->tx_pb.txpb_req_q_lock);
				hdd_err("Failed to remove req_id: %d pending_reqs: %d",
					req->req_id,
					qdf_list_size(&hdd_ctx->tx_pb.txpb_req_q));
				return status;
			}
		}
	} while (QDF_STATUS_SUCCESS ==
		 qdf_list_peek_next(&hdd_ctx->tx_pb.txpb_req_q,
		 node, &ptr_node));

	qdf_mutex_release(&hdd_ctx->tx_pb.txpb_req_q_lock);
	hdd_err("TPB: Failed to find matching cookie: %llx", cookie);
	return QDF_STATUS_E_INVAL;
}

static int
__tx_power_boost_mmap(struct hdd_context *hdd_ctx,
		      struct vm_area_struct *vma)
{
	int ret = 0;
	struct page *page = NULL;
	unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

	if (!wlan_hdd_validate_modules_state(hdd_ctx))
		return -EINVAL;

	if (size > hdd_ctx->tx_pb.dma.size) {
		hdd_err_rl("TPB: mmap size check failed (%lu %u)",
			size, hdd_ctx->tx_pb.dma.size);
		return -EINVAL;
	}

	page = virt_to_page((unsigned long)hdd_ctx->tx_pb.dma.vaddr +
				(vma->vm_pgoff << PAGE_SHIFT));
	ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page),
			      size, vma->vm_page_prot);
	hdd_debug("TPB: mmap for %zu bytes success", size);

	return ret;
}

static int
tx_power_boost_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret;
	struct osif_psoc_sync *psoc_sync;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		return ret;

	ret = osif_psoc_sync_op_start(wiphy_dev(hdd_ctx->wiphy),
				      &psoc_sync);
	if (ret)
		return ret;

	ret = __tx_power_boost_mmap(hdd_ctx, vma);

	osif_psoc_sync_op_stop(psoc_sync);

	return ret;
}

static ssize_t
__tx_power_boost_read(struct hdd_context *hdd_ctx, char *buffer,
		      size_t len)
{
	int ret;

	if (!wlan_hdd_validate_modules_state(hdd_ctx))
		return -EINVAL;

	if (len > hdd_ctx->tx_pb.dma.size) {
		hdd_err_rl("TPB: Read overflow! (%zu %u)", len,
			    hdd_ctx->tx_pb.dma.size);
		return -EFAULT;
	}

	if (copy_to_user(buffer, hdd_ctx->tx_pb.dma.vaddr,
			 len) == 0) {
		hdd_debug("TPB: copy %zu bytes to the app", len);
		ret = len;
	} else {
		ret = -EFAULT;
	}

	return ret;
}

static ssize_t
tx_power_boost_read(struct file *filep, char *buffer, size_t len,
		    loff_t *offset)
{
	int ret;
	struct osif_psoc_sync *psoc_sync;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		return ret;

	ret = osif_psoc_sync_op_start(wiphy_dev(hdd_ctx->wiphy),
				      &psoc_sync);
	if (ret)
		return ret;

	ret = __tx_power_boost_read(hdd_ctx, buffer, len);

	osif_psoc_sync_op_stop(psoc_sync);

	return ret;
}

static int
tx_power_boost_open(struct inode *inodep, struct file *filep)
{
	int ret = 0;

	hdd_debug("TPB: Device opened");
	return ret;
}

static int
tx_power_boost_release(struct inode *inodep, struct file *filep)
{
	hdd_debug("TPB: Device successfully closed");

	return 0;
}

static const struct file_operations tx_power_boost_fops = {
	.open = tx_power_boost_open,
	.read = tx_power_boost_read,
	.write = NULL,
	.release = tx_power_boost_release,
	.mmap = tx_power_boost_mmap,
	.owner = THIS_MODULE,
};

#ifdef WLAN_CTRL_NAME
extern struct class *class;
extern dev_t device;
static struct cdev tx_pb_cdev;
unsigned int major, minor;

void wlan_hdd_tx_power_boost_dev_destroy(void)
{
	cdev_del(&tx_pb_cdev);
	device_destroy(class, MKDEV(major, minor));
}

QDF_STATUS wlan_hdd_tx_power_boost_dev_create(void)
{
	int ret;
	struct device  *device_txpb;

	major = MAJOR(device);
	minor = MINOR(device) + 1;

	device_txpb = device_create(class, NULL, MKDEV(major, minor),
			       NULL, TXPB_DEVICE_NAME);
	if (IS_ERR(device_txpb)) {
		hdd_err("TPB: device_create (%s) failed", TXPB_DEVICE_NAME);
		return QDF_STATUS_E_FAILURE;
	}

	cdev_init(&tx_pb_cdev, &tx_power_boost_fops);
	tx_pb_cdev.owner = THIS_MODULE;
	ret = cdev_add(&tx_pb_cdev, MKDEV(major, minor), 1);
	if (ret) {
		pr_err("Failed to add cdev error");
		goto cdev_add_err;
	}

	hdd_debug("TPB: device '%s' major: %d minor: %d initialized",
		  TXPB_DEVICE_NAME, major, minor);
	return QDF_STATUS_SUCCESS;

cdev_add_err:
	device_destroy(class, MKDEV(major, minor));
	return QDF_STATUS_E_FAILURE;
}
#else
void wlan_hdd_tx_power_boost_dev_destroy(void)
{
}

QDF_STATUS wlan_hdd_tx_power_boost_dev_create(void)
{
	return QDF_STATUS_SUCCESS;
}

#endif

/**
 * hdd_get_tx_pb_event_len() - calculate length of skb
 * required for sending tx powerboost event
 *
 * Return: length of skb
 */
static uint32_t hdd_get_tx_pb_event_len(void)
{
	uint32_t len;

	len = NLMSG_HDRLEN;
	/* STAGE */
	len += nla_total_size(sizeof(u32));
	/* MCS */
	len += nla_total_size(sizeof(u32));
	/* BW */
	len += nla_total_size(sizeof(u32));
	/* TEMPERATURE */
	len += nla_total_size(sizeof(s32));
	/* CHANNEL_FREQ */
	len += nla_total_size(sizeof(u32));
	/* CENTER_FREQ_1 */
	len += nla_total_size(sizeof(u32));
	/* CENTER_FREQ_2 */
	len += nla_total_size(sizeof(u32));
	/* PHY_MODE */
	len += nla_total_size(sizeof(u32));
	/* SAMPLE_SIZE */
	len += nla_total_size(sizeof(u32));
	/* INFERENCE_STATUS */
	len += nla_total_size(sizeof(u32));
	/* TX_PWR */
	len += nla_total_size(sizeof(s32));
	/* TX_CHAIN_IDX */
	len += nla_total_size(sizeof(u32));
	/* COOKIE */
	len += nla_total_size(sizeof(u64));

	return len;
}

/**
 * hdd_tx_pb_convert_status_reg_to_nl() - Convert the WMI status value
 * to NL equivalent attribute
 * @status: power boost status
 *
 * Return: NL attribute
 */
static uint32_t
hdd_tx_pb_convert_status_reg_to_nl(
		enum reg_host_pdev_power_boost_event_status status)
{
	switch (status) {
	case REG_HOST_POWER_BOOST_START_INFERENCE:
		return STATUS_INFERENCE;
	case REG_HOST_POWER_BOOST_ABORT:
		return STATUS_ABORT;
	case REG_HOST_POWER_BOOST_COMPLETE:
		return STATUS_COMPLETE;
	default:
		hdd_err("TPB: Invalid status: %d", status);
		return 0;
	}
}

/**
 * hdd_tx_pb_convert_inf_stage_reg_to_nl() - Convert the WMI Inferencing
 * stage value to NL equivalent
 * @stage: inferencing stage
 *
 * Return: NL attribute
 */
static uint32_t
hdd_tx_pb_convert_inf_stage_reg_to_nl(
			enum reg_host_tx_pb_inference_stage stage)
{
	switch (stage) {
	case REG_HOST_TX_PB_INFERENCE_FIRST_PASS:
		return STAGE_FIRST_PASS;
	case REG_HOST_TX_PB_INFERENCE_SECOND_PASS:
		return STAGE_SECOND_PASS;
	default:
		hdd_err("TPB: Invalid inference stage: %d", stage);
		return 0;
	}
}

/**
 * hdd_tx_power_boost_pack_resp_nlmsg() - pack the skb with
 * tx power boost metadata from the firmware
 * @reply_skb: skb to store the response
 * @params: Pointer to tx power boost metadata
 *
 * Return: QDF_STATUS_SUCCESS on Success, QDF_STATUS_E_FAILURE
 * on failure
 */
static QDF_STATUS
hdd_tx_power_boost_pack_resp_nlmsg(struct sk_buff *reply_skb,
				   struct reg_txpb_evt_params *params)
{
	int attr;

	attr = STAGE;
	if (nla_put_u32(reply_skb, attr,
		hdd_tx_pb_convert_inf_stage_reg_to_nl(params->cmn_params.inference_stage))) {
		hdd_err("TPB: Failed to nla put inference_stage");
		return QDF_STATUS_E_INVAL;
	}

	attr = MCS;
	if (nla_put_u32(reply_skb, attr, params->cmn_params.mcs)) {
		hdd_err("TPB: Failed to nla put mcs");
		return QDF_STATUS_E_INVAL;
	}

	attr = BW;
	if (nla_put_u32(reply_skb, attr, params->cmn_params.bandwidth)) {
		hdd_err("TPB: Failed to nla put bandwidth");
		return QDF_STATUS_E_INVAL;
	}

	attr = TEMPERATURE;
	if (nla_put_s32(reply_skb, attr, params->cmn_params.temperature_degreeC)) {
		hdd_err("TPB: Failed to nla put temperature_degreeC");
		return QDF_STATUS_E_INVAL;
	}

	attr = CHANNEL_FREQ;
	if (nla_put_u32(reply_skb, attr, params->cmn_params.primary_chan_mhz)) {
		hdd_err("TPB: Failed to nla put primary_chan_mhz");
		return QDF_STATUS_E_INVAL;
	}

	attr = CENTER_FREQ_1;
	if (nla_put_u32(reply_skb, attr, params->cmn_params.center_freq1)) {
		hdd_err("TPB: Failed to nla put center_freq1");
		return QDF_STATUS_E_INVAL;
	}

	attr = CENTER_FREQ_2;
	if (nla_put_u32(reply_skb, attr, params->cmn_params.center_freq2)) {
		hdd_err("TPB: Failed to nla put center_freq2");
		return QDF_STATUS_E_INVAL;
	}

	attr = PHY_MODE;
	if (nla_put_u32(reply_skb, attr, params->cmn_params.phy_mode)) {
		hdd_err("TPB: Failed to nla put phy_mode");
		return QDF_STATUS_E_INVAL;
	}

	attr = SAMPLE_SIZE;
	if (nla_put_u32(reply_skb, attr, params->iq_sample_buf_size)) {
		hdd_err("TPB: Failed to nla put iq_sample_buf_size");
		return QDF_STATUS_E_INVAL;
	}

	attr = INFERENCE_STATUS;
	if (nla_put_u32(reply_skb, attr,
			hdd_tx_pb_convert_status_reg_to_nl(params->cmn_params.status))) {
		hdd_err("TPB: Failed to nla put iq_status");
		return QDF_STATUS_E_INVAL;
	}

	attr = TX_PWR;
	if (nla_put_s32(reply_skb, attr, params->tx_pwr)) {
		hdd_err("TPB: Failed to nla put tx power");
		return QDF_STATUS_E_INVAL;
	}

	attr = TX_CHAIN_IDX;
	if (nla_put_u32(reply_skb, attr, params->tx_chain_idx)) {
		hdd_err("TPB: Failed to nla put tx_chain_idx");
		return QDF_STATUS_E_INVAL;
	}

	return QDF_STATUS_SUCCESS;
}

void wlan_hdd_cfg80211_tx_pb_callback(void *arg,
				      struct reg_txpb_evt_params *rsp)
{
	struct hdd_context *hdd_ctx = (struct hdd_context *)arg;
	struct sk_buff *vendor_event;
	QDF_STATUS status;
	int ret;
	uint64_t cookie;
	uint32_t len;

	if (!rsp) {
		hdd_err("TPB: Invalid result");
		return;
	}

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (0 != ret) {
		hdd_err("TPB: Invalid HDD context");
		return;
	}

	qdf_wake_lock_timeout_acquire(&hdd_ctx->tx_pb.txpb_wake_lock,
				      TX_PB_WAKE_LOCK_DURATION);
	qdf_runtime_pm_prevent_suspend(&hdd_ctx->tx_pb.txpb_runtime_lock);

	len = hdd_get_tx_pb_event_len() + NLA_HDRLEN;
	vendor_event = wlan_cfg80211_vendor_event_alloc(
			hdd_ctx->wiphy, NULL, len,
			QCA_NL80211_VENDOR_SUBCMD_TX_POWER_BOOST_INDEX,
			GFP_KERNEL);
	if (!vendor_event) {
		hdd_err("TPB: vendor_event skb alloc failed");
		return;
	}

	status = hdd_tx_power_boost_pack_resp_nlmsg(vendor_event, rsp);
	if (QDF_IS_STATUS_ERROR(status)) {
		wlan_cfg80211_vendor_free_skb(vendor_event);
		hdd_err("TPB: Failed to pack Tx power boost response");
		return;
	}

	status = hdd_txpb_req_enqueue(hdd_ctx, &rsp->cmn_params, &cookie);
	if (QDF_IS_STATUS_ERROR(status)) {
		wlan_cfg80211_vendor_free_skb(vendor_event);
		hdd_err("TPB: Failed to enqueue TxPb request");
		return;
	}

	if (hdd_wlan_nla_put_u64(vendor_event, COOKIE, cookie)) {
		wlan_cfg80211_vendor_free_skb(vendor_event);
		hdd_err("TPB: Failed to nla put cookie");
		return;
	}

	wlan_cfg80211_vendor_event(vendor_event, GFP_KERNEL);
	hdd_debug("TPB: NL event sent to userspace");
}

static QDF_STATUS
hdd_txpb_inference_cmd(struct hdd_context *hdd_ctx, struct nlattr **tb)
{
	int id;
	QDF_STATUS status;
	uint64_t cookie;
	struct reg_txpb_cmd_params params = {0};

	id = COOKIE;
	if (!tb[id]) {
		hdd_err_rl("TPB: IQ_DATA_INFERENCE_COOKIE is not set");
		return QDF_STATUS_E_INVAL;
	}

	cookie = nla_get_u64(tb[id]);
	status = hdd_txpb_req_dequeue(hdd_ctx, &params.cmn_params, cookie);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err_rl("TPB: Cookie: %llx didn't match", cookie);
		return QDF_STATUS_E_INVAL;
	}

	id = EVM;
	if (!tb[id]) {
		hdd_err_rl("TPB: IQ_DATA_INFERENCE_EVM is not set");
		return QDF_STATUS_E_INVAL;
	}
	params.tx_evm = nla_get_s32(tb[id]);

	id = MASK_MARGIN;
	if (!tb[id]) {
		hdd_err_rl("TPB: IQ_DATA_INFERENCE_MASK_MARGIN is not set");
		return QDF_STATUS_E_INVAL;
	}
	params.mask_margin = nla_get_s32(tb[id]);

	params.cmn_params.status = REG_HOST_PDEV_POWER_BOOST_CMD_STATUS_ESTIMATED_DATA;
	status = ucfg_reg_txpb_send_inference_cmd(hdd_ctx->pdev, &params);
	if (QDF_IS_STATUS_ERROR(status))
		hdd_err("TPB: sme_txpb_send_inference_cmd failed: %d",
			status);

	return status;
}

static QDF_STATUS
hdd_txpb_inference_cmd_result(struct hdd_context *hdd_ctx,
			      struct nlattr **tb)
{
	return hdd_txpb_inference_cmd(hdd_ctx, tb);
}

static QDF_STATUS
hdd_txpb_inference_send_abort(struct hdd_context *hdd_ctx,
			      struct reg_txpb_cmn_params *pb_metadata)
{
	struct reg_txpb_cmd_params params = {0};

	qdf_mem_copy(&params, pb_metadata,
		     sizeof(struct reg_txpb_cmn_params));
	params.cmn_params.status = REG_HOST_PDEV_POWER_BOOST_CMD_STATUS_ABORT;

	return ucfg_reg_txpb_send_inference_cmd(hdd_ctx->pdev, &params);
}

static QDF_STATUS
hdd_txpb_inference_app_stop(struct hdd_context *hdd_ctx,
			    struct reg_txpb_cmn_params *pb_metadata)
{
	QDF_STATUS status;

	if (hdd_ctx->driver_status != DRIVER_MODULES_ENABLED && !hdd_ctx->pdev) {
		/*
		 * Sometimes when system is overloaded and user does
		 * wifi-off, race condition may happen and user thread
		 * scheduling gets delayed and idle shutdown can happen
		 * first and pdev can be deleted. Hence pdev will be NULL here
		 *
		 * In that case, firmware already cleared Tx powerboost
		 * state, it is ok not to send app_stop to firmware but
		 * host driver needs to clear its request queue and
		 * txpb_app_launched status to false, so that upon next
		 * wifi-on, it can send app_start to firmware.
		 * It is treated as graceful success scenario
		 */
		hdd_warn("TPB: pdev is NULL");
		status = QDF_STATUS_SUCCESS;
		goto end;
	}

	status = hdd_txpb_inference_send_abort(hdd_ctx, pb_metadata);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("TPB: hdd_txpb_inference_send_abort failed: %d",
			status);
		return status;
	}

end:
	hdd_txpb_req_queue_cleanup(hdd_ctx);
	hdd_ctx->tx_pb.txpb_app_launched = false;
	return status;
}

static
QDF_STATUS hdd_txpb_issue_boost_ready(struct hdd_context *hdd_ctx)
{
	QDF_STATUS status;
	struct reg_txpb_cmd_params params = {0};

	params.cmn_params.status = REG_HOST_PDEV_POWER_BOOST_CMD_STATUS_READY;
	status = ucfg_reg_txpb_send_inference_cmd(hdd_ctx->pdev, &params);
	if (QDF_IS_STATUS_ERROR(status))
		hdd_err("TPB: sme_txpb_send_inference_cmd failed: %d",
			status);

	return status;
}

static QDF_STATUS
hdd_txpb_issue_app_stop_ready(struct hdd_context *hdd_ctx,
			      struct reg_txpb_cmn_params *pb_metadata,
			      const char *stage, const char *cmd)
{
	QDF_STATUS status;

	/* Send Abort first and then Ready as per FW request */
	status = hdd_txpb_inference_app_stop(hdd_ctx, pb_metadata);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("TPB: %s: Failed to send CMD_ABORT for %s",
			stage, cmd);
		return QDF_STATUS_E_FAILURE;
	}
	hdd_debug("TPB: %s: Send CMD_ABORT for %s successful", stage, cmd);

	status = hdd_txpb_issue_boost_ready(hdd_ctx);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("TPB: %s: Failed to send CMD_READY for %s",
			stage, cmd);
		return QDF_STATUS_E_FAILURE;
	}

	hdd_debug("TPB: %s: Send CMD_READY for %s successful", stage, cmd);
	hdd_ctx->tx_pb.txpb_app_launched = true;

	return status;
}

static QDF_STATUS
hdd_txpb_inference_cmd_failure(struct hdd_context *hdd_ctx,
			       struct nlattr **tb)
{
	QDF_STATUS status;
	uint64_t cookie;
	uint32_t id;
	struct reg_txpb_cmn_params params = {0};

	id = COOKIE;
	if (!tb[id]) {
		hdd_err_rl("TPB: IQ_DATA_INFERENCE_COOKIE is not set");
		return QDF_STATUS_E_INVAL;
	}
	cookie = nla_get_u64(tb[id]);
	status = hdd_txpb_req_dequeue(hdd_ctx, &params, cookie);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err_rl("TPB: Cookie: %llx didn't match", cookie);
		return QDF_STATUS_E_INVAL;
	}

	/*
	 * The difference between CMD_FAILURE and CMD_APP_STOP is,
	 * CMD_FAILURE is when inference failure happens and CMD_APP_STOP
	 * is when user space app exits, in both the case FW behaviour
	 * is to Abort the ANN Sampling, but from host driver perspective
	 * in case of CMD_FAILURE, Issue Abort to firmware and
	 * send CMD_STATUS_READY again
	 */
	status = hdd_txpb_issue_app_stop_ready(hdd_ctx, &params,
					       "Fail_Init",
					       "CMD_FAILURE");
	return status;
}

static QDF_STATUS
hdd_txpb_inference_app_start(struct hdd_context *hdd_ctx)
{
	QDF_STATUS status;
	struct reg_txpb_cmn_params params = {0};

	if (hdd_ctx->tx_pb.txpb_app_launched) {
		hdd_warn("TPB: Boost ready already sent, no need to send again");
		return QDF_STATUS_SUCCESS;
	}

	status = hdd_txpb_issue_app_stop_ready(hdd_ctx, &params, "Init",
					       "APP_START");

	return status;
}

QDF_STATUS hdd_tx_powerboost_reinit(struct hdd_context *hdd_ctx)
{
	QDF_STATUS status;
	struct reg_txpb_cmn_params params = {0};

	if (!hdd_ctx->tx_pb.txpb_app_launched)
		return QDF_STATUS_SUCCESS;

	hdd_debug("TPB: Issue boost ready after SSR reinit");

	status = hdd_txpb_issue_app_stop_ready(hdd_ctx, &params, "Reinit",
					       "APP_START");

	return status;
}

QDF_STATUS hdd_txpb_wifi_off_app_stop(struct hdd_context *hdd_ctx)
{
	struct reg_txpb_cmn_params params = {0};

	if (!hdd_ctx->tx_pb.txpb_app_launched)
		return QDF_STATUS_SUCCESS;

	hdd_debug("TPB: Issue app stop due to WiFi off");
	return hdd_txpb_inference_app_stop(hdd_ctx, &params);
}

/**
 * hdd_tx_pb_configure - Process the Tx Power boost config
 * operation in the received vendor command
 * @hdd_ctx: HDD context
 * @tb: nl attributes
 *
 * Handles QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE
 *
 * Return: 0 for Success and negative value for failure
 */
static int hdd_tx_pb_configure(struct hdd_context *hdd_ctx,
			       struct nlattr **tb)
{
	enum qca_wlan_vendor_iq_inference_cmd_type oper;
	struct nlattr *oper_attr;
	uint32_t id;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct reg_txpb_cmn_params params = {0};

	if (!hdd_ctx->tx_pb.tx_powerboost_enabled) {
		hdd_warn("TPB: feature is not enabled");
		return -EINVAL;
	}

	id = CMD_TYPE;
	oper_attr = tb[id];

	if (!oper_attr) {
		hdd_err("TPB: Inference cmd type NOT specified");
		status = QDF_STATUS_E_INVAL;
		goto end;
	}

	oper = nla_get_u32(oper_attr);
	hdd_debug("TPB: Inference cmd type: %d", oper);

	if ((oper == CMD_FAILURE) || (oper == CMD_RESULT) ||
		(oper == CMD_APP_STOP)) {
		qdf_runtime_pm_allow_suspend(&hdd_ctx->tx_pb.txpb_runtime_lock);
		qdf_wake_lock_release(&hdd_ctx->tx_pb.txpb_wake_lock,
				WIFI_POWER_EVENT_WAKELOCK_TX_POWER_BOOST);

		if (hdd_ctx->tx_pb.dma.vaddr) {
			qdf_mem_set(hdd_ctx->tx_pb.dma.vaddr,
				    hdd_ctx->tx_pb.dma.size, 0);
		}
	}

	switch (oper) {
	case CMD_APP_START:
		status = hdd_txpb_inference_app_start(hdd_ctx);
		if (QDF_IS_STATUS_ERROR(status))
			goto end;

		break;

	case CMD_FAILURE:
		status = hdd_txpb_inference_cmd_failure(hdd_ctx, tb);
		if (QDF_IS_STATUS_ERROR(status)) {
			hdd_err("TPB: Failed to send CMD_FAILURE");
			goto end;
		}
		hdd_debug("TPB: Send CMD_FAILURE successful");
		break;

	case CMD_RESULT:
		status = hdd_txpb_inference_cmd_result(hdd_ctx, tb);
		if (QDF_IS_STATUS_ERROR(status)) {
			hdd_err("TPB: Failed to send CMD_ESTIMATED_DATA");
			goto end;
		}
		hdd_debug("TPB: Send CMD_ESTIMATED_DATA successful");
		break;

	case CMD_APP_STOP:
		status = hdd_txpb_inference_app_stop(hdd_ctx, &params);

		if (QDF_IS_STATUS_ERROR(status)) {
			hdd_err("TPB: Failed to send CMD_ABORT for APP_STOP");
			goto end;
		}
		hdd_debug("TPB: Send CMD_ABORT for APP_STOP successful");
		break;
	default:
		hdd_err("TPB: Invalid Inference cmd type: %d", oper);
		status = QDF_STATUS_E_INVAL;
		goto end;
	}

end:
	return qdf_status_to_os_return(status);
}

/**
 * __wlan_hdd_cfg80211_tx_power_boost_config() - Tx power boost config
 * vendor command
 * @wiphy: wiphy device pointer
 * @wdev: wireless device pointer
 * @data: Vendor command data buffer
 * @data_len: Buffer length
 *
 * Handles QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
 *
 * Return: 0 for Success and negative value for failure
 */
static int
__wlan_hdd_cfg80211_tx_power_boost_config(struct wiphy *wiphy,
					  struct wireless_dev *wdev,
					  const void *data, int data_len)
{
	struct net_device *dev = wdev->netdev;
	struct hdd_context *hdd_ctx  = wiphy_priv(wiphy);
	struct nlattr *tb[ATTR_INFERENCE_MAX + 1];
	int errno;

	hdd_enter_dev(dev);
	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		return errno;

	if (wlan_cfg80211_nla_parse(tb,
			ATTR_INFERENCE_MAX,
			data, data_len,
			qca_wlan_vendor_power_boost_policy)) {
		hdd_err("TPB: nla_parse failed for IQ DATA Inference");
		return -EINVAL;
	}

	errno = hdd_tx_pb_configure(hdd_ctx, tb);

	return errno;
}

int wlan_hdd_cfg80211_tx_power_boost_config(struct wiphy *wiphy,
					    struct wireless_dev *wdev,
					    const void *data,
					    int data_len)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_tx_power_boost_config(wiphy, wdev,
							  data, data_len);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

QDF_STATUS hdd_tx_powerboost_init(struct hdd_context *hdd_ctx)
{
	QDF_STATUS status;

	if (!hdd_ctx->tx_pb.tx_powerboost_enabled) {
		hdd_warn("TPB: feature not enabled");
		return QDF_STATUS_SUCCESS;
	}

	status = hdd_tx_powerboost_init_dma(hdd_ctx);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("TPB: init dma failed: %d", status);
		return status;
	}
	qdf_wake_lock_create(&hdd_ctx->tx_pb.txpb_wake_lock, "txpb_wake_lock");
	qdf_runtime_lock_init(&hdd_ctx->tx_pb.txpb_runtime_lock);
	hdd_txpb_req_queue_init(hdd_ctx);
	ucfg_reg_txpb_register_callback(hdd_ctx->psoc,
					wlan_hdd_cfg80211_tx_pb_callback,
					hdd_ctx);

	hdd_debug("TPB: init done");
	return QDF_STATUS_SUCCESS;
}

void hdd_tx_powerboost_deinit(struct hdd_context *hdd_ctx)
{
	if (!hdd_ctx->tx_pb.tx_powerboost_enabled) {
		hdd_warn("TPB: feature not enabled");
		return;
	}

	ucfg_reg_txpb_unregister_callback(hdd_ctx->psoc);
	hdd_txpb_req_queue_deinit(hdd_ctx);
	qdf_runtime_lock_deinit(&hdd_ctx->tx_pb.txpb_runtime_lock);
	qdf_wake_lock_destroy(&hdd_ctx->tx_pb.txpb_wake_lock);
	hdd_tx_powerboost_deinit_dma(hdd_ctx);
	hdd_debug("TPB: deinit done");
}

#undef ATTR_INFERENCE_MAX
#undef CMD_TYPE
#undef BW
#undef CHANNEL_FREQ
#undef CENTER_FREQ_1
#undef CENTER_FREQ_2
#undef MCS
#undef TEMPERATURE
#undef STAGE
#undef EVM
#undef MASK_MARGIN
#undef PHY_MODE
#undef SAMPLE_SIZE
#undef CMD_APP_START
#undef CMD_APP_STOP
#undef CMD_RESULT
#undef CMD_FAILURE
#undef STAGE_FIRST_PASS
#undef STAGE_SECOND_PASS
#undef INFERENCE_STATUS
#undef STATUS_INFERENCE
#undef TX_PWR
#undef TX_CHAIN_IDX
#undef STATUS_ABORT
#undef STATUS_COMPLETE
#undef COOKIE

#endif
