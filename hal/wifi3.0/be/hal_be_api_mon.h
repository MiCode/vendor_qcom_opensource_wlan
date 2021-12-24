/*
 * Copyright (c) 2021-2022, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
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

#ifndef _HAL_BE_API_MON_H_
#define _HAL_BE_API_MON_H_

#ifdef QCA_MONITOR_2_0_SUPPORT

#include <mon_ingress_ring.h>
#include <mon_destination_ring.h>

#define HAL_MON_BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_OFFSET 0x00000000
#define HAL_MON_BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_LSB 0
#define HAL_MON_BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_MASK 0xffffffff

#define HAL_MON_BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_OFFSET 0x00000004
#define HAL_MON_BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_LSB 0
#define HAL_MON_BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_MASK 0x000000ff

#define HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_31_0_OFFSET 0x00000008
#define HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_31_0_LSB 0
#define HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_31_0_MSB 31
#define HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_31_0_MASK 0xffffffff

#define HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_63_32_OFFSET 0x0000000c
#define HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_63_32_LSB 0
#define HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_63_32_MSB 31
#define HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_63_32_MASK 0xffffffff

#define HAL_MON_PADDR_LO_SET(buff_addr_info, paddr_lo) \
		((*(((unsigned int *) buff_addr_info) + \
		(HAL_MON_BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_OFFSET >> 2))) = \
		(paddr_lo << HAL_MON_BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_LSB) & \
		HAL_MON_BUFFER_ADDR_INFO_0_BUFFER_ADDR_31_0_MASK)

#define HAL_MON_PADDR_HI_SET(buff_addr_info, paddr_hi) \
		((*(((unsigned int *) buff_addr_info) + \
		(HAL_MON_BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_OFFSET >> 2))) = \
		(paddr_hi << HAL_MON_BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_LSB) & \
		HAL_MON_BUFFER_ADDR_INFO_1_BUFFER_ADDR_39_32_MASK)

#define HAL_MON_VADDR_LO_SET(buff_addr_info, paddr_lo) \
		((*(((unsigned int *) buff_addr_info) + \
		(HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_31_0_OFFSET >> 2))) = \
		(paddr_lo << HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_31_0_LSB) & \
		HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_31_0_MASK)

#define HAL_MON_VADDR_HI_SET(buff_addr_info, paddr_hi) \
		((*(((unsigned int *) buff_addr_info) + \
		(HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_63_32_OFFSET >> 2))) = \
		(paddr_hi << HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_63_32_LSB) & \
		HAL_MON_MON_INGRESS_RING_BUFFER_VIRT_ADDR_63_32_MASK)

/**
 * struct hal_mon_desc () - HAL Monitor descriptor
 *
 * @buf_addr: virtual buffer address
 * @ppdu_id: ppdu id
 *	     - TxMon fills scheduler id
 *	     - RxMON fills phy_ppdu_id
 * @end_offset: offset (units in 4 bytes) where status buffer ended
 *		i.e offset of TLV + last TLV size
 * @end_reason: 0 - status buffer is full
 *		1 - flush detected
 *		2 - TX_FES_STATUS_END or RX_PPDU_END
 *		3 - PPDU truncated due to system error
 * @initiator:	1 - descriptor belongs to TX FES
 *		0 - descriptor belongs to TX RESPONSE
 * @empty_descriptor: 0 - this descriptor is written on a flush
 *			or end of ppdu or end of status buffer
 *			1 - descriptor provided to indicate drop
 * @ring_id: ring id for debugging
 * @looping_count: count to indicate number of times producer
 *			of entries has looped around the ring
 */
struct hal_mon_desc {
	uint64_t buf_addr;
	uint32_t ppdu_id;
	uint32_t end_offset:12,
		 reserved_3a:4,
		 end_reason:2,
		 initiator:1,
		 empty_descriptor:1,
		 ring_id:8,
		 looping_count:4;
};

/**
 * hal_be_get_mon_dest_status() - Get monitor descriptor
 * @hal_soc_hdl: HAL Soc handle
 * @desc: HAL monitor descriptor
 *
 * Return: none
 */
static inline void
hal_be_get_mon_dest_status(hal_soc_handle_t hal_soc,
			   void *hw_desc,
			   struct hal_mon_desc *status)
{
	struct mon_destination_ring *desc = hw_desc;

	status->buf_addr = ((u64)desc->stat_buf_virt_addr_31_0 |
				((u64)desc->stat_buf_virt_addr_63_32 << 32));
	status->ppdu_id = desc->ppdu_id;
	status->end_offset = desc->end_offset;
	status->end_reason = desc->end_reason;
	status->initiator = desc->initiator;
	status->empty_descriptor = desc->empty_descriptor;
	status->looping_count = desc->looping_count;
}

/**
 * hal_mon_buff_addr_info_set() - set desc address in cookie
 * @hal_soc_hdl: HAL Soc handle
 * @mon_entry: monitor srng
 * @desc: HAL monitor descriptor
 *
 * Return: none
 */
static inline
void hal_mon_buff_addr_info_set(hal_soc_handle_t hal_soc_hdl,
				void *mon_entry,
				void *mon_desc_addr,
				qdf_dma_addr_t phy_addr)
{
	uint32_t paddr_lo = ((u64)phy_addr & 0x00000000ffffffff);
	uint32_t paddr_hi = ((u64)phy_addr & 0xffffffff00000000) >> 32;
	uint32_t vaddr_lo = ((u64)(uintptr_t)mon_desc_addr & 0x00000000ffffffff);
	uint32_t vaddr_hi = ((u64)(uintptr_t)mon_desc_addr & 0xffffffff00000000) >> 32;

	HAL_MON_PADDR_LO_SET(mon_entry, paddr_lo);
	HAL_MON_PADDR_HI_SET(mon_entry, paddr_hi);
	HAL_MON_VADDR_LO_SET(mon_entry, vaddr_lo);
	HAL_MON_VADDR_HI_SET(mon_entry, vaddr_hi);
}

#endif /* QCA_MONITOR_2_0_SUPPORT */
#endif /* _HAL_BE_API_MON_H_ */
