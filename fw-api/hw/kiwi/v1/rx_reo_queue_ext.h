
/*
 * Copyright (c) 2021 Qualcomm Innovation Center, Inc. All rights reserved.
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











#ifndef _RX_REO_QUEUE_EXT_H_
#define _RX_REO_QUEUE_EXT_H_
#if !defined(__ASSEMBLER__)
#endif

#include "rx_mpdu_link_ptr.h"
#include "uniform_descriptor_header.h"
#define NUM_OF_DWORDS_RX_REO_QUEUE_EXT 32


struct rx_reo_queue_ext {
	     struct   uniform_descriptor_header                                 descriptor_header;
	     uint32_t reserved_1a                                             : 32;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_0;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_1;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_2;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_3;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_4;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_5;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_6;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_7;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_8;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_9;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_10;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_11;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_12;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_13;
	     struct   rx_mpdu_link_ptr                                          mpdu_link_pointer_14;
};







#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_OWNER_OFFSET                             0x00000000
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_OWNER_LSB                                0
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_OWNER_MSB                                3
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_OWNER_MASK                               0x0000000f




#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_BUFFER_TYPE_OFFSET                       0x00000000
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_BUFFER_TYPE_LSB                          4
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_BUFFER_TYPE_MSB                          7
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_BUFFER_TYPE_MASK                         0x000000f0




#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_RESERVED_0A_OFFSET                       0x00000000
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_RESERVED_0A_LSB                          8
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_RESERVED_0A_MSB                          31
#define RX_REO_QUEUE_EXT_DESCRIPTOR_HEADER_RESERVED_0A_MASK                         0xffffff00




#define RX_REO_QUEUE_EXT_RESERVED_1A_OFFSET                                         0x00000004
#define RX_REO_QUEUE_EXT_RESERVED_1A_LSB                                            0
#define RX_REO_QUEUE_EXT_RESERVED_1A_MSB                                            31
#define RX_REO_QUEUE_EXT_RESERVED_1A_MASK                                           0xffffffff










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000008
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x0000000c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x0000000c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x0000000c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_0_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000010
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x00000014
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x00000014
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x00000014
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_1_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000018
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x0000001c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x0000001c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x0000001c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_2_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000020
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x00000024
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x00000024
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x00000024
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_3_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000028
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x0000002c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x0000002c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x0000002c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_4_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000030
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x00000034
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x00000034
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x00000034
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_5_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000038
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x0000003c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x0000003c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x0000003c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_6_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000040
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x00000044
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x00000044
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x00000044
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_7_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000048
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x0000004c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x0000004c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x0000004c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_8_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000050
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x00000054
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x00000054
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x00000054
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_9_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000058
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x0000005c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x0000005c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x0000005c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_10_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000060
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x00000064
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x00000064
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x00000064
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_11_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000068
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x0000006c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x0000006c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x0000006c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_12_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000070
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x00000074
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x00000074
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x00000074
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_13_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000










#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_OFFSET 0x00000078
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_31_0_MASK 0xffffffff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_OFFSET 0x0000007c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_LSB 0
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MSB 7
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_BUFFER_ADDR_39_32_MASK 0x000000ff




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_OFFSET 0x0000007c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_LSB 8
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MSB 11
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_RETURN_BUFFER_MANAGER_MASK 0x00000f00




#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_OFFSET 0x0000007c
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_LSB 12
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MSB 31
#define RX_REO_QUEUE_EXT_MPDU_LINK_POINTER_14_MPDU_LINK_DESC_ADDR_INFO_SW_BUFFER_COOKIE_MASK 0xfffff000



#endif
