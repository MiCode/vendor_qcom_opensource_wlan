
/* Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
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

 
 
 
 
 
 
 


#ifndef _MON_BUFFER_ADDR_H_
#define _MON_BUFFER_ADDR_H_
#if !defined(__ASSEMBLER__)
#endif

#define NUM_OF_DWORDS_MON_BUFFER_ADDR 4

#define NUM_OF_QWORDS_MON_BUFFER_ADDR 2


struct mon_buffer_addr {
#ifndef BIG_ENDIAN_HOST
             uint32_t buffer_virt_addr_31_0                                   : 32; // [31:0]
             uint32_t buffer_virt_addr_63_32                                  : 32; // [31:0]
             uint32_t dma_length                                              : 12, // [11:0]
                      reserved_2a                                             :  4, // [15:12]
                      msdu_continuation                                       :  1, // [16:16]
                      truncated                                               :  1, // [17:17]
                      reserved_2b                                             : 14; // [31:18]
             uint32_t tlv64_padding                                           : 32; // [31:0]
#else
             uint32_t buffer_virt_addr_31_0                                   : 32; // [31:0]
             uint32_t buffer_virt_addr_63_32                                  : 32; // [31:0]
             uint32_t reserved_2b                                             : 14, // [31:18]
                      truncated                                               :  1, // [17:17]
                      msdu_continuation                                       :  1, // [16:16]
                      reserved_2a                                             :  4, // [15:12]
                      dma_length                                              : 12; // [11:0]
             uint32_t tlv64_padding                                           : 32; // [31:0]
#endif
};


/* Description		BUFFER_VIRT_ADDR_31_0

			Lower 32 bits of the 64-bit virtual address of the packet
			 buffer
			<legal all>
*/

#define MON_BUFFER_ADDR_BUFFER_VIRT_ADDR_31_0_OFFSET                                0x0000000000000000
#define MON_BUFFER_ADDR_BUFFER_VIRT_ADDR_31_0_LSB                                   0
#define MON_BUFFER_ADDR_BUFFER_VIRT_ADDR_31_0_MSB                                   31
#define MON_BUFFER_ADDR_BUFFER_VIRT_ADDR_31_0_MASK                                  0x00000000ffffffff


/* Description		BUFFER_VIRT_ADDR_63_32

			Upper 32 bits of the 64-bit virtual address of the packet
			 buffer
			<legal all>
*/

#define MON_BUFFER_ADDR_BUFFER_VIRT_ADDR_63_32_OFFSET                               0x0000000000000000
#define MON_BUFFER_ADDR_BUFFER_VIRT_ADDR_63_32_LSB                                  32
#define MON_BUFFER_ADDR_BUFFER_VIRT_ADDR_63_32_MSB                                  63
#define MON_BUFFER_ADDR_BUFFER_VIRT_ADDR_63_32_MASK                                 0xffffffff00000000


/* Description		DMA_LENGTH

			The number of bytes DMA'd into the packet buffer MINUS 1.
			
			
			The packet could be truncated in case of a 'TX_FLUSH' or
			 'RX_FLUSH,' or in case of drops due to back-pressure.
			<legal all>
*/

#define MON_BUFFER_ADDR_DMA_LENGTH_OFFSET                                           0x0000000000000008
#define MON_BUFFER_ADDR_DMA_LENGTH_LSB                                              0
#define MON_BUFFER_ADDR_DMA_LENGTH_MSB                                              11
#define MON_BUFFER_ADDR_DMA_LENGTH_MASK                                             0x0000000000000fff


/* Description		RESERVED_2A

			<legal 0>
*/

#define MON_BUFFER_ADDR_RESERVED_2A_OFFSET                                          0x0000000000000008
#define MON_BUFFER_ADDR_RESERVED_2A_LSB                                             12
#define MON_BUFFER_ADDR_RESERVED_2A_MSB                                             15
#define MON_BUFFER_ADDR_RESERVED_2A_MASK                                            0x000000000000f000


/* Description		MSDU_CONTINUATION

			When set, this packet buffer was not able to hold the entire
			 MSDU. The next buffer will therefore contain additional
			 packet bytes.
			<legal all>
*/

#define MON_BUFFER_ADDR_MSDU_CONTINUATION_OFFSET                                    0x0000000000000008
#define MON_BUFFER_ADDR_MSDU_CONTINUATION_LSB                                       16
#define MON_BUFFER_ADDR_MSDU_CONTINUATION_MSB                                       16
#define MON_BUFFER_ADDR_MSDU_CONTINUATION_MASK                                      0x0000000000010000


/* Description		TRUNCATED

			When set, this TLV belongs to a previously truncated MPDU.
			
			<legal all>
*/

#define MON_BUFFER_ADDR_TRUNCATED_OFFSET                                            0x0000000000000008
#define MON_BUFFER_ADDR_TRUNCATED_LSB                                               17
#define MON_BUFFER_ADDR_TRUNCATED_MSB                                               17
#define MON_BUFFER_ADDR_TRUNCATED_MASK                                              0x0000000000020000


/* Description		RESERVED_2B

			<legal 0>
*/

#define MON_BUFFER_ADDR_RESERVED_2B_OFFSET                                          0x0000000000000008
#define MON_BUFFER_ADDR_RESERVED_2B_LSB                                             18
#define MON_BUFFER_ADDR_RESERVED_2B_MSB                                             31
#define MON_BUFFER_ADDR_RESERVED_2B_MASK                                            0x00000000fffc0000


/* Description		TLV64_PADDING

			Automatic DWORD padding inserted while converting TLV32 
			to TLV64 for 64 bit ARCH
			<legal 0>
*/

#define MON_BUFFER_ADDR_TLV64_PADDING_OFFSET                                        0x0000000000000008
#define MON_BUFFER_ADDR_TLV64_PADDING_LSB                                           32
#define MON_BUFFER_ADDR_TLV64_PADDING_MSB                                           63
#define MON_BUFFER_ADDR_TLV64_PADDING_MASK                                          0xffffffff00000000



#endif   // MON_BUFFER_ADDR
