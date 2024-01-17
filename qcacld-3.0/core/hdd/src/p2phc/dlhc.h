// MIUI ADD: WIFI_P2PHC
#ifndef _DLHC_H_
#define _DLHC_H_
/*
 * Packet types (must not conflict with IP protocol version)
 *
 * The top nibble of the first octet is the packet type.  There are
 * three possible types: IP (not proto TCP or tcp with one of the
 * control flags set); uncompressed TCP (a normal IP/TCP packet but
 * with the 8-bit protocol field replaced by an 8-bit connection id --
 * this type of packet syncs the sender & receiver); and compressed
 * TCP (described above).
 *
 * LSB of 4-bit field is TCP "PUSH" bit (a worthless anachronism) and
 * is logically part of the 4-bit "changes" field that follows.  Top
 * three bits are actual packet type.  For backward compatibility
 * and in the interest of conserving bits, numbers are chosen so the
 * IP protocol version number (4) which normally appears in this nibble
 * means "IP packet".
 */

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* SLIP compression masks for len/vers byte */
#define DL_TYPE_IP	 				0x40
#define DL_TYPE_UNCOMPRESSED_TCP 	0x70
#define DL_TYPE_COMPRESSED_TCP 		0x80
#define DL_TYPE_UNCOMPRESSED_UDP 	0x90
#define DL_TYPE_COMPRESSED_UDP 		0xA0
#define DL_TYPE_ERROR 				0x00
#define DL_TYPE_MASK 				0xF0

/* Bits in first octet of compressed packet */
#define NEW_C			0x08
#define TCP_PUSH_BIT 	0x04

typedef __u8 byte_t;

/*
 * "state" data for each active tcp conversation on the wire.  This is
 * basically a copy of the entire IP/TCP header from the last packet
 * we saw from the conversation together with a small identifier
 * the transmit & receive ends of the line use to locate saved header.
 */
struct cstate {
	byte_t	cs_this;	/* connection id number (xmit) */
	bool	initialized;	/* true if initialized */
	struct cstate *next;	/* next in ring (xmit) */
	struct iphdr cs_ip;	/* ip/tcp hdr from most recent packet */
	struct tcphdr cs_tcp;
	struct udphdr cs_udp;
	unsigned char cs_ipopt[64];
	unsigned char cs_tcpopt[64];
};
#define NULLSLSTATE	(struct cstate *)0

/*
 * all the state data for one serial line (we need one of these per line).
 */
struct dlhc {
	struct cstate *tstate;	/* transmit connection states (array)*/
	struct cstate *rstate;	/* receive connection states (array)*/

	byte_t tslot_limit;	/* highest transmit slot id (0-l)*/
	byte_t rslot_limit;	/* highest receive slot id (0-l)*/

	byte_t xmit_oldest;	/* oldest xmit in ring */
	byte_t xmit_current;	/* most recent xmit id */
	byte_t recv_current;	/* most recent rcvd id */

	byte_t flags;
#define DLHC_F_TCP	0x80
#define DLHC_F_UDP	0x40
#define DLHC_F_TOSS	0x01	/* tossing rcvd frames until id received */

	unsigned int stat_o_nontcp;	/* outbound non-TCP packets */
	unsigned int stat_o_tcp;	/* outbound TCP packets */
	unsigned int stat_o_uncompressed;	/* outbound uncompressed packets */
	unsigned int stat_o_compressed;	/* outbound compressed packets */
	unsigned int stat_o_searches;	/* searches for connection state */
	unsigned int stat_o_misses;	/* times couldn't find conn. state */

	unsigned int stat_i_uncompressed;	/* inbound uncompressed packets */
	unsigned int stat_i_compressed;	/* inbound compressed packets */
	unsigned int stat_i_error;	/* inbound error packets */
	unsigned int stat_i_tossed;	/* inbound packets tossed because of error */
	unsigned int stat_i_runt;
	unsigned int stat_i_badcheck;
};

struct dlhc *dlhc_init(int rslots, int tslots);
void dlhc_free(struct dlhc *comp);
int dlhc_reset(struct dlhc *comp);
int dlhc_compress(struct dlhc *comp, unsigned char *icp, int isize,
		  unsigned char *ocp, unsigned char **cpp, int compress_cid);
int dlhc_uncompress(struct dlhc *comp, unsigned char *icp, int isize);
int dlhc_remember(struct dlhc *comp, unsigned char *icp, int isize);
int dlhc_toss(struct dlhc *comp);

#endif	/* _DLHC_H_ */

// END WIFI_P2PHC
