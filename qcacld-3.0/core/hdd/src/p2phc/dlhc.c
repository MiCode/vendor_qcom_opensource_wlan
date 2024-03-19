// MIUI ADD: WIFI_P2PHC
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include "dlhc.h"

#ifdef CONFIG_INET
/* Entire module is for IP only */
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/termios.h>
#include <linux/in.h>
#include <linux/fcntl.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <net/checksum.h>
#include <asm/unaligned.h>

static unsigned char * put16(unsigned char *cp, unsigned short x);
static unsigned char * put32(unsigned char *cp, unsigned int x);
static unsigned short pull16(unsigned char **cpp);
static unsigned int pull32(unsigned char **cpp);

/* Allocate compression data structure
 *	slots must be in range 0 to 255 (zero meaning no compression)
 * Returns pointer to structure or ERR_PTR() on error.
 */
static struct dlhc *__dlhc_init(struct dlhc *comp, int rslots, int tslots, unsigned char flags)
{
	short i;
	struct cstate *ts;

	if (! comp)
		goto out_fail;

	if (rslots > 0) {
		size_t rsize = rslots * sizeof(struct cstate);
		comp->rstate = kzalloc(rsize, GFP_KERNEL);
		if (! comp->rstate)
			goto out_fail;
		comp->rslot_limit = rslots - 1;
	}

	if (tslots > 0) {
		size_t tsize = tslots * sizeof(struct cstate);
		comp->tstate = kzalloc(tsize, GFP_KERNEL);
		if (! comp->tstate)
			goto out_free;
		comp->tslot_limit = tslots - 1;
	}

	comp->xmit_oldest = 0;
	comp->xmit_current = 255;
	comp->recv_current = 255;
	/*
	 * don't accept any packets with implicit index until we get
	 * one with an explicit index.  Otherwise the uncompress code
	 * will try to use connection 255, which is almost certainly
	 * out of range
	 */
	comp->flags |= DLHC_F_TOSS;
	comp->flags |= flags;

	if ( tslots > 0 ) {
		ts = comp->tstate;
		for(i = comp->tslot_limit; i > 0; --i){
			ts[i].cs_this = i;
			ts[i].next = &(ts[i - 1]);
		}
		ts[0].next = &(ts[comp->tslot_limit]);
		ts[0].cs_this = 0;
	}
	return comp;

out_free:
	kfree(comp->rstate);
out_fail:
	return ERR_PTR(-ENOMEM);
}

struct dlhc *dlhc_init(int rslots, int tslots)
{
	struct dlhc *comp, *comp_tcp, *comp_udp;

	if (rslots < 0 || rslots > 255 || tslots < 0 || tslots > 255)
		return ERR_PTR(-EINVAL);

	comp = kzalloc(sizeof(struct dlhc) * 2, GFP_KERNEL);
	if (! comp)
		goto out_fail;

	/* tcp */
	comp_tcp = comp;
	comp_tcp = __dlhc_init(comp_tcp, rslots, tslots, DLHC_F_TCP);
	if (IS_ERR(comp_tcp)) {
		kfree(comp);
		goto out_fail;
	}
	/* udp */
	comp_udp = comp + 1;
	comp_udp = __dlhc_init(comp_udp, rslots, tslots, DLHC_F_UDP);
	if (IS_ERR(comp_udp)) {
		dlhc_free(comp);
		goto out_fail;
	}
	return comp;

out_fail:
	return ERR_PTR(-ENOMEM);
}

void dlhc_free(struct dlhc *comp)
{
	struct dlhc *comp2;

	if ( IS_ERR_OR_NULL(comp) )
		return;

	if ( comp->tstate != NULLSLSTATE )
		kfree( comp->tstate );

	if ( comp->rstate != NULLSLSTATE )
		kfree( comp->rstate );

	comp2 = comp + 1;
	if ( comp2->tstate != NULLSLSTATE )
		kfree( comp2->tstate );

	if ( comp2->rstate != NULLSLSTATE )
		kfree( comp2->rstate );

	kfree( comp );
}

int dlhc_reset(struct dlhc *comp)
{
	int i;
	struct cstate *ts;
	struct cstate *rs;
	struct dlhc *comp2;

	if ( IS_ERR_OR_NULL(comp) )
		return -1;

	/* tcp tx */
	comp->xmit_current = 255;
	comp->xmit_oldest = 0;
	ts = comp->tstate;
	memset(ts, 0, (comp->tslot_limit + 1) * sizeof(struct cstate));
	for (i = comp->tslot_limit; i > 0; --i) {
			ts[i].cs_this = i;
			ts[i].next = &(ts[i - 1]);
	}
	ts[0].next = &(ts[comp->tslot_limit]);

	/* tcp rx */
	comp->recv_current = 255;
	comp->flags |= DLHC_F_TOSS;
	rs = comp->rstate;
	for (i = comp->rslot_limit; i > 0; --i) {
		rs[i].initialized = false;
	}

	comp2 = comp + 1;
	/* udp tx */
	comp2->xmit_current = 255;
	comp2->xmit_oldest = 0;
	ts = comp2->tstate;
	memset(ts, 0, (comp2->tslot_limit + 1) * sizeof(struct cstate));
	for (i = comp2->tslot_limit; i > 0; --i) {
			ts[i].cs_this = i;
			ts[i].next = &(ts[i - 1]);
	}
	ts[0].next = &(ts[comp2->tslot_limit]);

	/* udp rx */
	comp2->recv_current = 255;
	comp2->flags |= DLHC_F_TOSS;
	rs = comp2->rstate;
	for (i = comp2->rslot_limit; i > 0; --i) {
		rs[i].initialized = false;
	}

	return 0;
}

/* Put a short in host order into a char array in network order */
static inline unsigned char *put16(unsigned char *cp, unsigned short x)
{
	*cp++ = x >> 8;
	*cp++ = x;

	return cp;
}

static inline unsigned char *put32(unsigned char *cp, unsigned int x)
{
	*cp++ = x >> 24;
	*cp++ = x >> 16;
	*cp++ = x >> 8;
	*cp++ = x;

	return cp;
}

/* Pull a 16-bit integer in host order from buffer in network byte order */
static unsigned short pull16(unsigned char **cpp)
{
	short rval;

	rval = *(*cpp)++;
	rval <<= 8;
	rval |= *(*cpp)++;
	return rval;
}

static unsigned int pull32(unsigned char **cpp)
{
	unsigned int rval;

	rval = *(*cpp)++;
	rval <<= 8;
	rval |= *(*cpp)++;
	rval <<= 8;
	rval |= *(*cpp)++;
	rval <<= 8;
	rval |= *(*cpp)++;
	return rval;
}

/*
 * icp and isize are the original packet.
 * ocp is a place to put a copy if necessary.
 * cpp is initially a pointer to icp.  If the copy is used,
 *    change it to ocp.
 */
static int __dlhc_compress_tcp(struct dlhc *comp, unsigned char *icp, int isize,
	unsigned char *ocp, unsigned char **cpp, int compress_cid)
{
	struct cstate *ocs = &(comp->tstate[comp->xmit_oldest]);
	struct cstate *lcs = ocs;
	struct cstate *cs = lcs->next;
	int nlen, hlen;
	unsigned char *cp;
	struct iphdr *ip;
	struct tcphdr *th;

	ip = (struct iphdr *) icp;
	nlen = ip->ihl * 4;
	if (isize < nlen + sizeof(struct tcphdr))
		return isize;

	th = (struct tcphdr *)(icp + nlen);
	if (th->doff < sizeof(struct tcphdr) / 4)
		return isize;
	hlen = nlen + th->doff * 4;

	/*  Bail if the TCP packet isn't `compressible' (i.e., ACK isn't set or
	 *  some other control bit is set). Also uncompressible if
	 *  it's a runt.
	 */
	if(hlen > isize || th->syn || th->fin || th->rst || th->urg ||
	    ! (th->ack)){
		/* TCP connection stuff; send as regular IP */
		comp->stat_o_tcp++;
		return isize;
	}
	/*
	 * Packet is compressible -- we're going to send either a
	 * COMPRESSED_TCP or UNCOMPRESSED_TCP packet.  Either way,
	 * we need to locate (or create) the connection state.
	 *
	 * States are kept in a circularly linked list with
	 * xmit_oldest pointing to the end of the list.  The
	 * list is kept in lru order by moving a state to the
	 * head of the list whenever it is referenced.  Since
	 * the list is short and, empirically, the connection
	 * we want is almost always near the front, we locate
	 * states via linear search.  If we don't find a state
	 * for the datagram, the oldest state is (re-)used.
	 */
	for ( ; ; ) {
		if( ip->saddr == cs->cs_ip.saddr
		 && ip->daddr == cs->cs_ip.daddr
		 && th->source == cs->cs_tcp.source
		 && th->dest == cs->cs_tcp.dest)
			goto found;

		/* if current equal oldest, at end of list */
		if ( cs == ocs )
			break;
		lcs = cs;
		cs = cs->next;
		comp->stat_o_searches++;
	}
	/*
	 * Didn't find it -- re-use oldest cstate.  Send an
	 * uncompressed packet that tells the other side what
	 * connection number we're using for this conversation.
	 *
	 * Note that since the state list is circular, the oldest
	 * state points to the newest and we only need to set
	 * xmit_oldest to update the lru linkage.
	 */
	comp->stat_o_misses++;
	comp->xmit_oldest = lcs->cs_this;
	goto uncompressed;

found:
	/*
	 * Found it -- move to the front on the connection list.
	 */
	if(lcs == ocs) {
 		/* found at most recently used */
	} else if (cs == ocs) {
		/* found at least recently used */
		comp->xmit_oldest = lcs->cs_this;
	} else {
		/* more than 2 elements */
		lcs->next = cs->next;
		cs->next = ocs->next;
		ocs->next = cs;
	}

	/*
	 * Make sure that only what we expect to change changed.
	 * Check the following:
	 * IP protocol version, header length & type of service.
	 * The "Don't fragment" bit.
	 * The time-to-live field.
	 * The TCP header length.
	 * IP options, if any.
	 * TCP options, if any.
	 * If any of these things are different between the previous &
	 * current datagram, we send the current datagram `uncompressed'.
	 */
	if(ip->version != cs->cs_ip.version || ip->ihl != cs->cs_ip.ihl
	 || ip->tos != cs->cs_ip.tos
	 || (ip->frag_off & htons(0x4000)) != (cs->cs_ip.frag_off & htons(0x4000))
	 || ip->ttl != cs->cs_ip.ttl
	 || th->doff != cs->cs_tcp.doff
	 || (ip->ihl > 5 && memcmp(ip+1,cs->cs_ipopt,((ip->ihl)-5)*4) != 0)
	 || (th->doff > 5 && memcmp(th+1,cs->cs_tcpopt,((th->doff)-5)*4) != 0)){
		goto uncompressed;
	}

	if (!(th->urg) && (th->urg_ptr != cs->cs_tcp.urg_ptr)) {
		/* argh! URG not set but urp changed -- a sensible
		 * implementation should never do this but RFC793
		 * doesn't prohibit the change so we have to deal
		 * with it. */
		goto uncompressed;
	}

	//memcpy(&cs->cs_ip, ip, 20);
	//memcpy(&cs->cs_tcp, th, 20);

	if(compress_cid == 0 || comp->xmit_current != cs->cs_this){
		cp = ocp;
		*cpp = ocp;
		*cp++ = NEW_C;
		*cp++ = cs->cs_this;
		comp->xmit_current = cs->cs_this;
	} else {
		cp = ocp;
		*cpp = ocp;
		*cp++ = 0;
	}

	cp = put16(cp, ntohs(ip->id));
	cp = put32(cp, ntohl(th->seq));
	cp = put32(cp, ntohl(th->ack_seq));
	cp = put16(cp, ntohs(th->window));
	cp = put16(cp, ntohs(th->check));
	if(th->psh)
		ocp[0] |= TCP_PUSH_BIT;

	memcpy(cp, icp + hlen, isize - hlen);
	ocp[0] &= ~DL_TYPE_MASK;
	ocp[0] |= DL_TYPE_COMPRESSED_TCP;

	comp->stat_o_compressed++;
	return isize - hlen + (cp - ocp);

	/* Update connection state cs & send uncompressed packet (i.e.,
	 * a regular ip/tcp packet but with the 'conversation id' we hope
	 * to use on future compressed packets in the protocol field).
	 */
uncompressed:
	memcpy(&cs->cs_ip,ip,20);
	memcpy(&cs->cs_tcp,th,20);
	if (ip->ihl > 5)
	  memcpy(cs->cs_ipopt, ip+1, ((ip->ihl) - 5) * 4);
	if (th->doff > 5)
	  memcpy(cs->cs_tcpopt, th+1, ((th->doff) - 5) * 4);
	comp->xmit_current = cs->cs_this;
	comp->stat_o_uncompressed++;
	memcpy(ocp, icp, isize);
	*cpp = ocp;
	ocp[9] = cs->cs_this;
	ocp[0] &= ~DL_TYPE_MASK;
	ocp[0] |= DL_TYPE_UNCOMPRESSED_TCP;
	return isize;
}

static int __dlhc_compress_udp(struct dlhc *comp, unsigned char *icp, int isize,
	unsigned char *ocp, unsigned char **cpp, int compress_cid)
{
	struct cstate *ocs = &(comp->tstate[comp->xmit_oldest]);
	struct cstate *lcs = ocs;
	struct cstate *cs = lcs->next;
	int nlen, hlen;
	unsigned char *cp;
	struct iphdr *ip;
	struct udphdr *uh;

	ip = (struct iphdr *) icp;
	nlen = ip->ihl * 4;
	hlen = nlen + sizeof(struct udphdr);
	if (isize < hlen)
		return isize;

	uh = (struct udphdr *)(icp + nlen);

	/*
	 * Packet is compressible -- we're going to send either a
	 * COMPRESSED_TCP or UNCOMPRESSED_TCP packet.  Either way,
	 * we need to locate (or create) the connection state.
	 *
	 * States are kept in a circularly linked list with
	 * xmit_oldest pointing to the end of the list.  The
	 * list is kept in lru order by moving a state to the
	 * head of the list whenever it is referenced.  Since
	 * the list is short and, empirically, the connection
	 * we want is almost always near the front, we locate
	 * states via linear search.  If we don't find a state
	 * for the datagram, the oldest state is (re-)used.
	 */
	for ( ; ; ) {
		if( ip->saddr == cs->cs_ip.saddr
		 && ip->daddr == cs->cs_ip.daddr
		 && uh->source == cs->cs_udp.source
		 && uh->dest == cs->cs_udp.dest)
			goto found;

		/* if current equal oldest, at end of list */
		if ( cs == ocs )
			break;
		lcs = cs;
		cs = cs->next;
		comp->stat_o_searches++;
	}
	/*
	 * Didn't find it -- re-use oldest cstate.  Send an
	 * uncompressed packet that tells the other side what
	 * connection number we're using for this conversation.
	 *
	 * Note that since the state list is circular, the oldest
	 * state points to the newest and we only need to set
	 * xmit_oldest to update the lru linkage.
	 */
	comp->stat_o_misses++;
	comp->xmit_oldest = lcs->cs_this;
	goto uncompressed;

found:
	/*
	 * Found it -- move to the front on the connection list.
	 */
	if(lcs == ocs) {
 		/* found at most recently used */
	} else if (cs == ocs) {
		/* found at least recently used */
		comp->xmit_oldest = lcs->cs_this;
	} else {
		/* more than 2 elements */
		lcs->next = cs->next;
		cs->next = ocs->next;
		ocs->next = cs;
	}

	/*
	 * Make sure that only what we expect to change changed.
	 * Check the following:
	 * IP protocol version, header length & type of service.
	 * The "Don't fragment" bit.
	 * The time-to-live field.
	 * IP options, if any.
	 * If any of these things are different between the previous &
	 * current datagram, we send the current datagram `uncompressed'.
	 */
	if(ip->version != cs->cs_ip.version || ip->ihl != cs->cs_ip.ihl
	 || ip->tos != cs->cs_ip.tos
	 || (ip->frag_off & htons(0x4000)) != (cs->cs_ip.frag_off & htons(0x4000))
	 || ip->ttl != cs->cs_ip.ttl
	 || (ip->ihl > 5 && memcmp(ip+1,cs->cs_ipopt,((ip->ihl)-5)*4) != 0)) {
		goto uncompressed;
	}
	
	//memcpy(&cs->cs_ip, ip, 20);
	//memcpy(&cs->cs_udp, uh, 8);

	if(compress_cid == 0 || comp->xmit_current != cs->cs_this){
		cp = ocp;
		*cpp = ocp;
		*cp++ = NEW_C;
		*cp++ = cs->cs_this;
		comp->xmit_current = cs->cs_this;
	} else {
		cp = ocp;
		*cpp = ocp;
		*cp++ = 0;
	}

	cp = put16(cp, ntohs(ip->id));
	cp = put16(cp, ntohs(uh->len));
	cp = put16(cp, ntohs(uh->check));

	memcpy(cp, icp + hlen, isize - hlen);
	ocp[0] &= ~DL_TYPE_MASK;
	ocp[0] |= DL_TYPE_COMPRESSED_UDP;

	comp->stat_o_compressed++;
	return isize - hlen + (cp - ocp);

	/* Update connection state cs & send uncompressed packet (i.e.,
	 * a regular ip/tcp packet but with the 'conversation id' we hope
	 * to use on future compressed packets in the protocol field).
	 */
uncompressed:
	memcpy(&cs->cs_ip,ip,20);
	memcpy(&cs->cs_udp,uh,8);
	if (ip->ihl > 5)
	  memcpy(cs->cs_ipopt, ip+1, ((ip->ihl) - 5) * 4);
	comp->xmit_current = cs->cs_this;
	comp->stat_o_uncompressed++;
	memcpy(ocp, icp, isize);
	*cpp = ocp;
	ocp[9] = cs->cs_this;
	ocp[0] &= ~DL_TYPE_MASK;
	ocp[0] |= DL_TYPE_UNCOMPRESSED_UDP;
	return isize;
}

int dlhc_compress(struct dlhc *comp, unsigned char *icp, int isize,
	unsigned char *ocp, unsigned char **cpp, int compress_cid)
{
	struct iphdr *ip;

	/*
	 *	Don't play with runt packets.
	 */
	if(isize < sizeof(struct iphdr))
		return isize;

	ip = (struct iphdr *) icp;
	if (ip->version != 4 || ip->ihl < 5)
		return isize;

	/* Bail if this packet is an IP fragment */
	if (ntohs(ip->frag_off) & 0x3fff) {
		return isize;
	}

	if (ip->protocol == IPPROTO_TCP) {
		return __dlhc_compress_tcp(comp, icp, isize, ocp, cpp, compress_cid);
	} else if (ip->protocol == IPPROTO_UDP) {
		return __dlhc_compress_udp(comp + 1, icp, isize, ocp, cpp, compress_cid);
	}

	return isize;	
}

static int __dlhc_uncompress_tcp(struct dlhc *comp, unsigned char *icp, int isize)
{
	unsigned char changes;
	long x;
	struct tcphdr *thp;
	struct iphdr *ip;
	struct cstate *cs;
	int len, hdrlen;
	unsigned char *cp = icp;

	comp->stat_i_compressed++;
	if(isize < 15){
		comp->stat_i_error++;
		return 0;
	}
	changes = *cp++;
	if(changes & NEW_C){
		/* Make sure the state index is in range, then grab the state.
		 * If we have a good state index, clear the 'discard' flag.
		 */
		x = *cp++;	/* Read conn index */
		if(x < 0 || x > comp->rslot_limit)
			goto bad;

		/* Check if the cstate is initialized */
		if (!comp->rstate[x].initialized)
			goto bad;

		comp->flags &=~ DLHC_F_TOSS;
		comp->recv_current = x;
	} else {
		/* this packet has an implicit state index.  If we've
		 * had a line error since the last time we got an
		 * explicit state index, we have to toss the packet. */
		if(comp->flags & DLHC_F_TOSS){
			comp->stat_i_tossed++;
			return 0;
		}
	}
	cs = &comp->rstate[comp->recv_current];
	thp = &cs->cs_tcp;
	ip = &cs->cs_ip;

	ip->id = htons(pull16(&cp));
	thp->seq = htonl(pull32(&cp));
	thp->ack_seq = htonl(pull32(&cp));
	thp->window = htons(pull16(&cp));
	thp->check = htons(pull16(&cp));
	thp->psh = (changes & TCP_PUSH_BIT) ? 1 : 0;

	hdrlen = ip->ihl * 4 + thp->doff * 4;

	/*
	 * At this point, cp points to the first byte of data in the
	 * packet.  Put the reconstructed TCP and IP headers back on the
	 * packet.  Recalculate IP checksum (but not TCP checksum).
	 */
	len = isize - (cp - icp);
	if (len < 0)
		goto bad;
	len += hdrlen;
	ip->tot_len = htons(len);
	ip->check = 0;

	memmove(icp + hdrlen, cp, len - hdrlen);

	cp = icp;
	memcpy(cp, ip, 20);
	cp += 20;

	if (ip->ihl > 5) {
	  memcpy(cp, cs->cs_ipopt, (ip->ihl - 5) * 4);
	  cp += (ip->ihl - 5) * 4;
	}

	put_unaligned(ip_fast_csum(icp, ip->ihl),
		      &((struct iphdr *)icp)->check);

	memcpy(cp, thp, 20);
	cp += 20;

	if (thp->doff > 5) {
	  memcpy(cp, cs->cs_tcpopt, ((thp->doff) - 5) * 4);
	  cp += ((thp->doff) - 5) * 4;
	}

	return len;
bad:
	comp->stat_i_error++;
	return dlhc_toss( comp );
}

static int __dlhc_uncompress_udp(struct dlhc *comp, unsigned char *icp, int isize)
{
	unsigned char changes;
	long x;
	struct udphdr *uhp;
	struct iphdr *ip;
	struct cstate *cs;
	int len, hdrlen;
	unsigned char *cp = icp;

	comp->stat_i_compressed++;
	if(isize < 7){
		comp->stat_i_error++;
		return 0;
	}
	changes = *cp++;
	if(changes & NEW_C){
		/* Make sure the state index is in range, then grab the state.
		 * If we have a good state index, clear the 'discard' flag.
		 */
		x = *cp++;	/* Read conn index */
		if(x < 0 || x > comp->rslot_limit)
			goto bad;

		/* Check if the cstate is initialized */
		if (!comp->rstate[x].initialized)
			goto bad;

		comp->flags &=~ DLHC_F_TOSS;
		comp->recv_current = x;
	} else {
		/* this packet has an implicit state index.  If we've
		 * had a line error since the last time we got an
		 * explicit state index, we have to toss the packet. */
		if(comp->flags & DLHC_F_TOSS){
			comp->stat_i_tossed++;
			return 0;
		}
	}
	cs = &comp->rstate[comp->recv_current];
	uhp = &cs->cs_udp;
	ip = &cs->cs_ip;

	ip->id = htons(pull16(&cp));
	uhp->len = htons(pull16(&cp));
	uhp->check = htons(pull16(&cp));

	hdrlen = (ip->ihl * 4) + 8;

	/*
	 * At this point, cp points to the first byte of data in the
	 * packet.  Put the reconstructed UDP and IP headers back on the
	 * packet.  Recalculate IP checksum (but not UDP checksum).
	 */
	len = isize - (cp - icp);
	if (len < 0)
		goto bad;
	len += hdrlen;
	ip->tot_len = htons(len);
	ip->check = 0;

	memmove(icp + hdrlen, cp, len - hdrlen);

	cp = icp;
	memcpy(cp, ip, 20);
	cp += 20;

	if (ip->ihl > 5) {
	  memcpy(cp, cs->cs_ipopt, (ip->ihl - 5) * 4);
	  cp += (ip->ihl - 5) * 4;
	}

	put_unaligned(ip_fast_csum(icp, ip->ihl),
		      &((struct iphdr *)icp)->check);

	memcpy(cp, uhp, 8);
	cp += 8;

	return len;
bad:
	comp->stat_i_error++;
	return dlhc_toss( comp );
}

int dlhc_uncompress(struct dlhc *comp, unsigned char *icp, int isize)
{
	unsigned char dl_type = icp[0] & DL_TYPE_MASK;

	if (dl_type == DL_TYPE_COMPRESSED_TCP) {
		return __dlhc_uncompress_tcp(comp, icp, isize);
	} else if (dl_type == DL_TYPE_COMPRESSED_UDP) {
		return __dlhc_uncompress_udp(comp + 1, icp, isize);
	}
	return 0;
}

static int __dlhc_remember_tcp(struct dlhc *comp, unsigned char *icp, int isize)
{
	struct cstate *cs;
	unsigned ihl;
	unsigned char index;

	if(isize < 20) {
		/* The packet is shorter than a legal IP header */
		comp->stat_i_runt++;
		return dlhc_toss( comp );
	}
	/* Peek at the IP header's IHL field to find its length */
	ihl = icp[0] & 0xf;
	if(ihl < 20 / 4){
		/* The IP header length field is too small */
		comp->stat_i_runt++;
		return dlhc_toss( comp );
	}

	if (ip_fast_csum(icp, ihl)) {
		/* Bad IP header checksum; discard */
		comp->stat_i_badcheck++;
		return dlhc_toss( comp );
	}

	index = icp[9];
	if(index > comp->rslot_limit) {
		comp->stat_i_error++;
		return dlhc_toss(comp);
	}

	icp[0] &= ~DL_TYPE_MASK;
	icp[0] |= DL_TYPE_IP;
	icp[9] = IPPROTO_TCP;
	ip_send_check((struct iphdr *)icp);

	/* Update local state */
	cs = &comp->rstate[comp->recv_current = index];
	comp->flags &=~ DLHC_F_TOSS;
	memcpy(&cs->cs_ip,icp,20);
	memcpy(&cs->cs_tcp,icp + ihl*4,20);
	if (ihl > 5)
	  memcpy(cs->cs_ipopt, icp + sizeof(struct iphdr), (ihl - 5) * 4);
	if (cs->cs_tcp.doff > 5)
	  memcpy(cs->cs_tcpopt, icp + ihl*4 + sizeof(struct tcphdr), (cs->cs_tcp.doff - 5) * 4);
	cs->initialized = true;
	/* Put headers back on packet
	 * Neither header checksum is recalculated
	 */
	comp->stat_i_uncompressed++;
	return isize;
}

static int __dlhc_remember_udp(struct dlhc *comp, unsigned char *icp, int isize)
{
	struct cstate *cs;
	unsigned ihl;
	unsigned char index;

	if(isize < 20) {
		/* The packet is shorter than a legal IP header */
		comp->stat_i_runt++;
		return dlhc_toss( comp );
	}
	/* Peek at the IP header's IHL field to find its length */
	ihl = icp[0] & 0xf;
	if(ihl < 20 / 4){
		/* The IP header length field is too small */
		comp->stat_i_runt++;
		return dlhc_toss( comp );
	}

	if (ip_fast_csum(icp, ihl)) {
		/* Bad IP header checksum; discard */
		comp->stat_i_badcheck++;
		return dlhc_toss( comp );
	}

	index = icp[9];
	if(index > comp->rslot_limit) {
		comp->stat_i_error++;
		return dlhc_toss(comp);
	}

	icp[0] &= ~DL_TYPE_MASK;
	icp[0] |= DL_TYPE_IP;
	icp[9] = IPPROTO_UDP;
	ip_send_check((struct iphdr *)icp);

	/* Update local state */
	cs = &comp->rstate[comp->recv_current = index];
	comp->flags &=~ DLHC_F_TOSS;
	memcpy(&cs->cs_ip, icp, 20);
	memcpy(&cs->cs_udp, icp + ihl*4, 8);
	if (ihl > 5)
	  memcpy(cs->cs_ipopt, icp + sizeof(struct iphdr), (ihl - 5) * 4);
	cs->initialized = true;

	comp->stat_i_uncompressed++;
	return isize;
}

int dlhc_remember(struct dlhc *comp, unsigned char *icp, int isize)
{
	unsigned char dl_type = icp[0] & DL_TYPE_MASK;

	if (dl_type == DL_TYPE_UNCOMPRESSED_TCP) {
		return __dlhc_remember_tcp(comp, icp, isize);
	} else if (dl_type == DL_TYPE_UNCOMPRESSED_UDP) {
		return __dlhc_remember_udp(comp + 1, icp, isize);
	}
	return 0;
}

int dlhc_toss(struct dlhc *comp)
{
	if ( comp == NULL )
		return 0;

	comp->flags |= DLHC_F_TOSS;
	return 0;
}

#else /* CONFIG_INET */

int
dlhc_toss(struct dlhc *comp)
{
  printk(KERN_DEBUG "Called IP function on non IP-system: dlhc_toss");
  return -EINVAL;
}
int
dlhc_uncompress(struct dlhc *comp, unsigned char *icp, int isize)
{
  printk(KERN_DEBUG "Called IP function on non IP-system: dlhc_uncompress");
  return -EINVAL;
}
int
dlhc_compress(struct dlhc *comp, unsigned char *icp, int isize,
	unsigned char *ocp, unsigned char **cpp, int compress_cid)
{
  printk(KERN_DEBUG "Called IP function on non IP-system: dlhc_compress");
  return -EINVAL;
}

int
dlhc_remember(struct dlhc *comp, unsigned char *icp, int isize)
{
  printk(KERN_DEBUG "Called IP function on non IP-system: dlhc_remember");
  return -EINVAL;
}

int dlhc_reset(struct dlhc *comp)
{
	printk(KERN_DEBUG "Called IP function on non IP-system: dlhc_reset");
}

void
dlhc_free(struct dlhc *comp)
{
  printk(KERN_DEBUG "Called IP function on non IP-system: dlhc_free");
}

struct dlhc *
dlhc_init(int rslots, int tslots)
{
  printk(KERN_DEBUG "Called IP function on non IP-system: dlhc_init");
  return NULL;
}

#endif /* CONFIG_INET */
// END WIFI_P2PHC
