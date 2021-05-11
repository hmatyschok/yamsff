/*
 * Copyright (c) 2008 Claudio Jeker <claudio@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
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
/*-
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*-
 * Copyright (c) 2015 Henning Matyschok
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. 
 */

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_mpls.h"
#include "opt_mpls_debug.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/pfil.h>
#include <net/vnet.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/ip_options.h>
#include <netinet/tcp.h>
#include <netinet/icmp_var.h>
#include <machine/in_cksum.h>
#include <netinet/ip_fw.h>
#include <netpfil/ipfw/ip_fw_private.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#endif /* INET6 */

#include <netmpls/mpls.h>

extern struct mbuf *	mpls_shim_pop(struct mbuf *);
extern struct mbuf *	mpls_shim_swap(struct mbuf *, struct mpls_ro *);
extern struct mbuf *	mpls_shim_push(struct mbuf *, struct mpls_ro *);
extern void	mpls_rtalert_input(struct mbuf *, int);

extern struct protosw mplssw[];

/*
 * Input processing and forwarding.
 */

int	mpls_ip_checkbasic(struct mbuf **);
#ifdef INET6
int	mpls_ip6_checkbasic(struct mbuf **);
#endif /* INET6 */
int	mpls_pfil(struct mbuf **, struct ifnet *, int);

struct mbuf * 	mpls_ip_adjttl(struct mbuf *, uint8_t);
#ifdef INET6
struct mbuf * 	mpls_ip6_adjttl(struct mbuf *, uint8_t);
#endif /* INET6 */

static int	mpls_ip_fragment(struct ifnet *, struct mbuf *, 
	struct shim_hdr *, size_t);
static struct mbuf *	mpls_icmp_reflect(struct mbuf *);
static struct mbuf *	mpls_icmp_error(struct mbuf *, int, int, 
	uint32_t, int); 
static struct mbuf *	mpls_do_error(struct mbuf *, int);

static void	mpls_dummynet(struct mbuf *, struct ifnet *);

static void 	mpls_input(struct mbuf *);
 
static void 	mpls_forward(struct mbuf *);
void	mpls_init(void);

static void 	mpls_bridge_if(void *arg __unused, struct ifnet *, int);

/*
 * Service access point for dummynet(4).
 */
void	(*mpls_dn_p)(struct mbuf *, struct ifnet *);

/*
 * Defines set containing nhlfe. 
 */
struct mpls_head mpls_ifaddrhead;
struct rwlock mpls_ifaddr_lock;

RW_SYSINIT(mpls_ifadddr_lock, &mpls_ifaddr_lock, "mpls_ifaddr_lock");

/*
 * MPLS input queue is managed by netisr(9).
 */
static struct netisr_handler mpls_nh = {
	.nh_name 		= "mpls layer",
	.nh_handler 		= mpls_input,
	.nh_proto 		= NETISR_MPLS,
	.nh_policy 		= NETISR_POLICY_FLOW,
};

static struct netisr_handler mpls_forward_nh = {
	.nh_name 		= "mpls forwarding",
	.nh_handler 		= mpls_forward,
	.nh_proto 		= NETISR_MPLS_FWD,
	.nh_policy 		= NETISR_POLICY_FLOW,
};

/*
 * MPLS initialisation.
 */
void
mpls_init(void)
{
	TAILQ_INIT(&mpls_ifaddrhead);
	EVENTHANDLER_REGISTER(mpls_bridge_event, mpls_bridge_if, 
		NULL, EVENTHANDLER_PRI_ANY);
	mpls_dn_p = mpls_dummynet;
	netisr_register(&mpls_nh);
	netisr_register(&mpls_forward_nh);
}

/*
 * Restore cached MPLS label stack, when pdu leaves dummynet(4) subsystem.
 * 
 * See by mbuf_tags(9) denoted manual page for further details.
 */	
static void
mpls_dummynet(struct mbuf *m, struct ifnet *ifp)
{
	struct m_tag_mpls *mtm;

	mtm = (struct m_tag_mpls *)
		m_tag_locate(m, MTAG_MPLS, MTAG_MPLS_STACK, NULL);
	if (mtm == NULL) {
		m_freem(m);
		return;
	}	
	M_PREPEND(m, mtm->mtm_size, M_NOWAIT);
	if (m == NULL)
		return;
			
	bcopy(&mtm->mtm_stk, mtod(m, caddr_t), mtm->mtm_size);
	m_tag_delete(m, &mtm->mtm_tag);
	
	netisr_dispatch(NETISR_MPLS_FWD, m);
}

/*
 * Receive mbuf(9) originating
 *
 *  (a) if_simloop or
 *
 *  (b) ether_demux or
 *
 *  (c) mpe_input,
 * 
 * if MPLS label remains Bottom of Stack (BoS) and denotes reserved MPLS label
 * value (but its value denotes not MPLS_LABEL_IMPLNULL), mbuf(9) will be   
 * passed to higher layer by its label value mapped input procedure call. 
 * 
 * Further, if MPLS label value denotes MPLS_RTALERT and its position is not 
 * BoS, then pdu containing mbuf(9) is passed into socket layer (directly) by
 * mpls_rtalert_input. Any other cases are handled by mpls_forward.
 */
static void
mpls_input(struct mbuf *m)
{	
	struct ifnet *ifp;

	M_ASSERTPKTHDR(m);
	
	if (m->m_flags & (M_BCAST|M_MCAST)) 
		goto bad;
		
	if (m->m_pkthdr.len < MPLS_HDRLEN) 
		goto bad;

	if (m->m_len < MPLS_HDRLEN) {
		if ((m = m_pullup(m, MPLS_HDRLEN)) == NULL)
			return;
	}
	
	if ((ifp = m->m_pkthdr.rcvif) == NULL)
		goto bad;
	
	if ((ifp->if_flags & IFF_MPLS) == 0)
		goto bad;
/* 
 * Service Access Point (sap) for Inspection Access Point (iap) on pfil(9).
 */
	if (PFIL_HOOKED(&V_inet_pfil_hook)
#ifdef INET6
	    || PFIL_HOOKED(&V_inet6_pfil_hook)
#endif
	) {    
		if (mpls_pfil(&m, ifp, PFIL_IN) != 0)
			return;
		if (m == NULL)
			return;
	}

#ifdef MPLS_DEBUG
	(void)printf("%s: on=%s \n", __func__, ifp->if_xname);
#endif /* MPLS_DEBUG */

	netisr_dispatch(NETISR_MPLS_FWD, m);
	return;	
bad:
	m_freem(m);	
}

/*
 * Validate ttl and decrement. If invalid, sdu 
 * is replaced by icmp packet as exception 
 * handling. 
 *
 * Perform MPLS label stack specific operations:
 *
 *  1. Get SHIM and perform operations mapped to 
 *	   reserved labels, pop and reiterate, if any.
 *
 *  2. Use incoming label as key for routing table
 *     and fetch ilm, if any.
 *
 *  3. Perform by rt_gateway encoded operation.
 *
 *  4. Forward pdu or demultiplex and pass sdu into 
 *
 *       (a) link-layer or 
 * 
 *       (b) protocol-layer or 
 *
 *       (c) socket-layer,
 *
 *     if possible. 
 */
static void
mpls_forward(struct mbuf *m)
{
	struct ifnet *ifp = NULL;
	struct mpls_ro mplsroute;
	struct mpls_ro *mro;
	
	struct shim_hdr *shim;

	uint8_t ttl;
	int i, hasbos;
	
	struct sockaddr_mpls *seg;
	
	mro = &mplsroute;
	bzero(mro, sizeof(*mro));
/*
 * Map incoming segment (seg_in) and 
 * perform exception handling, if ttl 
 * exceeds.
 */		
	shim = mtod(m, struct shim_hdr *);	

	ttl = MPLS_TTL_GET(shim->shim_label);

	if (ttl-- <= 1) {	
		if ((m = mpls_do_error(m, 0)) == NULL) 			
			goto done; 					
	}
	seg = (struct sockaddr_mpls *)&mro->mro_gw;
	seg->smpls_len = sizeof(*seg);
	seg->smpls_family = AF_MPLS;
	
	for (i = 0; i < mpls_inkloop; i++) {
	
		seg->smpls_label = shim->shim_label & MPLS_LABEL_MASK;
		hasbos = MPLS_BOS(shim->shim_label);
		
#ifdef MPLS_DEBUG
		(void)printf(" | %02d: label %d ttl %d bos %d\n", 
			i, MPLS_LABEL_GET(seg->smpls_label),
			ttl, hasbos);
#endif /* MPLS_DEBUG */
		
		if (IS_RESERVED(seg->smpls_label)) {
/*
 * Perform by reserved MPLS label bound operations.
 */			
			if ((m = mpls_shim_pop(m)) == NULL)
				goto done;
				
			switch (MPLS_LABEL_GET(seg->smpls_label)) {
			case MPLS_LABEL_IPV4NULL:
/*
 * RFC 4182 relaxes the position of the explicit NULL labels. 
 * They no longer need to be at the beginning of the stack.
 */
				if (hasbos == 0) 
					break;		
do_v4:
				if ((m = mpls_ip_adjttl(m, ttl)) != NULL)
					netisr_dispatch(NETISR_IP, m);
				
				goto done;
			case MPLS_LABEL_RTALERT:
/*
 * Pass pdu into socket-layer.
 */					
				if (hasbos != 0)
					goto out;
			
				mpls_rtalert_input(m, 0);
				goto done;
#ifdef INET6
			case MPLS_LABEL_IPV6NULL:
			
				if (hasbos == 0) 
					break;
do_v6:				
				if ((m = mpls_ip6_adjttl(m, ttl)) != NULL)
					netisr_dispatch(NETISR_IPV6, m);
	
				goto done;
				break;
#endif /* INET6 */
			case MPLS_LABEL_IMPLNULL:
				
				if (hasbos == 0)
					break;
				
				switch (*mtod(m, u_char *) >> 4) {
				case IPVERSION:
					goto do_v4;
#ifdef INET6
				case IPV6_VERSION >> 4:
					goto do_v6;
#endif /* INET6 */
				default:
					break; 
				}
				goto out;
			case MPLS_RD_ETHDEMUX:
/*
 * Decapsulate and broadcast frame.
 */		
				if (hasbos != 0 && ifp != NULL) {
do_link:			
					switch (ifp->if_type) {
					case IFT_ETHER:
					case IFT_FDDI:
						
						if (mpls_empty_cw != 0) 
							m_adj(m, MPLS_CWLEN);
						
						if (*mtod(m, uint32_t *) == 0)
							m_adj(m, MPLS_CWLEN);

						(void)(*ifp->if_transmit)(ifp, m);	
						break;
					case IFT_MPLS:
						(*ifp->if_input)(ifp, m);
						break;
					default:
						goto out;	
					}		
					goto done;
				}
				goto out;
			default:
/* 
 * Other cases are not yet handled. 
 */
				goto out;
			}
			shim = mtod(m, struct shim_hdr *);	
			mpls_rtfree(mro);
			continue;
		}
/*
 * Fetch ilm.
 */		
		mpls_rtalloc_fib(mro, M_GETFIB(m));
		if (mro->mro_flags == 0) {
#ifdef MPLS_DEBUG
			(void)printf("%s: seg_in particular "
				"lsp %d not found\n", __func__,
				MPLS_LABEL_GET(seg->smpls_label));
#endif /* MPLS_DEBUG */
			goto out;
		}
		ifp = mro->mro_ilm->rt_ifp;

		switch (satosftn_op(mro->mro_ilm->rt_gateway)) {
		case RTF_POP:				
/*
 * If not BoS, pop MPLS label and re-iterate.
 */
			if (hasbos == 0) {

				if ((m = mpls_shim_pop(m)) != NULL) 
					mro->mro_flags |= RTF_STK;
				
				break;		
			}
/*
 * Divert, if inclusion mapping on if_mpe(4). 
 */
			if (ifp->if_type == IFT_MPLS) {
				(ifp->if_input)(ifp, m);
				goto done;
			}
/*
 * Handoff into protocol- or link-layer.
 */				
			if ((m = mpls_shim_pop(m)) == NULL) 
				break;
			
			switch (mro->mro_ilm->rt_gateway->sa_family) {
			case AF_INET:				
				goto do_v4;
#ifdef INET6
			case AF_INET6:
				goto do_v6;
#endif /* INET6 */
			case AF_LINK:
				goto do_link;
			
			default: /* unsupported domain */
				break;
			}
			goto out;
		case RTF_PUSH:
			m = mpls_shim_push(m, mro);
			break;
		case RTF_SWAP: 
			m = mpls_shim_swap(m, mro);
			break;
		default:	/* unsupported operation */
			goto out;	
		}
		
		if (m == NULL)
			goto done;
/*
 * Refetch.
 */	
 		shim = mtod(m, struct shim_hdr *);
		if ((mro->mro_flags & RTF_STK) == 0) 
			break;

		mpls_rtfree(mro);		
	}

	if (mro->mro_ilm == NULL)
		goto out;
/*
 * Update ttl and call mpls_output.
 */	
	shim->shim_label &= ~MPLS_TTL_MASK;
	shim->shim_label |= htonl(ttl) & MPLS_TTL_MASK;	
	
	seg->smpls_label = /* seg_out */
		shim->shim_label & MPLS_LABEL_MASK;
	
	(void)(*ifp->if_output)
		(ifp, m, (struct sockaddr *)seg, (struct route *)mro);
done:
	mpls_rtfree(mro);		
	return;
out:
	m_freem(m);
	goto done;
}	

/*
 * Provides access for packet inspection either 
 * by ipfw(4) or by pfil(9) defined hooks.
 *
 * Derived from bridge_pfil, parts of code 
 * sections in bridge_pfil are reused entirely. 
 *
 * See net/if_bridge.c for_further details.
 */
int
mpls_pfil(struct mbuf **mp, struct ifnet *ifp, int dir)
{
	struct m_tag_mpls *mtm;
	size_t nstk, hlen, i;
	struct ip *ip;
	int error = -1, ipver;

	if (ifp == NULL || *mp == NULL)
		goto done;
		
	if (mpls_pfil_hook == 0) {
		error = 0; /* filtering is disabled */
		goto done;
	}
/*
 * Allocate MTAG_MPLS containing cached MPLS label stack.
 */
	mtm = (struct m_tag_mpls *)
			m_tag_alloc(MTAG_MPLS, MTAG_MPLS_STACK, 
				sizeof(struct m_tag_mpls), M_NOWAIT);
 	if (mtm == NULL)
 		goto bad;	
/*
 * Strip off MPLS label stack and keep a copy.
 */
	for (nstk = 0; nstk < MPLS_INKERNEL_LOOP_MAX; nstk++) {
		if ((*mp)->m_len < MPLS_HDRLEN) {
		    if (((*mp) = m_pullup(*mp, MPLS_HDRLEN)) == NULL)
				goto done;
		}
		mtm->mtm_stk[nstk] = *mtod(*mp, struct shim_hdr *);
		m_adj(*mp, MPLS_HDRLEN);
		if (MPLS_BOS(mtm->mtm_stk[nstk].shim_label))
			break;
	}
	mtm->mtm_size = (nstk + 1) * MPLS_HDRLEN;
/*
 * Annotate.
 */
	m_tag_prepend(*mp, &mtm->mtm_tag);	
	
	i = min((*mp)->m_pkthdr.len, max_protohdr);
	if ((*mp)->m_len < i) {
	    if ((*mp = m_pullup(*mp, i)) == NULL) {
			printf("%s: m_pullup failed\n", __func__);
			goto done;
	    }
	}
	ipver = *mtod(*mp, u_char *) >> 4; 

	if (dir == PFIL_IN) {
		switch (ipver) {
		case IPVERSION:
			error = mpls_ip_checkbasic(mp);
			break;
#ifdef INET6
		case IPV6_VERSION >> 4:
			error = mpls_ip6_checkbasic(mp);
			break;
#endif /* INET6 */
		default:
			goto out;
		}	
		
		if (error != 0)
			goto bad;
	}
	error = 0;
/*
 * Pass MPI into by pfil(9) defined IAP, if enabled.
 */
	switch (ipver) {
	case IPVERSION:
/*
 * Before entering iap, swap fields the same 
 * as IPv4 does. Correct header alignement is
 * still assumed.
 */
 		ip = mtod(*mp, struct ip *);
		ip->ip_len = ntohs(ip->ip_len);
		ip->ip_off = ntohs(ip->ip_off);

		if (mpls_pfil_hook && ifp != NULL)
			error = pfil_run_hooks(&V_inet_pfil_hook, mp, ifp,
					dir, NULL);

		if (*mp == NULL || error != 0) /* filter may consume */
			break;
/* 
 * Ensure fragmentation, if any. 
 */
		if (ifp != NULL && dir == PFIL_OUT) {
			i = (*mp)->m_pkthdr.len;
			if (i > (ifp->if_mtu - mtm->mtm_size)) {
				error = mpls_ip_fragment(ifp, *mp, 
					mtm->mtm_stk, mtm->mtm_size);
				goto done;
			}
		}
		ip = mtod(*mp, struct ip *);
/* 
 * Recalculate ip checksum and restore byte ordering. 
 */
		hlen = ip->ip_hl << 2;
		if (hlen < sizeof(struct ip))
			goto bad;
		if (hlen > (*mp)->m_len) {
			if ((*mp = m_pullup(*mp, hlen)) == 0)
				goto bad;
			if ((ip = mtod(*mp, struct ip *)) == NULL)
				goto bad;
		}
		ip->ip_len = htons(ip->ip_len);
		ip->ip_off = htons(ip->ip_off);
		ip->ip_sum = 0;
		
		if (hlen == sizeof(struct ip))
			ip->ip_sum = in_cksum_hdr(ip);
		else
			ip->ip_sum = in_cksum(*mp, hlen);
		break;
#ifdef INET6
	case IPV6_VERSION >> 4:
		
		if (mpls_pfil_hook && ifp != NULL)
			error = pfil_run_hooks(&V_inet6_pfil_hook, mp, ifp,
					dir, NULL);
		break;
#endif /* INET6 */
	default:
		error = 0;
	}
	
	if (*mp == NULL)
		goto done;
	if (error != 0)
		goto bad;
/* 
 * Restore cached stack. 
 */
	error = -1;
out:
	M_PREPEND(*mp, mtm->mtm_size, M_NOWAIT);
	if (*mp == NULL)
		goto done;
			
	bcopy(mtm->mtm_stk, mtod(*mp, caddr_t), mtm->mtm_size);
	m_tag_delete(*mp, &mtm->mtm_tag);
	error = 0;
done:	
	return (error);
bad:
	m_freem(*mp);
	*mp = NULL;
	goto done;
}

/*
 * Perform basic checks on header size since pfil(9) assumes ip_input has
 * already processed it for it. The Implementation of bridge_ip_checkbasic 
 * where remains in if_bridge(4) is reused entirely. 
 *
 * See net/if_bridge.c for_further details.
 *
 * XXX: stats are not yet implemented.
 */
int
mpls_ip_checkbasic(struct mbuf **mp)
{
	int error = 0;
	struct mbuf *m;
	struct ip *ip;
	int len, hlen;
	u_short sum;

	if ((m = *mp) == NULL)
		goto bad;

	if (IP_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0) {
		if ((m = m_copyup(m, sizeof(struct ip),
			(max_linkhdr + 3) & ~3)) == NULL) 
			goto bad;
	} else if (__predict_false(m->m_len < sizeof(struct ip))) {
		if ((m = m_pullup(m, sizeof (struct ip))) == NULL) 
			goto bad;
	}

	if ((ip = mtod(m, struct ip *)) == NULL) 
		goto bad;

	if (ip->ip_v != IPVERSION)
		goto bad;

	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(struct ip)) /* minimum header length */
		goto bad;
	 
	if (hlen > m->m_len) {
		if ((m = m_pullup(m, hlen)) == 0)
			goto bad;
		 
		ip = mtod(m, struct ip *);
		if (ip == NULL) 
			goto bad;
	}

	if (m->m_pkthdr.csum_flags & CSUM_IP_CHECKED) {
		sum = !(m->m_pkthdr.csum_flags & CSUM_IP_VALID);
	} else {
		if (hlen == sizeof(struct ip)) 
			sum = in_cksum_hdr(ip);
		else 
			sum = in_cksum(m, hlen);
	}
	if (sum) 
		goto bad;
/* 
 * Retrieve the packet length. 
 */
	len = ntohs(ip->ip_len);
/*
 * Check for additional length bogosity.
 */
	if (len < hlen) 
		goto bad;
/*
 * Check, such that the amount of data in the buffers
 * is as at least much as the IP header would have 
 * us expect. 
 * 
 * Drop packet if shorter than we expect.
 */
	if (m->m_pkthdr.len < len)
		goto bad;
/* 
 * Checks out, proceed. 
 */
out:
	*mp = m;
	return (error);
bad:
	error = -1;
	goto out;
}

/*
 * Provides similar functionality as in case of mpls_ip_checkbasic, but only
 * for IPv6. The implementation of bridge_ip6_checkbasic in if_bridge(4) is 
 * reused. 
 *
 * See net/if_bridge.c for_further details.
 *
 * XXX: stats are not yet implemented.
 */
#ifdef INET6
int
mpls_ip6_checkbasic(struct mbuf **mp)
{
	int error = 0;
	struct mbuf *m;
	struct ip6_hdr *ip6;
	
	if ((m = *mp) == NULL)
		goto bad;
/*
 * If the IPv6 header is not aligned, slurp it up into a new
 * mbuf with space for link headers, in the event we forward
 * it.  Otherwise, if it is aligned, make sure the entire base
 * IPv6 header is in the first mbuf of the chain.
 */
	if (IP6_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0) {
		if ((m = m_copyup(m, sizeof(struct ip6_hdr),
			    (max_linkhdr + 3) & ~3)) == NULL) 
			goto bad;
	} else if (__predict_false(m->m_len < sizeof(struct ip6_hdr))) {
		if ((m = m_pullup(m, sizeof(struct ip6_hdr))) == NULL) 
			goto bad;
	}
	ip6 = mtod(m, struct ip6_hdr *);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) 
		goto bad;
/* 
 * Checks out, proceed. 
 */
out:
	*mp = m;
	return (error);

bad:
	error = -1;
	goto out;
}
#endif /* INET6 */

/*
 * Genarates icmp packet, if TTL exceeds.
 */
static struct mbuf *
mpls_do_error(struct mbuf *m, int destmtu)
{
	struct shim_hdr stk[MPLS_INKERNEL_LOOP_MAX];
	size_t nstk, stksize;
	struct shim_hdr *shim;
	struct ip *ip;
	size_t hlen;
	struct icmp *icp;
/*
 * Strip off MPLS label stack and keep a copy.
 */	
	for (nstk = 0; nstk < MPLS_INKERNEL_LOOP_MAX; nstk++) {
		if (m->m_len < MPLS_HDRLEN) {
		    if ((m = m_pullup(m, MPLS_HDRLEN)) == NULL)
				goto out;
		}
		stk[nstk] = *mtod(m, struct shim_hdr *);
		m_adj(m, MPLS_HDRLEN);
		if (MPLS_BOS(stk[nstk].shim_label))
			break;
	}
	stksize = (nstk + 1) * MPLS_HDRLEN;
	shim = &stk[0];
/*
 * XXX: outstanding ICMPv6 integration.
 */
	switch (*mtod(m, u_char *) >> 4) {
	case IPVERSION:
		if (m->m_len < sizeof(*ip)) {
			if ((m = m_pullup(m, sizeof(*ip))) == NULL)
				goto out;
		}
/*
 * Build sdu for ip(4) datagram.
 */
		m = mpls_icmp_error(m, ICMP_TIMXCEED, 
			ICMP_TIMXCEED_INTRANS, 0, destmtu);
		if (m == NULL)
			goto out;
/*
 * Build ip(4) pci.
 */
		if ((m = mpls_icmp_reflect(m)) == NULL)
			goto out;

		ip = mtod(m, struct ip *);
		ip->ip_v = IPVERSION;
		ip->ip_id = htons(ip_randomid());
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum(m, sizeof(*ip));
		hlen = ip->ip_hl << 2;
		icp = (struct icmp *)(mtod(m, caddr_t) + sizeof(*ip));
		icp->icmp_cksum = 0;
		icp->icmp_cksum = in_cksum(m, ip->ip_len - hlen);
		     
		break;
	default:
		goto bad;
	}
	M_PREPEND(m, stksize, M_NOWAIT);
	if (m == NULL)
		goto out;
	
	bcopy(stk, mtod(m, caddr_t), stksize);
	shim = mtod(m, struct shim_hdr *);
	shim->shim_label =
	    (shim->shim_label & ~MPLS_TTL_MASK) | htonl(mpls_defttl);
out:
	return (m);
bad:
	m_freem(m);
	m = NULL;
	goto out;
}

/*
 * Implementation of icmp_reflect is reused completely. 
 *
 * See netinet/ip_icmp.c for further details.   
 */
static struct mbuf *
mpls_icmp_reflect(struct mbuf *m)
{
	struct ip *ip = mtod(m, struct ip *);
	struct in_addr t;
	struct mbuf *opts = 0;
	int optlen = (ip->ip_hl << 2) - sizeof(struct ip);

	if ((IN_MULTICAST(ntohl(ip->ip_src.s_addr))) 
		|| (IN_EXPERIMENTAL(ntohl(ip->ip_src.s_addr)))
		|| (IN_ZERONET(ntohl(ip->ip_src.s_addr)))) 
		goto bad;
		
	t = ip->ip_dst;
	ip->ip_dst = ip->ip_src;
	ip->ip_src = t;
	ip->ip_ttl = V_ip_defttl;

	if (optlen > 0) {
		register u_char *cp;
		int opt, cnt;
		u_int len;

		cp = (u_char *) (ip + 1);
		if (((opts = ip_srcroute(m)) == 0) 
			&& (opts = m_gethdr(M_NOWAIT, MT_DATA))) {
			opts->m_len = sizeof(struct in_addr);
			mtod(opts, struct in_addr *)->s_addr = 0;
		}
		if (opts) {
#ifdef ICMPPRINTFS
		    if (icmpprintfs)
			    printf("icmp_reflect optlen %d rt %d => ",
				optlen, opts->m_len);
#endif
		    for (cnt = optlen; cnt > 0; cnt -= len, cp += len) {
			    opt = cp[IPOPT_OPTVAL];
			    if (opt == IPOPT_EOL)
				    break;
			    if (opt == IPOPT_NOP)
				    len = 1;
			    else {
				    if (cnt < IPOPT_OLEN + sizeof(*cp))
					    break;
				    len = cp[IPOPT_OLEN];
				    if (len < IPOPT_OLEN + sizeof(*cp) 
				    	|| len > cnt)
					    break;
			    }

			    if ((opt == IPOPT_RR) 
			    	|| (opt == IPOPT_TS) 
			    	|| (opt == IPOPT_SECURITY)) {
				    bcopy((caddr_t)cp,
					mtod(opts, caddr_t) + opts->m_len, len);
				    opts->m_len += len;
			    }
		    }
		    cnt = opts->m_len % 4;
		    if (cnt) {
			    for (; cnt < 4; cnt++) {
				    *(mtod(opts, caddr_t) + opts->m_len) =
					IPOPT_EOL;
				    opts->m_len++;
			    }
		    }
#ifdef ICMPPRINTFS
		    if (icmpprintfs)
			    printf("%d\n", opts->m_len);
#endif
		}
		ip->ip_len -= optlen;
		ip->ip_v = IPVERSION;
		ip->ip_hl = 5;
		m->m_len -= optlen;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len -= optlen;
		optlen += sizeof(struct ip);
		bcopy((caddr_t)ip + optlen, (caddr_t)(ip + 1),
			 (unsigned)(m->m_len - sizeof(struct ip)));
	}
	m_tag_delete_nonpersistent(m);
	m->m_flags &= ~(M_BCAST|M_MCAST);
	if (opts)
		(void)m_free(opts);
out:
	return (m);
bad:
	ICMPSTAT_INC(icps_badaddr);
	m_freem(m);	
	m = NULL;
	goto out;
}

/*
 * Generate an error packet of type error. The implementation icmp_error is 
 * reused completely. 
 *
 * See netinet/ip_icmp.c for further details.
 */
static struct mbuf *
mpls_icmp_error(struct mbuf *n, int type, int code, uint32_t dest, int mtu)
{
	struct ip *oip = mtod(n, struct ip *), *nip;
	unsigned oiphlen = oip->ip_hl << 2;
	struct icmp *icp;
	struct mbuf *m;
	unsigned icmplen, icmpelen, nlen;

	KASSERT((u_int)type <= ICMP_MAXTYPE, ("%s: illegal ICMP type", __func__));
#ifdef ICMPPRINTFS
	if (icmpprintfs)
		printf("icmp_error(%p, %x, %d)\n", oip, type, code);
#endif
	if (type != ICMP_REDIRECT)
		ICMPSTAT_INC(icps_error);

	if (n->m_flags & M_DECRYPTED)
		goto freeit;
	if (oip->ip_off & ~(IP_MF|IP_DF))
		goto freeit;
	if (n->m_flags & (M_BCAST|M_MCAST))
		goto freeit;
	if ((oip->ip_p == IPPROTO_ICMP && type != ICMP_REDIRECT) 
		&& (n->m_len >= oiphlen + ICMP_MINLEN) 
		&& (!ICMP_INFOTYPE(((struct icmp *)
			((caddr_t)oip + oiphlen))->icmp_type))) {
		ICMPSTAT_INC(icps_oldicmp);
		goto freeit;
	}
	
	if (oiphlen + 8 > n->m_len)
		goto freeit;

	nlen = m_length(n, NULL);
	if (oip->ip_p == IPPROTO_TCP) {
		struct tcphdr *th;
		int tcphlen;

		if ((oiphlen + sizeof(struct tcphdr) > n->m_len) 
			&& (n->m_next == NULL))
			goto stdreply;
		if ((n->m_len < oiphlen + sizeof(struct tcphdr)) 
			&& ((n = m_pullup(n, oiphlen + sizeof(struct tcphdr))) 
				== NULL))
			goto freeit;
		th = (struct tcphdr *)((caddr_t)oip + oiphlen);
		tcphlen = th->th_off << 2;
		if (tcphlen < sizeof(struct tcphdr))
			goto freeit;
		if (oip->ip_len < oiphlen + tcphlen)
			goto freeit;
		if (oiphlen + tcphlen > n->m_len && n->m_next == NULL)
			goto stdreply;
		if ((n->m_len < oiphlen + tcphlen) 
			&& ((n = m_pullup(n, oiphlen + tcphlen)) == NULL))
			goto freeit;
		icmpelen = max(tcphlen, min(8, oip->ip_len - oiphlen));
	} else
stdreply:	icmpelen = max(8, min(8, oip->ip_len - oiphlen));

	icmplen = min(oiphlen + icmpelen, nlen);
	if (icmplen < sizeof(struct ip))
		goto freeit;

	if (MHLEN > sizeof(struct ip) + ICMP_MINLEN + icmplen)
		m = m_gethdr(M_NOWAIT, MT_DATA);
	else
		m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		goto freeit;

	icmplen = 
		min(icmplen, M_TRAILINGSPACE(m) - sizeof(struct ip) - ICMP_MINLEN);
	m_align(m, ICMP_MINLEN + icmplen);
	m->m_len = ICMP_MINLEN + icmplen;

	M_SETFIB(m, M_GETFIB(n));
	icp = mtod(m, struct icmp *);
	ICMPSTAT_INC(icps_outhist[type]);
	icp->icmp_type = type;
	if (type == ICMP_REDIRECT)
		icp->icmp_gwaddr.s_addr = dest;
	else {
		icp->icmp_void = 0;
		if (type == ICMP_PARAMPROB) {
			icp->icmp_pptr = code;
			code = 0;
		} else if (type == ICMP_UNREACH &&
			code == ICMP_UNREACH_NEEDFRAG && mtu) {
			icp->icmp_nextmtu = htons(mtu);
		}
	}
	icp->icmp_code = code;
	
	m_copydata(n, 0, icmplen, (caddr_t)&icp->icmp_ip);
	nip = &icp->icmp_ip;
	nip->ip_len = htons(nip->ip_len);
	nip->ip_off = htons(nip->ip_off);

	m->m_flags |= n->m_flags & M_SKIP_FIREWALL;
	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);
	m->m_pkthdr.len = m->m_len;
	m->m_pkthdr.rcvif = n->m_pkthdr.rcvif;
	nip = mtod(m, struct ip *);
	bcopy((caddr_t)oip, (caddr_t)nip, sizeof(struct ip));
	nip->ip_len = m->m_len;
	nip->ip_v = IPVERSION;
	nip->ip_hl = 5;
	nip->ip_p = IPPROTO_ICMP;
	nip->ip_tos = 0;
out:	
	return (m);
freeit:
	m_freem(n);
	m = NULL;
	goto out;
}

/*
 * Perform fragmentation, if any. The implementation of bridge_ip_fragment 
 * is reused entirely. 
 *
 * See net/if_bridge.c for further details.
 */
static int
mpls_ip_fragment(struct ifnet *ifp, struct mbuf *m, 
		struct shim_hdr *stk, size_t stksize)
{
	struct mbuf *m0;
	struct ip *ip;
	int error = -1;

	if (m->m_len < sizeof(struct ip) &&
	    (m = m_pullup(m, sizeof(struct ip))) == NULL)
		goto bad;
	ip = mtod(m, struct ip *);

	error = ip_fragment(ip, &m, (ifp->if_mtu - stksize), ifp->if_hwassist);
	if (error)
		goto bad;

	/* walk the chain and re-add stack */
	for (m0 = m; m0; m0 = m0->m_nextpkt) {
		if (error == 0) {
			M_PREPEND(m0, stksize, M_DONTWAIT);
			if (m0 == NULL) {
				error = ENOBUFS;
				continue;
			}
			bcopy(stk, mtod(m0, caddr_t), stksize);
		} else
			m_freem(m);
	}
out:	
	return (error);
bad:
	m_freem(m);
	goto out;
}


struct mbuf * 
mpls_ip_adjttl(struct mbuf *m, uint8_t ttl)
{
	struct ip *ip; 
	size_t hlen; 
	
	if (mpls_mapttl_ip != 0) {
		if (m->m_len < sizeof(struct ip)) {
			if ((m = m_pullup(m, sizeof(struct ip))) == NULL)
				goto out;
		}
		ip = mtod(m, struct ip *);
		hlen = ip->ip_hl << 2;
		if (m->m_len < hlen) {
			if ((m = m_pullup(m, hlen)) == NULL)
				goto out;
			ip = mtod(m, struct ip *);
		}

		if (in_cksum(m, hlen) != 0) {
			m_freem(m);
			m = NULL;
			goto out;
		}
		ip->ip_ttl = ttl;
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum(m, hlen);
	}
out:
	return (m);
} 

#ifdef INET6
struct mbuf * 
mpls_ip6_adjttl(struct mbuf *m, uint8_t ttl)
{
	struct ip6_hdr *ip6hdr;
	
	if (mpls_mapttl_ip6 != 0) {
		if (m->m_len < sizeof(struct ip6_hdr)) {
		    if ((m = m_pullup(m, sizeof(struct ip6_hdr))) == NULL)
				goto out;
		}
		ip6hdr = mtod(m, struct ip6_hdr *);
		ip6hdr->ip6_hlim = ttl;
	}
out:	
	return (m);
} 
#endif	/* INET6 */


/*
 * Eventhandler for if_bridge(4).
 *
 * Associate MPLS_RD_ETHDEMUX MPLS route distinguisher with nhlfe.
 *
 * This procedure is called by bridge(4), if instance of if_mpe(4) is either
 * assumed to be member by operation maps to BRDGADD (RTM_ADD) or will be
 * removed by BRDGDEL (RTM_DELETE) bound operation.
 */
static void 
mpls_bridge_if(void *arg __unused, struct ifnet *ifp, int cmd)
{
	struct ifaddr *ifa = NULL;

#ifdef MPLS_DEBUG
	(void)printf("%s\n",__func__);
#endif /* MPLS_DEBUG */

	IF_AFDATA_RLOCK(ifp);
	ifa = MPLS_IFINFO_IFA(ifp);
	IF_AFDATA_RUNLOCK(ifp);	
	
	if (ifa == NULL) 
		return;
	
	KASSERT((ifa->ifa_flags & IFA_NHLFE), "requested ftn invalid");
	
	ifa_ref(ifa);

	switch (cmd) {
	case RTM_ADD:
	case RTM_CHANGE:
		satosftn_vprd(ifa->ifa_dstaddr) = /* map vprd */
			MPLS_LABEL_SET(MPLS_RD_ETHDEMUX);	
		
		ifa->ifa_flags |= NHLFE_PW2;	
		break;
	case RTM_DELETE:
		satosftn_vprd(ifa->ifa_dstaddr) = /* restore segment */
			satosftn_label(ifa->ifa_addr);
		
		ifa->ifa_flags &= ~NHLFE_PW2;
		break;	
	default:
		break;
	}
	ifa_free(ifa);
}
