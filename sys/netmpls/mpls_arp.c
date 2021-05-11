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
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSMPLSESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISMPLSG IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*-
 * Copyright (c) 2015 Henning Matyschok
 * All rights reserved.
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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llc.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_llatbl.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <machine/in_cksum.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/nd6.h>
#endif

#include <netmpls/mpls.h>

extern int 	mpls_ip_checkbasic(struct mbuf **);
#ifdef INET6
extern int 	mpls_ip6_checkbasic(struct mbuf **);
#endif /* INET6 */

/*
 * The implementation of MPLS_ARP is derived from those still 
 * resides in netinet/if_ether.c. 
 *
 *  1. Alice performs x-connect such that corrosponding 
 *     llentry{} is allocated by mpls_arp_ifinit. 
 * 
 *  2. By mpls_output tx PDU will be cached by 
 *     mpls_arpresolve selected llentry{} and 
 *     mpls_arprequest tx reused PDU containing 
 *     ARPOP_REQUEST.
 * 
 *  3. Bob rx ARPOP_REQUEST by mpls_arpinput.
 *  
 *  4. If Bob is label peer, then Bob replies by
 *     tx ARPOP_REPLY containing requested lla.
 * 
 *  5. Alice rx ARPOP_REPLY, maps lla to corrosponding
 *     llentry{} and tx by 2. cached PDU.
 *
 * If mpls_proxy_arp OID remains in enabled state, Bob tx 
 * during 4. an ARPOP_REQUEST downstream, before tx
 * ARPOP_REPLY against Alice takes place.
 *
 *   +------+       < seg_i >                    < seg_j >        
 *   |       \
 *   | Alice  +---[req, bcast]--->+------+               
 *   |       /                    |       \
 *   +------+                     | Bob    +---[req, bcast]--->
 *           \                    |       /                  
 *            +<--[repl, ucast]---+------+                   
 *                                        \
 *                                         +<---[repl, ucast]--
 * 
 * (upstream)                                        (downstream)   
 *
 * This cascade causes by mpls_output tx PDU is cached only by 
 * LSR_in during mpls_arpresolve and not by any intermediary 
 * LSR until LSR_out in LSP. 
 *
 * XXX: Maybe, proxy_arp could be used as a starting point for 
 * XXX: an implementation for a traceroute mechanism or for an 
 * XXX: MPLS_ARP piggybacked label distribution engine.
 * XXX: 
 * XXX: Missing implementation about ARP statistics.
 */
 
SYSCTL_DECL(_net_link_ether);
SYSCTL_NODE(_net_link_ether, AF_MPLS, mpls, CTLFLAG_RW, 0, "");

static int mpls_arp = 1;
static int mpls_arp_maxhold = 1;
static int mpls_arp_maxtries = 5;

/*
 * Release by nhlfe bound llentry{}.
 */
static int
sysctl_mpls_arp(SYSCTL_HANDLER_ARGS)
{
	struct mpls_ifaddr *nhlfe;
	int enable = mpls_arp;
	int error;

	error = sysctl_handle_int(oidp, &enable, 0, req);
	enable = (enable) ? 1 : 0;

	if (enable != mpls_arp) {
		
		MPLS_IFADDR_WLOCK();
		TAILQ_FOREACH(nhlfe, &mpls_ifaddrhead, mia_link) {
			nhlfe->mia_lle = NULL;
		}		
		MPLS_IFADDR_WUNLOCK();	
		
		mpls_arp = enable;
	}
	return (error);
}
SYSCTL_PROC(_net_link_ether_mpls, OID_AUTO, mpls_arp, 
	CTLTYPE_INT|CTLFLAG_RW, &mpls_arp, 0,  
	&sysctl_mpls_arp, "I", "Use MPLS_ARP");
SYSCTL_INT(_net_link_ether_mpls, OID_AUTO, arp_maxhold, CTLFLAG_RW,
	&mpls_arp_maxhold, 0, 
	"Number of packets to hold per MPLS_ARP entry");
SYSCTL_INT(_net_link_ether_mpls, OID_AUTO, arp_maxtries, CTLFLAG_RW,
	&mpls_arp_maxtries, 0, 
	"MPLS_ARP resolution attempts before returning error");

#define MPLS_ARQ_LEN(arh, ifp) \
	((sizeof((arh))) + \
	(2*MPLS_HDRLEN) + \
	(2*((ifp)->if_addrlen)))

#define SMPLS(s) ((struct sockaddr_mpls *)s)
#define SDL(s) ((struct sockaddr_dl *)s)

static void 	mpls_arprequest(struct ifnet *, const struct sockaddr_mpls *, 
	u_char *);

int 	mpls_arp_ifinit(struct ifnet *, struct ifaddr *);
void 	mpls_arpinput(struct mbuf *);
int 	mpls_arpresolve(struct ifnet *, struct rtentry *, struct mbuf *, 
	const struct sockaddr *, u_char *, struct llentry **);

/*
 * Resolve particular lsp into lla. 
 *
 * Due to interoperabilty with different 
 * MPLS implementations, use of ARP or 
 * ND6 (experimental) is possible by 
 * enabling OID use_arp_by_fec.
 */
int
mpls_arpresolve(struct ifnet *ifp, struct rtentry *rt, struct mbuf *m,
		const struct sockaddr *dst, u_char *lla, struct llentry **lle)
{ 
	struct sockaddr_mpls *seg;
	
	struct llentry *la;
	struct mbuf *curr;
	struct mbuf *next; 

	int error;
	
	*lle = NULL;
	
	seg = (struct sockaddr_mpls *)dst;
	
	if ((ifp->if_flags & IFF_MPLS) == 0) {
		error = ENXIO;
		goto bad;
	}
	
	if (m->m_flags & M_BCAST) {
		bcopy(ifp->if_broadcastaddr, lla, ifp->if_addrlen);
		error = 0;
		goto out;
	}
/*
 * Annotate mbuf(9).
 */	
	m->m_flags |= M_MPLS;	
/*
 * Resolve LLA by held rtentry(9) either 
 * denotes ilm or fec'. Otherwise, by 
 * enclosing Next Hop Label Forwarding
 * entry. 
 */	
	if (mpls_arp == 0) {
		struct ifaddr *ifa;
		struct sockaddr *gw;
		
		if (rt == NULL) {
			IF_ADDR_RLOCK(ifp);
			TAILQ_FOREACH(ifa, 
				&ifp->if_addrhead, ifa_link) {
	
				if ((ifa->ifa_flags & IFA_NHLFE) == 0)
					continue;
	
				if (satosftn_label(ifa->ifa_dstaddr) == 
					seg->smpls_label) {
					ifa_ref(ifa);		
					break;
				}
			}
			IF_ADDR_RUNLOCK(ifp);
			
			if (ifa == NULL) {
				error = EHOSTUNREACH;
				goto bad;
			}
			gw = ifa->ifa_dstaddr;
			ifa_free(ifa);

		} else if (rt->rt_flags & RTF_MPLS)
			gw = rt->rt_gateway;
		else if (rt->rt_flags & RTF_MPE) 
			gw = rt_key(rt);
		else {
			error = EINVAL;
			goto bad;	
		}
		
		switch (gw->sa_family) {
		case AF_INET:			
			error = arpresolve(ifp, rt, m, gw, lla, lle);	
			break;
#ifdef INET6 
		case AF_INET6: 
			error = nd6_storelladdr(ifp, m, gw, (u_char *)lla, lle);	
			break;	
#endif /* INET6 */		
		default:													
			error = EAFNOSUPPORT;
			goto bad;
		}
		goto out;	
	}
	error = ECONNABORTED;
/*
 * Resolve LLA by MPLS label (seg_out) on cache in AF_MPLS.
 */			
	IF_AFDATA_RLOCK(ifp);
	la = lla_lookup(MPLS_LLTABLE(ifp), 0, dst);
	IF_AFDATA_RUNLOCK(ifp);
	
	if (la == NULL) {				
		log(LOG_DEBUG,
			"%s: seg: %d software caused "
			"connection abort\n", __func__,
			MPLS_LABEL_GET(seg->smpls_label));	
		goto bad;
	}

	if (la->la_flags & LLE_VALID) {
		bcopy(&la->ll_addr, lla, ifp->if_addrlen);
		
		*lle = la;
		error = 0;
		goto done;
	}
	log(LOG_DEBUG, "%s: seg: %d -> empty llinfo\n", __func__, 
		MPLS_LABEL_GET(seg->smpls_label));			

	if (la->la_numheld >= mpls_arp_maxhold) {
		if (la->la_hold != NULL) {
			next = la->la_hold->m_nextpkt;
			
			m_freem(la->la_hold);
			
			la->la_hold = next;
			la->la_numheld--;
		} else
			goto bad;
	}

	if ((curr = la->la_hold) != NULL) {
		while (curr->m_nextpkt != NULL)
			curr = curr->m_nextpkt;

		curr->m_nextpkt = m;
	} else
		la->la_hold = m;
	
	la->la_numheld++;		
	
	if (la->la_asked < mpls_arp_maxtries)
		error = EWOULDBLOCK;
	else
		error = (rt != NULL && (rt->rt_flags & RTF_GATEWAY)) ? 
			EHOSTUNREACH : EHOSTDOWN;

	la->la_asked++;
	
	mpls_arprequest(ifp, seg, IF_LLADDR(ifp));
done:
	if (la->la_flags & LLE_EXCLUSIVE)
		LLE_WUNLOCK(la);
	else
		LLE_RUNLOCK(la);
out:
		
#ifdef MPLS_DEBUG
	if (error == 0) {
		(void)printf("%s: seg: %d -> %*D on %s\n", __func__, 
			MPLS_LABEL_GET(seg->smpls_label),
			ifp->if_addrlen, (u_char *)lla, ":", 
			if_name(ifp));
	}
#endif /* MPLS_DEBUG */	
	
	return (error);
bad:	
	m_freem(m);
	goto out;
}

/*
 * Broadcast ARPOP_REQUEST.
 */
static void
mpls_arprequest(struct ifnet *ifp, const struct sockaddr_mpls *seg, u_char *lla)
{
	struct mbuf *m;
	struct arphdr *arh;
	struct sockaddr sa;

	MGETHDR(m, (M_NOWAIT|M_ZERO), MT_DATA);
	if (m == NULL)
		return;
	MCLGET(m, (M_NOWAIT|M_ZERO));	
	if ((m->m_flags & M_EXT) == 0) {
		m_freem(m);
		return;
	}		
	m->m_len = MPLS_ARQ_LEN(*arh, ifp);
	m->m_pkthdr.len = m->m_len;
	
	MH_ALIGN(m, m->m_len);
	
	m->m_flags |= (M_BCAST|M_PKTHDR|M_MPLS);
	
	arh = mtod(m, struct arphdr *);
	arh->ar_pro = htons(ETHERTYPE_MPLS);
	arh->ar_hln = ifp->if_addrlen;
	arh->ar_pln = MPLS_HDRLEN;
	arh->ar_op = htons(ARPOP_REQUEST);
	
	bcopy((caddr_t)lla, (caddr_t)ar_sha(arh), arh->ar_hln);
	bcopy((caddr_t)&seg->smpls_label, 
		(caddr_t)ar_spa(arh), arh->ar_pln);
			
	bzero(&sa, sizeof(sa));	
	sa.sa_family = AF_ARP;
	sa.sa_len = 2;
		
#ifdef MPLS_DEBUG 
	(void)printf("%s: seg: %d\n", __func__, 
		satosmpls_label_get(seg)); 
#endif /* MPLS_DEBUG */
		
	(void)(*ifp->if_output)(ifp, m, &sa, NULL);
}

static int mpls_log_arp_permanent_modify = 1;
static int mpls_allow_arp_multicast = 0;
static int mpls_proxy_arp = 1;

SYSCTL_INT(_net_link_ether_mpls, 
	OID_AUTO, log_arp_permanent_modify, CTLFLAG_RW,
	&mpls_log_arp_permanent_modify, 0,
	"log arp replies from MACs different than the"
	" one in the permanent arp entry");
SYSCTL_INT(_net_link_ether_mpls, 
	OID_AUTO, allow_arp_multicast, CTLFLAG_RW,
	&mpls_allow_arp_multicast, 0, "accept multicast addresses");
SYSCTL_INT(_net_link_ether_mpls, 
	OID_AUTO, proxy_arp, CTLFLAG_RW,
	&mpls_proxy_arp, 0, "accept multicast addresses");	
	
/*
 * Receive incoming request.
 */	
void
mpls_arpinput(struct mbuf *m)
{
	int flags = 0, drop = 1;
	
	struct ifnet *ifp0 = m->m_pkthdr.rcvif;

	u_int8_t *lla;
	
	struct arphdr *arh;
	size_t arq_len;	
	
	struct mpls_ro mplsroute;
	struct mpls_ro *mro;
	struct sockaddr_mpls *seg;
	
	struct ifnet *ifp;
/*
 * Interface is reused for tx replies.
 */
	if (ifp0 == NULL) 
		goto done;
	
	if ((ifp0->if_flags & IFF_MPLS) == 0)
		goto done;

	lla = (u_int8_t *)IF_LLADDR(ifp0);
	arh = mtod(m, struct arphdr *);
	arq_len = MPLS_ARQ_LEN(*arh, ifp0);
	
	if (m->m_len < arq_len) { 
		if ((m = m_pullup(m, arq_len)) == NULL) {
			log(LOG_NOTICE, 
				"%s: runt packet -- m_pullup failed\n", __func__);
			return;
		}
	}
	arh = mtod(m, struct arphdr *);
	
	if (arh->ar_pro != htons(ETHERTYPE_MPLS)) {
		log(LOG_NOTICE, "%s: invalid format of protocol address\n",
		    __func__);
		goto done;
	}	
	
	if (arh->ar_hln != ifp0->if_addrlen) {
		log(LOG_NOTICE, "%s: requested lla length != %zu\n",
		    __func__, ifp0->if_addrlen);
		goto done;
	}

	if (arh->ar_pln != MPLS_HDRLEN) {
		log(LOG_NOTICE, "%s: requested protocol length != %zu\n",
		    __func__, MPLS_HDRLEN);
		goto done;
	}
	
	if (bcmp((caddr_t)ar_sha(arh), 
		ifp0->if_broadcastaddr, 
		ifp0->if_addrlen) == 0) {
		log(LOG_NOTICE, "%s: %*D is broadcast\n", __func__,
		    ifp0->if_addrlen, (u_char *)ar_sha(arh), ":");
		goto done;
	}
	
	if ((mpls_allow_arp_multicast == 0) 
		&& (ETHER_IS_MULTICAST((caddr_t)ar_sha(arh)))) {
		log(LOG_NOTICE, "%s: %*D is multicast\n", __func__,
		    ifp0->if_addrlen, (u_char *)ar_sha(arh), ":");
		goto done;
	}
	
	if (bcmp((caddr_t)ar_sha(arh), 
		lla, ifp0->if_addrlen) == 0)
		goto done;	

	mro = &mplsroute;
	bzero(mro, sizeof(*mro));
	seg = (struct sockaddr_mpls *)&mro->mro_gw;
/*
 * Get particular lsp.
 */	
	seg->smpls_len = sizeof(*seg);
	seg->smpls_family = AF_MPLS; 
 
	bcopy((caddr_t)ar_spa(arh), 
		(caddr_t)&seg->smpls_label, arh->ar_pln);	
	
	seg->smpls_label &= MPLS_LABEL_MASK;
	
	switch (ntohs(arh->ar_op)) { 
	case ARPOP_REQUEST:
/*
 * Received by Bob. Fetch ilm (downstream), if any.
 */
 		mpls_rtalloc_fib(mro, M_GETFIB(m));
		if (mro->mro_flags == 0) {
			log(LOG_NOTICE, "%s: seg: %d not found\n", __func__,
				MPLS_LABEL_GET(seg->smpls_label));	
#ifdef MPLS_DEBUG
			(void)printf("%s: seg: %d not found\n", __func__,
				MPLS_LABEL_GET(seg->smpls_label));
#endif /* MPLS_DEBUG */
			break;
		}
		ifp = mro->mro_ilm->rt_ifp;
		
		if ((mpls_proxy_arp != 0) 
			&& (satosftn_op(mro->mro_ilm->rt_gateway) != RTF_POP)) {			
/* 
 * Request lla downstream, if enabled.
 */	
			seg->smpls_label = 
				satosftn_label(mro->mro_ilm->rt_gateway);			
				
			mpls_arprequest(ifp, seg, IF_LLADDR(ifp));
		}
/*
 * Reply ucast lla upstream.
 */		
		bcopy((caddr_t)ar_sha(arh), 
			(caddr_t)ar_tha(arh), arh->ar_hln);
		bcopy(lla, (caddr_t)ar_sha(arh), arh->ar_hln);
		
		arh->ar_op = htons(ARPOP_REPLY);

		m->m_len = MPLS_ARQ_LEN(*arh, ifp0);
		m->m_pkthdr.len = m->m_len;
		m->m_pkthdr.rcvif = NULL;

		m->m_flags &= ~(M_BCAST|M_MCAST);
		m->m_flags |= M_MPLS;
		
		seg->smpls_family = AF_ARP;
		seg->smpls_len = 2;
		
		(void)(*ifp0->if_output)(ifp0, m, (struct sockaddr *)seg, NULL);	
		
		drop = 0;
		break;		
	case ARPOP_REPLY:	
/* 
 * Received by Alice. Identify particular lsp (upstream).
 */	
		IF_ADDR_RLOCK(ifp0);
		TAILQ_FOREACH(mro->mro_ifa, 
			&ifp0->if_addrhead, ifa_link) {
	
			if ((mro->mro_ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
		
			if (satosftn_label(mro->mro_ifa->ifa_dstaddr) 
				== seg->smpls_label) {
				ifa_ref(mro->mro_ifa);	 
				break;
			}
		}
		IF_ADDR_RUNLOCK(ifp0);
		
		if (mro->mro_ifa == NULL) {
			IFNET_RLOCK_NOSLEEP();
			TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		
				if ((ifp->if_flags & IFF_MPLS) == 0)
					continue;
		
				if ((M_GETFIB(m) != RT_ALL_FIBS) 
					&& (ifp->if_fib != M_GETFIB(m)))
					continue;
			
				IF_ADDR_RLOCK(ifp);
				TAILQ_FOREACH(mro->mro_ifa, 
					&ifp->if_addrhead, ifa_link) {
			
					if ((mro->mro_ifa->ifa_flags & IFA_NHLFE) == 0)
						continue;
			
					if (satosftn_label(mro->mro_ifa->ifa_dstaddr) 
						== seg->smpls_label) {
						ifa_ref(mro->mro_ifa);
						IF_ADDR_RUNLOCK(ifp);
						goto found;
					}
				}
				IF_ADDR_RUNLOCK(ifp);
			}
			mro->mro_ifa = NULL;
found:
			IFNET_RUNLOCK_NOSLEEP();
		}
		
		if (mro->mro_ifa == NULL)
			break;
		
		IF_AFDATA_LOCK(ifp0);
		mro->mro_lle = lla_lookup(MPLS_LLTABLE(ifp0), 
			flags, (struct sockaddr *)seg);
		IF_AFDATA_UNLOCK(ifp0);
		
		if (mro->mro_lle == NULL) {
			ifa_free(mro->mro_ifa);
			break;
		}
		bcopy((caddr_t)ar_sha(arh), &mro->mro_lle->ll_addr, 
			ifp0->if_addrlen); 
			
		mro->mro_lle->la_flags |= LLE_VALID;
/*
 * See ether_output in net/if_ethersubr.c for further details.
 */
		if (mpls_lle(mro->mro_ifa) != mro->mro_lle)
			mpls_lle(mro->mro_ifa) = mro->mro_lle;
	
		if (mro->mro_lle->la_hold != NULL) {
			struct mbuf *m_hold, *m_hold_next;
/*
 * Tx cached mbuf(9) downstream.
 */
			m_hold = mro->mro_lle->la_hold;
			
			mro->mro_lle->la_hold = NULL;
			mro->mro_lle->la_numheld = 0;
			
			seg->smpls_label = MPLS_SEG(mro->mro_lle)->smpls_label;
			
			LLE_WUNLOCK(mro->mro_lle);
			
			for (; m_hold != NULL; m_hold = m_hold_next) {
				m_hold_next = m_hold->m_nextpkt;
				m_hold->m_nextpkt = NULL;
				m_hold->m_flags |= M_MPLS;

#ifdef MPLS_DEBUG
	(void)printf(" mpls_arp: ");  
#endif /* MPLS_DEBUG */

				(void)(*ifp0->if_output)
					(ifp0, m_hold, (struct sockaddr *)seg, 
						(struct route *)mro);
			}
		} else
			LLE_WUNLOCK(mro->mro_lle); 
		
		ifa_free(mro->mro_ifa);
		break;
	default:
		break;
	} 

	if (mro != NULL) 
		mpls_rtfree(mro);
done:	
	if (drop != 0)
		m_freem(m);
}

/*
 * Map llentry{} to particular lsp.
 */
int 
mpls_arp_ifinit(struct ifnet *ifp, struct ifaddr *ifa)
{
	int error = 0;
	struct sockaddr_mpls smpls;
	struct sockaddr_mpls *seg;
	struct lltable *llt;
	struct llentry *lle;
	
#ifdef MPLS_DEBUG	
	(void)printf("%s\n", __func__);
	
	if (ifa == NULL)
		return (EINVAL);
	
	if ((ifa->ifa_flags & IFA_NHLFE) == 0)
		return (EINVAL);
		
	if (ifp == NULL)
		return (EINVAL);
#endif /* MPLS_DEBUG */

	bzero((seg = &smpls), sizeof(*seg));
	
	seg->smpls_len = sizeof(*seg);
	seg->smpls_family = AF_MPLS;
	seg->smpls_label = /* particular lsp */ 
		satosftn_label(ifa->ifa_dstaddr) & MPLS_LABEL_MASK;
	
	llt = MPLS_LLTABLE(ifp);

	KASSERT((llt != NULL), ("lltable{} not defined"));
	
	switch (ifp->if_type) {
	case IFT_ETHER: 	
	case IFT_FDDI: 
					/* FALLTHROUGH */
					
		lle = lla_lookup(llt, LLE_CREATE, smplstosa(seg));
		if (lle == NULL) {
			log(LOG_INFO, 
				"%s: cannot create mpls_arp "
			    "entry for particular lsp %d\n", __func__,
			    MPLS_LABEL_GET(seg->smpls_label));
			error = ENOBUFS;
		} else 
			LLE_RUNLOCK(lle);
		break;
	case IFT_LOOP:	
		break;
	default:
		break;
	}
	
#ifdef MPLS_DEBUG
	(void)printf("%s: %d\n", __func__, 
		MPLS_LABEL_GET(seg->smpls_label));
#endif /* MPLS_DEBUG */

	return (error);
}

