/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
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
#include <sys/sockio.h>
#include <sys/malloc.h>
#include <sys/priv.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netmpls/mpls.h>
#include <netinet/in.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif /* INET6 */

static int 	mpls_ifinit(struct ifnet *, struct mpls_ifaddr *, 
	struct rtentry *, struct sockaddr *, int);
static int 	mpls_ifscrub(struct ifnet *, struct mpls_ifaddr *, 
	struct rtentry *);	

struct ifaddr * 	mpls_ifaof_ifpforseg(struct sockaddr *, 
	struct ifnet *, int);
struct ifaddr * 	mpls_ifawithseg_fib(struct sockaddr *, u_int, int);
int 	mpls_ifawithseg_check_fib(struct sockaddr *, u_int);
struct ifaddr * 	mpls_ifaof_ifpforxconnect(struct sockaddr *, 
	struct sockaddr *, struct ifnet *, int);
struct ifaddr * 	mpls_ifawithxconnect_fib(struct sockaddr *, 
	struct sockaddr *, u_int, int);

void 	mpls_purgeaddr(struct ifaddr *);
void 	mpls_link_rtrequest(int, struct rtentry *, 
	struct rt_addrinfo *);
int 	mpls_control(struct socket *, u_long, caddr_t, 
	struct ifnet *, struct thread *);

/*
 * Locate Next Hop Label Forwarding Entry (nhlfe) by its key (seg_in).
 */

struct ifaddr *
mpls_ifaof_ifpforseg(struct sockaddr *seg, struct ifnet *ifp, int getref)
{
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	
		if ((ifa->ifa_flags & IFA_NHLFE) == 0)
			continue;
	
		if (ifa->ifa_addr->sa_family != af)
			continue;
		
		if (satosmpls_label(ifa->ifa_addr) == i) 
			break;
	}
	IF_ADDR_RUNLOCK(ifp);
	
	if (ifa && getref == 0)
		ifa_free(ifa);
			
	return (ifa);
}

struct ifaddr *
mpls_ifawithseg_fib(struct sockaddr *seg, u_int fibnum, int getref)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		
		if ((ifp->if_flags & IFF_MPLS) == 0)
			continue;
		
		if ((fibnum != RT_ALL_FIBS) && (ifp->if_fib != fibnum))
			continue;
			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
			
			if (ifa->ifa_addr->sa_family != af)
				continue;
			
			if (satosmpls_label(ifa->ifa_addr) == i) {
				ifa_ref(ifa);
				IF_ADDR_RUNLOCK(ifp);
				goto done;
			}
		}
		IF_ADDR_RUNLOCK(ifp);
	}
	ifa = NULL;
done:
	IFNET_RUNLOCK_NOSLEEP();
	
	if (ifa && getref == 0)
		ifa_free(ifa);
	return (ifa);
}

int
mpls_ifawithseg_check_fib(struct sockaddr *seg, u_int fibnum)
{
	return (mpls_ifawithseg_fib(seg, fibnum, 0) != NULL);
}

/*
 * Locate nhlfe by key (seg_in) -> (nh) x < op, seg_out, rd >  on ftn.
 */
 
struct ifaddr *
mpls_ifaof_ifpforxconnect(struct sockaddr *seg, struct sockaddr *nh, 
		struct ifnet *ifp, int getref)
{
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t len = SFTN_LEN;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	if (nh->sa_len != len)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	
		if ((ifa->ifa_flags & IFA_NHLFE) == 0)
			continue;
			
		if (ifa->ifa_addr->sa_family != af)
			continue;
			
		if (satosmpls_label(ifa->ifa_addr) != i) 
			continue;
			
		if (ifa->ifa_dstaddr->sa_len != len)
			continue;		
		
		if (mpls_sa_equal(ifa->ifa_dstaddr, nh)) {
			ifa_ref(ifa);
			IF_ADDR_RUNLOCK(ifp);
			break;
		}
	}
	IF_ADDR_RUNLOCK(ifp);
	
	if (ifa && getref == 0)
		ifa_free(ifa);
			
	return (ifa);
}
 
struct ifaddr *
mpls_ifawithxconnect_fib(struct sockaddr *seg, struct sockaddr *nh, 
		u_int fibnum, int getref)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t len = SFTN_LEN;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	if (nh->sa_len != len)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		
		if ((ifp->if_flags & IFF_MPLS) == 0)
			continue;
			
		if ((fibnum != RT_ALL_FIBS) && (ifp->if_fib != fibnum))
			continue;
			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
			
			if (ifa->ifa_addr->sa_family != af)
				continue;
			
			if (satosmpls_label(ifa->ifa_addr) != i) 
				continue;
		
			if (ifa->ifa_dstaddr->sa_len != len)
				continue;	
		
			if (mpls_sa_equal(ifa->ifa_dstaddr, nh)) {
				ifa_ref(ifa);
				IF_ADDR_RUNLOCK(ifp);
				goto done;
			}
		}
		IF_ADDR_RUNLOCK(ifp);
	}
	ifa = NULL;
done:
	IFNET_RUNLOCK_NOSLEEP();
	
	if (ifa && getref == 0)
		ifa_free(ifa);
	return (ifa);
}

/*
 * Implements temporary queue, holds set containing 
 * nhlfe maps to fec during mpls_link_rtrequest.
 */
struct mpls_ifaddrbuf {
	TAILQ_ENTRY(mpls_ifaddrbuf)	ib_chain;
	struct mpls_ifaddr	*ib_nhlfe;
};
TAILQ_HEAD(mpls_ifaddrbuf_hd, mpls_ifaddrbuf);

/*
 * Purge ftn maps to fec, when fec invalidates. 
 *
 * XXX: incomplete...
 */
void
mpls_link_rtrequest(int cmd, struct rtentry *fec, struct rt_addrinfo *rti)
{
	struct mpls_ifaddrbuf_hd hd;
	struct mpls_ifaddrbuf *ib;
	
	struct ifnet *ifp;
	struct ifaddr *ifa;
	
#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */

	RT_LOCK_ASSERT(fec);
	TAILQ_INIT(&hd);
	ifp = fec->rt_ifp;

	switch (cmd) {
	case RTM_ADD:
		break;
	case RTM_CHANGE:
	case RTM_DELETE:
/*
 * Build subset.
 */			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
				
			if (mpls_sa_equal(rt_key(fec), ifa->ifa_dstaddr) == 0)
				continue;
	
			ifa_ref(ifa);
/*
 * Can't fail.
 */			
			ib = malloc(sizeof(*ib), M_TEMP, M_WAITOK|M_ZERO);
			ib->ib_nhlfe = ifatomia(ifa);	
			
			TAILQ_INSERT_TAIL(&hd, ib, ib_chain);
		}
		IF_ADDR_RUNLOCK(ifp);	
/*
 * Purge collection.
 */
		while (!TAILQ_EMPTY(&hd)) {
			ib = TAILQ_FIRST(&hd);
			
			if (mpls_ifscrub(ifp, ib->ib_nhlfe, fec) == 0) {
/*
 * Dequeue nhlfe scoped on interface.
 */				
				ifa = &ib->ib_nhlfe->mia_ifa;
	
				IF_ADDR_WLOCK(ifp);
				TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);	
				IF_ADDR_WUNLOCK(ifp);
		
				ifa_free(ifa);
/*
 * Dequeue nhlfe globally.
 */				
				MPLS_IFADDR_WLOCK();
				TAILQ_REMOVE(&mpls_ifaddrhead, ib->ib_nhlfe, mia_link);	
				MPLS_IFADDR_WUNLOCK();

				ifa_free(&ib->ib_nhlfe->mia_ifa);
			}	
/*
 * Release by nhlfe bound ressources.
 */			
			ifa_free(&ib->ib_nhlfe->mia_ifa);
			ib->ib_nhlfe = NULL;
			
			free(ib, M_TEMP);
		}
	    break;
	default:
		break;
	}			
	fec->rt_mtu = ifp->if_mtu;
}

/*
 * Purge x-connect.
 */
void	
mpls_purgeaddr(struct ifaddr *ifa)
{	
	struct mpls_aliasreq ifra;
	struct mpls_ifaddr *mia;
	struct ifnet *ifp;
	size_t len;
	
#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */

	KASSERT((ifa != NULL), ("Invalid argument"));
	
	if ((ifa->ifa_flags & IFA_NHLFE) == 0)
		return;
	
	mia = ifatomia(ifa);
	ifp = mia->mia_ifp;

	bzero(&ifra, sizeof(ifra));
	bcopy(mia->mia_addr, &ifra.ifra_seg, mia->mia_addr->sa_len);
	
	ifra.ifra_x.sftn_len = mia->mia_x->ifa_addr->sa_len;
	ifra.ifra_x.sftn_family = mia->mia_dstaddr->sa_family;
	
	len = ifra.ifra_x.sftn_len - offsetof(struct sockaddr, sa_data);
	bcopy(mia->mia_dstaddr->sa_data, ifra.ifra_x.sftn_data, len);
	
	ifra.ifra_flags = mia->mia_rt_flags;
	
	(void)mpls_control(NULL, SIOCDIFADDR, (caddr_t)&ifra, ifp, NULL);
}

/*
 * Generic mpls control operations.
 *
 */ 
 
int
mpls_control(struct socket *so __unused, u_long cmd, caddr_t data, 
		struct ifnet *ifp, struct thread *td)
{
	
	struct mpls_aliasreq *ifra = (struct mpls_aliasreq *)data;
	struct ifreq *ifr = (struct ifreq *)data;
	struct mpls_ifaddr *mia = NULL;
	struct rtentry *fec = NULL;
	struct ifaddr *oifa = NULL;
	struct ifaddr *ifa = NULL;
	int omsk = RTF_MPLS_OMASK;
	int fmsk = RTF_MPLS; 
	int priv = 0;
	int flags = 0;
	int error = 0;
	
	struct sockaddr *seg, *x;

#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */

	if (ifp == NULL) {
		error = EADDRNOTAVAIL;
		goto out;
	}
	
	if ((ifp->if_ioctl == NULL) 
		|| (ifp->if_addr == NULL)) { 
		error = ENXIO;
		goto out;
	}

	if ((ifp->if_flags & IFF_MPLS) == 0) {
		error = EADDRNOTAVAIL;
 		goto out;			
 	}

	switch (cmd) {
	case SIOCAIFADDR:
	case SIOCSIFADDR:
/*
 * Superuser is only capable adding MPLS label bindings.
 */			
		priv = PRIV_NET_ADDIFADDR;
			
							/* FALLTHROUGH */	
	case SIOCDIFADDR:	
/*
 * Superuser is only capable removing MPLS label bindings.
 */				
 		if (priv != PRIV_NET_ADDIFADDR)
			priv = PRIV_NET_DELIFADDR;
 		
 		if (td != NULL) {
 			error = priv_check(td, priv);
			if (error != 0) 
				goto out;					
		}
	}	
	
	switch (cmd) {
	case SIOCAIFADDR: 
 	case SIOCDIFADDR: 	/* FALLTHROUGH */
 			
		if (ifra == NULL) {
			error = EINVAL;
			goto out;
		}
		
		if (ifra->ifra_seg.sftn_family != AF_MPLS) {
			error = EINVAL;
			goto out;
		}
		
		if (ifra->ifra_seg.sftn_len > sizeof(ifra->ifra_seg)) {
			error = EMSGSIZE;
			goto out;
		}
		seg = (struct sockaddr *)&ifra->ifra_seg;	
		x = (struct sockaddr *)&ifra->ifra_x;	
	
		if (x->sa_family == AF_UNSPEC) {
/*
 * Per-interface MPLS label space.
 */		
			ifa_ref(ifp->if_addr);
			oifa = ifp->if_addr;
			x = oifa->ifa_addr;
 
			flags = (RTF_MPLS|RTF_LLDATA|RTF_PUSH|RTF_MPE);
		} else 
			flags = ifra->ifra_flags;
 		
 		break;
 	case SIOCGIFADDR:
 	case SIOCSIFADDR: 	/* FALLTHROUGH */
 	
 		if (ifr == NULL) {
			error = EINVAL;
			goto out;
		}
	
		if (ifr->ifr_addr.sa_family != AF_MPLS) {
			error = EINVAL;
			goto out;
		}
		
		if (ifr->ifr_addr.sa_len > sizeof(ifr->ifr_addr)) {
			error = EMSGSIZE;
			goto out;
		}
		seg = &ifr->ifr_addr;

		ifa_ref(ifp->if_addr);
		oifa = ifp->if_addr;
		x = oifa->ifa_addr;
	}
 	
	switch (cmd) {
	case SIOCSIFADDR: 
/*
 * MPLS label binding scoping per-interface label space.
 *
 * RTF_MPE, by fec generated nhlfe encodes with seg_j initial 
 * label of Label Switch Path (lsp) in data plane.
 *
 * RTF_LLDATA, nhlfe is linked to an interface in link-layer 
 * where targeted interface represents fec by nhlfe itself. 
 */	
		flags = (RTF_MPLS|RTF_LLDATA|RTF_PUSH|RTF_MPE);
				
	case SIOCAIFADDR:	
/*
 * Determine, if MPLS label binding is possible.
 */	
		if ((fmsk = (flags & fmsk)) == 0)  {
			error = EINVAL;
			goto out;
		}
		fmsk |= (flags & RTF_GATEWAY) ? RTF_GATEWAY : RTF_LLDATA;
	
		if ((fmsk = (flags & fmsk)) == 0)  {
			error = EINVAL;
			goto out;
		}
		fmsk |= (flags & omsk);

		switch (fmsk & omsk) {
		case RTF_POP:
		case RTF_PUSH: 	/* FALLTRHOUGH */
		case RTF_SWAP:
			break;
		default:			
			error = EOPNOTSUPP;
			goto out;
		}
		fmsk |= (flags & RTF_STK) ? RTF_STK : RTF_MPE;	
		flags = (flags & fmsk);
	
	case SIOCDIFADDR:	 	/* FALLTHROUGH */
/*
 * Determine, if Forward Equivalence Class (fec) still exists 
 * as precondition for MPLS label binding on MPLS label space 
 * scoping set containing fec.
 */
 		if ((x->sa_family == AF_LINK)
			&& (flags & RTF_LLDATA)
			&& (flags & RTF_PUSH) 
			&& (flags & RTF_MPE)) {
/*
 * Per-interface MPLS label space.
 */
			if (oifa == NULL) {
				ifa_ref(ifp->if_addr);
				oifa = ifp->if_addr;
			}
	  
		} else if (((fec = rtalloc1_fib(x, 0, 0UL, 0)) != NULL) 
			&& (fec->rt_gateway != NULL) 
			&& (fec->rt_ifp != NULL)
			&& (fec->rt_ifa != NULL) 
			&& (fec->rt_flags & RTF_UP)) {
/*
 * MPLS label space scoped by set containing fec.
 */
			if (fec->rt_ifp != ifp) 
				error = ESRCH;
		} else 
			error = ESRCH;
		
		if (error != 0) 	
			goto out;
							/* FALLTHROUGH */
	case SIOCGIFADDR:
/*
 * Fetch Next Hop Label Forwarding Entry (nhlfe).
 */ 
		MPLS_IFADDR_RLOCK();
		TAILQ_FOREACH(mia, &mpls_ifaddrhead, mia_link) {
			
			if (mia->mia_ifp != ifp) 
				continue;
			
			if (satosmpls_label(mia->mia_addr) 
					== satosmpls_label(seg)) {		
				ifa_ref(&mia->mia_ifa);
				break;
			}
		}
/* 
 * Step out, if RTF_SWAP as precondition for rfc-3021, 3.26. Label Merging.
 */	
		if (flags & RTF_SWAP) {
			MPLS_IFADDR_RUNLOCK();	
			break;
		}
		
		if (mia == NULL) {
/*
 * If not found, try to fetch nhlfe by destination x in fec.
 */				
			TAILQ_FOREACH(mia, &mpls_ifaddrhead, mia_link) {
			
				if (mia->mia_ifp != ifp) 
					continue;
				
				if (mpls_sa_equal(x, mia->mia_dstaddr)) {
					ifa_ref(&mia->mia_ifa);
					break;
				}
			}
		}
		MPLS_IFADDR_RUNLOCK();	
	}
	
	switch (cmd) {
	case SIOCAIFADDR:	
	case SIOCSIFADDR:	/* FALLTHROUGH */	
	
 		if (mia == NULL) { 
/*
 * Allocate, if possible.
 */	
			mia = (struct mpls_ifaddr *)
				malloc(sizeof(*mia), M_IFADDR, 
					M_ZERO|M_NOWAIT);
			if (mia == NULL) {			
				error = ENOBUFS;
				break;
			}	
			ifa = &mia->mia_ifa;
			ifa_init(ifa);
			ifa->ifa_ifp = ifp;	
			ifa->ifa_metric = ifp->if_metric;
			
			ifa->ifa_flags |= IFA_NHLFE;
				
			ifa->ifa_addr = (struct sockaddr *)&mia->mia_seg;
			ifa->ifa_dstaddr = (struct sockaddr *)&mia->mia_nh;
			ifa->ifa_netmask = (struct sockaddr *)&mia->mia_seg;
/*
 * Enqueue globally.
 */				
 			ifa_ref(&mia->mia_ifa);

			MPLS_IFADDR_WLOCK();
			TAILQ_INSERT_TAIL(&mpls_ifaddrhead, mia, mia_link);	
			MPLS_IFADDR_WUNLOCK();
/*
 * Append nhlfe on lla.
 */	
			ifa_ref(&mia->mia_ifa);
			
			IF_ADDR_WLOCK(ifp);
			TAILQ_INSERT_AFTER(&ifp->if_addrhead, 
				ifp->if_addr, ifa, ifa_link);
			IF_ADDR_WUNLOCK(ifp);
			
		} else { 
/*
 * Reinitialize, if possible.
 */
			error = mpls_ifscrub(ifp, mia, fec);
			if (error != 0)
				break;		
		} 
		error = mpls_ifinit(ifp, mia, fec, seg, flags);
		if (error == 0)
			break;
							/* FALLTHROUGH */	
	case SIOCDIFADDR:
 	
 		if (mia == NULL) {
 			error = EADDRNOTAVAIL;	
 			break;
 		}
 		error = mpls_ifscrub(ifp, mia, fec);
		if (error != 0) 
			break;
/*
 * Dequeue nhlfe.
 */	
		ifa = miatoifa(mia);
		IF_ADDR_WLOCK(ifp);
		TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);	
		IF_ADDR_WUNLOCK(ifp);
		
		ifa_free(&mia->mia_ifa);
		
		MPLS_IFADDR_WLOCK();
		TAILQ_REMOVE(&mpls_ifaddrhead, mia, mia_link);	
		MPLS_IFADDR_WUNLOCK();

		ifa_free(&mia->mia_ifa);
		break;
	case SIOCGIFADDR:

		if (ifa == NULL) {
 			error = EADDRNOTAVAIL;	
 			break;
 		}
 		*(struct sockaddr_mpls *)&ifr->ifr_addr = 
 			*(struct sockaddr_mpls *)ifa->ifa_addr;
		break;
	default:
		error = (*ifp->if_ioctl)(ifp, cmd, data);
		break;
	}
out:
	if (fec != NULL) 
		RTFREE_LOCKED(fec);

	if (oifa != NULL)
		ifa_free(oifa);

	if (mia != NULL)
		ifa_free(&mia->mia_ifa);

	return (error);	
}

/*
 * Finalize MPLS label binding.
 */
static int  
mpls_ifscrub(struct ifnet *ifp, struct mpls_ifaddr *mia, struct rtentry *rt)
{
	struct sockaddr_ftn sftn;
	struct sockaddr *seg;
	int error = 0;
	
#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */
	
	if (rt == NULL) {
/*
 * Remove MPLS label binding scoped on per-interface MPLS label space.
 */	
		IF_AFDATA_WLOCK(ifp);
		if (MPLS_IFINFO_IFA(ifp) != NULL) {
			ifa_free(MPLS_IFINFO_IFA(ifp));
			MPLS_IFINFO_IFA(ifp) = NULL;
			ifp->if_flags &= ~IFF_MPE;
		}
		IF_AFDATA_WUNLOCK(ifp);	
	} else {
		RT_LOCK_ASSERT(rt);	
/*
 * Remove MPLS label binding scoped on set containing fec.
 */			
		if (mia->mia_rt_flags & RTF_STK) 
			rt->rt_flags &= ~RTF_STK;
		else if (mia->mia_rt_flags & RTF_PUSH) {
/*
 * Restore former gateway address, if fec denotes fastpath.
 */	
			bzero(&sftn, sizeof(sftn));
			
			if (rt->rt_flags & RTF_GATEWAY) {
				bcopy(rt->rt_gateway, &sftn, 
					rt_key(rt)->sa_len);
				sftn.sftn_len = rt_key(rt)->sa_len;
			} else {
				bcopy(rt->rt_gateway, &sftn, 
					sizeof(struct sockaddr_dl));
				sftn.sftn_len = sizeof(struct sockaddr_dl);
			}
			error = rt_setgate(rt, rt_key(rt), 
				(struct sockaddr *)&sftn);
			if (error != 0)
				goto out;
				
			rt->rt_mtu += MPLS_HDRLEN;
			rt->rt_flags &= ~RTF_MPE;
		} else {
/*
 * Terminate by nhlfe enclosed Incoming Label Map (ilm).
 */			
			error = rtrequest_fib((int)RTM_DELETE, 
				mia->mia_addr, 
				mia->mia_dstaddr, 
				mia->mia_netmask, 
				mia->mia_rt_flags, 
				NULL, ifp->if_fib);
			
			if (error != 0)
				goto out;	
		}
	} 
	bzero(&sftn, sizeof(sftn));
	seg = (struct sockaddr *)&sftn;
/*
 * Remove corrosponding llentry{} on MPLS_ARP cache.
 */		
 	seg->sa_len = SMPLS_LEN;
	seg->sa_family = AF_MPLS;
 	
	if (mia->mia_rt_flags & RTF_PUSH)  
		satosmpls_label(seg) = satosmpls_label(mia->mia_addr);
	else 
		satosmpls_label(seg) = satosftn_label(mia->mia_dstaddr);
	
	switch (ifp->if_type) {
	case IFT_ETHER:	
	case IFT_FDDI: 	/* FALLTHROUGH */
														
		lltable_prefix_free(seg->sa_family, seg, NULL, 0);		
		break;
	case IFT_LOOP:	
	case IFT_MPLS:
		break;
	default:
		break;
	}
/*
 * Finalize.
 */
	if (mia->mia_x != NULL) {
		ifa_free(mia->mia_x);
		mia->mia_x = NULL;
	}
	mia->mia_lle = NULL;	
	
	mia->mia_flags &= ~IFA_ROUTE;
out:
	return (error);
}

/*
 * Initialize MPLS label binding.
 */
static int  
mpls_ifinit(struct ifnet *ifp, struct mpls_ifaddr *mia, struct rtentry *rt, 
		struct sockaddr *sa, int flags)
{
	struct rtentry *ilm = NULL;
	struct ifaddr *ifa = NULL;
	struct sockaddr *gw = NULL;
	struct sockaddr_ftn sftn;
	size_t len;
	int error;
	
#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */


/*
 * Prepare storage for gateway address and < op, seg_out, rd >.	
 */
	if (rt == NULL) 
		ifa = ifp->if_addr;
	else {
		RT_LOCK_ASSERT(rt);
		ifa = rt->rt_ifa;
	}
	ifa_ref(ifa);	
/*
 * XXX; ugly... but I'll reimplement this...
 */		
	ifa_ref(ifa);
	mia->mia_x = ifa;

	ifa->ifa_rtrequest = mpls_link_rtrequest;
/*
 * Map out-segment.
 */		
	if (rt == NULL) 
		gw = ifa->ifa_addr;
	else
		gw = rt_key(rt);
	
	bzero(&sftn, sizeof(sftn));
	sftn.sftn_len = sizeof(sftn);
	sftn.sftn_family = gw->sa_family;
	
	len = gw->sa_len - offsetof(struct sockaddr, sa_data);
	bcopy(gw->sa_data, sftn.sftn_data, len);	
		
	sftn.sftn_op = flags & RTF_MPLS_OMASK;
	
	if (flags & RTF_PUSH)  
		sftn.sftn_label = satosmpls_label(sa) & MPLS_LABEL_MASK;
	else 
		sftn.sftn_label = satosftn_label(sa) & MPLS_LABEL_MASK;
	
	sftn.sftn_vprd = sftn.sftn_label;
	
	bcopy(&sftn, mia->mia_dstaddr, sftn.sftn_len);
/*
 * Map in-segment.
 */
	mia->mia_addr->sa_len = SMPLS_LEN;
	mia->mia_addr->sa_family = AF_MPLS;
	satosmpls_label(mia->mia_addr) = satosmpls_label(sa) & MPLS_LABEL_MASK;	

	mia->mia_rt_flags = flags;		
/*
 * Create llentry{} on MPLS_ARP cache by SIOCSIFADDR command.
 */		
	error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (void *)mia);
	if (error != 0) 	
		goto out;

	if (rt == NULL) {
/*
 * Bind interface, if MPLS label binding was 
 * caused by SIOC[AS]IFADDR control operation.
 */		
		IF_AFDATA_WLOCK(ifp);
		ifa_ref(&mia->mia_ifa);
		MPLS_IFINFO_IFA(ifp) = &mia->mia_ifa;
		ifp->if_flags |= IFF_MPE;	
		IF_AFDATA_WUNLOCK(ifp);		
	
	} else {
/*
 * MPLS label binding scoped on set containing fec.			
 */			
		if (flags & RTF_STK) 
			rt->rt_flags |= RTF_STK;
		else if (flags & RTF_PUSH) {
/* 
 * Fastpath into MPLS transit will be applied on fec, when 
 * MPLS label binding states initial label (lsp_in) on Label 
 * Switch Path (lsp). 
 *
 * The gateway address on by fec implementing rtentry(9) is 
 * extended by < op, lsp_in, rd > where is defined by fec
 * generated nhlfe.
 *
 *     + rt_key               .       + MPLS label (BoS)
 *     |                      .       |
 *     v                      .       v
 *   +-------------+----------+-----+------+------+
 *   | 192.168.3.6 | 10.6.1.6 | Op  | 666  | VPRD |
 *   +-------------+----------+-----+------+------+
 *                   A
 *                   |
 *                   + rt_gateway
 *
 * This avoids a second routing table lookup by service 
 * providing MPLS layer, when handoff by protocol-layer
 * processed message primitives (mpi) into MPLS data 
 * plane was performed. 
 *
 * Because by service requesting protocol-layer performed
 * routing decision led to a rtentry(9) with an extended 
 * gateway address (see above), where is therefore accepted 
 * as argument by mpls_output.
 */
			gw = rt->rt_gateway;
			len = gw->sa_len - offsetof(struct sockaddr, sa_data);
			
			if (sftn.sftn_family != gw->sa_family) {
				sftn.sftn_family = gw->sa_family;
				bzero(sftn.sftn_data, SFTN_DATA_LEN);
			}
			bcopy(gw->sa_data, sftn.sftn_data, len);
			gw = (struct sockaddr *)&sftn;	
/*
 * Anotate gateway address with < op, lsp_in, rd >.
 */		
			error = rt_setgate(rt, rt_key(rt), gw);
			if (error == 0) {
				rt->rt_mtu -= MPLS_HDRLEN;
				rt->rt_flags |= RTF_MPE;
			}
		} else {
/*
 * Generate by nhlfe enclosed ilm. 
 */			
			error = rtrequest_fib((int)RTM_ADD, 
				mia->mia_addr, 
				mia->mia_dstaddr, 
				mia->mia_netmask, 
				mia->mia_rt_flags, 
				&ilm, ifp->if_fib);

			if (ilm != NULL) {			
				RT_LOCK(ilm);
/*
 * On success, inherite metrics from its enclosing fec.
 */				
				ilm->rt_mtu = rt->rt_mtu;
				ilm->rt_weight = rt->rt_weight;
				ilm->rt_expire = rt->rt_expire;
#ifdef MPLS_DEBUG	
	(void)printf("%s: rt_refcnt= %d\n", __func__, ilm->rt_refcnt);
#endif /* MPLS_DEBUG */	
				RT_UNLOCK(ilm);		
			}
		}
	}
	
	if (error == 0) 
		mia->mia_flags |= IFA_ROUTE;
out:
	if (ifa != NULL)
		ifa_free(ifa);

	return (error);
}

/*
 * Following lltable{} specific functions and procedures are 
 * derived from present implementation of IPv4 protocol stack. 
 * 
 * See netinet/in.c, netinet/if_ether.c and net/if_llatabl.c
 * for further details. 
 */

struct mpls_llentry {
	struct llentry		ml_base;	/* corrosponding lla */
	struct sockaddr_mpls	ml_seg;	/* particular lsp */
};

static void
mpls_lltable_free(struct lltable *llt, struct llentry *lle)
{
	LLE_WLOCK_ASSERT(lle);
	LLE_WUNLOCK(lle);
	LLE_LOCK_DESTROY(lle);
	
	free(lle, M_LLTABLE);
}

/*
 * Dtor, find llentry{} by out-segmentand release bound ressources.. 
 */
static void
mpls_lltable_prefix_free(struct lltable *llt, const struct sockaddr *sa0,
   		const struct sockaddr *sa1, u_int flags)
{
	const struct sockaddr_mpls *seg = (const struct sockaddr_mpls *)sa0;
	int i;
	struct llentry *lle, *next;
	size_t pkts_dropped;

	IF_AFDATA_WLOCK(llt->llt_ifp);
	
	for (i = 0; i < LLTBL_HASHTBL_SIZE; i++) {
		LIST_FOREACH_SAFE(lle, &llt->lle_head[i], lle_next, next) {

			if (MPLS_SEG(lle)->smpls_label != seg->smpls_label) 
				continue;
				
			LLE_WLOCK(lle);
			LLE_REMREF(lle);
			pkts_dropped = llentry_free(lle);		
		}
	}	
	IF_AFDATA_WUNLOCK(llt->llt_ifp);
}

/*
 * Ctor, map particular lsp to corrosponding link layer interface.
 */
static struct llentry *
mpls_lltable_new(const struct sockaddr *sa, u_int flags)
{
	const struct sockaddr_mpls *seg = (const struct sockaddr_mpls *)sa;
	struct llentry *lle = NULL;
	struct mpls_llentry *ml;

#ifdef MPLS_DEBUG
	KASSERT((seg != NULL), ("segment not defined"));
#endif /* MPLS_DEBUG */	
	
	if ((ml = malloc(sizeof(*ml), M_LLTABLE, M_NOWAIT|M_ZERO)) == NULL)		
		goto out;

	ml->ml_seg = *seg;
	lle = &ml->ml_base;
	
	LLE_LOCK_INIT(lle);
	
	lle->la_expire = time_uptime;
	lle->lle_refcnt = 1;
	lle->lle_free = mpls_lltable_free;
out:
	return (lle);
}

/*
 * Returns locked llentry{} from cache.
 */
static struct llentry *
mpls_lltable_lookup(struct lltable *llt, u_int flags, const struct sockaddr *sa)
{
	const struct sockaddr_mpls *seg = (const struct sockaddr_mpls *)sa;
	struct llentry *lle = NULL;
	u_int hashkey;
	struct llentries *lleh;
	
	IF_AFDATA_LOCK_ASSERT(llt->llt_ifp);
	
	hashkey = seg->smpls_label & MPLS_LABEL_MASK;
	lleh = &llt->lle_head[LLATBL_HASH(hashkey, LLTBL_HASHMASK)];

	LIST_FOREACH(lle, lleh, lle_next) {
		
		if (lle->la_flags & LLE_DELETED)
			continue;
		
		if (MPLS_SEG(lle)->smpls_label == seg->smpls_label)
			break;
	}
/*
 * Create llentry{}.
 */	
	if (lle == NULL) {
		
#ifdef MPLS_DEBUG
		if (flags & LLE_DELETE)
			log(LOG_INFO, "mpls label is missing from cache = %d  "
				"in delete\n", seg->smpls_label);
#endif
		
		if ((flags & LLE_CREATE) == 0) {
			lle = NULL;
			goto out;
		}
		
		if ((lle = mpls_lltable_new(sa, flags)) == NULL) {
			log(LOG_INFO, "lla_lookup: new lle malloc failed\n");
			goto out;
		}
		lle->la_flags = flags & ~LLE_CREATE;
		
		if ((flags & (LLE_CREATE|LLE_IFADDR)) 
			== (LLE_CREATE|LLE_IFADDR)) {
			bcopy(IF_LLADDR(llt->llt_ifp), &lle->ll_addr, 
				llt->llt_ifp->if_addrlen);
		}
		lle->lle_tbl  = llt;
		lle->lle_head = lleh;
		lle->la_flags |= LLE_LINKED;
		
		LIST_INSERT_HEAD(lleh, lle, lle_next);
	
	} else if (flags & LLE_DELETE) {
/*
 * Finalize llentry{}.
 */
		if (((lle->la_flags & LLE_IFADDR) == 0) 
			|| (flags & LLE_IFADDR)) {
			
			LLE_WLOCK(lle);
			
			lle->la_flags |= LLE_DELETED;
			llentry_free(lle);
			LLE_WUNLOCK(lle);
		}
		lle = (void *)-1;
	}
	
	if (LLE_IS_VALID(lle)) {
		if (flags & LLE_EXCLUSIVE)
			LLE_WLOCK(lle);
		else
			LLE_RLOCK(lle);
	}
out:
	return (lle);
}

/*
 * Dumps entire cache.
 * 
 * XXX: untested...
 */
static int
mpls_lltable_dump(struct lltable *llt, struct sysctl_req *wr)
{
	struct llentry *lle;
	struct {
		struct rt_msghdr	rtm;
		struct sockaddr_mpls	seg;
		struct sockaddr_dl	sdl;
	} arpc;
	int error, i;

	LLTABLE_LOCK_ASSERT();

	for (error = 0, i = 0; i < LLTBL_HASHTBL_SIZE; i++) {
		
		LIST_FOREACH(lle, &llt->lle_head[i], lle_next) {
/* 
 * Skip deleted entries. 
 */
			if ((lle->la_flags & LLE_DELETED) == LLE_DELETED)
				continue;
				
			bzero(&arpc, sizeof(arpc));	
/*
 * Prepare buffer denotes SPI containing cached llentry{}.
 */		
			arpc.rtm.rtm_msglen = sizeof(arpc);
			arpc.rtm.rtm_version = RTM_VERSION;
			arpc.rtm.rtm_type = RTM_GET;
			arpc.rtm.rtm_flags = RTF_UP;
			arpc.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;

			arpc.seg.smpls_family = AF_MPLS;
			arpc.seg.smpls_len = sizeof(arpc.seg);
			arpc.seg.smpls_label = MPLS_SEG(lle)->smpls_label;

			if (lle->la_flags & LLE_PUB) 
				arpc.rtm.rtm_flags |= RTF_ANNOUNCE;

			arpc.sdl.sdl_family = AF_LINK;
			arpc.sdl.sdl_len = sizeof(arpc.sdl);
			arpc.sdl.sdl_index = llt->llt_ifp->if_index;
			arpc.sdl.sdl_type = llt->llt_ifp->if_type;
			
			if ((lle->la_flags & LLE_VALID) == LLE_VALID) {
				arpc.sdl.sdl_alen = llt->llt_ifp->if_addrlen;
				bcopy(&lle->ll_addr, LLADDR(&arpc.sdl), 
					llt->llt_ifp->if_addrlen);
			} else {
				arpc.sdl.sdl_alen = 0;
				bzero(LLADDR(&arpc.sdl), llt->llt_ifp->if_addrlen);
			}
			arpc.rtm.rtm_rmx.rmx_expire = lle->la_expire;
			arpc.rtm.rtm_flags |= (RTF_HOST | RTF_LLDATA);
			arpc.rtm.rtm_index = llt->llt_ifp->if_index;
/*
 * Send SPI to caller.
 */			
			if ((error = SYSCTL_OUT(wr, &arpc, sizeof(arpc))) != 0)
				break;
		}
	}	
	return (error);
}

extern int	mpls_output(struct ifnet *, struct mbuf *, struct sockaddr *,
	struct route *ro);
void *	mpls_domifattach(struct ifnet *);
void	mpls_domifdetach(struct ifnet *, void *);

/*
 * Bind cache. 
 *
 * See kern/uiopc_domain.c and net/if.c for further details.
 */
void *
mpls_domifattach(struct ifnet *ifp)
{
	struct mpls_ifinfo *mii = NULL;
	struct lltable *llt;

	if (ifp == NULL)
		goto out;

	mii = malloc(sizeof(*mii), M_IFADDR, M_WAITOK|M_ZERO);
	
	if ((llt = lltable_init(ifp, AF_MPLS)) != NULL) {
		llt->llt_prefix_free = mpls_lltable_prefix_free;
		llt->llt_lookup = mpls_lltable_lookup;
		llt->llt_dump = mpls_lltable_dump;
		
		mii->mii_llt = llt;
	} else {
		free(mii, M_IFADDR);
		mii = NULL;
	}
out:
	return (mii);
}

/*
 * Detach cache.
 */
void
mpls_domifdetach(struct ifnet *ifp, void *aux)
{
	struct mpls_ifinfo *mii;
	struct lltable *llt;
	
	if ((mii = (struct mpls_ifinfo *)aux) == NULL)
		return;

	if (ifp == NULL)
		return;
		
	if ((llt = mii->mii_llt) == NULL)
		return;

	switch (ifp->if_type) {
	case IFT_ETHER:
	case IFT_FDDI:
	case IFT_LOOP:
		
		if (ifp->if_flags & IFF_MPLS) {
			ifp->if_flags &= ~IFF_MPLS;
			ifp->if_output = mii->mii_output;
		}
		break;
	case IFT_MPLS: 
		break;
	default:
		break;
	}
	lltable_free(llt);
	free(mii, M_IFADDR);
} 


