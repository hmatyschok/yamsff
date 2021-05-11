/*-
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@spootnik.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in ampe copies.
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
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_bridgevar.h>
#include <net/if_clone.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <machine/in_cksum.h>

#ifdef INET6
#include <netinet/ip6.h>
#endif /* INET6 */

#include <netmpls/mpls.h>

extern struct mbuf * 	mpls_ip_adjttl(struct mbuf *, uint8_t);
#ifdef INET6
struct mbuf * 	mpls_ip6_adjttl(struct mbuf *, uint8_t);
#endif /* INET6 */

extern void	mpls_rtalloc(struct route *, u_int);

extern struct ifaddr *	mpls_ifawithinseg(struct sockaddr *, int);
extern struct mbuf *	mpls_shim_pop(struct mbuf *);
extern struct mbuf *	mpls_encap(struct mbuf *, 
	const struct sockaddr *, struct mpls_ro *);

#define MPENAME	"mpe"
#define MPE_MTU		1500
#define MPE_MTU_MIN	256
#define MPE_MTU_MAX	8192

/*
 * MPLS Provider Edge (PE). 
 *
 * Any output by if_bridge(4) is processed by mpe_start,
 * if instance of if_mpe(4) is bridge member. Otherwise,
 * protocol layer calls mpe_output directly. 
 *
 *                  + pr_output(), i. e. ip_output            
 *  mpe_start()    / 
 *            +   /
 *             \ /
 * mpe_output() +--tx--> MPLS VP Label (Virtual Path ID)
 *               \ 	
 *                + mpls_output() +--tx--> MPLS Label (Tunnel ID)
 *                 \
 *                  + if_output() +--> if_start()
 *
 * PE tx Protocol Data Units (PDU) by using network
 * interfaces as proxy. 
 */
 
struct mpe_softc {
	struct ifnet	*sc_ifp;		/* the interface */
	struct ifnet	*sc_proxy;		/* its proxy */
	struct mtx	sc_mtx;
	LIST_ENTRY(mpe_softc)	sc_list;
};
#define	MPE_LOCK_INIT(sc)	mtx_init(&(sc)->sc_mtx, "mpe_sc",	\
				     NULL, MTX_DEF)
#define	MPE_LOCK_DESTROY(sc)	mtx_destroy(&(sc)->sc_mtx)
#define	MPE_LOCK(sc)		mtx_lock(&(sc)->sc_mtx)
#define	MPE_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	MPE_LOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_mtx, MA_OWNED)

static int	mpe_clone_create(struct if_clone *, int, caddr_t);
static void	mpe_clone_destroy(struct ifnet *);

static struct if_clone *mpe_cloner;
static const char mpe_name[] = "mpe";

static struct mtx mpe_list_mtx;
static LIST_HEAD(, mpe_softc) mpeif_list;

static void	mpe_input(struct ifnet*, struct mbuf *);
static void	mpe_start(struct ifnet *);
static int	mpe_output(struct ifnet *, struct mbuf *, 
	const struct sockaddr *, struct route *);
static void	mpe_init(void *);

static int	mpe_ioctl(struct ifnet *, u_long, caddr_t);

/*
 * Ctor.
 */
static int
mpe_clone_create(struct if_clone *ifc, int unit, caddr_t data)
{
	struct mpe_softc *sc;
	struct ifnet *ifp;
	
 	sc = malloc(sizeof(*sc), M_DEVBUF, M_WAITOK|M_ZERO);
 	ifp = sc->sc_ifp = if_alloc(IFT_MPLS);
	if (ifp == NULL) {
		free(sc, M_DEVBUF);
		return (ENOSPC);
	}	
	if_initname(ifp, mpe_name, unit);
	
	MPE_LOCK_INIT(sc);
/*
 * Map instance to itself.
 */			
	sc->sc_proxy = ifp;
	ifp->if_softc = sc; 
	
	ifp->if_ioctl = mpe_ioctl;
	ifp->if_input = mpe_input;
	ifp->if_output = mpe_output;
	ifp->if_init = mpe_init;
	ifp->if_start = mpe_start;
	
	ifp->if_flags = (IFF_BROADCAST|IFF_MULTICAST|IFF_MPLS);

	IFQ_SET_MAXLEN(&ifp->if_snd, ifqmaxlen);
	ifp->if_snd.ifq_drv_maxlen = ifqmaxlen;
	IFQ_SET_READY(&ifp->if_snd);

	ifp->if_mtu = MPE_MTU;
 	
 	if_attach(ifp);
 	bpfattach(ifp, DLT_NULL, sizeof(uint32_t));
 	
 	mtx_lock(&mpe_list_mtx);
	LIST_INSERT_HEAD(&mpeif_list, sc, sc_list);
	mtx_unlock(&mpe_list_mtx);
	
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
	ifp->if_flags |= IFF_UP;
	
	return (0);
}

/*
 * Dtor.
 */
static void
mpe_clone_destroy(struct ifnet *ifp)
{
	struct mpe_softc *sc = ifp->if_softc;

	MPE_LOCK_DESTROY(sc);
	mtx_lock(&mpe_list_mtx);
	LIST_REMOVE(sc, sc_list);
	mtx_unlock(&mpe_list_mtx);
	bpfdetach(ifp);
	if_detach(ifp);
	free(sc, M_DEVBUF);
}

/* ARGSUSED */
static int
mpe_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct mpe_softc *sc = ifp->if_softc;
	struct sockaddr_mpls *smpls;
	struct sockaddr_dl *sdl;
	struct ifaddr *ifa;
	int error;

	error = 0;
	ifa = NULL;
		
	switch (cmd) {
	case SIOCADDMULTI:
	case SIOCDELMULTI: 	/* FALLTHROUGH */
	case SIOCGIFADDR:
		break;
	case SIOCSIFADDR:
	
		if ((ifa = (struct ifaddr *)data) != NULL)
			ifa_ref(ifa);
		
		if ((ifp->if_flags & IFF_UP) == 0)
			if_up(ifp);
/*
 * Ensure, if MPLS_RD_ETHDEMUX is set, iff
 * focussed instance is if_bridge(4) member.
 */		
		if (ifp->if_bridge != NULL)
			EVENTHANDLER_INVOKE(mpls_bridge_event, ifp, RTM_CHANGE);
/*
 * Map focussed instance to itself.
 */		
		if (ifa != NULL && ifa->ifa_flags & IFA_NHLFE)
			sc->sc_proxy = ifp;		
		break;
	case SIOCGLIFPHYADDR:
/*
 * Get lla from proxy, if any.
 */			
		smpls = (struct sockaddr_mpls *)
			&(((struct if_laddrreq *)data)->addr);
		sdl = (struct sockaddr_dl *)
			&(((struct if_laddrreq *)data)->dstaddr);
		
		if (smpls->smpls_family != AF_MPLS) {
			error = EAFNOSUPPORT;
			break;
		}	
		
		if (smpls->smpls_len != sizeof(*smpls)) {
			error = EINVAL;
			break;
		}
		
		if (sdl->sdl_family != AF_LINK) {
			error = EAFNOSUPPORT;
			break;
		}	
		
		if (sdl->sdl_len != sizeof(*sdl)) {
			error = EINVAL;
			break;
		}	
		
		if (sc->sc_proxy == NULL || sc->sc_proxy == ifp) {
			error = EADDRNOTAVAIL;
			break;
		}
		bcopy(sc->sc_proxy->if_addr->ifa_addr, sdl, 
			sc->sc_proxy->if_addr->ifa_addr->sa_len);
		break;
	case SIOCSIFPHYADDR:
/*
 * Bind interface for proxyfied transmission.
 */			
		smpls = (struct sockaddr_mpls *)
			&(((struct ifaliasreq *)data)->ifra_addr);
		sdl = (struct sockaddr_dl *)
			&(((struct ifaliasreq *)data)->ifra_broadaddr);
		
		if (smpls->smpls_family != AF_MPLS) {
			error = EAFNOSUPPORT;
			break;
		}
		
		if (sdl->sdl_family != AF_LINK) {
			error = EAFNOSUPPORT;
			break;
		}	
		IF_AFDATA_RLOCK(ifp);	
		ifa = MPLS_IFINFO_IFA(ifp);
		IF_AFDATA_RUNLOCK(ifp);	
 		
 		if (ifa == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
		ifa_ref(ifa);					
/*
 * Fetch target interface by its name.
 */	
		sc->sc_proxy = ifunit(sdl->sdl_data);
		if (sc->sc_proxy == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
/*
 * Finally, map requested proxy to focussed instance, iff 
 * target remains in MPLS enabled state and its type does 
 * not denotes IFT_MPLS or IFT_LOOP.
 */	
		switch (sc->sc_proxy->if_type) {
		case IFT_ETHER:
		case IFT_FDDI:
/*
 * Create by segment on particular lsp corrosponding llentry{}. 
 */
			if (sc->sc_proxy->if_flags & IFF_MPLS) { 
				error = (*sc->sc_proxy->if_ioctl)
					(sc->sc_proxy, SIOCSIFADDR, (void *)ifa);
			} else
				error = ENXIO;		
			break;
		default:
			error = EADDRNOTAVAIL;
			break;	
		}
		break;
	case SIOCDIFPHYADDR:
/*
 * Detach for proxyfied transmission used interface.
 */		
		smpls = (struct sockaddr_mpls *)&ifr->ifr_addr;
		
		if (smpls->smpls_family != AF_MPLS) {
			error = EAFNOSUPPORT;
			break;
		}
		
 		
 		if (ifa == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
		ifa_ref(ifa);
/*
 * Remove segment corrosponding llentry{} from cache.
 */			
		lltable_prefix_free(ifa->ifa_addr->sa_family, 
			ifa->ifa_addr, NULL, 0);	
/*
 * Reflexive mapping.
 */		
		sc->sc_proxy = ifp;
		break;
	case SIOCSIFFLAGS:
	
		if (ifp->if_flags & IFF_UP)
			ifp->if_flags |= IFF_DRV_RUNNING;
		else
			ifp->if_flags &= ~IFF_DRV_RUNNING;
		break;
	case SIOCSIFMTU:
	
		if ((ifr->ifr_mtu < MPE_MTU_MIN) 
			|| (ifr->ifr_mtu > MPE_MTU_MAX))
			error = EINVAL;
		else
			ifp->if_mtu = ifr->ifr_mtu;
		break;
	default:
		error = EOPNOTSUPP;	
		break;
	}
	
	if (ifa != NULL) 
		ifa_free(ifa);
			
	return (error);
}

static void
mpe_init(void *xsc)
{
	struct mpe_softc *sc = (struct mpe_softc *)xsc;
	struct ifnet *ifp;
 
	MPE_LOCK(sc);
	ifp = sc->sc_ifp;
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
	ifp->if_flags |= (IFF_UP|IFF_MPE);
	MPE_UNLOCK(sc);
}

/*
 * Receive output from if_bridge(4) where if_mpe(4) is member 
 * when if_transmit was called by bridge_enqueue.
 * 
 * See net/if_bridge.c and net/if.c for further details.
 */
static void
mpe_start(struct ifnet *ifp)
{
	struct mbuf *m;
	
	ifp->if_drv_flags |= IFF_DRV_OACTIVE;
	for (;;) {
		IFQ_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL)
			break;
/*
 * Ethernet frames are in AF_LINK domain.
 */
		(void)(*ifp->if_output)
			(ifp, m, mpls_if_lladdr(ifp), NULL);
	}
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}

/*
 * Encapsulate received packets and 
 * perform transmission by proxyfied
 * interface on link-layer. 
 */ 
static int
mpe_output(struct ifnet *ifp, struct mbuf *m, 
		const struct sockaddr *dst, struct route *ro)
{
	struct mpls_ro mplsroute;
	struct mpls_ro *mro;
	struct sockaddr *gw;
	struct mpe_softc *sc;
	struct mbuf *m0;
	uint32_t af;
	size_t len;
	int mflags;
	int	error;
	
	mro = &mplsroute;
	bzero(mro, sizeof(*mro));
	gw = sftntosa(&mro->mro_gw);
	
	if (ro == NULL)
		ro = (struct route *)mro;
	
	if ((ifp->if_flags & IFF_UP) == 0) {
		error = ENETDOWN;
		goto bad;
	}
	
	if ((sc = ifp->if_softc) == NULL) {
		error = ENXIO;
		goto bad;
	}
	IF_AFDATA_RLOCK(ifp);
	mro->mro_ifa = MPLS_IFINFO_IFA(ifp);
	IF_AFDATA_RUNLOCK(ifp);
/*
 * Abort transmission, if MPLS label binding does not exist.
 */	
	if (mro->mro_ifa == NULL) {
		error = ENETUNREACH;
		goto bad1;
	}
	af = dst->sa_family;
/*
 * Handoff into bpf(4), Inspection Access Point (iap).
 */		
	BPF_MTAP2(ifp, &af, sizeof(af), m);
	
	len = m->m_pkthdr.len;
	mflags = m->m_flags;
	
	M_ASSERTPKTHDR(m);
	
	for (; m; m = m0) {
		m0 = m->m_nextpkt;
		m->m_nextpkt = NULL;
/*
 * Ensure stacking, if mbuf(9) originates AF_MPLS domain.
 */ 
		if (af == AF_MPLS)
			mro->mro_flags |= RTF_STK;

		m = mpls_encap(m, mro->mro_ifa->ifa_dstaddr, mro);
		if (m == NULL) {
			ifp->if_oerrors++;
			continue;
		} 
/*
 * If instance maps to itself, loop back.
 */		
		if (sc->sc_proxy == ifp)
			if_simloop(ifp, m, gw->sa_family, 0);
		else {
			error = (*sc->sc_proxy->if_output)
				(sc->sc_proxy, m, gw, ro);
		}
		mro->mro_flags &= ~RTF_STK;
	}
	
	if (error == 0) { 
		ifp->if_opackets++;
		ifp->if_obytes += len;
		
		if (mflags & M_MCAST)
			ifp->if_omcasts++;
	}
done:
	return (error);
bad1:		
	ifp->if_oerrors++;
bad:
	m_freem(m);
	goto done;
}

/*
 * Accept by mpls_forward diverted mbuf(9), 
 * if ilm maps to if_mpe(4) and RTF_POP.  
 */
static void	
mpe_input(struct ifnet *ifp, struct mbuf *m)
{
	struct shim_hdr *shim;
	uint32_t af, isr;
	uint8_t ttl;

#ifdef MPLS_DEBUG
	(void)printf("%s\n",__func__);
#endif /* MPLS_DEBUG */

	if ((m->m_flags & M_PKTHDR) == 0)
		goto bad;

	if ((ifp->if_flags & IFF_UP) == 0)
		goto bad;
	
	m->m_pkthdr.rcvif = ifp;
		
	shim = mtod(m, struct shim_hdr *);
	ttl = MPLS_TTL_GET(shim->shim_label);
	
	if ((m = mpls_shim_pop(m)) == NULL)  
		goto bad1;

	switch (*mtod(m, u_char *) >> 4) {
	case IPVERSION:
		
		if ((m = mpls_ip_adjttl(m, ttl)) == NULL)
			goto bad;
		
		isr = NETISR_IP;
		af = AF_INET;
		
		BPF_MTAP2(ifp, &af, sizeof(af), m);
		break;
#ifdef INET6
	case IPV6_VERSION >> 4:
		
		if ((m = mpls_ip6_adjttl(m, ttl)) == NULL)
			goto bad;
		
		isr = NETISR_IPV6;
		af = AF_INET6;	
		
		BPF_MTAP2(ifp, &af, sizeof(af), m);
		break;
#endif /* INET6 */
	default:
	
		if (mpls_empty_cw != 0) 
			m_adj(m, MPLS_CWLEN);
		
		if (*mtod(m, uint32_t *) == 0)
			m_adj(m, MPLS_CWLEN);
		
		af = AF_UNSPEC,
		isr = NETISR_ETHER;
		
		break;
	}
	ifp->if_ibytes += m->m_pkthdr.len;
	ifp->if_ipackets++;
	
	M_SETFIB(m, ifp->if_fib);

	netisr_dispatch(isr, m);
	return;
bad:
	m_freem(m);
bad1:
	ifp->if_ierrors++;	
}

/*
 * Faked glue between address resolution code 
 * for synchronized reception by ether_input.
 */
 
static void *
mpe_alloc(u_char type, struct ifnet *ifp)
{
	struct arpcom *ac;
/*
 * Can't fail.
 */
	ac = malloc(sizeof(struct arpcom), M_DEVBUF, M_WAITOK|M_ZERO);
	ac->ac_ifp = ifp;

	return (ac);
}

static void 
mpe_free(void *com, u_char type)
{

	free(com, M_DEVBUF);
}

/*
 * Module event handler.
 */

static int
mpe_mod_event(module_t mod, int event, void *data)
{
	int error = 0;
 
	switch (event) {
	case MOD_LOAD:
		mtx_init(&mpe_list_mtx, 
			"mpeif_list", NULL, MTX_DEF);
		mpe_cloner = if_clone_simple(mpe_name,
			mpe_clone_create, mpe_clone_destroy, 0);
		if_register_com_alloc(IFT_MPLS, mpe_alloc, mpe_free);
		break;
	case MOD_UNLOAD:	
		if (LIST_EMPTY(&mpeif_list)) {
			mtx_destroy(&mpe_list_mtx);
			if_clone_detach(mpe_cloner);
			if_deregister_com_alloc(IFT_MPLS);
		} else	
			error = EBUSY;
		break;
	default:
		error = EOPNOTSUPP;
	}
	return (error);
} 

static moduledata_t mpe_mod = {
	"if_mpe",
	mpe_mod_event,
	0
};
DECLARE_MODULE(if_mpe, mpe_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);

