/*
 * Copyright (c) 2014, 2015 Henning Matyschok
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
 
/*
 * Copyright (c) 2009 Theo de Raadt
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
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/libkern.h>
#include <sys/socket.h> 
#include <sys/sockio.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_clone.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_bridgevar.h>
#include <net/if_llatbl.h>

/*
 * Virtual Ethernet interface, ported from OpenBSD. This interface 
 * operates in conjunction with if_bridge(4).
 *
 * Suppose instance of if_vether(4) denotes ifp0 and ifp denotes 
 * different Ethernet NIC, which is member of instance of if_bridge(4) 
 * where ifp0 is member.  
 *
 * Frame output: 
 * -------------
 *
 *  + inet_output()             + ng_ether_rcv_lower()
 *  |                           |
 *  v                           | 
 *  + (*ifp0->if_output)()      |
 *   \                          v   
 *    \                         + ether_output_frame()
 *     \                        |
 *      \                       + (*ifp0->if_transmit)()
 *       \                      |
 *        \                     + (*ifp0->if_start)()
 *         \                   /
 *          \     +-----------+ vether_start_locked()
 *           \   / 
 *            \ /
 *             + bridge_output(), selects NIC for tx frames
 *             |
 *             + bridge_enqueue()  
 *             |
 *             + (*ifp->if_transmit)()
 *             |
 *             v
 *             +-{ physical broadcast media } 
 *
 * Frame input:
 * ------------
 *
 *  +-{ physical broadcast media } 
 *  |
 *  v
 *  + (*ifp->if_input)(), NIC rx frame 
 *  |
 *  + bridge_input()
 *  |                           
 *  + bridge_forward(), selects ifp0 denotes instance of if_vether(4)
 *  |
 *  + bridge_enqueue()
 *  |
 *  + (*ifp0->if_transmit)()
 *   \            
 *    + vether_start_locked()
 *     \     
 *      + (*ifp0->if_input)() 
 *     / \
 *    /   +--->+ ng_ether_input()  
 *   /
 *  + bridge_input(), but forwarding is stalled by
 *  |           
 *  |                  if (ifp0->if_type == IFT_VETHER)
 *  |                          return (m);
 *  v
 *  + ether_demux() 
 */
struct vether_softc {
	struct ifnet	*sc_ifp;	/* network interface. */
	struct mtx	sc_mtx;	
	struct ifmedia	sc_ifm;		/* fake media information */
	int	sc_status;
	LIST_ENTRY(vether_softc) vether_list;
};
#define	VETHER_LOCK_INIT(sc)	mtx_init(&(sc)->sc_mtx, "vether softc",	\
				     NULL, MTX_DEF)
#define	VETHER_LOCK_DESTROY(sc)	mtx_destroy(&(sc)->sc_mtx)
#define	VETHER_LOCK(sc)		mtx_lock(&(sc)->sc_mtx)
#define	VETHER_UNLOCK(sc)		mtx_unlock(&(sc)->sc_mtx)
#define	VETHER_LOCK_ASSERT(sc)	mtx_assert(&(sc)->sc_mtx, MA_OWNED)	

static int	vether_clone_create(struct if_clone *, int, caddr_t);
static void	vether_clone_destroy(struct ifnet *);
 
static struct if_clone *vether_cloner;
static const char vether_name[] = "vether";

static LIST_HEAD(, vether_softc) vether_list;

static struct mtx vether_list_mtx;

static void	vether_init(void *);
static void	vether_stop(struct ifnet *, int);
static void	vether_start_locked(struct vether_softc *,struct ifnet *);
static void	vether_start(struct ifnet *);

static int	vether_media_change(struct ifnet *);
static void	vether_media_status(struct ifnet *, struct ifmediareq *);
static int	vether_ioctl(struct ifnet *, u_long, caddr_t);

/*
 * Ctor.
 */
static int
vether_clone_create(struct if_clone *ifc, int unit, caddr_t data)
{
	struct vether_softc *sc;
	struct ifnet *ifp;	
	uint32_t randval;
	uint8_t	lla[ETHER_ADDR_LEN];
/*
 * Allocate software context.
 */ 
	sc = malloc(sizeof(struct vether_softc), M_DEVBUF, M_WAITOK|M_ZERO);
	ifp = sc->sc_ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		free(sc, M_DEVBUF);
		return (ENOSPC);
	}
	if_initname(ifp, vether_name, unit);
/*
 * Bind software context.
 */ 	
	VETHER_LOCK_INIT(sc);
	ifp->if_softc = sc;
/*
 * Initialize specific attributes.
 */ 
	ifp->if_init = vether_init;
	ifp->if_ioctl = vether_ioctl;
	ifp->if_start = vether_start;
 
 	ifp->if_snd.ifq_maxlen = ifqmaxlen;
 	ifp->if_flags = (IFF_SIMPLEX|IFF_BROADCAST|IFF_MULTICAST|IFF_VETHER);
 
	ifp->if_capabilities = IFCAP_VLAN_MTU|IFCAP_JUMBO_MTU;
	ifp->if_capenable = IFCAP_VLAN_MTU|IFCAP_JUMBO_MTU;
	
	ifmedia_init(&sc->sc_ifm, 0, vether_media_change, vether_media_status);
	ifmedia_add(&sc->sc_ifm, IFM_ETHER|IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_ifm, IFM_ETHER|IFM_AUTO);
 	
 	sc->sc_status = IFM_AVALID;
/*
 * Generate randomized lla.  
 */
	lla[0] = 0x0;
	randval = arc4random();
	memcpy(&lla[1], &randval, sizeof(uint32_t));
	lla[5] = (uint8_t)unit; /* Interface major number */
/*
 * Initialize ethernet specific attributes and perform inclusion 
 * mapping on link layer, netgraph(4) domain and generate by bpf(4) 
 * implemented Inspection Access Point maps to by ifnet(9) defined 
 * generic interface.
 */ 	
 	ether_ifattach(ifp, lla);
 	ifp->if_baudrate = 0;
 
	mtx_lock(&vether_list_mtx);
	LIST_INSERT_HEAD(&vether_list, sc, vether_list);
	mtx_unlock(&vether_list_mtx);

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
 
	return (0);
}

/*
 * Dtor.
 */
static void
vether_clone_destroy(struct ifnet *ifp)
{
	struct vether_softc *sc;	
	
	sc = ifp->if_softc;	
 
	VETHER_LOCK(sc);
	vether_stop(ifp, 1);
	
	ifp->if_flags &= ~IFF_UP;	
	VETHER_UNLOCK(sc);		

	mtx_lock(&vether_list_mtx);
	LIST_REMOVE(sc, vether_list);
	mtx_unlock(&vether_list_mtx);	
/*
 * Inverse element of ether_ifattach.
 */
	ether_ifdetach(ifp);
/*
 * Release bound ressources.
 */	
	if_free(ifp);
	
	VETHER_LOCK_DESTROY(sc);
	free(sc, M_DEVBUF);
}
 
/*
 * Initializes interface.
 */
static void
vether_init(void *xsc)
{
	struct vether_softc *sc = (struct vether_softc *)xsc;
	struct ifnet *ifp;
 
	VETHER_LOCK(sc);
	ifp = sc->sc_ifp;
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
	VETHER_UNLOCK(sc);
}
 
/*
 * Stops focussed instance of if_vether(4).
 */
static void
vether_stop(struct ifnet *ifp, int disable)
{
	struct vether_softc *sc;
	
	sc = ifp->if_softc;
	VETHER_LOCK_ASSERT(sc);
	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
}	
 
/*
 * I/O.
 */
static void
vether_start(struct ifnet *ifp)
{
	struct vether_softc	*sc = ifp->if_softc;

	VETHER_LOCK(sc);
	vether_start_locked(sc, ifp);
	VETHER_UNLOCK(sc);
}

static void
vether_start_locked(struct vether_softc	*sc, struct ifnet *ifp)
{
	struct mbuf *m;
	int error;

	VETHER_LOCK_ASSERT(sc);
	
	ifp->if_drv_flags |= IFF_DRV_OACTIVE;
	for (;;) {
		IFQ_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL) 
			break;
			
		if ((m->m_flags & M_PKTHDR) == 0) {
			m_freem(m);
			continue;
		}
		
		if (m->m_pkthdr.rcvif == NULL) {
/*
 * IAP for transmission.
 */				
			ETHER_BPF_MTAP(ifp, m);
			ifp->if_opackets++;	
/* 
 * Discard any frame, if not if_bridge(4) member.
 */				
			if (ifp->if_bridge == NULL) {
				m_freem(m);
				continue;
			}			
/* 
 * Discard any frame, if monitoring is enabled.
 */		
			if (ifp->if_flags & IFF_MONITOR) {
				m_freem(m);
				continue;
			}
/* 
 * Discard, if frame not passed ng_ether_rcv_lower.
 */
			if ((m->m_flags & M_PROTO2) == 0) {
				m_freem(m);
				continue;
			}
			m->m_flags &= ~M_PROTO2;
			m->m_pkthdr.rcvif = ifp;			
/*
 * Broadcast frame via if_bridge(4).
 */			
			BRIDGE_OUTPUT(ifp, m, error);	
		} else if (m->m_pkthdr.rcvif != ifp) {
/*
 * IAP for reception.
 */				
			ETHER_BPF_MTAP(ifp, m);	
			ifp->if_ipackets++;	
/* 
 * Discard any frame, if monitoring is enabled.
 */		
			if (ifp->if_flags & IFF_MONITOR) {
				m_freem(m);
				continue;
			}
			m->m_pkthdr.rcvif = ifp;
/*
 * Demultiplex frame by ether_input.
 */	
			(*ifp->if_input)(ifp, m);
		} else {
/*
 * Discard any duplicated frame.
 */ 		
			m_freem(m);
			continue;
		}		
	}								
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}

/*
 * Media types can't be changed.
 */
static int
vether_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct vether_softc *sc = ifp->if_softc;	
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0;
 
	switch (cmd) {
	case SIOCSIFMTU:
		if (ifr->ifr_mtu > ETHER_MAX_LEN_JUMBO) 
			error = EINVAL;
		else 
			ifp->if_mtu = ifr->ifr_mtu;	
		break;
	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_ifm, cmd);
		break;
	case SIOCSIFFLAGS:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
	case SIOCSIFPHYS:
		error = EOPNOTSUPP;
		break;
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}
	return (error);
} 

static int
vether_media_change(struct ifnet *ifp)
{
	return (0);
}
 
static void
vether_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	ifmr->ifm_active = IFM_ETHER|IFM_AUTO;
	ifmr->ifm_status = IFM_AVALID|IFM_ACTIVE;
}

/*
 * Module event handler.
 */
static int
vether_mod_event(module_t mod, int event, void *data)
{
	int error = 0;
 
	switch (event) {
	case MOD_LOAD:
		mtx_init(&vether_list_mtx, "if_vether_list", NULL, MTX_DEF);
		vether_cloner = if_clone_simple(vether_name,
			vether_clone_create, vether_clone_destroy, 0);
		break;
	case MOD_UNLOAD:	
		if_clone_detach(vether_cloner);
		mtx_destroy(&vether_list_mtx);
		break;
	default:
		error = EOPNOTSUPP;
	}
 
	return (error);
} 
 
static moduledata_t vether_mod = {
	"if_vether",
	vether_mod_event,
	0
};
DECLARE_MODULE(if_vether, vether_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_DEPEND(if_vether, ether, 1, 1, 1);

