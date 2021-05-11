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
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/pfil.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip_carp.h>
#include <netinet/ip_var.h>
#include <netinet/ip_fw.h>
#include <netpfil/ipfw/ip_fw_private.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#endif /* INET6 */

#include <netmpls/mpls.h>

extern struct mbuf *	mpls_encap(struct mbuf *, 
	const struct sockaddr *, struct mpls_ro *);
extern int	mpls_pfil(struct mbuf **, struct ifnet *, int);
int	mpls_output(struct ifnet *, struct mbuf *, const struct sockaddr *,
	struct route *);
	
/*
 * Original (hw independent) Link layer output routine is wrapped by 
 * mpls_output, if focussed Link layer interface remains in MPLS enabled 
 * state. Original output routine is hooked by mpls_ifinfo{} and called 
 * by mpls_output.
 *
 * Any by protocol layer above transmitted mbuf(9) containing Protocol 
 * Data Uniit (pdu) must pass MPLS layer, if for transmission used interface
 * on link-layer remains in MPLS enabled state. 
 * 
 * I/O Path, IPv4:
 *
 *              rip_input() +{ socket layer }+ rip_output()
 *                         /                  \
 *                        /                    \
 *      +-->+ ip_input() +-->+ ip_forward() +-->+ ip_output()
 *     /     \                                   \
 *    /       \                                   +
 *   +         +<------+                          |
 *   |                  \                         v 
 *   + mpls_input() +--->+ mpls_forward() +------>+ mpls_output()			
 *   |\                                          /|
 *   | \                               +<-------+ |
 *   |  \                             /           |
 *   |   +<-----------+ if_simloop() +<-----------+ if_output()
 *   |                                            |
 *   + if_input()                                 |
 *   A                                            |
 *   |                                            V
 *
 */
int
mpls_output(struct ifnet *ifp, struct mbuf *m, 
		const struct sockaddr *dst, struct route *ro)
{	
	struct mpls_ifinfo *mii;
	struct mpls_ro mplsroute;
	struct mpls_ro *mro;
	struct sockaddr *gw;
	
	int error = 0;
	
#ifdef MPLS_DEBUG
	struct shim_hdr *shim;
#endif /* MPLS_DEBUG */ 	
	
	if ((ifp->if_flags & IFF_MPLS) == 0) {
/*
 * Any pdu originates MPLS-layer are looped back into its 
 * domain, if for transmission used interface cannot accept 
 * by MPLS-layer processed pdu.
 *
 * See net/if_ethersubr.c and net/if_loop.c for further details.
 */
		if (dst->sa_family == AF_MPLS) 
			if_simloop(ifp, m, dst->sa_family, 0);
		else 
			error = (*ifp->if_output)(ifp, m, dst, ro);
		goto out;
	}	
	IF_AFDATA_RLOCK(ifp);
	mii = MPLS_IFINFO(ifp);
	IF_AFDATA_RUNLOCK(ifp);
	
	mro = &mplsroute;
	bzero(mro, sizeof(*mro));
	
	if (ro == NULL) 
		ro = (struct route *)mro;	

	if (ro->ro_rt != NULL) {
/*
 * If route exists, three cases are considered:
 * 
 *  (a) held route denotes fastpath. 
 *  (b) held route denotes ilm,
 *
 * or
 *  
 *  (c) held route originates not AF_MPLS domain.
 */
		if (ro->ro_rt->rt_flags & RTF_MPE) { 
			gw = ro->ro_rt->rt_gateway;
			
			if ((m = mpls_encap(m, gw, mro)) == NULL) {
				error = ECONNABORTED;
				goto done;
			}
			gw = (struct sockaddr *)&mro->mro_gw;
		} else
			gw = (struct sockaddr *)dst;		
	} else
		gw = (struct sockaddr *)dst;
	
	if (m->m_flags & M_MPLS) {
/*
 * Bypass tagging, if mbuf(9) was cached by MPLS_ARP.
 */
		m->m_flags &= ~M_MPLS;
	} else if (mii->mii_nhlfe != NULL) {
/*
 * Otherwise, mbuf(9) must pass mpls_encap, if 
 * interface is bound by MPLS label binding on
 * per-interface MPLS label space.  
 */	
		mro->mro_ifa = mii->mii_nhlfe;
		gw = mro->mro_ifa->ifa_dstaddr;
/*
 * Per interface MPLS label space.
 */					
		if ((m = mpls_encap(m, gw, mro)) == NULL) {
			error = ECONNABORTED;
			goto done;
		}
		gw = (struct sockaddr *)&mro->mro_gw;
	}
	
	if (gw->sa_family == AF_MPLS) {
/* 
 * Defines iap for pfil(9) processing.
 */
		if (PFIL_HOOKED(&V_inet_pfil_hook)
#ifdef INET6
	    	|| PFIL_HOOKED(&V_inet6_pfil_hook)
#endif
	    ) {		
			if (mpls_pfil(&m, ifp, PFIL_OUT) != 0)
				goto done;
				
			if (m == NULL)
				goto done;
		}
		
#ifdef MPLS_DEBUG
	shim = mtod(m, struct shim_hdr *);
	(void)printf("%s: on %s label %d ttl %d bos %d\n", 
		__func__, ifp->if_xname, 
		MPLS_LABEL_GET(shim->shim_label), 
		MPLS_TTL_GET(shim->shim_label), 
		MPLS_BOS(shim->shim_label));
#endif /* MPLS_DEBUG */	

		m->m_flags &= ~(M_BCAST|M_MCAST);
	}
	error = (*mii->mii_output)(ifp, m, gw, ro);
done:	
	if (mro != NULL)
		mpls_rtfree(mro);
out:	
	return (error);
}

