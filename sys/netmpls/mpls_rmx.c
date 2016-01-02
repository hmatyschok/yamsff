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
#include <sys/sockio.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llc.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_llatbl.h>
#include <net/route.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netmpls/mpls.h>

extern int	mpls_control(struct socket *, u_long, caddr_t, struct ifnet *,
    struct thread *);

/*
 * Radix-trie containing (free) generated ilm.
 */

SYSCTL_DECL(_net_mpls);

static int mpls_rtq_max_routes = 2048;

SYSCTL_INT(_net_mpls, OID_AUTO, rtmaxcache, CTLFLAG_RW,
	&mpls_rtq_max_routes, 0,
	"Upper limit on dynamically learned routes");
/*
 * Debugging hooks.
 */

static struct radix_node *
mpls_rn_delroute(void *v_arg, void *netmask_arg, struct radix_node_head *head)
{	

	return (rn_delete(v_arg, netmask_arg, head));
}

static struct radix_node *
mpls_rn_addroute(void *v_arg, void *n_arg, struct radix_node_head *head,
	    struct radix_node *treenodes)
{
	
	return (rn_addroute(v_arg, n_arg, head, treenodes));
}

static struct radix_node *
mpls_rn_lookup(void *v_arg, void *m_arg, struct radix_node_head *head)
{
	
	return (rn_lookup(v_arg, m_arg, head));
}

static struct radix_node *
mpls_rn_match(void *v_arg, struct radix_node_head *rnh)
{

	return (rn_match(v_arg, rnh));
}

/*
 * Remove incoming-label map (ilm).
 */
static void	
mpls_rn_clsroute(struct radix_node *rn, struct radix_node_head *rnh)
{
	struct rtentry *rt = (struct rtentry *)rn;
	
	KASSERT((rnh != NULL), ("radix_node_head{} not defined"));
	KASSERT((rt != NULL), ("ilm not defined"));
	
	RT_LOCK_ASSERT(rt);

	if ((rt->rt_flags & RTF_UP) 
		&& (rt->rt_refcnt < 1)) 
			rtexpunge(rt);
}
int	mpls_rn_inithead(void **, int);

/*
 * Initialize tree.
 */
int
mpls_rn_inithead(void **rnh0, int off)
{
	int error;
	struct radix_node_head *rnh;
	
	if ((error = rn_inithead(rnh0, off)) != 0) {
		rnh = *rnh0;
		
		rnh->rnh_close = mpls_rn_clsroute;
		rnh->rnh_deladdr = mpls_rn_delroute;
		rnh->rnh_matchaddr = mpls_rn_match;

		rnh->rnh_addaddr = mpls_rn_addroute;
		rnh->rnh_lookup = mpls_rn_lookup;	
	}
	return (error);
}

/*
 * Accessor macros for rtinfo{} Service Primitive (spi).
 */
#define	rti_dst(_rti) 	((_rti)->rti_info[RTAX_DST])
#define	rti_gateway(_rti) 	((_rti)->rti_info[RTAX_GATEWAY])
#define	rti_netmask(_rti) 	((_rti)->rti_info[RTAX_NETMASK])
#define	rti_ifaaddr(_rti) 	((_rti)->rti_info[RTAX_IFA])
#define	rti_ifpaddr(_rti) 	((_rti)->rti_info[RTAX_IFP])
#define	rti_brd(_rti) 	((_rti)->rti_info[RTAX_BRD])
#define	rti_flags(_rti) 	((_rti)->rti_flags)
#define rti_ifa(_rti) 	((_rti)->rti_ifa)
#define rti_ifp(_rti) 	((_rti)->rti_ifp)
 
/*
 * X-connect.
 */

int 	mpls_rt_output_fib(struct rt_msghdr *, struct rt_addrinfo *, 
	struct rtentry **, u_int);

/*
 * Accept by socket(4) in AF_ROUTE received service requests.
 *
 *  o RTAX_DST holds key x for fec = < x, nh > where nh -> ifp
 *
 *  o RTAX_GATEWAY holds by sockaddr_ftn{} for MPLS label
 *    binding necessary 
 *
 *     < seg_i , seg_j > 
 *
 *    tuple where seg_i denotes key for by nhlfe generated ilm, 
 *    Furthermore, seg_j denotes typically upstream label for 
 *    transmission downstream by interface ifp in link-layer.
 *  
 *  o In rt_addrinfo{} Service Primitive (spi) contained flags 
 *    encodes with MPLS label binding linked operation.
 *   
 *     RTF_{POP|PUSH|SWAP} - self expanatory.
 *
 *     RTF_MPE, denotes initial label of Label Switch Path.
 *
 *     RTF_STK, denotes label stacking, but not yet fully
 *     implemented.
 */
int
mpls_rt_output_fib(struct rt_msghdr *rtm, struct rt_addrinfo *rti, 
		struct rtentry **rt, u_int fibnum)
{ 		
	struct rtentry *fec = NULL;
	struct ifnet *ifp = NULL;
	struct mpls_aliasreq ifra;
	int error = 0, cmd = 0;
	
#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */

	if (rti_dst(rti)->sa_len > sizeof(ifra.ifra_x)) {
		log(LOG_INFO, "%s: destination x in fec invalid\n", __func__);
		error = EMSGSIZE;
		goto out;
	}
	
	if (rti_gateway(rti)->sa_family != AF_MPLS) {
		log(LOG_INFO, "%s: segment invalid\n", __func__);
		error = EINVAL;
		goto out;
	}
		
	if (rti_gateway(rti)->sa_len > sizeof(ifra.ifra_seg)) {
		log(LOG_INFO, "%s: segment invalid\n", __func__);
		error = EMSGSIZE;
		goto out;
	}
/*
 * Fetch interface by Forward Equivalence Class (fec).
 */	
 	fec = rtalloc1_fib(rti_dst(rti), 0, 0UL, fibnum);
	if ((fec == NULL) 
		|| (fec->rt_gateway == NULL) 
		|| ((ifp = fec->rt_ifp) == NULL)
		|| (fec->rt_ifa == NULL) 
		|| ((fec->rt_flags & RTF_UP) == 0)) {
		error = ESRCH;
		goto out;
	}
	bzero(&ifra, sizeof(ifra));
	bcopy(rti_dst(rti), &ifra.ifra_x, rti_dst(rti)->sa_len);
	
 	switch ((int)rtm->rtm_type) {
	case RTM_ADD:	
/*
 * Apply MPLS label binding on Forward Equivalence Class (fec).
 */	
		cmd = SIOCAIFADDR;
			
				/* FALLTHROUGH */

	case RTM_DELETE:
/*
 * Delete MPLS label binding on fec.
 */	
		cmd = (cmd == 0) ? SIOCDIFADDR : cmd;
/*
 * Perform MPLS control operations on interface-layer.
 */		
 		bcopy(rti_gateway(rti), &ifra.ifra_seg, rti_gateway(rti)->sa_len);
		ifra.ifra_flags = rti_flags(rti);
 		
 		RT_UNLOCK(fec);
 		error = mpls_control(NULL, cmd, (caddr_t)&ifra, ifp, NULL);
		RT_LOCK(fec); 
		break;
	case RTM_GET: 
/*
 * XXX: looks ugly... I'll delegate this operation 
 * XXX: back to rt_output, but I'm not yet sure, if 
 * XXX: I'll should do that...
 */
		ifra.ifra_seg.sftn_len = SMPLS_LEN;
		ifra.ifra_seg.sftn_family = AF_MPLS;
		
		((struct sockaddr_mpls *)&ifra.ifra_seg)->smpls_label = 
			satosmpls_label(rti_gateway(rti));
/*
 * Fetch Incoming Label Map (ilm) by MPLS label binding on fec.
 */		
		*rt = ((ifra.ifra_flags & RTF_MPE) == 0) 
			? rtalloc1_fib((struct sockaddr *)&ifra.ifra_seg, 
				0, 0UL, ifp->if_fib) : NULL;	
		
		if (*rt != NULL) {
/*
 * Update by socket(2) on route(4) used Service Data Unit (sdu).
 */			
			bcopy(rt_key(*rt), rti_dst(rti), 
				rt_key(*rt)->sa_len); 
			bcopy((*rt)->rt_gateway, rti_gateway(rti), 
				(*rt)->rt_gateway->sa_len);
		} else
		 	error = EADDRNOTAVAIL;
					
		break;
	default:
		log(LOG_INFO, "%s: command invalid\n", __func__);		
		error = EOPNOTSUPP;
		break;
	}	
out:	
	if (fec != NULL) 
		RTFREE_LOCKED(fec);
	
	return (error);
}
#undef rti_dst
#undef rti_gateway
#undef rti_netmask
#undef rti_ifaaddr
#undef rti_ifpaddr
#undef rti_brd
#undef rti_flags
#undef rti_ifa
