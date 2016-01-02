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
/*
 * Copyright (C) 1999, 2000 and 2001 AYAME Project, WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE 
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
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/systm.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <machine/in_cksum.h>

#ifdef INET6
#include <netinet/ip6.h>
#endif /* INET6 */

#include <netmpls/mpls.h>

struct mbuf *	mpls_shim_pop(struct mbuf *);
struct mbuf *	mpls_shim_swap(struct mbuf *, struct mpls_ro *);
struct mbuf *	mpls_shim_push(struct mbuf *, struct mpls_ro *);
struct mbuf *	mpls_encap(struct mbuf *, const struct sockaddr *, 
	struct mpls_ro *);

/*
 * Strip off label or decapsulate, if BoS.
 */
struct mbuf *
mpls_shim_pop(struct mbuf *m)
{
	m_adj(m, MPLS_HDRLEN);
	if (m->m_len < MPLS_HDRLEN)
		m = m_pullup(m, MPLS_HDRLEN);
		
	return (m);
}

/*
 * Allocates space for PCI and prepends it
 * by mpls_shim_swap.
 */
struct mbuf *
mpls_shim_push(struct mbuf *m, struct mpls_ro *mro)
{	
	M_PREPEND(m, MPLS_HDRLEN, (M_ZERO|M_NOWAIT));
	if (m == NULL)
		return (NULL);
	
	return (mpls_shim_swap(m, mro));
}

/*
 * Switches incoming with outgoing label on top of stack.
 */
struct mbuf *
mpls_shim_swap(struct mbuf *m, struct mpls_ro *mro)
{
	struct sockaddr_ftn *nh;
	struct shim_hdr *shim;
	
	nh = (struct sockaddr_ftn *)mro->mro_ilm->rt_gateway;

	if (m->m_len < MPLS_HDRLEN) {
		if ((m = m_pullup(m, MPLS_HDRLEN)) == NULL)
			return (NULL);
	}
	shim = mtod(m, struct shim_hdr *);	
/* 
 * Swap label 
 */	
	shim->shim_label &= ~MPLS_LABEL_MASK;
	shim->shim_label |= nh->sftn_label & MPLS_LABEL_MASK;

	if (mpls_exp_override != 0) {
		u_int32_t t = shim->shim_label & MPLS_EXP_MASK;
/* 
 * QoS bits.
 */			
		shim->shim_label &= ~MPLS_EXP_MASK;
		shim->shim_label |= t & MPLS_EXP_MASK;
	}	
	return (m);
}

/*
 * Encapsulate SDU, PE, upstream.
 * 
 * Two cases are considered here:
 * 
 *  (a) ingress route denotes fastpath (lsp_in).
 * 
 * or
 * 
 *  (b) Per-interface MPLS label binding.
 * 
 */
struct mbuf *	
mpls_encap(struct mbuf *m, const struct sockaddr *dst, struct mpls_ro *mro)
{
	uint32_t hasbos = MPLS_BOS_MASK;
	uint32_t hasvprd = 0;
	uint32_t ttl = mpls_defttl;
	struct sockaddr_mpls *smpls;
	struct shim_hdr *shim;
	struct ip *ip;
#ifdef INET6
	struct ip6_hdr *ip6hdr;
#endif /* INET6 */
	uint32_t label, vprd;	
	
	smpls = (struct sockaddr_mpls *)&mro->mro_gw;
	smpls->smpls_len = sizeof(*smpls);
	smpls->smpls_family = AF_MPLS;
/*
 * Abort tagging, if socket address cannot hold MPLS label binding. 
 */
	if (dst->sa_len != SFTN_LEN)
		goto bad;
/* 
 * Use default ttl value or extract.
 */
	switch (dst->sa_family) {
	case AF_INET:

		if (mpls_mapttl_ip != 0) {
			if (m->m_len < sizeof(*ip))
				goto bad;			
			ip = mtod(m, struct ip *);
			ttl = ip->ip_ttl;				
		}
		break;
#ifdef INET6
	case AF_INET6:
		
		if (mpls_mapttl_ip6 != 0) {
			if (m->m_len < sizeof(struct ip6_hdr))
				goto bad;			
			ip6hdr = mtod(m, struct ip6_hdr *);
			ttl = ip6hdr->ip6_hlim;
		}
		break;
#endif /* INET6 */	
	case AF_LINK: 
/*
 * See net/if_ethersubr.c for further details.
 */		
		mro->mro_lle = (mro->mro_ifa) ? 
			mpls_lle(mro->mro_ifa) : NULL;		
		
		break;
	case AF_MPLS:	
		shim = mtod(m, struct shim_hdr *);
		ttl = MPLS_TTL_GET(shim->shim_label);
/*
 * Not BoS.
 */		
		mro->mro_flags |= RTF_STK;
		break;
	default: 	/* unsupported domain */		
		goto bad;
	}
/*
 * Determine if MPLS label is BoS.
 */		
	smpls->smpls_label = (mro->mro_flags & RTF_STK) ?
		hasvprd : hasbos;
	
	label = satosftn_label(dst);
	vprd = satosftn_vprd(dst);
		
	if (label == vprd) 
		smpls->smpls_label |= label;
	else {
		hasvprd = 1;
		smpls->smpls_label |= vprd;
	}
again:	

	switch (MPLS_LABEL_GET(smpls->smpls_label)) { 
	case MPLS_RD_ETHDEMUX:		
		
		if (hasvprd == 0) 
			goto bad;
		
		if (MPLS_BOS(smpls->smpls_label) == 0)
			goto bad;
			
		if (mpls_empty_cw != 0) {
			M_PREPEND(m, sizeof(*shim), (M_ZERO|M_NOWAIT));
			if (m == NULL)
				goto out;
			
			shim = mtod(m, struct shim_hdr *);
			shim->shim_label = 0;
		}
		break;	
	case MPLS_LABEL_RTALERT:	
		
		if (hasvprd == 0) 
			goto bad;				
		
		if (MPLS_BOS(smpls->smpls_label) != 0)
			goto bad; 
		
		break;
	default:
		break;
	}
	smpls->smpls_label |= ntohl(ttl);
/*
 * Push MPLS label.
 */		
	M_PREPEND(m, sizeof(*shim), (M_ZERO|M_NOWAIT));
	if (m == NULL)
		goto out;
							
	shim = mtod(m, struct shim_hdr *);
	shim->shim_label = smpls->smpls_label; 					

	if (hasvprd != 0) {
		smpls->smpls_label = label;	
		hasvprd = 0;
		goto again;
	}
	smpls->smpls_label &= MPLS_LABEL_MASK;
	
	mro->mro_flags |= RTF_STK;
out:	
	return (m);
bad:
	m_freem(m);
	m = NULL;
	goto out;
}


