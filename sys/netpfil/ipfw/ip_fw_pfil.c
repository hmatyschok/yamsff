/*
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

/*-
 * Copyright (c) 2004 Andre Oppermann, Internet Business Solutions AG
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/10.1/sys/netpfil/ipfw/ip_fw_pfil.c 264813 2014-04-23 09:56:17Z ae $");

#include "opt_ipfw.h"
#include "opt_inet.h"
#include "opt_inet6.h"
#ifndef INET
#error IPFIREWALL requires INET.
#endif /* INET */

#include "opt_mpls.h"
#include "opt_mpls_debug.h"

#include "opt_pppoe_pfil.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>
#include <net/ethernet.h>
#include <net/pfil.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_fw.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif

#ifdef MPLS
#include <netmpls/mpls.h>
#endif /* MPLS */	
#ifdef PPPOE_PFIL
#include <net/if_bridgevar.h>
#endif /* PPPOE_PFIL */

#include <netgraph/ng_ipfw.h>

#include <netpfil/ipfw/ip_fw_private.h>

#include <machine/in_cksum.h>

static VNET_DEFINE(int, fw_enable) = 1;
#define V_fw_enable	VNET(fw_enable)

#ifdef INET6
static VNET_DEFINE(int, fw6_enable) = 1;
#define V_fw6_enable	VNET(fw6_enable)
#endif

static VNET_DEFINE(int, fwlink_enable) = 0;
#define V_fwlink_enable	VNET(fwlink_enable)

int ipfw_chg_hook(SYSCTL_HANDLER_ARGS);

/* Forward declarations. */
static int ipfw_divert(struct mbuf **, int, struct ipfw_rule_ref *, int);
static int ipfw_check_packet(void *, struct mbuf **, struct ifnet *, int,
	struct inpcb *);
static int ipfw_check_frame(void *, struct mbuf **, struct ifnet *, int,
	struct inpcb *);

#ifdef SYSCTL_NODE

SYSBEGIN(f1)

SYSCTL_DECL(_net_inet_ip_fw);
SYSCTL_VNET_PROC(_net_inet_ip_fw, OID_AUTO, enable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE3, &VNET_NAME(fw_enable), 0,
    ipfw_chg_hook, "I", "Enable ipfw");
#ifdef INET6
SYSCTL_DECL(_net_inet6_ip6_fw);
SYSCTL_VNET_PROC(_net_inet6_ip6_fw, OID_AUTO, enable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE3, &VNET_NAME(fw6_enable), 0,
    ipfw_chg_hook, "I", "Enable ipfw+6");
#endif /* INET6 */

SYSCTL_DECL(_net_link_ether);
SYSCTL_VNET_PROC(_net_link_ether, OID_AUTO, ipfw,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE3, &VNET_NAME(fwlink_enable), 0,
    ipfw_chg_hook, "I", "Pass ether pkts through firewall");

SYSEND

#endif /* SYSCTL_NODE */

/*
 * The pfilter hook to pass packets to ipfw_chk and then to
 * dummynet, divert, netgraph or other modules.
 * The packet may be consumed.
 */
static int
ipfw_check_packet(void *arg, struct mbuf **m0, struct ifnet *ifp, int dir,
    struct inpcb *inp)
{
	struct ip_fw_args args;
	struct m_tag *tag;
	int ipfw;
	int ret;

	/* convert dir to IPFW values */
	dir = (dir == PFIL_IN) ? DIR_IN : DIR_OUT;
	bzero(&args, sizeof(args));

again:
	/*
	 * extract and remove the tag if present. If we are left
	 * with onepass, optimize the outgoing path.
	 */
	tag = m_tag_locate(*m0, MTAG_IPFW_RULE, 0, NULL);
	if (tag != NULL) {
		args.rule = *((struct ipfw_rule_ref *)(tag+1));
		m_tag_delete(*m0, tag);
		if (args.rule.info & IPFW_ONEPASS)
			return (0);
	}

	args.m = *m0;
	args.oif = dir == DIR_OUT ? ifp : NULL;
	args.inp = inp;

	ipfw = ipfw_chk(&args);
	*m0 = args.m;

	KASSERT(*m0 != NULL || ipfw == IP_FW_DENY, ("%s: m0 is NULL",
	    __func__));

	/* breaking out of the switch means drop */
	ret = 0;	/* default return value for pass */
	switch (ipfw) {
	case IP_FW_PASS:
		/* next_hop may be set by ipfw_chk */
		if (args.next_hop == NULL && args.next_hop6 == NULL)
			break; /* pass */
#if (!defined(INET6) && !defined(INET))
		ret = EACCES;
#else
	    {
		struct m_tag *fwd_tag;
		size_t len;

		KASSERT(args.next_hop == NULL || args.next_hop6 == NULL,
		    ("%s: both next_hop=%p and next_hop6=%p not NULL", __func__,
		     args.next_hop, args.next_hop6));
#ifdef INET6
		if (args.next_hop6 != NULL)
			len = sizeof(struct sockaddr_in6);
#endif
#ifdef INET
		if (args.next_hop != NULL)
			len = sizeof(struct sockaddr_in);
#endif

		/* Incoming packets should not be tagged so we do not
		 * m_tag_find. Outgoing packets may be tagged, so we
		 * reuse the tag if present.
		 */
		fwd_tag = (dir == DIR_IN) ? NULL :
			m_tag_find(*m0, PACKET_TAG_IPFORWARD, NULL);
		if (fwd_tag != NULL) {
			m_tag_unlink(*m0, fwd_tag);
		} else {
			fwd_tag = m_tag_get(PACKET_TAG_IPFORWARD, len,
			    M_NOWAIT);
			if (fwd_tag == NULL) {
				ret = EACCES;
				break; /* i.e. drop */
			}
		}
#ifdef INET6
		if (args.next_hop6 != NULL) {
			bcopy(args.next_hop6, (fwd_tag+1), len);
			if (in6_localip(&args.next_hop6->sin6_addr))
				(*m0)->m_flags |= M_FASTFWD_OURS;
			(*m0)->m_flags |= M_IP6_NEXTHOP;
		}
#endif
#ifdef INET
		if (args.next_hop != NULL) {
			bcopy(args.next_hop, (fwd_tag+1), len);
			if (in_localip(args.next_hop->sin_addr))
				(*m0)->m_flags |= M_FASTFWD_OURS;
			(*m0)->m_flags |= M_IP_NEXTHOP;
		}
#endif
		m_tag_prepend(*m0, fwd_tag);
	    }
#endif /* INET || INET6 */
		break;

	case IP_FW_DENY:
		ret = EACCES;
		break; /* i.e. drop */

	case IP_FW_DUMMYNET:
		ret = EACCES;
		if (ip_dn_io_ptr == NULL)
			break; /* i.e. drop */
		if (mtod(*m0, struct ip *)->ip_v == 4)
			ret = ip_dn_io_ptr(m0, dir, &args);
		else if (mtod(*m0, struct ip *)->ip_v == 6)
			ret = ip_dn_io_ptr(m0, dir | PROTO_IPV6, &args);
		else
			break; /* drop it */
		/*
		 * XXX should read the return value.
		 * dummynet normally eats the packet and sets *m0=NULL
		 * unless the packet can be sent immediately. In this
		 * case args is updated and we should re-run the
		 * check without clearing args.
		 */
		if (*m0 != NULL)
			goto again;
		break;

	case IP_FW_TEE:
	case IP_FW_DIVERT:
		if (ip_divert_ptr == NULL) {
			ret = EACCES;
			break; /* i.e. drop */
		}
		ret = ipfw_divert(m0, dir, &args.rule,
			(ipfw == IP_FW_TEE) ? 1 : 0);
		/* continue processing for the original packet (tee). */
		if (*m0)
			goto again;
		break;

	case IP_FW_NGTEE:
	case IP_FW_NETGRAPH:
		if (ng_ipfw_input_p == NULL) {
			ret = EACCES;
			break; /* i.e. drop */
		}
		ret = ng_ipfw_input_p(m0, dir, &args,
			(ipfw == IP_FW_NGTEE) ? 1 : 0);
		if (ipfw == IP_FW_NGTEE) /* ignore errors for NGTEE */
			goto again;	/* continue with packet */
		break;

	case IP_FW_NAT:
		/* honor one-pass in case of successful nat */
		if (V_fw_one_pass)
			break; /* ret is already 0 */
		goto again;

	case IP_FW_REASS:
		goto again;		/* continue with packet */
	
	default:
		KASSERT(0, ("%s: unknown retval", __func__));
	}

	if (ret != 0) {
		if (*m0)
			FREE_PKT(*m0);
		*m0 = NULL;
	}

	return ret;
}

/*
 * ipfw processing for ethernet packets (in and out).
 * Inteface is NULL from ether_demux, and ifp from
 * ether_output_frame.
 */
static int
ipfw_check_frame(void *arg, struct mbuf **m0, struct ifnet *dst, int dir0,
    struct inpcb *inp)
{
#if defined(MPLS) || defined(PPPOE_PFIL)
#ifdef MPLS
	struct m_tag_mpls *mtm;
	size_t nstk;
#endif /* MPLS */	
#ifdef PPPOE_PFIL
 	struct m_tag_pppoe *mtp;
#endif /* PPPOE_PFIL */	
	u_int16_t ether_type;
#endif
	struct ether_header *eh;
	struct ether_header save_eh;
	struct mbuf *m;
	
	struct ip_fw_args args;
	struct m_tag *mtag;
	
	int i, error, dir;

    dir = dir0;
    error = 0;

	/* fetch start point from rule, if any */
	mtag = m_tag_locate(*m0, MTAG_IPFW_RULE, 0, NULL);
	if (mtag == NULL) {
		args.rule.slot = 0;
	} else {
		/* dummynet packet, already partially processed */
		struct ipfw_rule_ref *r;

		/* XXX can we free it after use ? */
		mtag->m_tag_id = PACKET_TAG_NONE;
		r = (struct ipfw_rule_ref *)(mtag + 1);
		if (r->info & IPFW_ONEPASS)
			return (error);
		args.rule = *r;
	}

	/* I need some amt of data to be contiguous */
	m = *m0;
	i = min(m->m_pkthdr.len, max_protohdr);
	if (m->m_len < i) {
		m = m_pullup(m, i);
		if (m == NULL) {
			error = ENOBUFS;
			goto bad;
		}
	}
	eh = mtod(m, struct ether_header *);
	save_eh = *eh;			/* save copy for restore below */
	m_adj(m, ETHER_HDR_LEN);	/* strip ethernet header */

#if defined(MPLS) || defined(PPPOE_PFIL)
	ether_type = ntohs(save_eh.ether_type);
	i = IP_FW_PASS;
/*
 * Cache pci of sdu.
 */
	switch (ether_type) {
#ifdef MPLS
	case ETHERTYPE_MPLS:
/*
 * Strip off MPLS label stack and keep a copy.
 */
		mtm = (struct m_tag_mpls *)
			m_tag_alloc(MTAG_MPLS, MTAG_MPLS_STACK, 
				sizeof(struct m_tag_mpls), M_NOWAIT);
 		if (mtm == NULL) {
 			error = ENOBUFS;
 			goto bad;
 		}
 		
		for (nstk = 0; nstk < MPLS_INKERNEL_LOOP_MAX; nstk++) {
			if (m->m_len < MPLS_HDRLEN) {
				m = m_pullup(m, MPLS_HDRLEN);
				if (m == NULL) {
 					error = ENOBUFS;
 					goto bad;
 				}
			}
			mtm->mtm_stk[nstk] = *mtod(m, struct shim_hdr *);
			m_adj(m, MPLS_HDRLEN);
			if (MPLS_BOS(mtm->mtm_stk[nstk].shim_label))
				break;
		}
		mtm->mtm_size = (nstk + 1) * MPLS_HDRLEN;
/*
 * Annotate mbuf(9).
 */
	 	m_tag_prepend(m, &mtm->mtm_tag);		
/*
 * Relabel protocol id, as precondition for parsing by ipfw_chk.
 */	
		switch (*mtod(m, u_char *) >> 4) {
		case IPVERSION:
			save_eh.ether_type = htons(ETHERTYPE_IP);
			break;				
#ifdef INET6
		case IPV6_VERSION >> 4:
			save_eh.ether_type = htons(ETHERTYPE_IPV6);
			break;
#endif /* INET6 */
		default:
/*
 * Bypass filtering, if sdu is not in AF_INET[6].
 */			
			goto done;
		}			
		break;	
#endif /* MPLS */
#ifdef PPPOE_PFIL
	case ETHERTYPE_PPPOE:
/*
 * Backup and strip off rfc-2516 and rfc-1661 pci.
 */	
		mtp = (struct m_tag_pppoe *)
			m_tag_alloc(MTAG_PPPOE, MTAG_PPPOE_PCI, 
						sizeof(struct m_tag_pppoe), M_NOWAIT);
 		if (mtp == NULL) {
 			error = ENOBUFS;
 			goto bad;
 		}
		m_copydata(m, 0, sizeof(struct pppoe_hdr), (caddr_t) &mtp->mtp_ph);
		m_adj(m, sizeof(struct pppoe_hdr));
		
		m_copydata(m, 0, sizeof(uint16_t), (caddr_t) &mtp->mtp_pr);
		m_adj(m, sizeof(uint16_t));
/*
 * Annotate mbuf(9).
 */			
 		m_tag_prepend(m, &mtp->mtp_tag);		
/*
 * Relabel protocol id, as precondition for parsing by ipfw_chk.
 */	
		switch (ntohs(mtp->mtp_pr)) {
		case PPP_IP:
			save_eh.ether_type = htons(ETHERTYPE_IP);
			break;
#ifdef INET6
		case PPP_IPV6:
			save_eh.ether_type = htons(ETHERTYPE_IPV6);
#endif /* INET6 */
			break;		
		default:
/*
 * Bypass filtering, if sdu is not in AF_INET[6].
 */		
			goto done;
		}	
		break;	
#endif /* PPPOE_PFIL */	
	default:
		break;		
	}					
#endif

	args.m = m;		/* the packet we are looking at		*/
	args.oif = dir == PFIL_OUT ? dst: NULL;	/* destination, if any	*/
	args.next_hop = NULL;	/* we do not support forward yet	*/
	args.next_hop6 = NULL;	/* we do not support forward yet	*/
	args.eh = &save_eh;	/* MAC header for bridged/MAC packets	*/
	args.inp = NULL;	/* used by ipfw uid/gid/jail rules	*/
/*
 * Parse frame by ipfw(4).
 */	
	i = ipfw_chk(&args);
	m = args.m;
	
	if (m == NULL) 
		goto out;

#if defined(MPLS) || defined(PPPOE_PFIL)
done:
/*
 * Restore frame.
 */	
	switch (ether_type) {
#ifdef MPLS
	case ETHERTYPE_MPLS:
/*
 * Prepend MPLS label stack.
 */	
	 	M_PREPEND(m, mtm->mtm_size, M_NOWAIT);
		if (m == NULL) {
 			error = ENOBUFS;
 			goto bad;
 		}
		bcopy(mtm->mtm_stk, mtod(m, caddr_t), mtm->mtm_size);
		m_tag_delete(m, &mtm->mtm_tag);
		break;
#endif /* MPLS */
#ifdef PPPOE_PFIL
	case ETHERTYPE_PPPOE:
/*
 * Prepend rfc-1661 protocol id. 
 */	
		M_PREPEND(m, sizeof(uint16_t), M_NOWAIT);
		if (m == NULL) {
 			error = ENOBUFS;
 			goto bad;
 		}
		bcopy(&mtp->mtp_pr, mtod(m, caddr_t), sizeof(uint16_t));
/*
 * Prepend rfc-2516 pci. 
 */			
		M_PREPEND(m, sizeof(struct pppoe_hdr), M_NOWAIT);
		if (m == NULL) {
 			error = ENOBUFS;
 			goto bad;
 		}
		bcopy(&mtp->mtp_ph, mtod(m, caddr_t), 
				sizeof(struct pppoe_hdr));
		m_tag_delete(m, &mtp->mtp_tag);
		break;
#endif /* PPPOE_PFIL */	
	default:
		break;
	}
#endif	

/*
 * Restore Ethernet pci.
 */
	M_PREPEND(m, ETHER_HDR_LEN, M_NOWAIT);
	if (m == NULL) {
 		error = ENOBUFS;
 		goto bad;
 	}
 	eh = mtod(m, struct ether_header *);
 	
#if defined(MPLS) || defined(PPPOE_PFIL)	
	save_eh.ether_type = htons(ether_type);
#endif
	
	bcopy(&save_eh, mtod(m, struct ether_header *), ETHER_HDR_LEN);
out:	
	*m0 = m;
	
	/* Check result of ipfw_chk() */
	switch (i) {
	case IP_FW_PASS:
		break;

	case IP_FW_DENY:
		error = EACCES;
		break; /* i.e. drop */

	case IP_FW_DUMMYNET:
		error = EACCES;

		if (ip_dn_io_ptr == NULL)
			break; /* i.e. drop */

		*m0 = NULL;
		dir = PROTO_LAYER2 | (dst ? DIR_OUT : DIR_IN);
		ip_dn_io_ptr(&m, dir, &args);
		return (error);

	default:
		KASSERT(0, ("%s: unknown retval", __func__));
	}

bad:
	if (error != 0) {
		if (*m0 != NULL)
			FREE_PKT(*m0);
		*m0 = NULL;
	}

	return (error);
}

/* do the divert, return 1 on error 0 on success */
static int
ipfw_divert(struct mbuf **m0, int incoming, struct ipfw_rule_ref *rule,
	int tee)
{
	/*
	 * ipfw_chk() has already tagged the packet with the divert tag.
	 * If tee is set, copy packet and return original.
	 * If not tee, consume packet and send it to divert socket.
	 */
	struct mbuf *clone;
	struct ip *ip = mtod(*m0, struct ip *);
	struct m_tag *tag;

	/* Cloning needed for tee? */
	if (tee == 0) {
		clone = *m0;	/* use the original mbuf */
		*m0 = NULL;
	} else {
		clone = m_dup(*m0, M_NOWAIT);
		/* If we cannot duplicate the mbuf, we sacrifice the divert
		 * chain and continue with the tee-ed packet.
		 */
		if (clone == NULL)
			return 1;
	}

	/*
	 * Divert listeners can normally handle non-fragmented packets,
	 * but we can only reass in the non-tee case.
	 * This means that listeners on a tee rule may get fragments,
	 * and have to live with that.
	 * Note that we now have the 'reass' ipfw option so if we care
	 * we can do it before a 'tee'.
	 */
	if (!tee) switch (ip->ip_v) {
	case IPVERSION:
	    if (ntohs(ip->ip_off) & (IP_MF | IP_OFFMASK)) {
		int hlen;
		struct mbuf *reass;

		reass = ip_reass(clone); /* Reassemble packet. */
		if (reass == NULL)
			return 0; /* not an error */
		/* if reass = NULL then it was consumed by ip_reass */
		/*
		 * IP header checksum fixup after reassembly and leave header
		 * in network byte order.
		 */
		ip = mtod(reass, struct ip *);
		hlen = ip->ip_hl << 2;
		ip->ip_sum = 0;
		if (hlen == sizeof(struct ip))
			ip->ip_sum = in_cksum_hdr(ip);
		else
			ip->ip_sum = in_cksum(reass, hlen);
		clone = reass;
	    }
	    break;
#ifdef INET6
	case IPV6_VERSION >> 4:
	    {
	    struct ip6_hdr *const ip6 = mtod(clone, struct ip6_hdr *);

		if (ip6->ip6_nxt == IPPROTO_FRAGMENT) {
			int nxt, off;

			off = sizeof(struct ip6_hdr);
			nxt = frag6_input(&clone, &off, 0);
			if (nxt == IPPROTO_DONE)
				return (0);
		}
		break;
	    }
#endif
	}

	/* attach a tag to the packet with the reinject info */
	tag = m_tag_alloc(MTAG_IPFW_RULE, 0,
		    sizeof(struct ipfw_rule_ref), M_NOWAIT);
	if (tag == NULL) {
		FREE_PKT(clone);
		return 1;
	}
	*((struct ipfw_rule_ref *)(tag+1)) = *rule;
	m_tag_prepend(clone, tag);

	/* Do the dirty job... */
	ip_divert_ptr(clone, incoming);
	return 0;
}

/*
 * attach or detach hooks for a given protocol family
 */
static int
ipfw_hook(int onoff, int pf)
{
	struct pfil_head *pfh;
	void *hook_func;

	pfh = pfil_head_get(PFIL_TYPE_AF, pf);
	if (pfh == NULL)
		return ENOENT;

	hook_func = (pf == AF_LINK) ? ipfw_check_frame : ipfw_check_packet;

	(void) (onoff ? pfil_add_hook : pfil_remove_hook)
	    (hook_func, NULL, PFIL_IN | PFIL_OUT | PFIL_WAITOK, pfh);

	return 0;
}

int
ipfw_attach_hooks(int arg)
{
	int error = 0;

	if (arg == 0) /* detach */
		ipfw_hook(0, AF_INET);
	else if (V_fw_enable && ipfw_hook(1, AF_INET) != 0) {
                error = ENOENT; /* see ip_fw_pfil.c::ipfw_hook() */
                printf("ipfw_hook() error\n");
        }
#ifdef INET6
	if (arg == 0) /* detach */
		ipfw_hook(0, AF_INET6);
	else if (V_fw6_enable && ipfw_hook(1, AF_INET6) != 0) {
                error = ENOENT;
                printf("ipfw6_hook() error\n");
        }
#endif
	if (arg == 0) /* detach */
		ipfw_hook(0, AF_LINK);
	else if (V_fwlink_enable && ipfw_hook(1, AF_LINK) != 0) {
                error = ENOENT;
                printf("ipfw_link_hook() error\n");
        }
	return error;
}

int
ipfw_chg_hook(SYSCTL_HANDLER_ARGS)
{
	int newval;
	int error;
	int af;

	if (arg1 == &V_fw_enable)
		af = AF_INET;
#ifdef INET6
	else if (arg1 == &V_fw6_enable)
		af = AF_INET6;
#endif
	else if (arg1 == &V_fwlink_enable)
		af = AF_LINK;
	else 
		return (EINVAL);

	newval = *(int *)arg1;
	/* Handle sysctl change */
	error = sysctl_handle_int(oidp, &newval, 0, req);

	if (error)
		return (error);

	/* Formalize new value */
	newval = (newval) ? 1 : 0;

	if (*(int *)arg1 == newval)
		return (0);

	error = ipfw_hook(newval, af);
	if (error)
		return (error);
	*(int *)arg1 = newval;

	return (0);
}
/* end of file */
