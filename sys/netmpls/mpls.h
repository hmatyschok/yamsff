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
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULARPURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, ORCONSEQUENTIAL 
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
#ifndef _NETMPLS_MPLS_H_
#define	_NETMPLS_MPLS_H_
 
#include <sys/param.h>
#include <sys/queue.h>
#ifdef _KERNEL
#include <sys/protosw.h>
#include <sys/socket.h>
#endif /* _KERNEL */

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/route.h>
#ifdef _KERNEL
#include <net/if_arp.h>
#include <net/if_llatbl.h>
#include <net/raw_cb.h>
#endif /* _KERNEL */

#include <netinet/in.h>

#ifdef INET6
#include <netinet/ip6.h>
#endif /* INET6 */

#define MPLS_INKERNEL_LOOP_MAX 	16
#define NETISR_MPLS 			13	/* SWI for MPLS input */
#define NETISR_MPLS_FWD 		14	/* SWI for MPLS forwarding */

/* 
 * During adress resulotion cached MPI in AF_MPLS. 
 */
#define M_MPLS  	0x01000000  

/*
 * Flags representing internal state during 
 * assessment by route(8).
 */
#define F_MPLS 	0x20 
#define F_STK0 	0x40 
#define F_STK1 	0x80 

/* 
 * Unused flags are "recycled" here. 
 * See net/route.h for further details.
 */
#define RTF_MPLS 	0x80	/* denotes MPLS Route */	
#define RTF_POP 	0x100	/* pop label from stack */
#define	RTF_PUSH 	0x20000	/* push label on stack */	
#define RTF_SWAP 	0x80000 /* swap label on top of stack */
#define RTF_MPLS_OMASK	\
	(RTF_POP|RTF_PUSH|RTF_SWAP)

#define RTF_MPE 	0x20000000 /* indicates fast-path */
#define RTF_STK 	0x80000000 /* reenter loop  */
#define RTF_MPLS_FMASK	\
	(RTF_MPLS|RTF_MPE|RTF_STK|RTF_MPLS_OMASK)

/*
 * By byte-swapping the constants, we avoid ever having to byte-swap IP
 * addresses inside the kernel.  Unfortunately, user-level programs rely
 * on these macros not doing byte-swapping.
 */

#ifdef _KERNEL
#define __MADDR(_x) 	((uint32_t)htonl((uint32_t)(_x)))
#else
#define __MADDR(_x) 	((uint32_t)(_x))
#endif 

#define MPLS_LABEL_MASK 	__MADDR(0xfffff000U)
#define MPLS_LABEL_OFFSET 	12
#define MPLS_EXP_MASK 		__MADDR(0x00000e00U)
#define MPLS_EXP_OFFSET 	9
#define MPLS_BOS_MASK 		__MADDR(0x00000100U)
#define MPLS_BOS_OFFSET 	8
#define MPLS_TTL_MASK 		__MADDR(0x000000ffU)
#define MPLS_SHIM_MASK 		0xffffffffU
#define MPLS_VPRD_MASK 		__MADDR(0xfff00000U)

/* 
 * Reserved label values (rfc-3032) 
 */
#define MPLS_LABEL_IPV4NULL 		0 /* IPv4 Explicit NULL Label */
#define MPLS_LABEL_RTALERT 			1 /* Router Alert Label       */
#define MPLS_LABEL_IPV6NULL 		2 /* IPv6 Explicit NULL Label */
#define MPLS_LABEL_IMPLNULL 		3 /* Implicit NULL Label      */
/*      MPLS_LABEL_RESERVED	4-15 */		/* Values 4-15 are reserved */
#define MPLS_RD_ETHDEMUX 			5 /* PW demux type (rfc-4446) */
#define MPLS_LABEL_RESERVED_MAX 	15

#define MPLS_BOS(_l)	\
	(((_l) & MPLS_BOS_MASK) == MPLS_BOS_MASK)
#define MPLS_EXP_GET(_l)		\
	((ntohl((_l) & MPLS_EXP_MASK)) >> MPLS_EXP_OFFSET)	
#define MPLS_LABEL_GET(_l)	\
	((ntohl((_l) & MPLS_LABEL_MASK)) >> MPLS_LABEL_OFFSET)
#define MPLS_LABEL_SET(_l) 	\
	((ntohl((_l) << MPLS_LABEL_OFFSET)) & MPLS_LABEL_MASK)
#define MPLS_TTL_GET(_l)		(ntohl((_l) & MPLS_TTL_MASK))	

#define IS_NOT_MPLS_LABEL(_l)	\
	((MPLS_LABEL_GET(_l)) > MPLS_LABEL_MAX)
#define IS_RESERVED(_l)	\
	((MPLS_LABEL_GET(_l)) < MPLS_LABEL_RESERVED_MAX)
	
#define MPLS_OP(_flags) \
	((_flags) & RTF_MPLS_OMASK)

static __inline int	is_mpls_op(int, int);
static __inline int	
is_mpls_op(int fb_vec, int tb_vec)
{
	
	return (((fb_vec & RTF_MPLS_OMASK) == tb_vec));
}

static __inline int	is_not_mpls_op(int, int);
static __inline int	
is_not_mpls_op(int fb_vec, int tb_vec)
{
	
	return (((fb_vec & RTF_MPLS_OMASK) != tb_vec));
}	
	
/*
 * Structure of a SHIM header.
 */
struct shim_hdr {
	u_int32_t shim_label;	/* < 20 bit label, 4 bit exp & BoS, 8 bit TTL > */
};
#define MPLS_LABEL_MAX		((1 << 20) - 1)
#define MPLS_CWLEN			(sizeof(uint32_t))
#define MPLS_HDRLEN			(sizeof(struct shim_hdr))

/*
 * MPLS socket address
 */
struct sockaddr_mpls {
	uint8_t 	smpls_len; 	/* length */
	sa_family_t 	smpls_family; 	/* AF_MPLS */
	uint16_t 	smpls_pad0;	
	uint32_t 	smpls_label; 	/* MPLS label */
	uint32_t 	smpls_pad1[2];				
};
#define SMPLS_LEN 	(sizeof(struct sockaddr_mpls))

#define satosmpls(_sa) 	((struct sockaddr_mpls *)(_sa))
#define smplstosa(_smpls) 	((struct sockaddr *)(_smpls))
#define satosmpls_label(_sa) 	(satosmpls(_sa)->smpls_label)
#define satosmpls_label_get(_sa) (MPLS_LABEL_GET(satosmpls(_sa)->smpls_label))

#define AF_MPLS	33	/* XXX: collides with AF_SLOW, see sys/socket.h */
#define MPLSPROTO_RTALERT 	1

/*
 * Let us consider
 * 
 *   fec     : Forward Equivalence Class
 *   ftn     : FEC-to-NHLFE Map 
 *   ilm     : Incoming Label Map
 *   nh      : next-hop or gateway address
 *   nhlfe   : Next Hop Label Forwarding Entry
 *   op      : MPLS operation
 *   rd      : MPLS Route Distinguisher or reserved label value
 *   seg_i   : in-segment (seg_in, lsp_in)
 *   seg_j   : out-segment (seg_out, lsp_out)
 *   seg     : particular Label Switch Path (LSP) in < SEG, SEG >
 *   x       : destination, key in fec or link-level address on ifnet(9)
 * 
 * if 	
 *  
 *   fec = < x, nh > in rtentry(9)
 *   
 *     (a)  x = fec(rt_key)
 *     (b)  nh = fec(rt_gateway) 
 *  	
 * and 
 * 
 *   seg = < seg_i, seg_j >
 * 
 * further 
 * 
 *   seg = < seg_in, seg_out >
 * 	
 * where	
 * 
 *   < op, seg_out, rd >
 * 
 * such that
 * 
 *   ftn = < x, < op, seg_out, rd > >
 * 
 * implies 
 * 
 *   nhlfe = < seg_in, ftn > in ifaddr(9)
 * 
 * is free generated by fec where 
 *       
 *   ilm = < seg_in, ftn > in rtentry(9)
 *
 *   (a) seg_in = ilm(rt_key)
 *   (b) ftn = ilm(rt_gateway)
 *     
 * is free generated by fec enclosed nhlfe if op denotes 
 *
 *   RTF_{POP|SWAP} and ! RTF_PUSH 
 *
 * but if RTF_PUSH then
 *
 *  fastpath = < nh, < op, seg_out, rd > >
 *    
 * where   
 *   
 *  nhlfe = < seg_in, ftn > 
 *
 * is free generated by
 *
 *  fec' = < x, fastpath >    
 * 
 * By ilm and nhlfe stored sockaddr_ftn{} encodes:
 * 
 *  (a) gateway address used by rtsock
 *   
 *  (b) ifa_dst in ifaddr{} denotes nhlfe
 *   
 *  (c) rt_gateway in rtentry(9) denotes ilm
 *   
 *  (d) rt_gateway in rtentry(9) denotes fec, fastpath
 *
 */
#define SFTN_DATA_LEN 	52
struct sockaddr_ftn {
    uint8_t 	sftn_len;    
    sa_family_t 	sftn_family;    /* address family, gateway address (nh) */   
    char 	sftn_data[SFTN_DATA_LEN];    /* stores data */
    uint32_t 	sftn_op;    /* MPLS operation */
    uint32_t 	sftn_label;    /* stores seg_out */
    uint32_t 	sftn_vprd;    /* route distinguisher */
};
#define SFTN_LEN 	(sizeof(struct sockaddr_ftn))

#define satosftn(_sa) 	((struct sockaddr_ftn *)(_sa))
#define sftntosa(_sftn) 	((struct sockaddr *)(_sftn))
#define satosftn_label(_sa) 	(satosftn(_sa)->sftn_label)
#define satosftn_vprd(_sa) 	(satosftn(_sa)->sftn_vprd)
#define satosftn_op(_sa) 	(satosftn(_sa)->sftn_op)
#define satosftn_fib(_sa) 	(satosftn(_sa)->sftn_fib)

/*
 * SPI for by ioctl(2) provided interface.
 */
struct mpls_aliasreq {
	char 	ifra_name[IFNAMSIZ];
	struct sockaddr_ftn 	ifra_seg; 	/* requested segment */
	struct sockaddr_ftn 	ifra_x; 	/* destination x in fec */
	int 	ifra_flags;
	void 	*ifra_arg;
};

#ifdef _KERNEL

/*
 * Next Hop Label Forwarding Entry. 
 */
struct mpls_ifaddr {
	struct ifaddr 	mia_ifa;		/* protocol-independent info */
#define mia_addr 	mia_ifa.ifa_addr
#define mia_netmask 	mia_ifa.ifa_netmask
#define mia_dstaddr 	mia_ifa.ifa_dstaddr
#define mia_ifp 	mia_ifa.ifa_ifp	
#define mia_flags 	mia_ifa.ifa_flags
#define mia_metric 	mia_ifa.ifa_metric
	TAILQ_ENTRY(mpls_ifaddr)	mia_link;
	
	struct sockaddr_ftn 	mia_seg; /* seg_i */
	struct sockaddr_ftn 	mia_nh; 	/* < x, < op, seg_j, rd > > */
	
	int 	mia_rt_flags;
	
	struct ifaddr 	*mia_x; 	/* backpointer for ifaddr(9) on fec */
	struct llentry 	*mia_lle; 	/* shortcut */	
};
#define IFA_NHLFE	RTF_MPLS	/* indicates nhlfe */
#define NHLFE_PW2 	RTF_PROTO2	/* if_mpe(4) is bridge(4) member */
#define NHLFE_MPE 	RTF_MPE

#define ifatomia(_ifa)		((struct mpls_ifaddr *)(_ifa))
#define miatoifa(_mia)	((struct ifaddr *)(_mia))

#define mpls_lle(_ifa) \
	(ifatomia(_ifa)->mia_lle)
#define mpls_x(_ifa) \
	(ifatomia(_ifa)->mia_x)	
#define mpls_flags(_ifa) \
	(ifatomia(_ifa)->mia_rt_flags)	
#define mpls_seg(_ifa) \
	(ifatomia(_ifa)->mia_seg)
#define mpls_nh(_ifa) \
	(ifatomia(_ifa)->mia_nh)	

/*
 * From route{} derived Service Primitive (SPI).
 */
struct mpls_ro {   
	struct rtentry 	*mro_ilm;		/* rtentry(9) */
	struct llentry 	*mro_lle;		/* shortcut */
	struct ifaddr 	*mro_ifa;		/* nhlfe */
	int  	mro_flags;					
	struct sockaddr_ftn mro_gw;	/* storage, destination */
};	
	
/*
 * Fetch ilm.  
 */
static __inline void	mpls_rtalloc_fib(struct mpls_ro *, u_int);
static __inline void	
mpls_rtalloc_fib(struct mpls_ro *mro, u_int fib)
{
	rtalloc_fib((struct route *)mro, fib);
	if ((mro->mro_ilm != NULL) 
		&& (mro->mro_ilm->rt_ifp != NULL)
		&& (mro->mro_ilm->rt_ifa != NULL) 
		&& (mro->mro_ilm->rt_flags & RTF_MPLS)
		&& (mro->mro_ilm->rt_flags & RTF_UP)) {
/*
 * Map corrosponding llentry{}.
 */		
		mro->mro_lle = mpls_lle(mro->mro_ilm->rt_ifa);
		mro->mro_ifa = mro->mro_ilm->rt_ifa;
		mro->mro_flags = mro->mro_ilm->rt_flags;
	} else {
/*
 * Abort transmission.
 */		
		mro->mro_flags = 0;
		mro->mro_lle = NULL;
		mro->mro_ifa = NULL;
	}
}

/*
 * Release ilm.
 */
static __inline void	mpls_rtfree(struct mpls_ro *);
static __inline void	
mpls_rtfree(struct mpls_ro *mro)
{
	RO_RTFREE((struct route *)mro);
	
	mro->mro_flags = 0;
	mro->mro_lle = NULL;
	mro->mro_ifa = NULL;
}

/*
 * Compare socket addresses.
 */
static __inline int 	mpls_sa_equal(struct sockaddr *, struct sockaddr *);
static __inline int 	
mpls_sa_equal(struct sockaddr *sa0, struct sockaddr *sa1) 
{
	int equals;
	const char *x_1; 
	const char *x_0; 
	const char *max;

	KASSERT((sa0 != NULL), ("Invalid argument"));
	KASSERT((sa1 != NULL), ("Invalid argument"));
/*
 * Constraint, x_0 maps to sa0 denotes prefix in x_1 maps to sa1.
 */	
	equals = 0;
	
	if (sa0->sa_len > sa1->sa_len)
		goto out;
		
	if (sa0->sa_family != sa1->sa_family)
		goto out;
	
	x_1 = (const char *)sa1->sa_data; 
	x_0 = (const char *)sa0->sa_data;

	max = x_0 + (sa0->sa_len - offsetof(struct sockaddr, sa_data));

	for (; x_0 < max; x_0++, x_1++) {
		if ((*x_0 ^ *x_1) & 0xff)
			goto out;
	}
	equals = 1;
out:	
	return (equals);
}

/*
 * MPLS per-interface state.
 */
struct mpls_ifinfo {
	struct lltable		*mii_llt;	/* mpls_arp cache */
	struct ifaddr		*mii_nhlfe;	 /* per interface MPLS label binding */ 
	int	(*mii_output)		/* hooked output routine (enqueue) */
		(struct ifnet *, struct mbuf *, const struct sockaddr *,
		     struct route *);	     
};
#define MPLS_LLTABLE(ifp)	\
	(((struct mpls_ifinfo *)(ifp)->if_afdata[AF_MPLS])->mii_llt)

#define MPLS_IFINFO(ifp) \
	((struct mpls_ifinfo *)(ifp)->if_afdata[AF_MPLS])	
#define MPLS_IFINFO_IFA(ifp) \
	(((struct mpls_ifinfo *)(ifp)->if_afdata[AF_MPLS])->mii_nhlfe)	

#define	MPLS_SEG(lle)	((struct sockaddr_mpls *)L3_ADDR(lle))
#define	MPLS_SEG_LEN(lle)	L3_ADDR_LEN(lle)

#define mpls_if_lladdr(_ifp) 	((_ifp)->if_addr->ifa_addr)

/*
 * Global queue holds NHLFE.
 */
TAILQ_HEAD(mpls_head, mpls_ifaddr);

extern struct mpls_head 	mpls_ifaddrhead;
extern struct rwlock 		mpls_ifaddr_lock;

#define	MPLS_IFADDR_LOCK_ASSERT() 	rw_assert(&mpls_ifaddr_lock, RA_LOCKED)
#define	MPLS_IFADDR_RLOCK() 		rw_rlock(&mpls_ifaddr_lock)
#define	MPLS_IFADDR_RLOCK_ASSERT() 	rw_assert(&mpls_ifaddr_lock, RA_RLOCKED)
#define	MPLS_IFADDR_RUNLOCK() 	rw_runlock(&mpls_ifaddr_lock)
#define	MPLS_IFADDR_WLOCK() 		rw_wlock(&mpls_ifaddr_lock)
#define	MPLS_IFADDR_WLOCK_ASSERT() 	rw_assert(&mpls_ifaddr_lock, RA_WLOCKED)
#define	MPLS_IFADDR_WUNLOCK() 	rw_wunlock(&mpls_ifaddr_lock)

extern u_long	mpls_raw_sendspace;
extern u_long	mpls_raw_recvspace;

extern int	mpls_defttl;
extern int	mpls_mapttl_ip;
extern int	mpls_mapttl_ip6;
extern int	mpls_inkloop;
extern int	mpls_exp_override;
extern int 	mpls_empty_cw;

extern int	mpls_pfil_hook; 

/*
 * Control block for raw socket for 
 * MPLS_RTALERT message processing.
 */
struct mpls_rawcb {
	struct rawcb 		mrc_rp;
	struct sockaddr_mpls 	mrc_seg;
};
#define	sotomplsrawcb(so) 	((struct mpls_rawcb *)(so)->so_pcb)

extern struct pr_usrreqs mpls_raw_usrreqs;
extern struct pr_usrreqs mpls_rtalert_usrreqs;
extern struct protosw mplssw[];
extern struct domain mplsdomain;

/*
 * Annotation, holds copy of MPLS label stack 
 * maps to by dummynet(4) processed PDU. 
 */
struct m_tag_mpls {
	struct m_tag 		mtm_tag;
	struct shim_hdr 	mtm_stk[MPLS_INKERNEL_LOOP_MAX];
	size_t 			mtm_size; 
/*	size_t 			mtm_nstk; 	 constraint */
};
#define	MTAG_MPLS  		1404759854
#define	MTAG_MPLS_STACK 	0

#include <sys/eventhandler.h>

typedef void (*mpls_bridge_event_fn)(void *, struct ifnet *, int);
EVENTHANDLER_DECLARE(mpls_bridge_event, mpls_bridge_event_fn);
#endif /* _KERNEL */

#endif /* !_NETMPLS_MPLS_H_ */
