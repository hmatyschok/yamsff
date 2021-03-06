<pre><code>
Yet another MPLS stack for FreeBSD (yamsff)
===========================================

This software is derived from MPLS implementation of OpenBSD operating system.
 
 o https://2011.eurobsdcon.org/papers/jeker/MPLS.pdf
 
 o http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/netmpls/
 o http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/net/if_mpe.c
 
Ongoing operational tasks:
--------------------------
 
 o Testing components and bugfixes (or refactoring some parts).
 o Review of ifconfig(8) and bugfixes (or refactoring some parts).
 o Adding by AF_MPLS domain extended netstat(8) command.
 o Writing detailed implementation notes.
 o Manual pages and misc. documentation.
 o Fixes targeting my bad orthography.
 o Establishing full rfc-3031 and rfc-3032 conformancy.
 o ...

Implementation notes
====================

NOTE: This software and its components are under active developement and far
NOTE: from correctness and containing (some serious) flaws implecitely.
NOTE:        
NOTE: Purpose of this operation is to teach myself about MPLS for a better 
NOTE: understanding. 
NOTE:        
NOTE: Stern warning: Do not use this software in production environments!

Directory structure
-------------------

Due to simplicity I've integrated the AF_MPLS domain into sys directory.

    /conf/       Extended configuration files.
   
    /sbin/       Extended system commands (User space).
   
                  (a) ifconfig(8)
                 
                  (b) route(8)

    /sys/        Kernel sources.

                 net/        
                 
                  Extensions implements inclusion mapping in AF_MPLS domain 
                  on interface-layer.
   
                  if.c      
                            
                            Generic ifnet(9) implementation.

                             (a) ifhwioctl, enabling / disabling IFF_MPLS
                                 by SIOCSIFFLAGS command.

                             (b) if_purgeaddrs, calls mpls_purgaddrs.

                  if.h      
                            Defined flags maps on link layer and 
                            on AF_MPLS domain.
 
                             (a) IFF_MPLS, enables inclusion mapping 
                                 from interface in AF_MPLS domain.        
                            
                             (b) IFF_MPE, MPLS label binding maps to
                                 interface, aggregate set of routes.
                             
                  if_bridge.c
                  
                            Inspection Access Point (iap) was extended.
                             
                             (a) Inspecting frames carrying rfc-2516
                                 Service Data Units (sdu).
                                 
                             (b) Inspecting frames originating AF_MPLS. 
                              
                            Only frames containing IPv{4|6} datagrams  
                            are processed by pfil(9).  
                              
                  if_bridgevar.h
                  
                            Definition of mbuf_tags(9) for caching 
                            Protocol Control Information (pci) on 
                            both cases as described as above. 
                  
                  if_ethersubr.c
                  
                             (a) Handoff decapsulated sdu by netisr(9) during
                                 ether_demux.
                             
                             (b) Resoluton by mpls_arpresolve 
                                 during ether_output.
                             
                             (c) SIOCSIFADDR invokes mpls_arp_ifinit 
                                 during ether_ioctl.
                  
                  if_fddisubr.c
                  
                             (a) Handoff decapsulated sdu by netisr(9) 
                                 during fddi_input.
                             
                             (b) Resoluton by mpls_arpresolve 
                                 during fddi_output.
                             
                             (c) SIOCSIFADDR invokes mpls_arp_ifinit 
                                 during fddi_ioctl.
                  
                  if_llatbl.c          
                             
                            Llatbl_lle_show dumps intire ARP cache
                            residing in AF_MPLS domain.
                      
                  if_loop.c
                     
                            Loopback of MPLS Protocol Data Units (pdu)
                            into AF_MPLS domain by if_simloop. 
                                       
                  if_mpe.c
                  
                            Implementation of generic interface still capable
                            operating as MPLS Provider Edge for OSI-L2/VPN in
                            conjunction with instance of if_bridge(4) as its
                            member.
                            
                            The implementation is derived from implementation 
                            in OpenBSD 4.7 release. 
                            
                  if_vether.c
                  
                            Port from implementation of if_vether(4), where 
                            it is implementetd in OpenBSD 4.7 release.
                            
                  route.c
                  
                             (a) Lookup of Incoming Label Map (ilm) on RADIX 
                                 Trie in AF_MPLS domain by rtalloc_fib1(9). 
                  
                             (b) Lookup for x-connect by ifa_ifwithroute_fib
                                 as precondition for generating by Next Hop
                                 Label Forwarding Entry (nhlfe) covered ilm.
                                
                             (c) Creation or deletion of ilm by 
                                 rtrequest1_fib(9). 
                  
                  rtsock.c

                            Access AF_MPLS domain by mpls_rt_output
                            during rt_output in AF_ROUTE domain.          
           
                 netinet/   
                 
                  Integration of AF_MPLS domain into address resolution code.
                  
                  if_ether.c
                  
                            Implements Service Access Point (sap) for 
                            handoff mbuf(9) containing MPLS_ARP sdu 
                            into AF_MPLS domain.                 
                 netinet6/   
                 
                  Integration of AF_MPLS domain into AF_INET6 domain.
                  
                  nd6.c
                  
                            Implements address resolution for mbuf(9) 
                            originatimg AF_MPLS domain and inclusion
                            mapping of fastpath into AF_MPLS domain.
                 
                 
                 netmpls/
                  
                  Implementation of AF_MPLS domain.   
                  
                  mpls.c

                            By ioctl(2) accessible generic control operations.
                            
                             (a) MPLS label assignement / removal scoped
                                 on interface layer.
                                 
                             (b) Attachment / detachement of link layer
                                 interfaces on instances of if_mpe(4).
                                 
                            ARP cache implementation in AF_MPLS domain.  

                  mpls.h
                  
                            Interface specification for accessing AF_MPLS
                            domain. 
                            
                            XXX: Internal order and structure of this .h 
                            XXX: is wrong.
                            XXX:
                            XXX: I'll externalize components into mpls_var.h.
                  
                  mpls_arp.c
                  
                            Implementation of MPLS_ARP protocol and access 
                            to protocol layer specific link layer address 
                            resolution code, if MPLS_ARP is disabled.  
                               
                  mpls_input.c
                  
                            Implementation of input processing, handoff
                            into service requesting operating system 
                            layer, forwarding and exception handling.
                             
                  mpls_output.c
                  
                            Implementation of output processing.
                  
                  mpls_proto.c
                  
                            Implementation of AF_MPLS domain.
                            
                  mpls_raw.c

                            Implementation of raw socket for accessing 
                            control operations in AF_MPLS domain.
                  
                  mpls_rmx.c
                  
                            Implementation of RADIX trie containing by nhlfe
                            covered ilm in AF_MPLS domain.
                            
                            Further, ctor and dtor for by Forward Equivalence
                            Class (fec) covered nhlfe are implented here.
                  
                  mpls_rtalert.c
                  
                            Implementation of raw socket processing pdu 
                            with MPLS_RTALERT pci.
                  
                  mpls_shim.c
                  
                            Kernel Programming Interface (kpi) for 
                            generating or manipulating MPLS labeled
                            pdu.
                            
                 pfil/   
                 
                  Integration of inspecting frames containing  
                  
                   (a) sdu originating AF_MPLS domain and  
                   
                   (b) rfc-2516 based sdu
                   
                  by ipfw(4).
                 
MPLS label binding - implementation notes
-----------------------------------------

Let us consider

    fec     : Forward Equivalence Class
    ftn     : FEC-to-NHLFE Map 
    ilm     : Incoming Label Map
    nh      : next-hop or gateway address
    nhlfe   : Next Hop Label Forwarding Entry
    op      : MPLS operation
    rd      : MPLS Route Distinguisher or reserved label value
    seg_i   : in-segment (seg_in, lsp_in)
    seg_j   : out-segment (seg_out, lsp_out)
    seg     : particular Label Switch Path (lsp) in < SEG, SEG >
    x       : destination, key in fec or link-level address on ifnet(9)

if     
 
    fec = < x, nh > in rtentry(9)
    
     (a)  x = fec(rt_key)
     (b)  nh = fec(rt_gateway)   
  
and 

    seg = < seg_i, seg_j >

further 

    seg = < seg_in, seg_out >
    
where    

    < op, seg_out, rd >

then

    ftn = < x, < op, seg_out, rd > >

implies 

    nhlfe = < seg_in, ftn > in ifaddr(9)

is free generated by fec where 
      
    ilm = < seg_in, ftn > in rtentry(9)
    
     (a) seg_in = ilm(rt_key)
     (b) ftn = ilm(rt_gateway)
    
is free generated by fec enclosed nhlfe if MPLS operation denotes 

    RTF_{POP|SWAP} and ! RTF_PUSH 
    
but if RTF_PUSH then

    fastpath = < nh, < op, seg_out, rd > >
    
where   
 
    nhlfe = < seg_in, ftn > 

is free generated by

   fec' = < x, fastpath >  
       
There exists basically two partitions for MPLS label bindings: 
 
 (a) Per-interface MPLS label space, aggregate set of routes.   
          
 (b) MPLS label space where any element maps to unique fec. 
     
Any MPLS label binding is implemented by fec enclosed nhlfe where the 
implementation of

    struct mpls_ifaddr {
        struct ifaddr     mia_ifa;        /* protocol-independent info */
    #define mia_addr     mia_ifa.ifa_addr
    #define mia_netmask     mia_ifa.ifa_netmask
    #define mia_dstaddr     mia_ifa.ifa_dstaddr
    #define mia_ifp     mia_ifa.ifa_ifp    
    #define mia_flags     mia_ifa.ifa_flags
    #define mia_metric     mia_ifa.ifa_metric
        TAILQ_ENTRY(mpls_ifaddr)    mia_link;
    
        struct sockaddr_ftn     mia_seg; /* seg_i */
        struct sockaddr_ftn     mia_nh;     /* < x, <op, seg_j, rd > > */
    
        int     mia_rt_flags;
        
        struct ifaddr     *mia_x;     /* backpointer for ifaddr(9) on fec */
        struct llentry     *mia_lle;     /* shortcut */    
    };
 
is derived from those of protocol-independent ifaddr(9). Call off

 # ifconfig em1 encap 
    
enables the inclusion mapping on AF_MPLS domain when ioctl(2) calls 

    static int
    ifhwioctl(u_long cmd, struct ifnet *ifp, caddr_t data, struct thread *td)
    {
        struct ifreq *ifr;
       
             ...
       
        int error = 0;
        int new_flags, temp_flags;
        
            ...
            
        ifr = (struct ifreq *)data;
        switch (cmd) {
    
            ...    
        
        case SIOCSIFFLAGS:
            
                ...
            
            else if (ifp->if_flags & IFF_MPLS &&
                 (new_flags & IFF_MPLS) == 0) {
/*
 * Disable MPLS.
 */
                int s = splimp();                
                if (ifp->if_type == IFT_ETHER
                    || ifp->if_type == IFT_FDDI
                    || ifp->if_type == IFT_LOOP) {
                    ifp->if_output = MPLS_IFINFO(ifp)->mii_output; 
                    MPLS_IFINFO(ifp)->mii_output = mpls_output;    
                }    
                splx(s);
            } else if (new_flags & IFF_MPLS &&
                (ifp->if_flags & IFF_MPLS) == 0) {
/*
 * Enable MPLS.
 */
                int s = splimp();                
                if (ifp->if_type == IFT_ETHER 
                    || ifp->if_type == IFT_FDDI
                    || ifp->if_type == IFT_LOOP) {
                    MPLS_IFINFO(ifp)->mii_output = ifp->if_output;
                    ifp->if_output = mpls_output;    
                }    
                splx(s);
            }
                   ...
   
            break;
        
            ...    

        default:
            error = ENOIOCTL;
            break;
        }
        return (error);
    }

in conjunction with SIOCSIFFLAGS Service Primitive (spi), where 
 
 em1: flags=3008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,MPLS> metric 0 mtu 1500
    options=9b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM>
    ether 08:00:27:19:9b:5b
    inet 10.0.1.1 netmask 0xffffff00 broadcast 10.0.1.255 
    media: Ethernet autoselect (1000baseT <full-duplex>)
    status: active

hardware-independent output routine on instance of ifnet(9) interface 
abstraction was replaced by

    int
    mpls_output(struct ifnet *ifp, struct mbuf *m, 
            const struct sockaddr *dst, struct route *ro)
    {    
        struct mpls_ro mplsroute;
        struct mpls_ifinfo *mii;
        struct mpls_ro *mro;
        struct sockaddr *gw;
    
        int error = 0;
    
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
        bzero(mro, sizeof(mro));
    
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
            
            m->m_flags &= ~(M_BCAST|M_MCAST);
        }
        error = (*mii->mii_output)(ifp, m, gw, ro);    
    done:    
        if (mro != NULL)
            mpls_rtfree(mro);
    out:    
        return (error);
    }

implecitely. 
                                                                  socket-layer
             rxxx_input() +{ socket layer }+ rxxx_output()       
                         /                  \                ---+-----   
                        /                    \
     +-->+ xxx_input() +-->+ xxx_forward() +->+ xxx_output()      protocol-layer
    /     \                                    \               
   /       \                                    +            ---+-----
  +         +<------+                           |              
  |                  \                          v                 mpls-layer
  + mpls_input() +--->+ mpls_forward() +------->+ mpls_output()   
  |\                                           /|               
  | \                               +<--------+ |            ---+-----
  |  \                             /            |               
  |   +<-----------+ if_simloop() +<------------+ if_output()     link-layer
  |                                             |
  + if_input()                                  |
  A                                             |
  |                                             V

Therefore, former delegated output routine, e. g. ether_output was hooked by 
mii_output on 

    struct mpls_ifinfo {
        struct lltable        *mii_llt;    
        struct ifaddr        *mii_nhlfe;   
        int    (*mii_output)    /* delegation */
            (struct ifnet *, struct mbuf *, const struct sockaddr *,
             struct route *);         
    };

which was allocated by mpls_domifattach during interface initialisation by 
if_attach called if_attachdomain1. Additionally mpls_ifinfo{} still holds 
interface specific MPLS_ARP cache and holds reference on MPLS label bindings 
scoped on interface-layer denotes aggregate set of routes, when call off

 # ifconfig em1 mpls 100

invokes by ioctl(2) called mpls_control in conjunction SIOC[AS]IFADDR spi.   

 em1: flags=3008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,MPLS,MPE> metric 0 mtu 1500
    options=9b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM>
    ether 08:00:27:19:9b:5b
    mpls 100 psh -> ether 08:00:27:19:9b:5b
    inet 10.0.1.1 netmask 0xffffff00 broadcast 10.0.1.255 
    media: Ethernet autoselect (1000baseT <full-duplex>)
    status: active

Any by mpls_output processed sdu will be encapsulated by MPLS label 100 during
runtime of mpls_output called 

    struct mbuf     
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
        default:     /* unsupported domain */        
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

if and only if (iff) service requesting protocol-layer still invokes em1 for 
broadcasting frames on transmission media. The most common case on MPLS label 
bindings are those where maps to unique fec. On operating system level, a fec 
is implemented as  

    struct rtentry {
        struct    radix_node rt_nodes[2];    /* tree glue, and other values */
    #define    rt_key(r)    (*((struct sockaddr **)(&(r)->rt_nodes->rn_key)))
    #define    rt_mask(r)    (*((struct sockaddr **)(&(r)->rt_nodes->rn_mask)))
        struct    sockaddr *rt_gateway;    /* value */
        struct    ifnet *rt_ifp;      /* the answer: interface to use */
        struct    ifaddr *rt_ifa;     /* the answer: interface address to use */
        int        rt_flags;   
        int        rt_refcnt;    
        u_int        rt_fibnum;   
        u_long        rt_mtu;      
        u_long        rt_weight;    
        u_long        rt_expire;    
    #define    rt_endzero    rt_pksent
        counter_u64_t    rt_pksent;    
        struct mtx    rt_mtx;       
    };    
         
denotes node in RADIX Trie on domain in protocol-layer (e. g. AF_INET). See by 
route(4) and rtentry(9) denoted manual pages for detailed description about its 
implementation.  
    Suppose a set of packets 

 # route add -4 172.16.1.3 10.0.1.1
 
in fec
 
 # route get -4 172.16.1.3 10.0.1.1
 
 route to: 172.16.1.3
 destination: 172.16.1.3
     gateway: 10.0.1.1
         fib: 0
   interface: em1
       flags: <UP,GATEWAY,HOST,DONE,STATIC>
  recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire
       0         0         0         0      1500         1         0 
       
invokes link-layer interface em1 for transmission. Then 

 # route add -4 172.16.1.3 -push 200    

binds MPLS label 200 in conjuction with

 em1: flags=3008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,MPLS,MPE> metric 0 mtu 1500
    options=9b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM>
    ether 08:00:27:19:9b:5b
    mpls 200 psh -> inet 172.16.1.3   
    mpls 100 psh -> ether 08:00:27:19:9b:5b
    inet 10.0.1.1 netmask 0xffffff00 broadcast 10.0.1.255 
    media: Ethernet autoselect (1000baseT <full-duplex>)
    status: active
 
on former introduced fec. Regarding rtentry(9), fastpath into MPLS transit will 
be applied on gateway address during runtime of mpls_ifinit called rt_setgate.
where gateway address on fec was extended by

      < op, seg, rd > = < psh, 200, 200 >  
 
and replaced by an instance of

    #define SFTN_DATA_LEN     52
    struct sockaddr_ftn {
        uint8_t     sftn_len;    
        sa_family_t     sftn_family;    /* address family, gateway address */   
        char     sftn_data[SFTN_DATA_LEN];    /* stores gateway address value */
        uint32_t     sftn_op;    /* MPLS operation */
        uint32_t     sftn_label;    /* stores seg_out */
        uint32_t     sftn_vprd;    /* route distinguisher */
    };
    #define SFTN_LEN     (sizeof(struct sockaddr_ftn))

still holds a copy of original gateway address value. 

        + rt_key               .       + MPLS label (BoS)
        |                      .       |
        v                      .       v
      +-------------+----------+-----+------+------+
      | 172.16.1.3  | 10.0.1.1 | psh | 200  | VPRD |
      +-------------+----------+-----+------+------+
                      A
                      |
                      + rt_gateway

This avoids a second routing table lookup by service providing MPLS-layer, 
when handoff by protocol-layer processed Message Primitives (mpi) into MPLS 
data plane was performed by call of mpls_output. 

               rip_input() +{ socket layer }+ rip_output()
                          /                  \
                         /                    \
       +-->+ ip_input() +-->+ ip_forward() +-->+ ip_output()
      /     \                                   \
     /       \                                   +
    +         +<------+                          |
    |                  \                         v 
    + mpls_input() +--->+ mpls_forward() +------>+ mpls_output()
    |\                                          /|
    | \                               +<-------+ |
    |  \                             /           |
    |   +<-----------+ if_simloop() +<-----------+ ether_output()
    |                                            |
    + ether_input()                              |
    A                                            |
    |                                            V
 
Implecitely, by service requesting protocol-layer performed routing decision 
during e. g. ip_output promotes a rtentry(9) where its enabled RTF_MPE flag, 
denotes fastpath in conjuction with annotation on gateway address. Thus, any 
sdu maps to fec' 
 
 # route get -4 172.16.1.3 10.0.1.1
 
    route to: 172.16.1.3
 destination: 172.16.1.3
     gateway: 10.0.1.1 <out#200>
         fib: 0
   interface: em1
       flags: <UP,GATEWAY,HOST,DONE,STATIC,MPE>
  recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire
       0         0         0         0      1496         1         0 
 
denotes fastpath into AF_MPLS domain will be encapsulated by mpls_encap during
runtime by ip_output recursively called mpls_output.
    It is obvious, any by fec enclosed MPLS label binding generates fec' denotes
fastpath does not generates an ilm. An ilm is an instance of rtentry(9) on RADIX
Trie in AF_MPLS domain, where its key is implemented by
 
    struct sockaddr_mpls {
        uint8_t     smpls_len;     /* length */
        sa_family_t     smpls_family;     /* AF_MPLS */
        uint16_t     smpls_pad0;    
        uint32_t     smpls_label;     /* MPLS label */
        uint32_t     smpls_pad1[2];                
    };
    #define SMPLS_LEN     (sizeof(struct sockaddr_mpls))

and its gateway address holds a copy by ifa_dstaddr reffered destination 
address on nhlfe. Any by mpls_control in conjuction with SIOC[AS]IFADDR
newly allocated or reused nhlfe inherites either 

 (a) the link-level address x 
 
or

 (b) the destination address x 
 
from its enclosing fec. Due to case of aggregate set of routes, by ifnet(9) 
implemented link-layer interface provides fec itself through reflexive mapping. 
Otherwise, the fec is implemented by rtentry(9) as mentioned before. Therefore, 
by ifa_dstaddr referred socket address on nhlfe holds an extended copy from its
enclosing fec inherited address x. 
    Regarding at the beginning on implementation notes defined terminology,
any ilm occours as by nhlfe enclosed rtentry(9)

        + rt_key (seg_in)               .       + MPLS label (seg_out)
        |                               .       |
        v                               .       v
      +-------------------+-------------+-----+------+------+
      | nhlfe(ifa_addr)   | fec(rt_key) | OP  | SEG  | VPRD |
      +-------------------+-------------+-----+------+------+
                            A
                            |
                            + rt_gateway

where 

 (a) rt_key     :=  copy of ifa_addr    maps to mia_seg on nhfle
  
 (b) rt_gateway :=  copy of ifa_dstaddr maps to mia_nh  on nhlfe

and

 (c) seg_in = ilm(rt_key) = nhlfe(ifa_addr)

 (d) x = fec(rt_key)

It is obvious

 # route add -4 172.16.1.3 -swap 300 -mpls 200
 
allocates ilm

 # route get -4 172.16.1.3 -swap 300 -mpls 200

    route to: 172.16.1.3
 destination: <in#300>
        mask: <in#300>
     gateway: 172.16.1.3 <out#200>
         fib: 0
   interface: em1
       flags: <UP,GATEWAY,DONE,MPLS,SWAP>
  recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire
        0         0         0         0      1496         1         0 

in conjuction with enclosing nhlfe on 
 
 em1: flags=3008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,MPLS,MPE> metric 0 mtu 1500
    options=9b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM>
    ether 08:00:27:19:9b:5b
    mpls 300 swp 200 -> inet 172.16.1.3
    mpls 200 psh -> inet 172.16.1.3
    mpls 100 psh -> ether 08:00:27:19:9b:5b
    inet 10.0.1.1 netmask 0xffffff00 broadcast 10.0.1.255 
    media: Ethernet autoselect (1000baseT <full-duplex>)
    status: active

where by RTF_SWAP denoted MPLS operation merges lsp 300 with lsp 200.

 ... to be continued.
</code></pre> 
 
Legal Notice: 
-------------
 
<pre><code>
  (a) FreeBSD is a trademark of the FreeBSD Foundation.
   
  (b) OpenBSD is a trademark of Theo DeRaadt.  
</code></pre>
 
 
 
 
 
 
 
 
 
  
