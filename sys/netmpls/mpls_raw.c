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
#include <sys/protosw.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_types.h>

/*
 * Defines interface maps to 
 * socket layer for accessing
 * MPLS layer by control plane.
 */

#include <netmpls/mpls.h>

#define MPLS_RAW_SNDQ	8192
#define MPLS_RAW_RCVQ	8192

SYSCTL_DECL(_net_mpls);
SYSCTL_NODE(_net, AF_MPLS, mpls, CTLFLAG_RW, 0, "MPLS Family");

u_long mpls_raw_sendspace = MPLS_RAW_SNDQ;
u_long mpls_raw_recvspace = MPLS_RAW_RCVQ;

SYSCTL_ULONG(_net_mpls, OID_AUTO, sendspace, CTLFLAG_RW,
    &mpls_raw_sendspace, 0, "Maximum outgoing raw MPLS PDU size");
SYSCTL_ULONG(_net_mpls, OID_AUTO, recvspace, CTLFLAG_RW,
    &mpls_raw_recvspace, 0, "Maximum space for incoming MPLS PDU");
    
int mpls_defttl = 255;
int mpls_inkloop = MPLS_INKERNEL_LOOP_MAX;

int mpls_mapttl_ip = 1;
#ifdef INET6
int mpls_mapttl_ip6 = 0;
#endif	/* INET6 */
int mpls_exp_override = 0;
int mpls_empty_cw = 0;

SYSCTL_INT(_net_mpls, OID_AUTO, default_ttl, CTLFLAG_RW,
	&mpls_defttl, 0,
	"MPLS maximum ttl");
SYSCTL_INT(_net_mpls, OID_AUTO, inkernel_loop_max, CTLFLAG_RW,
	&mpls_inkloop, 0,
	"Maximum loop count of incoming PDU");
SYSCTL_INT(_net_mpls, OID_AUTO, map_ttl_ip, CTLFLAG_RW,
	&mpls_mapttl_ip, 0,
	"Inherit ttl value from IP4 datagram");
#ifdef INET6
SYSCTL_INT(_net_mpls, OID_AUTO, map_ttl_ip6, CTLFLAG_RW,
	&mpls_mapttl_ip6, 0,
	"Inherit ttl value from IP6 datagram");
#endif	/* INET6 */
SYSCTL_INT(_net_mpls, OID_AUTO, exp_bits_override, CTLFLAG_RW,
	&mpls_exp_override, 0,
	"Inherit experimental bits from routing information.");
SYSCTL_INT(_net_mpls, OID_AUTO, exp_empty_cw, CTLFLAG_RW,
	&mpls_empty_cw, 0,
	"Prepend empty CW in case of OSI-L2/VPN for backward compatibility.");
	
int mpls_pfil_hook = 0;   

SYSCTL_INT(_net_mpls, OID_AUTO, pfil_enable, CTLFLAG_RW,
    &mpls_pfil_hook, 0, "Enables access to by pfil(9) implemented IAP");

extern int	mpls_control(struct socket *, u_long, caddr_t, struct ifnet *,
    struct thread *);

/*
 * Control socket.
 */ 

static int
mpls_attach(struct socket *so, int proto, struct thread *td)
{
	return (soreserve(so, mpls_raw_sendspace, mpls_raw_recvspace));
}

struct pr_usrreqs mpls_raw_usrreqs = {
	.pru_attach =	mpls_attach,
	.pru_control =	mpls_control,
};

 
