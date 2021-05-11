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
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

static struct pr_usrreqs nousrreqs;

#include <netmpls/mpls.h>

FEATURE(mpls, "Multi Protocol Label Switching");

extern void	mpls_init(void);
extern int	mpls_rtalert_output(struct mbuf *, struct socket *);

/*
 * MPLS protocol family.
 */
 
struct protosw mplssw[] = {
{ 
	.pr_type =		0,			
	.pr_domain =	&mplsdomain,		
	.pr_init =		mpls_init,
	.pr_usrreqs	=	&nousrreqs,
},
{ /* Raw socket for MPLS_RTALERT processing */
	.pr_type =		SOCK_RAW,		
	.pr_domain =	&mplsdomain,
	.pr_protocol =	MPLSPROTO_RTALERT,		
	.pr_flags =		PR_ATOMIC|PR_ADDR,
  	.pr_output =	mpls_rtalert_output,
  	.pr_usrreqs = 	&mpls_rtalert_usrreqs,
},
{ 
	.pr_type =		SOCK_RAW,			
	.pr_domain =	&mplsdomain,		
	.pr_init =		mpls_init,
	.pr_usrreqs	=	&nousrreqs,
},
{ /* control socket */
	.pr_type =		SOCK_DGRAM,		
	.pr_domain =	&mplsdomain,	
	.pr_flags =		PR_ATOMIC|PR_ADDR,	
  	.pr_usrreqs = 	&mpls_raw_usrreqs,
},
{ /* raw wildcard */
	.pr_type =		SOCK_RAW,		
	.pr_domain =	&mplsdomain,	
	.pr_flags =		PR_ATOMIC|PR_ADDR,
  	.pr_usrreqs = 	&mpls_raw_usrreqs,
},
};

extern void *	mpls_domifattach(struct ifnet *);
extern void	mpls_domifdetach(struct ifnet *, void *);
extern int mpls_rn_inithead(void **, int);

/*
 * Defines MPLS domain.
 */

struct domain mplsdomain = {
	.dom_family = 		AF_MPLS, 
	.dom_name = 		"mpls", 
	.dom_protosw =		mplssw,
	.dom_protoswNPROTOSW =	
		&mplssw[sizeof(mplssw)/sizeof(mplssw[0])],
	
	.dom_rtattach =		mpls_rn_inithead,
	.dom_rtoffset =		
		offsetof(struct sockaddr_mpls, smpls_label) << 3,
	
	.dom_maxrtkey = 	sizeof(struct sockaddr_mpls),
	.dom_ifattach =		mpls_domifattach,
	.dom_ifdetach = 	mpls_domifdetach
};
DOMAIN_SET(mpls);

