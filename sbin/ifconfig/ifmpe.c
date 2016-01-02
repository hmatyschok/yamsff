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
 *
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <stdlib.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "ifconfig.h"

#include <netmpls/mpls.h>

static void
mpe_status(int s)
{
	struct if_laddrreq iflr;
	struct sockaddr_mpls *smpls;
	struct sockaddr_dl *sdl;
	
	(void)memset(&iflr, 0, sizeof(iflr));
	(void)memcpy(iflr.iflr_name, name, IFNAMSIZ);	
	
	smpls = (struct sockaddr_mpls *)&iflr.addr;
	smpls->smpls_len = sizeof(*smpls);
	smpls->smpls_family = AF_MPLS;
	
	sdl = (struct sockaddr_dl *)&iflr.dstaddr;
	sdl->sdl_len = sizeof(*sdl);
	sdl->sdl_family = AF_LINK;	
	
	if (ioctl(s, SIOCGLIFPHYADDR, (caddr_t)&iflr) < 0)  
		return;
/*
 * Following code-section is reused from implementation 
 * of in af_link.c defined link_status procedure, part of
 * ifconfig(8) implementation. 
 */		
	(void)printf("\tlink ");
		
	if (sdl != NULL && sdl->sdl_alen > 0) {
		if ((sdl->sdl_type == IFT_ETHER 
			|| sdl->sdl_type == IFT_L2VLAN 
			|| sdl->sdl_type == IFT_BRIDGE) 
			&& sdl->sdl_alen == ETHER_ADDR_LEN) {
			
			(void)printf("%s ",
				ether_ntoa((struct ether_addr *)LLADDR(sdl)));
		} else {
			int n = sdl->sdl_nlen > 0 ? sdl->sdl_nlen + 1 : 0;
			
			(void)printf("%s ", link_ntoa(sdl) + n);
		}
	}	
}

static struct afswtch af_mpe = {
	.af_name	= "af_mpe",
	.af_af		= AF_MPLS,
	.af_other_status = mpe_status,
};

static __constructor void
mpe_ctor(void)
{
	
	af_register(&af_mpe);
}
