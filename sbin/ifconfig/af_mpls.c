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
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>	

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <netmpls/mpls.h>

#define MPLS_ADDRBUFSIZ 	(MAXHOSTNAMELEN * 2 + 1)
#define MPLS_WORKBUFSIZ 	(MPLS_ADDRBUFSIZ * 2 + 1)

static struct mpls_aliasreq mpls_addreq;

#include "ifconfig.h"

static void
mpls_status(int s __unused, const struct ifaddrs *ifa)
{
	char abuf[MPLS_ADDRBUFSIZ], wbuf[MPLS_WORKBUFSIZ], *cq;
	uint32_t iseg, op, oseg;

	if ((ifa == NULL) 
		|| ((ifa->ifa_addr) == NULL) 
		|| ((ifa->ifa_dstaddr) == NULL))
		return; 

	iseg = ntohl(satosmpls_label(ifa->ifa_addr)) >> MPLS_LABEL_OFFSET;
	op = satosftn_op(ifa->ifa_dstaddr);
	oseg = ntohl(satosftn_label(ifa->ifa_dstaddr)) >> MPLS_LABEL_OFFSET;
	
	cq = wbuf;
	cq += sprintf(cq, "\tmpls %d ", iseg);	

	switch (op) {
	case RTF_POP:
		cq += sprintf(cq, "pop ");
		break;
	case RTF_PUSH:
		cq += sprintf(cq, "psh ");
		break;
	case RTF_SWAP:
		cq += sprintf(cq, "swp ");
		break;
	default:
		break;
	}
	
	if (iseg != oseg)
		cq += sprintf(cq, "%d ", oseg);
	
	switch (ifa->ifa_dstaddr->sa_family) {
	case AF_INET:
		(void)snprintf(abuf, MPLS_ADDRBUFSIZ, "%s", 
			inet_ntoa(((struct sockaddr_in *)
			ifa->ifa_dstaddr)->sin_addr));
		cq += sprintf(cq, "-> inet %s", abuf);
		break;
	case AF_INET6:
		(void)inet_ntop(AF_INET6, 
			&((struct sockaddr_in6 *)
			ifa->ifa_dstaddr)->sin6_addr, 
			abuf, MPLS_ADDRBUFSIZ);	
		cq += sprintf(cq, "-> inet %s", abuf);
		break;
	case AF_MPLS: 
		cq += sprintf(cq, "-> mpls %d (downstream)", 
			ntohl(satosmpls_label(ifa->ifa_dstaddr)) 
				>> MPLS_LABEL_OFFSET);
		break;
	case AF_LINK: {
/*
 * Following code-section is reused from implementation 
 * of in af_link.c defined link_status procedure, part of
 * ifconfig(8) implementation. 
 */	
 		struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_dstaddr;
 
		if (sdl != NULL && sdl->sdl_alen > 0) {
			if ((sdl->sdl_type == IFT_ETHER 
				|| sdl->sdl_type == IFT_L2VLAN 
				|| sdl->sdl_type == IFT_BRIDGE) 
				&& sdl->sdl_alen == ETHER_ADDR_LEN)
				cq += sprintf(cq, "-> ether %s",
				    ether_ntoa((struct ether_addr *)LLADDR(sdl)));
			else {
				int n = sdl->sdl_nlen > 0 ? sdl->sdl_nlen + 1 : 0;
	
				cq += sprintf(cq, "-> link %s", link_ntoa(sdl) + n);
			}
		}		
		break;
	}
	default: 
		cq += sprintf(cq, "n/a");
		break;
	}
	(void)printf("%s", wbuf);
	putchar('\n');
}

/*
 * Request by mpls_control per interface MPLS label binding.
 */
static void
mpls_getaddr(const char *s, int which)
{
	struct mpls_aliasreq *ifra = &mpls_addreq;
	struct sockaddr *seg;
	uint32_t label;
	
	if (which != ADDR) 
		return;
	
	seg = (struct sockaddr *)&ifra->ifra_seg;
	
	label = strtoul(s, (char **)NULL, 10);	
	if (label > MPLS_LABEL_MAX) 
		errx(1, "ioctl (SIOC[AD]IFADDR)");

	label = htonl(label << MPLS_LABEL_OFFSET);
		
	seg->sa_len = SFTN_LEN;
	seg->sa_family = AF_MPLS; 
	
	satosmpls_label(seg) = label;
	satosftn_label(seg) = label;
}

/*
 * Bind link layer interface on if_mpe(4) 
 * performing proxyfied transmission. 
 */
static void
mpls_setproxy(const char *val, int d, int s, 
		const struct afswtch *afp)
{
	struct ifaliasreq ifra;
	struct sockaddr_mpls *smpls;
	struct sockaddr_dl *sdl;
	size_t nlen;

	if ((nlen = strnlen(val, IFNAMSIZ)) >= IFNAMSIZ) 
		errx(1, "ioctl (SIOCSIFPHYADDR)");
	
	(void)memset(&ifra, 0, sizeof(ifra));
	(void)memcpy(ifra.ifra_name, name, IFNAMSIZ);	
	
	smpls = (struct sockaddr_mpls *)&ifra.ifra_addr;
	smpls->smpls_len = sizeof(*smpls);
	smpls->smpls_family = AF_MPLS;
	
	sdl = (struct sockaddr_dl *)&ifra.ifra_broadaddr;
	sdl->sdl_len = sizeof(*sdl);
	sdl->sdl_family = AF_LINK;	
	sdl->sdl_nlen = nlen;
	
	(void)memcpy(sdl->sdl_data, val, nlen);

	if (ioctl(s, SIOCSIFPHYADDR, (caddr_t)&ifra) < 0)  
		errx(1, "ioctl (SIOCSIFPHYADDR)");
} 	

/*
 * Removes link layer interface bonding.
 */ 
static void
mpls_rmproxy(const char *val, int d, int s, 
		const struct afswtch *afp)
{
	struct ifreq ifr;
	struct sockaddr_mpls *smpls;
	
	(void)memset(&ifr, 0, sizeof(ifr));
	(void)memcpy(ifr.ifr_name, name, IFNAMSIZ);

	smpls = (struct sockaddr_mpls *)&ifr.ifr_addr;
	smpls->smpls_len = sizeof(*smpls);
	smpls->smpls_family = AF_MPLS;
	
	if (ioctl(s, SIOCDIFPHYADDR, (caddr_t)&ifr) < 0) 
		errx(1, "ioctl (SIOCDIFPHYADDR)");
}

/* 
 * Command table targeting if_mpe(4). 
 */
static struct cmd mpe_cmds[] = {
	DEF_CMD_ARG("proxy", mpls_setproxy),
	DEF_CMD("-proxy", 0, mpls_rmproxy),
};

/* 
 * Adress family specific descriptor. 
 */
static struct afswtch af_mpls = {
	.af_name	= "mpls",
	.af_af		= AF_MPLS,
	.af_status	= mpls_status,
	.af_getaddr	= mpls_getaddr,
	.af_difaddr	= SIOCDIFADDR,
	.af_aifaddr	= SIOCAIFADDR,
	.af_ridreq	= &mpls_addreq,
	.af_addreq	= &mpls_addreq,
};

/* 
 * Attach this module to ifconfig(8). 
 */
static __constructor void
mpls_ctor(void)
{
#define	N(a)	(sizeof(a) / sizeof(a[0]))
	int i;
 
	for (i = 0; i < N(mpe_cmds);  i++) 
		cmd_register(&mpe_cmds[i]);
	af_register(&af_mpls);
#undef N	
}

