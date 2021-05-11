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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/raw_cb.h>

#include <netmpls/mpls.h>

/*
 * Defines interface maps to socket layer for capturing 
 * and injecting by MPLS_LABEL_RTALERT annotated PDU.
 */
 
extern struct mbuf *	mpls_shim_pop(struct mbuf *);
extern int 	mpls_ifawithseg_check_fib(struct sockaddr *, u_int);

/*
 * Template.
 */
static struct sockaddr_mpls seg_rtalert = { 
	.smpls_len = 		sizeof(seg_rtalert), 
	.smpls_family = 	AF_MPLS,
};

static struct sockproto mpls_rtalert_proto = {
	.sp_family = 	AF_MPLS,
	.sp_protocol =		MPLSPROTO_RTALERT,
};

static void	mpls_rtalert_disconnect_internal(struct socket *, 
	struct mpls_rawcb *);
static void	mpls_rtalert_abort(struct socket *);
static int	mpls_rtalert_attach(struct socket *, int, struct thread *);
static void	mpls_rtalert_close(struct socket *);
static int	mpls_rtalert_connect(struct socket *, struct sockaddr *, 
	struct thread *);
static void	mpls_rtalert_detach(struct socket *);
static int	mpls_rtalert_disconnect(struct socket *);
static int	mpls_rtalert_send(struct socket *, int, struct mbuf *, 
	struct sockaddr *, struct mbuf *, struct thread *);
static int	mpls_rtalert_shutdown(struct socket *);

/*
 * Disconnects socket.
 */
static void 
mpls_rtalert_disconnect_internal(struct socket *so, struct mpls_rawcb *mrp)
{
	mtx_lock(&rawcb_mtx);
	mrp->mrc_seg = seg_rtalert;
	SOCK_LOCK(so);
	so->so_state &= ~SS_ISCONNECTED;
	SOCK_UNLOCK(so);
	mtx_unlock(&rawcb_mtx);
}

/*
 * Usrreqs.
 */

static void
mpls_rtalert_abort(struct socket *so)
{
	struct mpls_rawcb *mrp;

	mrp = sotomplsrawcb(so);
	KASSERT(mrp == NULL, 
		("mpls_rtalert_abort: mrp != NULL"));

	mpls_rtalert_disconnect_internal(so, mrp);
}

static int
mpls_rtalert_attach(struct socket *so, int proto, struct thread *td)
{
	struct mpls_rawcb *mrp;
	int error;

	KASSERT(so->so_pcb == NULL, 
		("mpls_rtalert_attach: so_pcb != NULL"));

	error = EPROTONOSUPPORT;

	if (proto != MPLSPROTO_RTALERT) 
		goto out;
	
	mrp = malloc(sizeof(*mrp), M_PCB, M_WAITOK|M_ZERO);
	if (mrp == NULL) {
		error = ENOBUFS;
		goto out;
	}
	so->so_pcb = (caddr_t)mrp;
	so->so_fibnum = td->td_proc->p_fibnum;
	error = raw_attach(so, proto);
	mrp = sotomplsrawcb(so);
	if (error != 0) {
		so->so_pcb = NULL;
		free(mrp, M_PCB);
		goto out;
	}
	mtx_lock(&rawcb_mtx);
	mrp->mrc_seg = seg_rtalert;
	mtx_unlock(&rawcb_mtx);
	soisconnected(so);
	so->so_options |= SO_USELOOPBACK;
out:
	return (error);
}

static void
mpls_rtalert_close(struct socket *so)
{
	struct mpls_rawcb *mrp;

	mrp = sotomplsrawcb(so);
	KASSERT(mrp == NULL, 
		("mpls_rtalert_close: mrp != NULL"));

	mpls_rtalert_disconnect_internal(so, mrp);
}

static int
mpls_rtalert_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct sockaddr_mpls *seg;
	struct mpls_rawcb *mrp; 
	int error;

	if (nam->sa_len != sizeof(*seg)) {
		error = EINVAL;
		goto out;
	}
	if (nam->sa_family != AF_MPLS) {
		error = EAFNOSUPPORT;
		goto out;
	}
	seg = (struct sockaddr_mpls *)nam;
	
	if ((IS_NOT_MPLS_LABEL(seg->smpls_label)) 
		|| (mpls_ifawithseg_check_fib(nam, so->so_fibnum) == 0)) {
		error = EADDRNOTAVAIL;
		goto out;
	} 
	mrp = sotomplsrawcb(so);
	KASSERT(mrp == NULL, 
		("mpls_rtalert_bind: mrp != NULL"));
	
	mtx_lock(&rawcb_mtx);
	mrp->mrc_seg = seg_rtalert;
	mrp->mrc_seg.smpls_label &= seg->smpls_label;
	soisconnected(so);
	mtx_unlock(&rawcb_mtx);
	
	error = 0;	
out:
	return (error);
}

static void
mpls_rtalert_detach(struct socket *so)
{
	struct mpls_rawcb *mrp;

	mrp = sotomplsrawcb(so);
	KASSERT(mrp == NULL, 
		("mpls_rtalert_detach: mrp != NULL"));
	KASSERT(mrp->mrc_seg.smpls_label == MPLS_LABEL_MASK,
		("mpls_rtalert_detach: not closed"));
	
	raw_usrreqs.pru_detach(so);
}

static int
mpls_rtalert_disconnect(struct socket *so)
{
	struct mpls_rawcb *mrp;

	mrp = sotomplsrawcb(so);
	KASSERT(mrp == NULL, 
		("mpls_rtalert_disconnect: mrp != NULL"));

	mpls_rtalert_disconnect_internal(so, mrp);
	return (0);
}

static int
mpls_rtalert_send(struct socket *so, int flags, struct mbuf *m, 
		struct sockaddr *nam, struct mbuf *control, struct thread *td)
{
	KASSERT(sotomplsrawcb(so) == NULL, 
		("mpls_rtalert_send: mrp != NULL"));
	
	return (raw_usrreqs.pru_send(so, flags, m, nam, control, td));
}

static int
mpls_rtalert_shutdown(struct socket *so)
{
	KASSERT(sotomplsrawcb(so) == NULL, 
		("mpls_rtalert_shutdown: mrp != NULL"));	
	
	return (raw_usrreqs.pru_shutdown(so));
}

extern int	mpls_control(struct socket *, u_long, caddr_t, struct ifnet *,
    struct thread *);

/*
 * Defines interface accessing socket 
 * for processing by MPLS_LABEL_RTALERT 
 * annotated PDU.
 */ 

struct pr_usrreqs mpls_rtalert_usrreqs = {
	.pru_abort =		mpls_rtalert_abort,
	.pru_attach =		mpls_rtalert_attach,
	.pru_connect =		mpls_rtalert_connect,
	.pru_control =		mpls_control,
	.pru_detach =		mpls_rtalert_detach,
	.pru_disconnect =	mpls_rtalert_disconnect,
	.pru_send =			mpls_rtalert_send,
	.pru_shutdown =		mpls_rtalert_shutdown,
	.pru_close =		mpls_rtalert_close,
};

void	mpls_rtalert_input(struct mbuf *, int);
int	mpls_rtalert_output(struct mbuf *, struct socket *);

/*
 * Callback function, validates if controlblock maps to sockaddr{}.
 */
static int
raw_input_mpls_rtalert_cb(struct mbuf *m, struct sockproto *proto, 
		struct sockaddr *sa, struct rawcb *rp)
{
	struct mpls_rawcb *mrp;
	struct sockaddr_mpls *seg;
	int fibnum;

	KASSERT(m != NULL, ("%s: m is NULL", __func__));
	KASSERT(proto != NULL, ("%s: proto is NULL", __func__));
	KASSERT(src != NULL, ("%s: sa is NULL", __func__));
	KASSERT(rp != NULL, ("%s: rp is NULL", __func__));
	
	mrp = (struct mpls_rawcb *)rp;
	seg = satosmpls(sa);
	fibnum = M_GETFIB(m);
	if ((proto->sp_family != AF_MPLS) 
		|| (rp->rcb_socket == NULL) 
		|| (rp->rcb_socket->so_fibnum == fibnum))
		return (0);

	if (mrp->mrc_seg.smpls_label != seg->smpls_label)
		return (0);

	return (1);
}

/*
 * Remove MPLS_LABEL_RTALERT annotation and equeue pdu.
 */
void
mpls_rtalert_input(struct mbuf *m, int off)
{
	struct sockaddr_mpls seg = seg_rtalert;
	struct shim_hdr *shim;
		
	shim = mtod(m, struct shim_hdr *);
	seg.smpls_label = (shim->shim_label & MPLS_LABEL_MASK);
	raw_input_ext(m, &mpls_rtalert_proto, smplstosa(&seg), 
		raw_input_mpls_rtalert_cb);
}

/*
 * Inject by application layer processed pdu.
 */
int
mpls_rtalert_output(struct mbuf *m, struct socket *so)
{
	int error;
	struct shim_hdr	*shim;
	u_int8_t ttl;	

	error = EINVAL;
	
	if (so == NULL)
		goto bad;
	
	if (m == NULL) 
		goto bad;
	
	if ((m->m_flags & M_PKTHDR) == 0) 
		goto bad;
	
	if (m->m_flags & (M_BCAST|M_MCAST))
		goto bad;

	if (m->m_pkthdr.len < MPLS_HDRLEN) 
		goto bad;

	if (m->m_len < MPLS_HDRLEN) {
		if ((m = m_pullup(m, MPLS_HDRLEN)) == NULL) {
			error = ENOBUFS;
			goto done;
		}
	}
	error = 0;
	shim = mtod(m, struct shim_hdr *);
	ttl = ntohl(shim->shim_label & MPLS_TTL_MASK);
	if (ttl <= 1) 
		ttl = mpls_defttl;

	shim->shim_label &= ~MPLS_TTL_MASK;
	shim->shim_label |= htonl(ttl);

	netisr_dispatch(NETISR_MPLS_FWD, m);
done:
	return (error);
bad:
	m_freem(m);
	goto done;
}	

