# $FreeBSD: releng/10.1/sys/modules/if_bridge/Makefile 160730 2006-07-26 22:15:15Z thompsa $

.include <bsd.own.mk>

.PATH:	${.CURDIR}/../../net
KMOD=	if_mpe
SRCS=	if_mpe.c opt_mpls.h opt_mpls_debug.h \
			opt_inet.h opt_inet6.h

.if !defined(KERNBUILDDIR)
opt_inet.h:
	echo "#define INET 1" > ${.TARGET}
	
.if ${MK_INET6_SUPPORT} != "no"
opt_inet6.h:
	echo "#define INET6 1" > ${.TARGET}
.endif
.endif

.include <bsd.kmod.mk>
