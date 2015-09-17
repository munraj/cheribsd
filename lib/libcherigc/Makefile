#
# $FreeBSD$
#

LIB=		cherigc
SRCS=		cherigc.c

MAN=
NEED_CHERI=	hybrid
NO_SHARED=	yes
CFLAGS=		-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/../../contrib/jemalloc/include/jemalloc/internal -I${.CURDIR}/../libc/include -I${.CURDIR}/../../contrib/jemalloc/include
CFLAGS+=	-g
.include <bsd.lib.mk>
