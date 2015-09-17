# $FreeBSD$

.PATH: ${LIBC_SRCTOP}/../libcherigc

#CHERIGCSRCS:=	cherigc.c

# XXX: MISRCS?
#MDSRCS+=	${CHERIGCSRCS}
#CLEANFILES+=	${CHERIGCSRCS:S/.c$/.o/}

CFLAGS+=	-DCHERIGC -I${LIBC_SRCTOP}/../libcherigc
