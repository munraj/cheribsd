# $FreeBSD$

PROG=cheri_gc_test
SRCS=gc_test.c								\
	gc_test_libcheri_classes.S

OBJDIR=${MAKEOBJDIRPREFIX}

MAN=
NEED_CHERI=hybrid
NO_SHARED=yes
CFLAGS=-g -I${.CURDIR}/../../lib/libcherigc
LDADD=-L${OBJDIR}/${.CURDIR}/../../lib/libc ${OBJDIR}/${.CURDIR}/../../lib/libc/libc.a ${OBJDIR}/${.CURDIR}/../../lib/libcherigc/libcherigc.a
# procstat and deps
LDADD+=../../lib/libprocstat/libprocstat.a ../../lib/libelf/libelf.a	\
	../../lib/libkvm/libkvm.a ../../lib/libutil/libutil.a
# pthreads
LDADD+=-pthread
LDADD+=-lcheri

.include <bsd.prog.mk>
