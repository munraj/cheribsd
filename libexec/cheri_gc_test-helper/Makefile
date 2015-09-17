# $FreeBSD$

PROG=cheri_gc_test-helper
SRCS=gc_test-helper.c

LDFLAGS+=	-Wl,--script=${.CURDIR}/../../lib/libc_cheri/sandbox.ld	\
		-nostdlib
MAN=

LIBADD=c_cheri

NEED_CHERI=pure
WANT_DUMP=yes
NO_SHARED=yes

.include <bsd.prog.mk>
