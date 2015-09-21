#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <machine/cheri.h>
#include <machine/cheric.h>

#include <cheri/sandbox.h>

#include "../../lib/libcherigc/cherigc_ctl.h"

/* Our methods (ambient -> sandbox calls). */
extern struct cheri_object cheri_gc_test;
#define	CHERI_GC_TEST_CCALL						\
	__attribute__((cheri_ccallee))					\
	__attribute__((cheri_method_class(cheri_gc_test)))
CHERI_GC_TEST_CCALL int	invoke_helper(struct cheri_object cheri_gc);

/* External methods (sandbox -> ambient calls). */
struct cheri_object cheri_gc_object;
#define	CHERI_GC_OBJECT_CCALL						\
	__attribute__((cheri_ccall))					\
	__attribute__((cheri_method_suffix("_c")))			\
	__attribute__((cheri_method_class(cheri_gc_object)))
CHERI_GC_OBJECT_CCALL __capability void	*cheri_gc_object_malloc(
					    size_t size, const char *file,
					    int line);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_collect(void);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_ctl(int cmd,
					    int key, void *val);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_getrefs(void *p);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_getrefs_uint64(
					    uint64_t addr);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_revoke(void *p);
struct cheri_object cheri_gc;

int	invoke(void) __attribute__((cheri_ccall));
int
invoke(void)
{

	return (-1);
}

static void *
malloc_wrapped2(size_t sz, const char *file, int line)
{

	return (cheri_gc_object_malloc_c(cheri_gc, sz, file, line));
}

static int
cherigc_collect(void)
{

	return (cheri_gc_object_collect_c(cheri_gc));
}

static int
cherigc_ctl(int cmd, int key, void *val)
{

	return (cheri_gc_object_ctl_c(cheri_gc, cmd, key, val));
}

static int
cherigc_getrefs(void *p)
{

	return (cheri_gc_object_getrefs_c(cheri_gc, p));
}

static int
cherigc_getrefs_uint64(uint64_t addr)
{

	return (cheri_gc_object_getrefs_uint64_c(cheri_gc, addr));
}

static int
cherigc_revoke(void *p)
{

	return (cheri_gc_object_revoke_c(cheri_gc, p));
}

#define mkcap(p, n) ((__capability void *)(p))
#undef	TAGGED_HASHES
#include "../../usr.sbin/cheri_gc_test/gc_tests.c"

int
invoke_helper(struct cheri_object _cheri_gc)
{
	void *p;
	cheri_gc = _cheri_gc;

	/* Simple sandbox test. */
	/*printf("start inside invoke_helper %lx\n", cheri_getoffset(cheri_gc.co_codecap));
	p = malloc_wrapped(100);
	printf("(in sandbox) malloc gave ptr: %lx\n", cheri_getbase(p));
	printf("(in sandbox) ptr tag: %lu\n", cheri_gettag(p));

	printf("(in sandbox) perform collection\n");
	(void)cheri_gc_object_collect_c(cheri_gc);
	printf("(in sandbox) done. pointer tag now: %lu\n", cheri_gettag(p));*/
	(void)p;

	(void)do_bintree_test;
	(void)do_linked_list_test;
	(void)do_revoke_test();

	return (1234789);
}
