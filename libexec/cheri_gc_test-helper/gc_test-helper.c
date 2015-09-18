#include <stdio.h>
#include <stdlib.h>

#include <machine/cheri.h>
#include <machine/cheric.h>

#include <cheri/sandbox.h>

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
					    size_t size);

int	invoke(void) __attribute__((cheri_ccall));
int
invoke(void)
{

	return (-1);
}

int
invoke_helper(struct cheri_object cheri_gc)
{

	printf("start inside invoke_helper %lx\n", cheri_getoffset(cheri_gc.co_codecap));
	(void)cheri_gc_object_malloc_c(cheri_gc, 100);
	printf("test from inside invoke_helper\n");

	return (1234789);
}
