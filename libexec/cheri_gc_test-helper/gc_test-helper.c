#include <machine/cheri.h>
#include <machine/cheric.h>

#include <cheri/sandbox.h>

extern struct cheri_object cheri_gc_test;
#define	CHERI_GC_TEST_CCALL						\
	__attribute__((cheri_ccallee))					\
	__attribute__((cheri_method_class(cheri_gc_test)))
CHERI_GC_TEST_CCALL int	invoke_helper(void);

int	invoke(void) __attribute__((cheri_ccall));
int
invoke(void)
{

	return (-1);
}

int
invoke_helper(void)
{

	return (1234789);
}
