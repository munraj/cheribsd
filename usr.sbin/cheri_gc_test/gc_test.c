#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#include <err.h>
#include <fcntl.h>
#include <unistd.h>

#include <machine/cheri.h>
#include <machine/cheric.h>

#include <cheri/cheri_class.h>
#include <cheri/cheri_type.h>
#include <cheri/sandbox.h>
#include <cheri/sandbox_methods.h>

#include <cherigc.h>
#include <cherigc_ctl.h>

static __capability void	*malloc_wrapped2(size_t size,
				    const char *file, int line);

/* Helper sandbox (for ambient -> sandbox calls). */
struct cheri_object cheri_gc_test;
#define	CHERI_GC_TEST_CCALL						\
	__attribute__((cheri_ccall))					\
	__attribute__((cheri_method_suffix("_cap")))			\
	__attribute__((cheri_method_class(cheri_gc_test)))
CHERI_GC_TEST_CCALL int	invoke_helper(struct cheri_object cheri_gc);
struct sandbox_class	*cheri_gc_test_classp;
struct sandbox_object	*cheri_gc_test_objectp;

/* GC object (for sandbox -> ambient calls). */
extern struct cheri_object cheri_gc_object;
#define	CHERI_GC_OBJECT_CCALL						\
	__attribute__((cheri_ccallee))					\
	__attribute__((cheri_method_suffix("_c")))			\
	__attribute__((cheri_method_class(cheri_gc_object)))
CHERI_GC_OBJECT_CCALL __capability void	*cheri_gc_object_malloc(
					    size_t size,
					    __capability const char *file,
					    int line);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_collect(void);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_ctl(int cmd,
					    int key,
					    __capability void *val);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_getrefs(
					    __capability void *p);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_revoke(
					    __capability void *p);
CHERI_CLASS_DECL(cheri_gc_object);
static __capability void	*cheri_gc_object_type;
__capability intptr_t		*cheri_gc_object_vtable;
struct cheri_gc_object {
	CHERI_SYSTEM_OBJECT_FIELDS;
};
int	cheri_gc_object_new(struct cheri_object *cop);
struct cheri_object		cheri_gc;
static struct sandbox_provided_classes	*cheri_gc_object_provided_classes;
static struct sandbox_required_methods	*cheri_gc_object_required_methods;

int
cheri_gc_object_new(struct cheri_object *cop)
{
	struct cheri_gc_object *cgp;

	cgp = calloc(1, sizeof(*cgp));
	if (cgp == NULL)
		return (-1);
	CHERI_SYSTEM_OBJECT_INIT(cgp, cheri_gc_object_vtable);

	cop->co_codecap = cheri_setoffset(cheri_getpcc(),
	    (register_t)CHERI_CLASS_ENTRY(cheri_gc_object));
	cop->co_codecap = cheri_seal(cop->co_codecap,
	    cheri_gc_object_type);
	cop->co_datacap = cheri_ptrperm(cgp, sizeof(*cgp),
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |
	    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP);
	cop->co_datacap = cheri_seal(cop->co_datacap, cheri_gc_object_type);

	return (0);
}

static __attribute__ ((constructor)) void
cheri_gc_object_init(void)
{

	cheri_gc_object_type = cheri_type_alloc();
}

__capability void *
cheri_gc_object_malloc(size_t size, __capability const char *file,
    int line)
{

	fprintf(stderr, "cheri_gc_object_malloc called\n");
	return (malloc_wrapped2(size, (const void *)file, line));
}

int
cheri_gc_object_collect(void)
{

	fprintf(stderr, "cheri_gc_object_collect called\n");
	return (cherigc_collect());
}

int
cheri_gc_object_ctl(int cmd, int key, __capability void *val)
{

	fprintf(stderr, "cheri_gc_object_ctl called\n");
	return (cherigc_ctl(cmd, key, (void *)val));
}

int
cheri_gc_object_getrefs(__capability void *p)
{

	fprintf(stderr, "cheri_gc_object_getrefs called\n");
	return (cherigc_getrefs((void *)p));
}

int
cheri_gc_object_revoke(__capability void *p)
{

	fprintf(stderr, "cheri_gc_object_revoke called\n");
	return (cherigc_revoke((void *)p));
}

static __capability void *
malloc_wrapped2(size_t size, const char *file, int line)
{
	__capability void *c;
	void *p;

	if (size < CHERIGC_MINSIZE) {
		printf("malloc_wrapped: rounding up %zu to %zu\n", size,
		    CHERIGC_MINSIZE);
		size = CHERIGC_MINSIZE;
	}

	p = malloc(size);

	if (p == NULL) {
		printf("malloc_wrapped: out of memory\n");
		exit(1);
	}

	printf("malloc_wrapped2: %p @ %s:%d\n", p, file, line);

	c = cheri_ptr(p, size);

	return (c);
}

/* XXX: Copied from sandbox_program_init() in libcheri/sandbox.c. */
static int
cheri_gc_object_init_vtable(void)
{
	int fd = -1;
	int mib[4];
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;
	char buf[MAXPATHLEN];
	size_t cb = sizeof(buf);

	/* XXXBD: do this with RTLD or hypothentical getexecfd(). */
	if ((sysctl(mib, 4, buf, &cb, NULL, 0) != -1) && cb > 0) {
		if ((fd = open(buf, O_RDONLY)) == -1)
			warn("%s: open %s (from kern.proc.pathname.(-1))",
			    __func__, buf);
	}

	if (sandbox_parse_ccall_methods(fd,
	    &cheri_gc_object_provided_classes,
	    &cheri_gc_object_required_methods) == -1) {
		warn("%s: sandbox_parse_ccall_methods for cheri_gc_object",
		    __func__);
		close(fd);
		return (-1);
	}
	if (sandbox_set_required_method_variables(cheri_getdefault(),
	    cheri_gc_object_required_methods) == -1) {
		warnx("%s: sandbox_set_required_method_variables for "
		    "cheri_gc_object", __func__);
		return (-1);
	}
	cheri_gc_object_vtable = sandbox_make_vtable(NULL,
	    "cheri_gc_object", cheri_gc_object_provided_classes);
	close(fd);
	return (0);

}

static int
do_libcheri_init(void)
{
	int rc;

	/* Initialize sandbox (for ambient -> sandbox calls). */
	rc = sandbox_class_new("/tmp2/cheri_gc_test-helper",
	    4 * 1024 * 1024, &cheri_gc_test_classp);
	if (rc != 0) {
		fprintf(stderr, "sandbox_class_new: %d\n", rc);
		return (rc);
	}

	rc = sandbox_object_new(cheri_gc_test_classp, 2 * 1024 * 1024,
	    &cheri_gc_test_objectp);
	if (rc != 0) {
		fprintf(stderr, "sandbox_object_new: %d\n", rc);
		return (rc);
	}

	/* Initialize a GC object (for sandbox -> ambient calls). */
	/*
	 * The vtable stuff is global and only requires initialization
	 * once.
	 */
	rc = cheri_gc_object_init_vtable();
	if (rc != 0) {
		fprintf(stderr, "cheri_gc_object_init_vtable: %d\n", rc);
		return (rc);
	}
	rc = cheri_gc_object_new(&cheri_gc);
	if (rc != 0) {
		fprintf(stderr, "cheri_gc_object_new: %d\n", rc);
		return (rc);
	}

	return (0);
}

#define mkcap	cheri_ptr
#define	TAGGED_HASHES
#include "gc_tests.c"

static int
do_sandbox_test(void)
{
	size_t sval;
	int rc, val;

	/* Disable collection for libcheri allocations (treat these
	 * allocations as roots), since they will not be reachable
	 * otherwise (they are not all stored as capabilities).
	 */
	val = 1;
	rc = cherigc_ctl(CHERIGC_CTL_SET, CHERIGC_KEY_IGNORE, &val);
	if (rc != 0) {
		fprintf(stderr, "cherigc_ctl: %d\n", rc);
		return (rc);
	}

	rc = do_libcheri_init();
	if (rc != 0)
		return (rc);
	(void)do_libcheri_init;

	/* Enable collection for future allocations. */
	val = 0;
	rc = cherigc_ctl(CHERIGC_CTL_SET, CHERIGC_KEY_IGNORE, &val);
	if (rc != 0) {
		fprintf(stderr, "cherigc_ctl: %d\n", rc);
		return (rc);
	}

	printf("call invoke_helper\n");
	rc = invoke_helper_cap(sandbox_object_getobject(cheri_gc_test_objectp),
	    cheri_gc);
	printf("rc from invoke_helper: %d\n", rc);

	rc = cherigc_ctl(CHERIGC_CTL_GET, CHERIGC_KEY_NALLOC, &sval);
	if (rc != 0) {
		fprintf(stderr, "cherigc_ctl: %d\n", rc);
		return (rc);
	}
	printf("nalloc: %zu\n", sval);

	return (0);
}

int
main(void)
{

	(void)do_sandbox_test();
	(void)do_bintree_test;
	(void)do_linked_list_test;
	(void)do_revoke_test;

	return (0);
}

__unused static int
old_main(void)
{
#define	PPMAX	10
	int i, j;
	__capability void *p, *pp[PPMAX];

	fprintf(stderr, "hello\n");

	volatile __capability void *reg2 = cheri_ptr((void *)0xDEADBEE, 0x34343434);
	__asm__ __volatile__ ("cmove $c4, %0" : : "C"(reg2) : "memory", "$c4");

	for (i = 0; i < PPMAX; i++) {
		if (i == 25)
			fprintf(stderr, "added %p\n", mmap(NULL, 100, PROT_READ, MAP_ANON, -1, 0));
		p = malloc_wrapped(i * 500);
		pp[i] = p;
		fprintf(stderr, "[%d] %p\n", i, (void *)p);
		if (i>1) *(__capability void **)((uintptr_t)p & ~(uintptr_t)31) = cheri_ptr((void *)0x1234, 0x5678);
		if (i == PPMAX - 1) {
			*(__capability void **)p = cheri_ptr((void *)0x1234, 0x5678);
			for (j = 0; j < PPMAX; j++)
				((__capability void **)pp[PPMAX - 1])[j + 1] = cheri_ptr((void *)pp[j], j);
		}
	}

	volatile __capability void *reg = cheri_ptr((void *)0xDEADBEED, 0x23232323);
	__asm__ __volatile__ ("cmove $c4, %0" : : "C"(reg) : "memory", "$c4");
	__asm__ __volatile__ ("" ::: "memory");
	cherigc_collect();
	//cherigc_scan_region((void *)pp[PPMAX - 1], CHERIGC_PAGESIZE);

	(void)reg;
	return (0);
}
