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

struct node {
	int v;
	__capability void *hash;
	__capability struct node *l, *r;
};

static void	*malloc_wrapped(size_t size);

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
					    size_t size);
CHERI_GC_OBJECT_CCALL int		 cheri_gc_object_collect(void);
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
cheri_gc_object_malloc(size_t size)
{
	void *p;

	fprintf(stderr, "cheri_gc_object_malloc called\n");
	p = malloc_wrapped(size);
	if (p != NULL)
		return (cheri_ptr(p, size));
	else
		return (NULL);
}

int
cheri_gc_object_collect(void)
{

	fprintf(stderr, "cheri_gc_object_collect called\n");
	return (cherigc_collect());
}

static void *
malloc_wrapped(size_t size)
{
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

	return (p);
}

#define	QHASH2_INNER(a0, a1, a2, a3, h) do {				\
	int i;								\
	uint64_t p[12], t;						\
									\
	p[0] = a0;							\
	p[1] = ~(a0 >> 16) ^ (a0 << 48);				\
	p[2] = (a0 >> 32) ^ ~(a0 << 32);				\
	p[3] = (a0 >> 48) ^ (a0 << 16);					\
									\
	for (i = 4; i < 12; i++)					\
		p[i] = ((p[i - 4] ^ p[i - 1]) << 3) ^ p[i - 3];		\
									\
	for (i = 0; i < 12; i++) {					\
		t = (a0 << 1) ^ (a0 >> 63) ^				\
		    (a1 << 1) ^ (a1 >> 63) ^				\
		    (a2 >> 1) ^ (a2 << 63) ^				\
		    (a3 >> 1) ^ (a3 << 63);				\
		a3 = ~a2;						\
		a2 = ~(a1 >> 4) ^ (a1 << 60);				\
		a1 = (a0 >> 4) ^ (a0 << 8) ^				\
		    (a0 << 16) ^ (a0 << 32);				\
		a0 = ~t ^ p[i];						\
									\
		h += a0 + a1 + a2 + a3;					\
	}								\
} while (0)

static uint64_t
qhash2(uint64_t v)
{
	uint64_t a0, a1, a2, a3, h;

	a0 = v;
	a1 = 0;
	a2 = 0;
	a3 = 0;

	h = 0;
	QHASH2_INNER(a0, a1, a2, a3, h);

	return (h);
}

static uint64_t
qhash2cap(__capability void *c)
{
	uint64_t v;

	if (c == NULL)
		return (0);

	v = qhash2(cheri_getbase(c));
	v ^= qhash2(cheri_getlen(c));
	v ^= qhash2(cheri_getperm(c));
	v ^= qhash2(cheri_getsealed(c));
	v ^= qhash2(cheri_gettag(c));

	return (v);
}

/* Returns non-zero iff the two capabilities are equal. */
static int
capeq(__capability void *a, __capability void *b)
{

	if (a == NULL || b == NULL)
		return (a == NULL && b == NULL);

	return (cheri_gettag(a) == cheri_gettag(b) &&
	    cheri_getbase(a) == cheri_getbase(b) &&
	    cheri_getlen(a) == cheri_getlen(b) &&
	    cheri_getperm(a) == cheri_getperm(b) &&
	    cheri_getsealed(a) == cheri_getsealed(b));
}

/*
 * Return a hash for checking memory corruption. The hash combines:
 * - The integer value v stored at the node.
 * - For non-NULL children, the base, length, etc. of the pointers to them.
 * - For non-NULL children, their hashes (resulting in a chain).
 * In addition, the hash is itself an invalid but tagged capability with
 * the hash value itself spread over the base and length.
 */
static __capability void *
mkhash(__capability struct node *n)
{
	uint64_t v;

	v = qhash2(n->v);
	v ^= qhash2cap(n->l);
	if (n->l != NULL)
		v ^= qhash2cap(n->l->hash);
	if (n->l == n->r) {
		v ^= qhash2(v);
	} else {
		v ^= qhash2cap(n->r);
		if (n->r != NULL)
			v ^= qhash2cap(n->r->hash);
	}
	return (cheri_ptr((void *)(v & 0xFFFFFFFF), v >> 32));
}

/* Check the hash stored in n with one computed now using mkhash. */
static int
chkhash(__capability struct node *n)
{
	__capability void *hash;

	hash = mkhash(n);
	if (!capeq(hash, n->hash))
		return (-1);

	return (0);
}

/* Check the binary tree for memory corruption. */
static int
chktree(__capability struct node *n, int *vp, int depth)
{
	int rc, rc2;

	if (depth == 0)
		return (0);

	rc = 0;
	if (depth != 0 && n == NULL) {
		printf("depth check failed: NULL node at depth %d, v %d\n",
		    depth, *vp);
		rc = -1;
	}

	if (*vp <= depth)
		printf("checking tree, depth %d...\n", *vp);

	rc2 = chkhash(n);
	if (rc2 != 0)
		printf("hash check failed: node %p, depth %d, v %d\n",
		    (void *)n, depth, *vp);
	rc |= rc2;
	(*vp)++;
	rc |= chktree(n->l, vp, depth - 1);
	rc |= chktree(n->r, vp, depth - 1);

	return (rc);
}

/* Construct a special binary tree for testing memory corruption. */
static __capability struct node *
mktree(int *vp, int depth)
{
	__capability struct node *n;
	size_t sz;

	if (depth == 0)
		return (NULL);

	sz = sizeof(*n) * (*vp + 1);

	n = (__capability void *)malloc_wrapped(sz);
	n = (__capability void *)malloc_wrapped(sz);
	n->hash = (__capability void *)malloc_wrapped(sz);
	n->v = (*vp)++;
	n->l = (__capability void *)malloc_wrapped(sz);
	n->l = mktree(vp, depth - 1);
	n->r = (__capability void *)malloc_wrapped(sz);
	n->r = mktree(vp, depth - 1);
	n->hash = mkhash(n);
	return (n);
}

static void
printtree(__capability struct node *n, size_t tab)
{
	size_t i;

	if (n == NULL)
		return;

	for (i = 0; i < tab; i++)
		printf(" ");
	printf("p=%p v=%d h=[%zx, %zx]\n", (void *)n, n->v,
	    (size_t)cheri_getbase(n->hash), cheri_getlen(n->hash));
	printtree(n->l, tab + 1);
	printtree(n->r, tab + 1);
}

static int
do_bintree_test(void)
{
	__capability struct node *bintree_root;
	int bintree_depth, v, rc;

	bintree_depth = 3;
	printf("constructing a binary tree of depth %d\n", bintree_depth);
	v = 0;
	bintree_root = mktree(&v, bintree_depth);

	printtree(bintree_root, 0);

	cherigc_collect();

	v = 0;
	rc = chktree(bintree_root, &v, bintree_depth);
	if (rc != 0)
		printf("chktree failed\n");
	else
		printf("ok\n");
	return (0);
}

static __capability struct node *
mklist(int size)
{
	__capability struct node *n, *p;
	int i;

	p = NULL;
	for (i = 0; i < size; i++) {
		n = (__capability void *)malloc_wrapped(i + sizeof(*n));
		n = (__capability void *)malloc_wrapped(i * 500 + sizeof(*n));
		n = (__capability void *)malloc_wrapped(i * 500 + sizeof(*n));
		n->v = i;
		n->l = (__capability void *)malloc_wrapped(i);
		n->r = (__capability void *)malloc_wrapped(i);
		n->l = p;
		n->r = p;
		n->hash = mkhash(n);
		p = n;
	}

	return (n);
}

static int
chklist(__capability struct node *n, int size)
{
	int i;
	int rc, rc2;

	rc = 0;
	for (i = 0; i < size; i++) {
		if (n->v != size - 1 - i) {
			printf("linked list value check failed: o=%d e=%d\n",
			    n->v, size - 1 - i);
			rc = -1;
		}
		if (n->l != n->r) {
			printf("linked list child check failed: l=%p r=%p\n",
			    (void *)n->l, (void *)n->r);
			rc = -1;
		}
		if (n->l == NULL && i != size - 1) {
			printf("unexpected linked list NULL node at i=%d\n",
			    i);
			rc = -1;
		}
		if (n->l != NULL && i == size - 1) {
			printf("linked list not properly terminated\n");
			rc = -1;
		}
		rc2 = chkhash(n);
		if (rc2 != 0)
			printf("hash check failed: node %p, depth %d\n",
			    (void *)n, i);
		rc |= rc2;
		n = n->l;
	}

	return (rc);
}

static void
printlist(__capability struct node *n)
{

	for (; n != NULL; n = n->l)
		printf("p=%p v=%d h=[%zx, %zx] l=%p r=%p\n", (void *)n,
		    n->v, (size_t)cheri_getbase(n->hash),
		    cheri_getlen(n->hash), (void *)n->l, (void *)n->r);
}

static int
do_linked_list_test(void)
{
	__capability struct node *linked_list_root;
	int linked_list_size, rc;

	linked_list_size = 100;
	printf("constructing a linked list of size %d\n", linked_list_size);
	linked_list_root = mklist(linked_list_size);

	printlist(linked_list_root);

	printf("ll: before collect\n");
	rc = chklist(linked_list_root, linked_list_size);
	if (rc != 0) {
		printf("chklist failed\n");
		return (rc);
	} else
		printf("chklist ok (before collect)\n");

	cherigc_collect();
	printf("ll: after collect\n");

	printlist(linked_list_root);
	rc = chklist(linked_list_root, linked_list_size);
	if (rc != 0)
		printf("chklist failed\n");
	else
		printf("ok\n");

	printf("=======BEGIN REFCHECK======\n");
	printf("checking refs to %p\n", (void *)linked_list_root->l);
	printf("refs: %d\n", cherigc_getrefs((void *)linked_list_root->l));

	return (0);
}

static int
do_revoke_test(void)
{
#define	REVOKE_BUFSZ		100
#define	REVOKE_TREEDEPTH	5
#define	REVOKE_LISTSZ		10
	__capability void *buf[REVOKE_BUFSZ];
	__capability void *tohide;
	__capability void *n;
	__capability void *l;
	__capability void *c0, *c1, *c2, *c3, *c4, *c5, *c6, *c7, *c8, *c9;
	__capability void *c10, *c11, *c12, *c13, *c14, *c15, *c16, *c17;
	__capability void *c18, *c19, *c20, *c21, *c22, *c23, *c24, *c25;
	__capability void *c26, *c27, *c28, *c29, *c30, *c31;
	volatile __capability struct node *t;
	uint64_t addr;
	size_t i;
	int v, rc, refs;

	printf("revoke test: allocating some stuff...\n");
	for (i = 0; i < REVOKE_BUFSZ; i++)
		buf[i] = (__capability void *)malloc_wrapped(i * 500);

	tohide = buf[REVOKE_BUFSZ / 2];

	/* Save address of hidden capability for checking later. */
	t = tohide;
	addr = (uint64_t)(volatile void *)t;

	printf("hiding %p in hard-to-find places.\n", (void *)tohide);
	/* Hide in a binary tree. */
	v = 0;
	n = mktree(&v, REVOKE_TREEDEPTH);
	t = n;
	for (i = (1 << (REVOKE_TREEDEPTH - 1)); i != 0; i >>= 1)
		if (i & 1) {
			printf("following left node\n");
			if (t->l == NULL)
				break;
			t = t->l;
		} else {
			printf("following right node\n");
			if (t->r == NULL)
				break;
			t = t->r;
		}
	t->hash = tohide;
	t = t->l;
	t = NULL;

	/* Hide in a linked list. */
	l = mklist(REVOKE_LISTSZ);
	t = l;
	for (i = 0; i < REVOKE_LISTSZ / 2; i++) {
		(void)malloc_wrapped(i);
		t = t->l;
	}
	t->hash = tohide;
	t = t->r;
	t = NULL;

	/* Clear away obvious roots. */
#define CLR_ROOTS							\
	c0 = cheri_ptr((void *)0, 0);					\
	c1 = cheri_ptr((void *)1, 1);					\
	c2 = cheri_ptr((void *)2, 2);					\
	c3 = cheri_ptr((void *)3, 3);					\
	c4 = cheri_ptr((void *)4, 4);					\
	c5 = cheri_ptr((void *)5, 5);					\
	c6 = cheri_ptr((void *)6, 6);					\
	c7 = cheri_ptr((void *)7, 7);					\
	c8 = cheri_ptr((void *)8, 8);					\
	c9 = cheri_ptr((void *)9, 9);					\
	c10 = cheri_ptr((void *)10, 10);				\
	c11 = cheri_ptr((void *)11, 11);				\
	c12 = cheri_ptr((void *)12, 12);				\
	c13 = cheri_ptr((void *)13, 13);				\
	c14 = cheri_ptr((void *)14, 14);				\
	c15 = cheri_ptr((void *)15, 15);				\
	c16 = cheri_ptr((void *)16, 16);				\
	c17 = cheri_ptr((void *)17, 17);				\
	c18 = cheri_ptr((void *)18, 18);				\
	c19 = cheri_ptr((void *)19, 19);				\
	c20 = cheri_ptr((void *)20, 20);				\
	c21 = cheri_ptr((void *)21, 21);				\
	c22 = cheri_ptr((void *)22, 22);				\
	c23 = cheri_ptr((void *)23, 23);				\
	c24 = cheri_ptr((void *)24, 24);				\
	c25 = cheri_ptr((void *)25, 25);				\
	c26 = cheri_ptr((void *)26, 26);				\
	c27 = cheri_ptr((void *)27, 27);				\
	c28 = cheri_ptr((void *)28, 28);				\
	c29 = cheri_ptr((void *)29, 29);				\
	c30 = cheri_ptr((void *)30, 30);				\
	c31 = cheri_ptr((void *)31, 31);				\
	printf("%p\n", (void *)c0);					\
	printf("%p\n", (void *)c1);					\
	printf("%p\n", (void *)c2);					\
	printf("%p\n", (void *)c3);					\
	printf("%p\n", (void *)c4);					\
	printf("%p\n", (void *)c5);					\
	printf("%p\n", (void *)c6);					\
	printf("%p\n", (void *)c7);					\
	printf("%p\n", (void *)c8);					\
	printf("%p\n", (void *)c9);					\
	printf("%p\n", (void *)c10);					\
	printf("%p\n", (void *)c11);					\
	printf("%p\n", (void *)c12);					\
	printf("%p\n", (void *)c13);					\
	printf("%p\n", (void *)c14);					\
	printf("%p\n", (void *)c15);					\
	printf("%p\n", (void *)c16);					\
	printf("%p\n", (void *)c17);					\
	printf("%p\n", (void *)c18);					\
	printf("%p\n", (void *)c19);					\
	printf("%p\n", (void *)c20);					\
	printf("%p\n", (void *)c21);					\
	printf("%p\n", (void *)c22);					\
	printf("%p\n", (void *)c23);					\
	printf("%p\n", (void *)c24);					\
	printf("%p\n", (void *)c25);					\
	printf("%p\n", (void *)c26);					\
	printf("%p\n", (void *)c27);					\
	printf("%p\n", (void *)c28);					\
	printf("%p\n", (void *)c29);					\
	printf("%p\n", (void *)c30);					\
	printf("%p\n", (void *)c31);
	CLR_ROOTS

	/*
	 * Count existing refs. Should have at least three (array, bintree,
	 * list), and not many more than three.
	 */
	refs = cherigc_getrefs((void *)tohide);
	if (refs < 3) {
		printf("ERROR: <3 refs\n");
		return (-1);
	} else if (refs > 5) {
		printf("ERROR: >5 refs\n");
		return (-1);
	}
	printf("%d refs\n", refs);

	/* Revoke the capability we want to hide. */
	rc = cherigc_revoke((void *)tohide);
	if (rc != 0) {
		printf("ERROR: cherigc_revoke\n");
		return (-1);
	}

	/*
	 * Force collection, but ensure GC keeps around enough information
	 * to determine whether tohide really was revoked.
	 */
	cherigc->gc_revoke_debugging = 1;
	rc = cherigc_collect();
	if (rc != 0) {
		printf("ERROR: cherigc_collect\n");
		return (-1);
	}
	cherigc->gc_revoke_debugging = 0;

	/* Now check that it really has been revoked. */
	refs = cherigc_getrefs((void *)addr);
	if (refs != 0) {
		printf("ERROR: cap not revoked! %d refs!\n", refs);
		return (-1);
	}
	printf("revoke ok: 0 refs\n");

	return (0);
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

int
main(void)
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

	cherigc_collect();

	rc = cherigc_ctl(CHERIGC_CTL_SET, CHERIGC_KEY_NALLOC, &sval);
	if (rc != 0) {
		fprintf(stderr, "cherigc_ctl: %d\n", rc);
		return (rc);
	}
	printf("nalloc: %zu\n", sval);

	(void)do_bintree_test;
	(void)do_linked_list_test;
	(void)do_revoke_test;

	(void)rc;
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
		p = cheri_ptr(malloc_wrapped(i * 500), i);
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
