#define malloc_wrapped(sz) malloc_wrapped2((sz), __FILE__, __LINE__)

struct node {
	int v;
	__capability void *hash;
	__capability struct node *l, *r;
};

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
	__capability void *h;
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

	h = mkcap((void *)(v & 0xFFFFFFFF), v >> 32);
#ifndef TAGGED_HASHES
	h = cheri_cleartag(h);
#endif
	return (h);
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

	printf("Checking tree, depth %d, node %d...\n", depth, *vp);

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

	n = malloc_wrapped(sz);
	n = malloc_wrapped(sz);
	n->hash = malloc_wrapped(sz);
	n->v = (*vp)++;
	n->l = malloc_wrapped(sz);
	n->l = mktree(vp, depth - 1);
	n->r = malloc_wrapped(sz);
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
	__capability struct node *bintree_roots[128];
	int bintree_depth, v, rc, orig_track_unmanaged, val;

#ifdef TAGGED_HASHES
	/*
	 * We'll create lots of invalid but tagged capabilities in our hash
	 * function, so make sure the GC doesn't bother scanning them.
	 */
	rc = cherigc_ctl(CHERIGC_CTL_GET, CHERIGC_KEY_TRACK_UNMANAGED,
	    &orig_track_unmanaged);
	if (rc != 0) {
		printf("ERROR: cherigc_ctl\n");
		return (-1);
	}
	val = 0;
	rc = cherigc_ctl(CHERIGC_CTL_SET, CHERIGC_KEY_TRACK_UNMANAGED,
	    &val);
	if (rc != 0) {
		printf("ERROR: cherigc_ctl\n");
		return (-1);
	}
#else
	(void)val;
	(void)orig_track_unmanaged;
#endif

	bintree_depth = 10;
	printf("constructing a binary tree of depth %d\n", bintree_depth);
	v = 0;
	bintree_root = mktree(&v, bintree_depth);

	printtree(bintree_root, 0);

	bintree_roots[0] = bintree_root;
	printf("bintree roots: %p\n", bintree_roots);
	cherigc_collect();

	v = 0;
	rc = chktree(bintree_root, &v, bintree_depth);
	if (rc != 0)
		printf("chktree failed\n");
	else
		printf("ok\n");


#ifdef TAGGED_HASHES
	/* Restore the track unmanaged state. */
	rc = cherigc_ctl(CHERIGC_CTL_SET, CHERIGC_KEY_TRACK_UNMANAGED,
	    &orig_track_unmanaged);
	if (rc != 0) {
		printf("ERROR: cherigc_ctl\n");
		return (-1);
	}
#endif

	return (0);
}

static __capability struct node *
mklist(int size)
{
	__capability struct node *n, *p;
	int i;

	p = NULL;
	for (i = 0; i < size; i++) {
		n = malloc_wrapped(i + sizeof(*n));
		n = malloc_wrapped(i * 500 + sizeof(*n));
		n = malloc_wrapped(i * 500 + sizeof(*n));
		n->v = i;
		n->l = malloc_wrapped(i);
		n->r = malloc_wrapped(i);
		n->l = p;
		n->r = p;
		n->hash = mkhash(n);
		p = n;
	}

	return (n);
}

static __capability struct node *
mklonglist(int size)
{
	__capability struct node *n, *p;
	int i;

	p = NULL;
	for (i = 0; i < size; i++) {
		n = malloc_wrapped(i + sizeof(*n));
		n = malloc_wrapped(i + sizeof(*n));
		n = malloc_wrapped(i + sizeof(*n));
		n->v = i;
		n->l = malloc_wrapped(i);
		n->r = malloc_wrapped(i);
		n->l = p;
		n->r = p;
		n->hash = mkhash(n);
		p = n;
	}

	return (n);
}

static __capability void * __capability *
mkarray(int size)
{
	__capability void * __capability *a;
	int i;

	a = (__capability void * __capability *)malloc_wrapped(size * sizeof(*a));
	for (i = 0; i < size; i++)
		a[i] = malloc_wrapped(64);

	return (a);
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
/*#define	REVOKE_ARRAYSZ		100000
#define	REVOKE_TREEDEPTH	10
#define	REVOKE_LISTSZ		10000*/
#define	REVOKE_ARRAYSZ		1000
#define	REVOKE_TREEDEPTH	10
#define	REVOKE_LISTSZ		1000
	__capability void * __capability *a;
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
	int v, rc, refs, val;

	/*printf("revoke test: &n is %p, base=%lx, offset=%lx\n", &n, cheri_getbase(&n), cheri_getoffset(&n));
	a=(__capability void*)&n;cherigc_revoke(a);
	n=(__capability void*)malloc(100);printf("revoke test: malloc(100) is base=%lx, offset=%lx\n", cheri_getbase(n), cheri_getoffset(n));*/

	printf("revoke test: mkarray\n");
	a = mkarray(REVOKE_ARRAYSZ);

	tohide = a[REVOKE_ARRAYSZ / 2];

	/* Save address of hidden capability for checking later. */
	t = tohide;
	addr = (uint64_t)cheri_getbase(tohide);
	t = tohide;

	printf("revoke test: hiding %" PRIx64 " in hard-to-find places.\n", addr);

	/* Hide in a binary tree. */
	printf("revoke test: mktree\n");
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
	printf("revoke test: mklist\n");
	l = mklonglist(REVOKE_LISTSZ);
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
	c0 = mkcap((void *)1, 1);					\
	c1 = mkcap((void *)1, 1);					\
	c2 = mkcap((void *)2, 2);					\
	c3 = mkcap((void *)3, 3);					\
	c4 = mkcap((void *)4, 4);					\
	c5 = mkcap((void *)5, 5);					\
	c6 = mkcap((void *)6, 6);					\
	c7 = mkcap((void *)7, 7);					\
	c8 = mkcap((void *)8, 8);					\
	c9 = mkcap((void *)9, 9);					\
	c10 = mkcap((void *)10, 10);				\
	c11 = mkcap((void *)11, 11);				\
	c12 = mkcap((void *)12, 12);				\
	c13 = mkcap((void *)13, 13);				\
	c14 = mkcap((void *)14, 14);				\
	c15 = mkcap((void *)15, 15);				\
	c16 = mkcap((void *)16, 16);				\
	c17 = mkcap((void *)17, 17);				\
	c18 = mkcap((void *)18, 18);				\
	c19 = mkcap((void *)19, 19);				\
	c20 = mkcap((void *)20, 20);				\
	c21 = mkcap((void *)21, 21);				\
	c22 = mkcap((void *)22, 22);				\
	c23 = mkcap((void *)23, 23);				\
	c24 = mkcap((void *)24, 24);				\
	c25 = mkcap((void *)25, 25);				\
	c26 = mkcap((void *)26, 26);				\
	c27 = mkcap((void *)27, 27);				\
	c28 = mkcap((void *)28, 28);				\
	c29 = mkcap((void *)29, 29);				\
	c30 = mkcap((void *)30, 30);				\
	c31 = mkcap((void *)31, 31);				\
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
	(void)c0;
	(void)c1;
	(void)c2;
	(void)c3;
	(void)c4;
	(void)c5;
	(void)c6;
	(void)c7;
	(void)c8;
	(void)c9;
	(void)c10;
	(void)c11;
	(void)c12;
	(void)c13;
	(void)c14;
	(void)c15;
	(void)c16;
	(void)c17;
	(void)c18;
	(void)c19;
	(void)c20;
	(void)c21;
	(void)c22;
	(void)c23;
	(void)c24;
	(void)c25;
	(void)c26;
	(void)c27;
	(void)c28;
	(void)c29;
	(void)c30;
	(void)c31;

	/*
	 * Count existing refs. Should have at least three (array, bintree,
	 * list), and not many more than three.
	 */
	printf("revoke test: getrefs before revoke\n");
	refs = cherigc_getrefs_uint64(addr);
	if (refs < 3) {
		printf("ERROR: <3 refs (%d)\n", refs);
		return (-1);
	} else if (refs > 10) {
		printf("ERROR: >10 refs (%d)\n", refs);
		return (-1);
	}
	printf("for %" PRIx64 ", %d refs\n", addr, refs);

	val = 0;
	rc = cherigc_ctl(CHERIGC_CTL_SET, CHERIGC_KEY_REVOKE_DEBUGGING,
	    &val);
	if (rc != 0) {
		printf("ERROR: cherigc_ctl\n");
		return (-1);
	}

	/* Revoke the capability we want to hide. */
	printf("revoke test: revoke\n");
	rc = cherigc_revoke(tohide);
	if (rc != 0) {
		printf("ERROR: cherigc_revoke\n");
		return (-1);
	}

	/*
	 * Force collection, but ensure GC keeps around enough information
	 * to determine whether tohide really was revoked.
	 */
	val = 1;
	rc = cherigc_ctl(CHERIGC_CTL_SET, CHERIGC_KEY_REVOKE_DEBUGGING,
	    &val);
	if (rc != 0) {
		printf("ERROR: cherigc_ctl\n");
		return (-1);
	}

	printf("revoke test: collect\n");
	rc = cherigc_collect();
	if (rc != 0) {
		printf("ERROR: cherigc_collect\n");
		return (-1);
	}

	val = 0;
	rc = cherigc_ctl(CHERIGC_CTL_SET, CHERIGC_KEY_REVOKE_DEBUGGING,
	    &val);
	if (rc != 0) {
		printf("ERROR: cherigc_ctl\n");
		return (-1);
	}

	/*
	 * Check that the root of the tree is still around, and the
	 * root of the linked list.
	 */
	printf("revoke test: gettag tree\n");
	if (!cheri_gettag(n)) {
		printf("ERROR: bintree node gone! no tag!\n");
		return (-1);
	}
	printf("revoke test: getrefs tree\n");
	refs = cherigc_getrefs_uint64(cheri_getbase(n));
	if (refs <= 0) {
		printf("ERROR: bintree node gone! %d refs!\n", refs);
		return (-1);
	}
	printf("revoke test: %d refs to bintree root\n", refs);

	printf("revoke test: gettag list\n");
	if (!cheri_gettag(l)) {
		printf("ERROR: linked list head gone! no tag!\n");
		return (-1);
	}
	printf("revoke test: getrefs list\n");
	refs = cherigc_getrefs_uint64(cheri_getbase(l));
	if (refs <= 0) {
		printf("ERROR: linked list head gone! %d refs!\n", refs);
		return (-1);
	}
	printf("revoke test: %d refs to list root\n", refs);

	/* Now check that it really has been revoked. */
	/*
	 * XXX: From within a sandbox, we can't reconstruct the revoked
	 * capability; therefore, we pass an integer pointer, and
	 * reonstruct it on the ambient side.
	 */
	printf("revoke test: getrefs tohide\n");
	refs = cherigc_getrefs_uint64(addr);
	if (refs != 0) {
		printf("ERROR: cap not revoked! %d refs!\n", refs);
		return (-1);
	}

	printf("revoke test: ok: 0 refs\n");

	return (0);
}
