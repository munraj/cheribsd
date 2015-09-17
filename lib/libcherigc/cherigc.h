#ifndef _CHERIGC_H_
#define _CHERIGC_H_

#include <stdint.h>
#include <stdlib.h>

/* Configurable fixed-size revoke list stack (in bytes). */
#define	CHERIGC_REVOKE_LIST_SIZE	CHERIGC_PAGESIZE

#define	CHERIGC_FREE_FILL		0x0DE1E7ED

/*
 * If defined, the collector will fill all objects with a pattern before
 * calling free().
 *
 * XXX: This might not play well with jemalloc, because we may write over
 * more than is allocated. For small objects which are aligned anyway, it
 * is probably OK; for pages, it may not be, depending on metadata storage
 * within jemalloc.
 */
#define	CHERIGC_INVALIDATE_ON_FREE

#define	CHERIGC_DEBUG

#ifdef CHERIGC_DEBUG
#define	cherigc_printf		_cherigc_printf
#define	cherigc_time_printf	_cherigc_time_printf
#define	cherigc_assert(x, ...)						\
	_cherigc_assert((int)(x), #x, __FILE__, __LINE__, __VA_ARGS__)
#else
#define	cherigc_printf(...)	do {} while (0)
#define	cherigc_time_printf(...)	do {} while (0)
#define	_cherigc_assert(...)	do {} while (0)
#endif

#if __has_feature(capabilities)
#define	CHERIGC_CAP_DEREF(p)	(*(__capability void **)(p))
#define	CHERIGC_PTR_CLRTAG(p)	cheri_cleartag(CHERIGC_CAP_DEREF(p))
#define	CHERIGC_PTR_GETTAG(p)	cheri_gettag(CHERIGC_CAP_DEREF(p))
#define	CHERIGC_PTR_GETBASE(p)	cheri_getbase(CHERIGC_CAP_DEREF(p))
#define	CHERIGC_PTR_GETOFFSET(p) cheri_getoffset(CHERIGC_CAP_DEREF(p))
#include <machine/cheri.h>
#include <machine/cheric.h>
#else
#define	__capability
#define	cheri_ptr(a, b)		(a)
#define	CHERIGC_CAP_DEREF(p)	NULL
#define	CHERIGC_PTR_GETTAG(p)	0
#define	CHERIGC_PTR_GETBASE(p)	NULL
#include <machine/cheri.h>
#include <machine/cheric.h>
#endif

struct cherigc_stats {
	/* Current number of objects allocated. */
	size_t		cs_nalloc;
	size_t		cs_nalloc_small;
	size_t		cs_nalloc_large;
	/* Current number of bytes allocated. */
	size_t		cs_nallocbytes;
	/* Current number of objects marked. */
	size_t		cs_nmark;
	size_t		cs_nrevoke;
};
#define	gc_nalloc	gc_stats.cs_nalloc
#define	gc_nalloc_small	gc_stats.cs_nalloc_small
#define	gc_nalloc_large	gc_stats.cs_nalloc_large
#define	gc_nallocbytes	gc_stats.cs_nallocbytes
#define	gc_nmark	gc_stats.cs_nmark
#define	gc_nrevoke	gc_stats.cs_nrevoke

struct cherigc_caps {
	void		*cc_cap;
	size_t		cc_size;
};

struct cherigc_stack_entry {
	void		*cse_ptr;
	size_t		cse_size;
};

struct cherigc_stack {
	struct cherigc_stack_entry	*cs_stack;
	/* Size in bytes. */
	size_t				cs_size;
	/* Current array index. */
	size_t				cs_idx;
};

/* Allocation map for a single page. */
struct cherigc_amap {
	uint8_t		*ca_map;
};

/* Assert: GA_DIV * GA_ENTSZ = 8. */
#define	CHERIGC_ADIV		4	/* amap entries per byte */
#define	CHERIGC_AENTSZ		2	/* size of amap entry in bits */
#define	CHERIGC_AUSED		1	/* `object used' value */
#define	CHERIGC_ASTART		2	/* `start-of-object' value */
/* `Object marked' value. Implies start-of-object. */
#define	CHERIGC_AMARK		3
#define	CHERIGC_AENTMASK	3	/* entry mask */
#define	CHERIGC_ABYTIDX(idx)	((idx) / CHERIGC_ADIV)
#define	CHERIGC_ABITIDX(idx)	(((idx) % CHERIGC_ADIV) * CHERIGC_AENTSZ)
#define	CHERIGC_AGETENT(ca, idx)					\
	(((ca)->ca_map[CHERIGC_ABYTIDX(idx)] >> CHERIGC_ABITIDX(idx)) &	\
	    CHERIGC_AENTMASK)
#define	CHERIGC_ASETENT(ca, idx, v)					\
	((ca)->ca_map[CHERIGC_ABYTIDX(idx)] =				\
	    ((ca)->ca_map[CHERIGC_ABYTIDX(idx)] &			\
	    ~(CHERIGC_AENTMASK << CHERIGC_ABITIDX(idx))) |		\
	((v) << CHERIGC_ABITIDX(idx)))
#define	CHERIGC_ACLRENT(ca, idx)					\
	((ca)->ca_map[CHERIGC_ABYTIDX(idx)] =				\
	    ((ca)->ca_map[CHERIGC_ABYTIDX(idx)] &			\
	    ~(CHERIGC_AENTMASK << CHERIGC_ABITIDX(idx))))
#define	CHERIGC_ASETUSED(ca, idx) CHERIGC_ASETENT(ca, idx, CHERIGC_AUSED)
#define	CHERIGC_ASETSTART(ca, idx) CHERIGC_ASETENT(ca, idx, CHERIGC_ASTART)
#define	CHERIGC_ASETMARK(ca, idx) CHERIGC_ASETENT(ca, idx, CHERIGC_AMARK)

#define	CHERIGC_LEAVEGC		(cherigc->gc_ingc = 0)
#define	CHERIGC_ENTERGC		(cherigc->gc_ingc = 1)
#define	CHERIGC_ISINGC		(cherigc->gc_ingc == 1)

#define	CHERIGC_CAPSIZE		(cherigc->gc_capsize)
#define	CHERIGC_PAGESIZE	(cherigc->gc_pagesize)
#define	CHERIGC_PAGEMASK	(CHERIGC_PAGESIZE - 1)
//#define	CHERIGC_MINSIZE		CHERIGC_CAPSIZE
#define	CHERIGC_MINSIZE		sizeof(void *)
#define	CHERIGC_AMAP_NENT	(CHERIGC_PAGESIZE / CHERIGC_MINSIZE)
#define	CHERIGC_AMAP_ADDR(idx)	((idx) * CHERIGC_MINSIZE)
#define	CHERIGC_AMAP_PAGEIDX(p)						\
	(((uint64_t)(p) & CHERIGC_PAGEMASK) / CHERIGC_MINSIZE)
/* Pointer to last byte in previous page. */
#define	CHERIGC_PREVPAGE_LASTBYTE(p)					\
	((void *)((((uintptr_t)(p) - CHERIGC_PAGESIZE) &		\
	    ~CHERIGC_PAGEMASK) + CHERIGC_PAGESIZE - 1))
/* Pointer to first byte in next page. */
#define	CHERIGC_NEXTPAGE(p)						\
	((void *)(((uintptr_t)(p) + CHERIGC_PAGESIZE) &		\
	    ~CHERIGC_PAGEMASK))
/* Pointer to first byte in previous page. */
#define	CHERIGC_PREVPAGE(p)						\
	((void *)(((uintptr_t)(p) - CHERIGC_PAGESIZE) &		\
	    ~CHERIGC_PAGEMASK))

#define	CHERIGC_ALIGNUP(p)						\
	((void *)(((uintptr_t)(p) + CHERIGC_CAPSIZE - 1) &		\
	    ~(CHERIGC_CAPSIZE - 1)))

/* VM entry. */
struct cherigc_vment {
	uint64_t	ce_addr;	/* page address */
	uint32_t	ce_prot;	/* protection */
	uint32_t	ce_type;	/* KVME type */
	uint32_t	ce_flags;	/* KVME flags */
	uint32_t	ce_gctype;	/* GC type */
	struct cherigc_amap ce_amap;
};

/* Entire page is free. */
#define	CHERIGC_VMENT_PAGE_FREE		0x00000000UL
/* Large object: entire page is allocated, this is the first page. */
#define	CHERIGC_VMENT_PAGE_START	0x00000001UL
/* Large object: marked (always set with VMENT_PAGE_START). */
#define	CHERIGC_VMENT_PAGE_MARK		0x00000002UL
/* Large object: revoked/to revoke (always set with VMENT_PAGE_START). */
#define	CHERIGC_VMENT_PAGE_REVOKE	0x00000004UL
/* Large object: entire page is allocated, this is continuation data. */
#define	CHERIGC_VMENT_PAGE_USED		0x00000008UL
/* Page split into amap. */
#define	CHERIGC_VMENT_PAGE_AMAP		0x00000010UL

/*
 * VM map.
 *
 * A VM map is like a multi-level page table. Each entry is either
 * another VM map or a final-level VM entry. Entries are indexed by some
 * bits of the address.
 *
 * The one used in the GC splits addresses as follows:
 * 0xIIIIIIABBCCDDPPP
 * I - ignored. These bits always seem to be zero in FreeBSD.
 * A - usually 0, but for the stack pages, a 7. Top level.
 * B - usually 0x12 (static), 0x16 (heap) or 0xff (stack). Second level.
 * C - third level.
 * D - fourth level.
 * P - page offset; not stored because amaps operate on page granularity.
 *
 * A cherigc_vidx structure stores the bit values at each level.
 */
struct cherigc_vmap {
	/* Table of cv_size many entries. */
	union {
		struct cherigc_vment	**cv_vment;
		struct cherigc_vmap	**cv_vmap;
	};
};

/* Indexing entry. */
struct cherigc_vidx {
	int		ci_type;	/* VMAP or VMENT. */
	size_t		ci_bits;	/* number of bits at this level */
	size_t		ci_size;	/* 1 << ci_bits */
	uint64_t	ci_shift;	/* shift on address before mask */
	uint64_t	ci_mask;	/* ci_size - 1 */
};

/* Array of indexing entries for each level. */
struct cherigc_vidxs {
	struct cherigc_vidx	*cvi_ci;
	size_t			cvi_nent;
};

#define	CHERIGC_CV_VMAP		0
#define	CHERIGC_CV_VMENT	1

#define	CHERIGC_NUM_SAVED_REGS	25

#define	CHERIGC_INVALIDATE_UNUSED_REGS		\
	CHERIGC_INVALIDATE_REG(3)

#define	CHERIGC_SAVE_REGS(buf)			\
	CHERIGC_SAVE_REG(17, buf, 0);		\
	CHERIGC_SAVE_REG(18, buf, 32);		\
	CHERIGC_SAVE_REG(19, buf, 64);		\
	CHERIGC_SAVE_REG(20, buf, 96);		\
	CHERIGC_SAVE_REG(21, buf, 128);		\
	CHERIGC_SAVE_REG(22, buf, 160);		\
	CHERIGC_SAVE_REG(23, buf, 192);		\
	CHERIGC_SAVE_REG(24, buf, 224);		\
	CHERIGC_SAVE_REG(25, buf, 256);		\
	CHERIGC_SAVE_REG(26, buf, 288);		\
	CHERIGC_SAVE_REG(1, buf, 320);		\
	CHERIGC_SAVE_REG(2, buf, 352);		\
	CHERIGC_SAVE_REG(4, buf, 384);		\
	CHERIGC_SAVE_REG(5, buf, 416);		\
	CHERIGC_SAVE_REG(6, buf, 448);		\
	CHERIGC_SAVE_REG(7, buf, 480);		\
	CHERIGC_SAVE_REG(8, buf, 512);		\
	CHERIGC_SAVE_REG(9, buf, 544);		\
	CHERIGC_SAVE_REG(10, buf, 576);		\
	CHERIGC_SAVE_REG(11, buf, 608);		\
	CHERIGC_SAVE_REG(12, buf, 640);		\
	CHERIGC_SAVE_REG(13, buf, 672);		\
	CHERIGC_SAVE_REG(14, buf, 704);		\
	CHERIGC_SAVE_REG(15, buf, 736);		\
	CHERIGC_SAVE_REG(16, buf, 768);		\

#define	CHERIGC_RESTORE_REGS(buf)			\
	CHERIGC_RESTORE_REG(17, buf, 0);		\
	CHERIGC_RESTORE_REG(18, buf, 32);		\
	CHERIGC_RESTORE_REG(19, buf, 64);		\
	CHERIGC_RESTORE_REG(20, buf, 96);		\
	CHERIGC_RESTORE_REG(21, buf, 128);		\
	CHERIGC_RESTORE_REG(22, buf, 160);		\
	CHERIGC_RESTORE_REG(23, buf, 192);		\
	CHERIGC_RESTORE_REG(24, buf, 224);		\
	CHERIGC_RESTORE_REG(25, buf, 256);		\
	CHERIGC_RESTORE_REG(26, buf, 288);		\
	CHERIGC_RESTORE_REG(1, buf, 320);		\
	CHERIGC_RESTORE_REG(2, buf, 352);		\
	CHERIGC_RESTORE_REG(4, buf, 384);		\
	CHERIGC_RESTORE_REG(5, buf, 416);		\
	CHERIGC_RESTORE_REG(6, buf, 448);		\
	CHERIGC_RESTORE_REG(7, buf, 480);		\
	CHERIGC_RESTORE_REG(8, buf, 512);		\
	CHERIGC_RESTORE_REG(9, buf, 544);		\
	CHERIGC_RESTORE_REG(10, buf, 576);		\
	CHERIGC_RESTORE_REG(11, buf, 608);		\
	CHERIGC_RESTORE_REG(12, buf, 640);		\
	CHERIGC_RESTORE_REG(13, buf, 672);		\
	CHERIGC_RESTORE_REG(14, buf, 704);		\
	CHERIGC_RESTORE_REG(15, buf, 736);		\
	CHERIGC_RESTORE_REG(16, buf, 768);		\

#define	CHERIGC_SAVE_REG(indx, buf, offset)		\
	__asm__ __volatile__ (			\
		"csc $c" #indx ", $zero, " #offset "($c" #buf ")" : : : \
	    "memory"				\
	)

#define	CHERIGC_RESTORE_REG(indx,buf,offset)		\
	__asm__ __volatile__ (			\
		"clc $c" #indx ", $zero, " #offset "($c" #buf ")" : : : \
	    "memory" \
	)

#define	CHERIGC_INVALIDATE_REG(indx)			\
	__asm__ __volatile__ (			\
		"ccleartag $c" #indx ", $c" #indx : : : "memory"	\
	)

struct cherigc {
	struct cherigc_vmap	gc_cv;
	struct cherigc_vidxs	gc_cvi;
	struct cheri_stack	gc_ts;		/* trusted stack storage */
	struct cherigc_caps	gc_tstack;	/* trusted stack */
	struct cherigc_caps	gc_regs;	/* saved registers */
	struct cherigc_caps	gc_stack;	/* saved stack */
	struct cherigc_stack	gc_mark_stack;	/* stack of marked objs */
	struct cherigc_stack	gc_revoked;	/* array of revoked objs */
	size_t			gc_capsize;
	size_t			gc_pagesize;
	struct cherigc_stats	gc_stats;
	/* If set, we are inside the collector; ignore notify_allocs. */
	int			gc_ingc;
	/* Total time spent in the collector. */
	uint64_t		gc_pausetime;
	/*
	 * If set, revoked objects will remain allocated in the tables, but
	 * still invalidated as normal. Useful for determining whether the
	 * collector really is invalidating revoked capabilities.
	 */
	int			gc_revoke_debugging;
};

#define	CHERIGC_PROT_RD		0x00000001UL
#define	CHERIGC_PROT_WR		0x00000002UL
#define	CHERIGC_PROT_EX		0x00000004UL

#define	CHERIGC_MAX_VMENT	32

#define	CHERIGC_FL_PRECISE	1
#define	CHERIGC_FL_NOPOINTER	2

/* Flags for *_print functions. */
/* Only print non-empty VM entries. */
#define	CHERIGC_FL_USED_ONLY	1
/* Only print object sizes. */
#define	CHERIGC_FL_AMAP_COMPACT	2

extern struct cherigc	_cherigc;
extern struct cherigc	*cherigc;

int			 cherigc_vmap_init(struct cherigc_vmap *_cv,
			    struct cherigc_vidx *_ci);
struct cherigc_vment	*cherigc_vmap_get(struct cherigc_vmap *_cv,
			    struct cherigc_vidxs *_cvi, void *_p);
struct cherigc_vment	*cherigc_vmap_put(struct cherigc_vmap *_cv,
			    struct cherigc_vidxs *_cvi, void *_p,
			    struct cherigc_vment **_old);
int			 cherigc_vmap_update(struct cherigc_vmap *_cv,
			    struct cherigc_vidxs *_cvi);
void			 cherigc_vmap_print(struct cherigc_vmap *_cv,
			    struct cherigc_vidxs *_cvi, size_t _idx,
			    int _flags);
void			 cherigc_amap_print(struct cherigc_amap *_ca,
			    uint64_t _base_addr, int _flags);

/* Collect statistics about the number of objects allocated, etc. */
void			 cherigc_amap_get_stats(struct cherigc_stats *_cs,
			    struct cherigc_vment *_ce);
void			 cherigc_vment_get_stats(struct cherigc_stats *_cs,
			    struct cherigc_vment *_ce);
void			 cherigc_vmap_get_stats(struct cherigc_stats *_cs,
			    struct cherigc_vmap *_cv,
			    struct cherigc_vidxs *_cvi, size_t _idx);
void			 cherigc_vm_print_stats(void);

/* Allocates amap. */
int			 cherigc_vment_init(struct cherigc_vment *_ce);
void			 cherigc_vment_print(struct cherigc_vment *_ce,
			    int _flags);

void			*cherigc_internal_alloc(size_t _sz);

__attribute__((constructor))
void			 cherigc_init(void);

struct cherigc_vment	*cherigc_find_or_add_page(void *_p);

/*
 * Safe; returns error if pointer not found. Size returned in *szp, object
 * start returned in *qp.
 */
int			 cherigc_get_size(void *_p, void **_qp,
			    size_t *_szp);
/* For AMAP type entries only. */
int			 cherigc_get_size_small(struct cherigc_vment *_ce,
			    void *_p, void **_qp, size_t *_szp);
/* For non-AMAP type entries only. */
int			 cherigc_get_size_large(struct cherigc_vment *_ce,
			    void *_p, void **_qp, size_t *_szp);

/*
 * Returns only the object start (not its size). For small objects this is
 * also as an index into an AMAP, returned in *idxp.
 */
int			 cherigc_get_object_start(void *p,
			    struct cherigc_vment **_cep, size_t *_idxp);
/* For AMAP type entries only. */
int			 cherigc_get_object_start_small(
			    struct cherigc_vment *_ce, void *p,
			    struct cherigc_vment **_cep, size_t *_idxp);
/* For non-AMAP type entries only. */
int			 cherigc_get_object_start_large(
			    struct cherigc_vment *_ce, void *p,
			    struct cherigc_vment **_cep);

/* Callback from the actual allocator. */
void			 cherigc_notify_alloc(void *_p, size_t _sz,
			    int _flags);

/* Print tracking information (useful for debugging). */
void			 cherigc_print_tracking(void);

int			 cherigc_gettid(void);
uint64_t		 cherigc_gettime(void);

/* Collection. */
void			 cherigc_scan_region(void *_p, size_t _sz);
void			 cherigc_scan_ptr(void *_p);

/* malloc-avoiding, unbuffered printf to stderr. */
void			 _cherigc_printf(const char *_fmt, ...);
void			 _cherigc_vprintf(const char *_fmt, va_list ap);
void			 _cherigc_time_printf(uint64_t _diff,
			    const char *_fmt, ...);

void			 _cherigc_assert(int _cond, const char *_str,
			    const char *_file, int _line, const char *_fmt,
			    ...);

/* User API. */
/* Calls the default allocator and wraps the result in a capability. */
__capability void	*cherigc_malloc(size_t _sz);

/* Force collect. */
int			 cherigc_collect(void);

/* Lazy revoke (invalidates happen on next collection). */
int			 cherigc_revoke(void *_p);

/*
 * Marking API.
 *
 * mark_all: Call a function on every reachable object. The internal
 * state of the collector is changed (mark bits are set to keep track of
 * visited objects). During a collection, this function is used internally
 * with a NULL callback to simply mark the objects. Externally, it is
 * expected to be used for debugging or checking.
 *
 * Note that it's probably a good idea to call cherigc_sweep() after
 * calling this, in order to reset the state of the mark bits.
 *
 * The callback is called for every object before the object is marked or
 * pushed to the mark stack. The arguments passed to the callback are:
 *
 * objp: a pointer to an offset in the object's parent at which is stored a
 * capability to the object. The capability can thus be modified; for
 * example, to revoke, the tag bit could be cleared.
 *
 * ctx: unmodified context as passed to cherigc_examine_reachable.
 */
typedef void		 cherigc_examine_fn(void *_objp, void *_ctx);
int			 cherigc_mark_all(cherigc_examine_fn *_fn,
			    void *_ctx);
/* Collection helpers. */
/* Marking. */
int			 cherigc_push_roots(struct cherigc_caps *_cc,
			    cherigc_examine_fn *_fn, void *_ctx);
int			 cherigc_mark_children(void *_p, size_t _sz,
			    cherigc_examine_fn *_fn, void *_ctx);
int			 cherigc_push_root(void *_p);
int			 cherigc_pushable(void *_p);
int			 cherigc_stack_push(struct cherigc_stack *_cs,
			    void *_p, size_t _sz);
int			 cherigc_stack_isfull(struct cherigc_stack *_cs);
int			 cherigc_stack_pop(struct cherigc_stack *_cs,
			    void **_p, size_t *_sz);
int			 cherigc_isrevoked_small(struct cherigc_vment *_ce,
			    size_t _idx);

/* Sweeping. */
void			 cherigc_sweep(void);
void			 cherigc_sweep_vmap(struct cherigc_vmap *_cv,
			    struct cherigc_vidxs *_cvi, size_t _idx,
			    int *_large_freecont, int *_small_freecont);
void			 cherigc_sweep_vment(struct cherigc_vment *_ce,
			    int *_large_freecont, int *_small_freecont);

/*
 * For debugging: check if a capability really is revoked.
 * Return values:
 * -1: error
 * >=0: number of capabilities still pointing to this object
 */
int			 cherigc_getrefs(void *_p);
cherigc_examine_fn	 cherigc_getrefs_cb;
struct cherigc_getrefs_s {
	int refs;
	uint64_t addr;
};

/* Get/set the trusted stack. */
int			 cherigc_get_ts(void);
int			 cherigc_put_ts(void);

/* Get/set capability registers. */
void			 cherigc_get_regs(void);
void			 cherigc_put_regs(void);

/* Return an object to jemalloc (call free(), basically). */
void			 cherigc_free_small(struct cherigc_vment *_ce,
			    size_t _idx);
void			 cherigc_free_large(struct cherigc_vment *_ce);
void			 cherigc_free_any(void *_p);

#endif /* !_CHERIGC_H_ */
