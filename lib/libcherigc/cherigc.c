#include <kvm.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#include <unistd.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sys/syscall.h>

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <machine/cheri.h>
#include <machine/cheric.h>
#include <machine/sysarch.h>

#include <jemalloc_internal.h>

#include "cherigc.h"
#include "cherigc_ctl.h"

/*
 * Defined in cherigc_libc.c.
 * XXX: Unfortunately, doesn't quite work the way we want it to. jemalloc's
 * internal isalloc() will throw assertions and do funny things if not
 * given allocated pointers. On the other hand, we want to use it to check
 * if a pointer points to an allocated object.
 */
int	__cherigc_je_isalloc(void *p, int demote);

struct cherigc _cherigc;
struct cherigc *cherigc;
/* To avoid bootstrapping problems with e.g. libcheri. */
static int cherigc_initialized;

void
_cherigc_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_cherigc_vprintf(fmt, ap);
	va_end(ap);
}

void
_cherigc_vprintf(const char *fmt, va_list ap)
{
	char s[512];

	(void)vsnprintf(s, sizeof(s), fmt, ap);
	fputs(s, stdout);
	fflush(stdout);
}

void
_cherigc_time_printf(uint64_t diff, const char *fmt, ...)
{
	va_list ap;

	_cherigc_printf("**GC time: ");
	va_start(ap, fmt);
	_cherigc_vprintf(fmt, ap);
	va_end(ap);
	_cherigc_printf(": %" PRIu64 " ms\n", diff);
}

void
_cherigc_assert(int cond, const char *str, const char *file, int line,
    const char *fmt, ...)
{
	va_list ap;

	if (cond)
		return;

	_cherigc_printf("ASSERTION FAILED: %s:%d: `%s' ", file, line, str);
	va_start(ap, fmt);
	_cherigc_vprintf(fmt, ap);
	va_end(ap);
	_cherigc_printf("\n");
	exit(1);
}

int
cherigc_vmap_init(struct cherigc_vmap *cv, struct cherigc_vidx *ci)
{
	void *p;
	size_t sz;

	sz = (ci->ci_type == CHERIGC_CV_VMAP) ? sizeof(*cv->cv_vmap) :
	    sizeof(*cv->cv_vment);
	sz *= ci->ci_size;
	p = cherigc_internal_alloc(sz);
	if (p == NULL)
		return (-1);
	if (ci->ci_type == CHERIGC_CV_VMAP)
		cv->cv_vmap = p;
	else
		cv->cv_vment = p;
	memset(p, 0, sz);

	return (0);
}

struct cherigc_vment *
cherigc_vmap_get(struct cherigc_vmap *cv, struct cherigc_vidxs *cvi,
    void *p)
{
	uint64_t addr, idx;
	struct cherigc_vidx *ci;

	addr = (uint64_t)p;

	for (ci = cvi->cvi_ci; cv != NULL; ci++) {
		idx = (addr >> ci->ci_shift) & ci->ci_mask;
		if (ci->ci_type == CHERIGC_CV_VMENT)
			return (cv->cv_vment[idx]);
		else
			cv = cv->cv_vmap[idx];
	}

	return (NULL);
}

struct cherigc_vment *
cherigc_vmap_put(struct cherigc_vmap *cv, struct cherigc_vidxs *cvi,
    void *p, struct cherigc_vment **old)
{
	struct cherigc_vidx *ci;
	struct cherigc_vment **cep;
	uint64_t addr, idx;

	addr = (uint64_t)p;

	for (ci = cvi->cvi_ci; cv != NULL; ci++) {
		idx = (addr >> ci->ci_shift) & ci->ci_mask;
		if (ci->ci_type == CHERIGC_CV_VMENT) {
			cep = &cv->cv_vment[idx];
			*old = *cep;
			if (*cep == NULL) {
				*cep = cherigc_internal_alloc(
				    sizeof(**cep));
				if (*cep == NULL)
					return (NULL);
				if (cherigc_vment_init(*cep) != 0) {
					cherigc_printf(
					    "cherigc_vment_init error\n");
					/*
					 * XXX: Leak! *cep still allocated.
					 */
					return (NULL);
				}
			}
			return (*cep);
		} else {
			if (cv->cv_vmap[idx] == NULL) {
				cv->cv_vmap[idx] = cherigc_internal_alloc(
				    sizeof(cv->cv_vmap[idx]));
				cherigc_vmap_init(cv->cv_vmap[idx],
				    &ci[1]);
			}
			cv = cv->cv_vmap[idx];
		}
	}

	return (NULL);
}

int
cherigc_vmap_update(struct cherigc_vmap *cv, struct cherigc_vidxs *cvi)
{
	struct procstat *ps;
	struct kinfo_vmentry *kv;
	struct kinfo_proc *kp;
	struct cherigc_vment *ce, *ceold;
	size_t i;
	uint64_t addr;
	unsigned cnt;

	ps = NULL;
	kp = NULL;
	kv = NULL;

	ps = procstat_open_sysctl();
	if (ps == NULL)
		goto error;

	cnt = 0;
	kp = procstat_getprocs(ps, KERN_PROC_PID, getpid(), &cnt);
	if (kp == NULL)
		goto error;
	cherigc_printf("getprocs retrieved %u procs\n", cnt);

	kv = procstat_getvmmap(ps, kp, &cnt);
	if (kv == NULL)
		goto error;
	cherigc_printf("getvmmap retrieved %u entries\n", cnt);

	for (i = 0; i < cnt; i++) {
		cherigc_printf("[%zu] %" PRIx64 " - %" PRIx64 "\n",
		    i, kv[i].kve_start, kv[i].kve_end);
		if (kv[i].kve_flags & KVME_FLAG_GROWS_DOWN) {
			/* XXX: Heuristic to find stack. */
			cherigc->gc_stack.cc_cap = (void *)kv[i].kve_start;
			cherigc->gc_stack.cc_size = kv[i].kve_end -
			    kv[i].kve_start;
			cherigc_printf("FOUND STACK: %" PRIx64 " - %"
			    PRIx64 "\n", kv[i].kve_start, kv[i].kve_end);
		}
		for (addr = kv[i].kve_start; addr < kv[i].kve_end;
		    addr += CHERIGC_PAGESIZE) {
			ce = cherigc_vmap_put(cv, cvi, (void *)addr,
			    &ceold);
			if (ce == NULL) {
				cherigc_printf("cherigc out of memory\n");
				goto error;
			}
			if (ceold == NULL) {
				/*
				 * Note, this is a new entry. We don't do
				 * anything special today, but we might
				 * want to tomorrow.
				 */
			}
			ce->ce_addr = addr;
			ce->ce_prot = kv[i].kve_protection;
			ce->ce_type = kv[i].kve_type;
			ce->ce_flags = kv[i].kve_flags;
		}
	}

	return (0);
error:
	if (kv != NULL)
		procstat_freevmmap(ps, kv);
	if (kp != NULL)
		procstat_freeprocs(ps, kp);
	if (ps != NULL)
		procstat_close(ps);
	return (-1);
}

void
cherigc_vmap_print(struct cherigc_vmap *cv, struct cherigc_vidxs *cvi,
    size_t idx, int flags)
{
	struct cherigc_vidx *ci;
	size_t i;

	ci = &cvi->cvi_ci[idx];
	if (ci->ci_type == CHERIGC_CV_VMENT) {
		for (i = 0; i < ci->ci_size; i++)
			if (cv->cv_vment[i] != NULL)
				cherigc_vment_print(cv->cv_vment[i],
				    flags);
	} else {
		for (i = 0; i < ci->ci_size; i++)
			if (cv->cv_vmap[i] != NULL)
				cherigc_vmap_print(cv->cv_vmap[i], cvi,
				    idx + 1, flags);
	}
}

void
cherigc_amap_print(struct cherigc_amap *ca, uint64_t base_addr, int flags)
{
	char s[5];
	size_t i, sz;
	int inobj, ismark, isstart, isused;
	uint64_t addr;
	uint8_t ent;

	/* Print amap. */
	/* XXX: page spans?? */
	inobj = 0;
	sz = 0;
	for (i = 0; i < CHERIGC_AMAP_NENT; i++) {
		ent = CHERIGC_AGETENT(ca, i);
		if (ent != 0) {
			ismark = (ent == CHERIGC_AMARK);
			isstart = (ent == CHERIGC_ASTART) || ismark;
			isused = (ent == CHERIGC_AUSED);
			if (flags & CHERIGC_FL_AMAP_COMPACT) {
				if (isstart) {
					if (inobj)
						cherigc_printf(
						    "\t0x%" PRIx64
						    " - 0x% " PRIx64
						    " (%zu bytes)\n",
						    addr, addr + sz, sz);
					sz = CHERIGC_MINSIZE;
					inobj = 1;
					addr = base_addr +
					    CHERIGC_AMAP_ADDR(i);
				} else if (isused)
					sz += CHERIGC_MINSIZE;
			} else {
				addr = base_addr + CHERIGC_AMAP_ADDR(i);
				s[0] = isstart ? 's' : '-';
				s[1] = isused ? 'u' : '-';
				s[2] = ismark ? 'm' : '-';
				s[3] = '-';
				s[4] = '\0';
				cherigc_printf("\t0x%" PRIx64 " : %s\n",
				    addr, s);
			}
		}
	}

	if ((flags & CHERIGC_FL_AMAP_COMPACT) && inobj) {
		cherigc_printf("\t0x%" PRIx64 " - 0x% " PRIx64
		    " (%zu bytes)\n", addr, addr + sz, sz);
	}
}

void
cherigc_amap_get_stats(struct cherigc_stats *cs, struct cherigc_vment *ce)
{
	size_t i;
	int isstart, ismark, isused, isrevoked;
	uint8_t ent;

	for (i = 0; i < CHERIGC_AMAP_NENT; i++) {
		ent = CHERIGC_AGETENT(&ce->ce_amap, i);
		if (ent != 0) {
			ismark = (ent == CHERIGC_AMARK);
			isstart = (ent == CHERIGC_ASTART) || ismark;
			isused = (ent == CHERIGC_AUSED);
			if (isstart) {
				isrevoked = cherigc_isrevoked_small(ce, i);
				cs->cs_nalloc++;
				cs->cs_nalloc_small++;
				if (isrevoked)
					cs->cs_nrevoke++;
			}
			if (ismark)
				cs->cs_nmark++;
			if (isstart || isused)
				cs->cs_nallocbytes += CHERIGC_MINSIZE;
		}
	}
}

void
cherigc_vment_get_stats(struct cherigc_stats *cs, struct cherigc_vment *ce)
{

	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP)
		cherigc_amap_get_stats(cs, ce);
	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_START) {
		cs->cs_nalloc++;
		cs->cs_nalloc_large++;
		cs->cs_nallocbytes += CHERIGC_PAGESIZE;
	}
	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_USED)
		cs->cs_nallocbytes += CHERIGC_PAGESIZE;
	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_MARK)
		cs->cs_nmark++;
	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_REVOKE)
		cs->cs_nrevoke++;
}

void
cherigc_vmap_get_stats(struct cherigc_stats *cs, struct cherigc_vmap *cv,
    struct cherigc_vidxs *cvi, size_t idx)
{
	struct cherigc_vidx *ci;
	size_t i;

	ci = &cvi->cvi_ci[idx];
	if (ci->ci_type == CHERIGC_CV_VMENT) {
		for (i = 0; i < ci->ci_size; i++)
			if (cv->cv_vment[i] != NULL)
				cherigc_vment_get_stats(cs,
				    cv->cv_vment[i]);
	} else {
		for (i = 0; i < ci->ci_size; i++)
			if (cv->cv_vmap[i] != NULL)
				cherigc_vmap_get_stats(cs, cv->cv_vmap[i],
				    cvi, idx + 1);
	}
}

void
cherigc_vm_print_stats(void)
{
	struct cherigc_stats cs;

	memset(&cs, 0, sizeof(cs));
	cherigc_vmap_get_stats(&cs, &cherigc->gc_cv, &cherigc->gc_cvi, 0);
	cherigc_printf("stats according to vmap:\n"
	    "nalloc:       %zu (%zu large, %zu small)\n"
	    "nallocbytes:  %zu\n"
	    "nmark:        %zu\n"
	    "nrevoke:      %zu\n",
	    cs.cs_nalloc, cs.cs_nalloc_large, cs.cs_nalloc_small,
	    cs.cs_nallocbytes, cs.cs_nmark, cs.cs_nrevoke);
	cherigc_printf("stats according to gc:\n"
	    "nalloc:       %zu (%zu large, %zu small)\n"
	    "nallocbytes:  %zu\n"
	    "nmark:        %zu\n"
	    "nrevoke:      %zu\n",
	    cherigc->gc_nalloc, cherigc->gc_nalloc_large,
	    cherigc->gc_nalloc_small, cherigc->gc_nallocbytes,
	    cherigc->gc_nmark, cherigc->gc_nrevoke);
}

int
cherigc_vment_init(struct cherigc_vment *ce)
{

	memset(ce, 0, sizeof(*ce));
	ce->ce_amap.ca_map = cherigc_internal_alloc(CHERIGC_AMAP_NENT /
	    CHERIGC_ADIV);
	/*cherigc_printf("amap bytes size: %zu\n", CHERIGC_AMAP_NENT /
	    CHERIGC_ADIV);*/
	if (ce->ce_amap.ca_map == NULL)
		return (-1);
	memset(ce->ce_amap.ca_map, 0, CHERIGC_AMAP_NENT / CHERIGC_ADIV);

	return (0);
}

void
cherigc_vment_print(struct cherigc_vment *ce, int flags)
{
	char s[4];
	size_t i;
	int amap_nonempty;

	if (flags & CHERIGC_FL_USED_ONLY) {
		if (ce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP) {
			amap_nonempty = 0;
			for (i = 0; i < CHERIGC_AMAP_NENT / CHERIGC_ADIV;
			    i++) {
				if (ce->ce_amap.ca_map[i] != 0)
					amap_nonempty = 1;
			}
			if (!amap_nonempty)
				return;
		} else if (ce->ce_gctype == CHERIGC_VMENT_PAGE_FREE)
			return;
	}

	s[0] = (ce->ce_prot & CHERIGC_PROT_RD) ? 'r' : '-';
	s[1] = (ce->ce_prot & CHERIGC_PROT_WR) ? 'w' : '-';
	s[2] = (ce->ce_prot & CHERIGC_PROT_EX) ? 'x' : '-';
	s[3] = '\0';
	cherigc_printf("0x%" PRIx64 ": %s KVME type 0x%" PRIx32 "\n",
	    ce->ce_addr, s, ce->ce_type);

	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP)
		cherigc_amap_print(&ce->ce_amap, ce->ce_addr, flags);
	else {
		cherigc_printf("\tEntire page object. Attributes: ");
		if (ce->ce_gctype == CHERIGC_VMENT_PAGE_FREE)
			cherigc_printf("free ");
		if (ce->ce_gctype & CHERIGC_VMENT_PAGE_START)
			cherigc_printf("start ");
		if (ce->ce_gctype & CHERIGC_VMENT_PAGE_MARK)
			cherigc_printf("marked ");
		if (ce->ce_gctype & CHERIGC_VMENT_PAGE_REVOKE)
			cherigc_printf("revoke ");
		if (ce->ce_gctype & CHERIGC_VMENT_PAGE_USED)
			cherigc_printf("cont ");
		cherigc_printf("\n");
	}
}

void *
cherigc_internal_alloc(size_t sz)
{
	void *p;

	cherigc_assert(CHERIGC_ISINGC, "");
	p = malloc(sz);
	return (p);
}

__attribute__((constructor))
void
cherigc_init(void)
{
	struct cherigc_vidxs *cvi;

	cherigc = &_cherigc;
	memset(cherigc, 0, sizeof(*cherigc));
	CHERIGC_ENTERGC;

	cherigc->gc_capsize = sizeof(__capability void *);
	cherigc->gc_pagesize = getpagesize();

	cherigc->gc_tstack.cc_cap = &cherigc->gc_ts;
	cherigc->gc_tstack.cc_size = sizeof(cherigc->gc_ts);

	cherigc->gc_regs.cc_size =
	    CHERIGC_NUM_SAVED_REGS * CHERIGC_CAPSIZE;
	cherigc->gc_regs.cc_cap = cherigc_internal_alloc(
	    cherigc->gc_regs.cc_size);
	cherigc_assert(cherigc->gc_regs.cc_cap != NULL, "");

	/* Initialize revoked stack to fixed size. */
	cherigc->gc_revoked.cs_size = CHERIGC_REVOKE_LIST_SIZE;
	cherigc->gc_revoked.cs_stack = cherigc_internal_alloc(
	    cherigc->gc_revoked.cs_size);
	cherigc_assert(cherigc->gc_revoked.cs_stack != NULL, "");

	/* Initialize unmanaged objects list to fixed size. */
	cherigc->gc_track_unmanaged = 1;
	cherigc->gc_unmanaged.cs_size = CHERIGC_UNMANAGED_LIST_SIZE;
	cherigc->gc_unmanaged.cs_stack = cherigc_internal_alloc(
	    cherigc->gc_unmanaged.cs_size);
	cherigc_assert(cherigc->gc_unmanaged.cs_stack != NULL, "");

	cherigc->gc_stack.cc_cap = NULL;
	cherigc->gc_stack.cc_size = 0;

	/* Initialize vmap indexing.
	 *
	 * XXX: Hardcoded bit values. See cherigc.h.
	 */
	cvi = &cherigc->gc_cvi;
	cvi->cvi_nent = 4;
	cvi->cvi_ci = cherigc_internal_alloc(cvi->cvi_nent *
	    sizeof(*cvi->cvi_ci));
	cvi->cvi_ci[0] = (struct cherigc_vidx){
		.ci_type = CHERIGC_CV_VMAP, .ci_bits = 4, .ci_size = 16,
		.ci_shift = 36, .ci_mask = 0xF
	};
	cvi->cvi_ci[1] = (struct cherigc_vidx){
		.ci_type = CHERIGC_CV_VMAP, .ci_bits = 8, .ci_size = 256,
		.ci_shift = 28, .ci_mask = 0xFF
	};
	cvi->cvi_ci[2] = (struct cherigc_vidx){
		.ci_type = CHERIGC_CV_VMAP, .ci_bits = 8, .ci_size = 256,
		.ci_shift = 20, .ci_mask = 0xFF
	};
	cvi->cvi_ci[3] = (struct cherigc_vidx){
		.ci_type = CHERIGC_CV_VMENT, .ci_bits = 8, .ci_size = 256,
		.ci_shift = 12, .ci_mask = 0xFF
	};

	cherigc_vmap_init(&cherigc->gc_cv, &cvi->cvi_ci[0]);
	printf("vmap_update: %d\n", cherigc_vmap_update(&cherigc->gc_cv,
	    &cherigc->gc_cvi));
	//cherigc_vmap_print(&cherigc->gc_cv, &cherigc->gc_cvi, 0);

	CHERIGC_LEAVEGC;
	cherigc_initialized = 1;
}

struct cherigc_vment *
cherigc_find_or_add_page(void *p)
{
	struct cherigc_vment *ce;

	ce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi, p);
	if (ce == NULL) {
		cherigc_printf("not found in vmap: %p; trying update\n",
		    p);
		cherigc_vmap_update(&cherigc->gc_cv, &cherigc->gc_cvi);
		ce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi,
		    p);
		if (ce == NULL) {
			cherigc_printf("error: still not found in vmap\n",
			    p);
			return (NULL);
		}
	}
	return (ce);
}

int
cherigc_get_object_start(void *p, struct cherigc_vment **cep, size_t *idxp)
{
	struct cherigc_vment *ce;

	ce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi, p);
	if (ce == NULL)
		return (-1);

	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP)
		return (cherigc_get_object_start_small(ce, p, cep, idxp));
	else if ((ce->ce_gctype & CHERIGC_VMENT_PAGE_START) ||
	    (ce->ce_gctype & CHERIGC_VMENT_PAGE_USED))
		return (cherigc_get_object_start_large(ce, p, cep));
	else
		return (-1);
}

int
cherigc_get_object_start_small(struct cherigc_vment *ce, void *p,
    struct cherigc_vment **cep, size_t *idxp)
{
	uint64_t i, idx;
	uint8_t ent;

	idx = CHERIGC_AMAP_PAGEIDX(p);
	/* 1) Find object start. */
	for (i = idx + 1; i != 0; i--) {
		ent = CHERIGC_AGETENT(&ce->ce_amap, i - 1);
		if (ent == CHERIGC_ASTART || ent == CHERIGC_AMARK)
			break;
		else if (ent != CHERIGC_AUSED)
			/* Pointing at unused area. */
			return (-1);
	}

	if (i == 0) {
		/* Start not found; must be in previous page. */
		p = CHERIGC_PREVPAGE_LASTBYTE(p);
		ce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi,
		    p);
		if (ce == NULL) {
			/* Impossible; corruption? */
			cherigc_assert(ce != NULL,
			    "expected previous page entry");
			return (-1);
		}
		idx = CHERIGC_AMAP_PAGEIDX(p);
		/* Go back until we find the object start. */
		for (i = idx + 1; i != 0; i--) {
			ent = CHERIGC_AGETENT(&ce->ce_amap, i - 1);
			if (ent == CHERIGC_ASTART || ent == CHERIGC_AMARK)
				break;
			else if (ent != CHERIGC_AUSED) {
				/* Impossible; corruption? */
				cherigc_assert(ent == CHERIGC_AUSED,
				    "expected used or start ent in pce");
				return (-1);
			}
		}
		if (i == 0) {
			/* Impossible; corruption? */
			cherigc_assert(i != 0,
			    "expected start of object in pce");
			return (-1);
		}
	}

	cherigc_printf("found object start index: %d\n", i - 1);

	*idxp = i - 1;
	*cep = ce;
	return (0);
}

int
cherigc_get_object_start_large(struct cherigc_vment *ce, void *p,
    struct cherigc_vment **cep)
{

	for (;;) {
		if (ce == NULL) {
			/* Impossible; corruption? */
			cherigc_assert(ce != NULL,
			    "expected previous page entry");
			return (-1);
		} else if (ce->ce_gctype & CHERIGC_VMENT_PAGE_START)
			break;
		else if (ce->ce_gctype & CHERIGC_VMENT_PAGE_USED) {
			p = CHERIGC_PREVPAGE(p);
			ce = cherigc_vmap_get(&cherigc->gc_cv,
			    &cherigc->gc_cvi, p);
		} else {
			/* Impossible; corruption? */
			cherigc_assert(
			    (ce->ce_gctype & CHERIGC_VMENT_PAGE_START) ||
			    (ce->ce_gctype & CHERIGC_VMENT_PAGE_USED),
			    "expected valid previous page entry");
			return (-1);
		}
	}

	*cep = ce;
	return (0);
}

int
cherigc_get_size(void *p, void **qp, size_t *szp)
{
	struct cherigc_vment *ce;

	ce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi, p);
	if (ce == NULL)
		return (-1);

	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP)
		return (cherigc_get_size_small(ce, p, qp, szp));
	else if ((ce->ce_gctype & CHERIGC_VMENT_PAGE_START) ||
	    (ce->ce_gctype & CHERIGC_VMENT_PAGE_USED))
		return (cherigc_get_size_large(ce, p, qp, szp));
	else
		return (-1);
}

int
cherigc_get_size_small(struct cherigc_vment *ce, void *p, void **qp,
    size_t *szp)
{
	struct cherigc_vment *pce;
	void *q;
	size_t sz;
	uint64_t i, j, idx, pidx;
	uint8_t ent;

	sz = 0;
	idx = CHERIGC_AMAP_PAGEIDX(p);
	/* 1) Find object start. */
	for (i = idx + 1; i != 0; i--) {
		ent = CHERIGC_AGETENT(&ce->ce_amap, i - 1);
		sz++;
		if (ent == CHERIGC_ASTART || ent == CHERIGC_AMARK)
			break;
		else if (ent != CHERIGC_AUSED)
			/* Pointing at unused area. */
			return (-1);
	}

	if (i == 0) {
		/* Start not found; must be in previous page. */
		pce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi,
		    CHERIGC_PREVPAGE_LASTBYTE(p));
		if (pce == NULL ||
		    !(pce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP)) {
			/* Impossible; corruption? */
			cherigc_assert(pce != NULL &&
			    (pce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP),
			    "expected previous page entry");
			return (-1);
		}
		pidx = CHERIGC_AMAP_PAGEIDX(CHERIGC_PREVPAGE_LASTBYTE(p));
		/* Go back until we find the object start. */
		for (j = pidx + 1; j != 0; j--) {
			ent = CHERIGC_AGETENT(&pce->ce_amap, j - 1);
			sz++;
			if (ent == CHERIGC_ASTART || ent == CHERIGC_AMARK)
				break;
			else if (ent != CHERIGC_AUSED) {
				/* Impossible; corruption? */
				cherigc_assert(ent == CHERIGC_AUSED,
				    "expected used or start ent in pce");
				return (-1);
			}
		}
		if (j == 0) {
			/* Impossible; corruption? */
			cherigc_assert(j != 0,
			    "expected start of object in pce");
			return (-1);
		}
		q = (void *)(CHERIGC_AMAP_ADDR(j - 1) + pce->ce_addr);
	} else
		q = (void *)(CHERIGC_AMAP_ADDR(i - 1) + ce->ce_addr);

	cherigc_printf("found (small) object start: %p\n", q);

	/*
	 * 2) Calculate remaining size, possibly spanning over to next
	 * page.
	 */
	for (i = idx + 1; i < CHERIGC_AMAP_NENT; i++) {
		ent = CHERIGC_AGETENT(&ce->ce_amap, i);
		if (ent != CHERIGC_AUSED)
			/* Reached unused area or start of next object. */
			break;
		else
			sz++;
	}
	cherigc_printf("found object size (current), index: %zu, %d, %d\n", sz * CHERIGC_MINSIZE, i, idx);
	if (i == CHERIGC_AMAP_NENT) {
		/*
		 * No start of next object found; end of object might be in
		 * next page.
		 */
		p = CHERIGC_NEXTPAGE(p);
		ce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi,
		    p);
		if (ce != NULL &&
		    (ce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP)) {
			/* Object may not have ended; check next amap. */
			for (i = 0; i < CHERIGC_AMAP_NENT; i++) {
				ent = CHERIGC_AGETENT(&ce->ce_amap, i);
				if (ent != CHERIGC_AUSED)
					/*
					 * Reached unused area or start of
					 * next object.
					 */
					break;
				else
					sz++;
			}
		}
	}

	cherigc_printf("found object size (final), index: %zu, %d, %d\n", sz * CHERIGC_MINSIZE, i, idx);
	sz *= CHERIGC_MINSIZE;

	*qp = q;
	*szp = sz;
	return (0);
}

int
cherigc_get_size_large(struct cherigc_vment *ce, void *p, void **qp,
    size_t *szp)
{
	struct cherigc_vment *qce;
	void *q;
	size_t sz;

	sz = 0;
	/*
	 * 1) Find object start. Caller guarantees that ce->ce_gctype has
	 * CHERIGC_VMENT_PAGE_START or CHERIGC_VMENT_PAGE_USED set.
	 */
	q = p;
	qce = ce;
	for (;;) {
		sz++;
		if (qce == NULL) {
			/* Impossible; corruption? */
			cherigc_assert(qce != NULL,
			    "expected previous page entry");
			return (-1);
		} else if (qce->ce_gctype & CHERIGC_VMENT_PAGE_START)
			break;
		else if (qce->ce_gctype & CHERIGC_VMENT_PAGE_USED) {
			q = CHERIGC_PREVPAGE(q);
			qce = cherigc_vmap_get(&cherigc->gc_cv,
			    &cherigc->gc_cvi, q);
		} else {
			/* Impossible; corruption? */
			cherigc_assert(
			    (qce->ce_gctype & CHERIGC_VMENT_PAGE_START) ||
			    (qce->ce_gctype & CHERIGC_VMENT_PAGE_USED),
			    "expected valid previous page entry");
			return (-1);
		}
	}

	cherigc_printf("found (large) object start: %p\n", q);

	/* 2) Calculate remaining size. */
	for (;;) {
		p = CHERIGC_NEXTPAGE(p);
		ce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi,
		    p);
		if (ce == NULL)
			/* Reached unused area. */
			break;
		else if (ce->ce_gctype & CHERIGC_VMENT_PAGE_USED)
			sz++;
		else
			/* Reached start of next object. */
			break;
	}

	sz *= CHERIGC_PAGESIZE;

	*qp = q;
	*szp = sz;
	return (0);
}

void
cherigc_notify_alloc(void *p, size_t sz, int flags)
{
	struct cherigc_vment *ce;
	struct cherigc_amap *ca;
	size_t aidx, i, len, end, max, acsz;
	uint64_t before, after, diff;

	(void)flags;

	acsz = 0;

	if (!cherigc_initialized)
		return;

	if (CHERIGC_ISINGC)
		return;

	if (cherigc->gc_ignore)
		return;

	CHERIGC_ENTERGC;

	before = cherigc_gettime();

	cherigc_get_regs();

	/* Save registers. */

	cherigc_printf("GC alloc: p=%p, sz=%zu, tid=%d\n",
	    p, sz, cherigc_gettid());

	/* Just for debugging, to catch test failures and things. */
	cherigc_assert(p != NULL, "");
	/*
	 * The GC actually requires alignment, or it doesn't know how to
	 * call free().
	 */
	cherigc_assert(((uintptr_t)p & (CHERIGC_MINSIZE - 1)) == 0, "%zu",
	    CHERIGC_MINSIZE);
	cherigc_assert(sz >= CHERIGC_MINSIZE, "%zu < %zu", sz,
	    CHERIGC_MINSIZE);

	/* Find the entry in the vmap. */
	ce = cherigc_find_or_add_page(p);
	if (ce == NULL) {
		cherigc_assert(ce != NULL, "");
		goto ret;
	}

	if (sz >= CHERIGC_PAGESIZE) {
		ce->ce_gctype = CHERIGC_VMENT_PAGE_START;
		len = (sz + CHERIGC_PAGESIZE - 1) / CHERIGC_PAGESIZE;
		for (i = 1; i < len; i++) {
			p = CHERIGC_NEXTPAGE(p);
			cherigc_printf("setting large p %p as used\n", p);
			ce = cherigc_vmap_get(&cherigc->gc_cv,
			    &cherigc->gc_cvi, p);
			/*
			 * XXX: assume the last cherigc_vmap_update mapped
			 * all allocated pages.
			 */
			cherigc_assert(ce != NULL,
			    "expected allocated pages to be mapped");
			ce->ce_gctype = CHERIGC_VMENT_PAGE_USED;
		}
		cherigc_printf("just set %zu pages as used\n", len);
		acsz = len * CHERIGC_PAGESIZE;
		cherigc->gc_nalloc_large++;
	} else {
		/* Set relevant bits in amap. */
		/* XXX: page spans?? TODO: Traverse multiple bits. */
		ce->ce_gctype = CHERIGC_VMENT_PAGE_AMAP;
		ca = &ce->ce_amap;
		aidx = CHERIGC_AMAP_PAGEIDX(p);
		CHERIGC_ASETSTART(ca, aidx);
		len = (sz + CHERIGC_MINSIZE - 1) / CHERIGC_MINSIZE;
		acsz = len * CHERIGC_MINSIZE;
		end = aidx + len - 1;
		cherigc_printf("len=%zu acsz=%zu aidx=%zu end=%zu\n",
		    len, acsz, aidx, end);
		max = (end < CHERIGC_AMAP_NENT) ? end :
		    CHERIGC_AMAP_NENT - 1;
		for (i = aidx + 1; i <= max; i++)
			CHERIGC_ASETUSED(ca, i);
		if (end >= CHERIGC_AMAP_NENT) {
			cherigc_printf("amap bounds: have %zu > %zu, "
			    "spilling to next page\n", end,
			    CHERIGC_AMAP_NENT);
			/* Spill to next page, but no more. */
			end -= CHERIGC_AMAP_NENT;
			cherigc_assert(end < CHERIGC_AMAP_NENT,
			    "unsupported object span over >2 pages\n");
			ce = cherigc_find_or_add_page(CHERIGC_NEXTPAGE(p));
			/*
			 * If we fail now, we've already set some bits, so
			 * we're a bit screwed.
			 */
			cherigc_assert(ce != NULL,
			    "expected second page to be mapped");
			ce->ce_gctype = CHERIGC_VMENT_PAGE_AMAP;
			ca = &ce->ce_amap;
			cherigc_printf("end is now %zu\n", end);
			for (i = 0; i <= end; i++)
				CHERIGC_ASETUSED(ca, i);
		}
		cherigc->gc_nalloc_small++;
	}

	{
		void *check_p;
		size_t check_sz;

		cherigc_get_size(p, &check_p, &check_sz);
		cherigc_printf("alloc size check: %p -> %p, %zu\n",
			p, check_p, check_sz);
		cherigc_assert(check_sz == acsz, "");
	}

ret:
	cherigc_put_regs();
	CHERIGC_LEAVEGC;
	after = cherigc_gettime();

	diff = after - before;
	//cherigc_time_printf(diff, "pause");
	cherigc->gc_pausetime += diff;
	//cherigc_time_printf(cherigc->gc_pausetime, "total pause");
	cherigc->gc_nalloc++;
	cherigc->gc_nallocbytes += acsz;
}

int
cherigc_notify_free(void *p, int flags)
{
	struct cherigc_vment *ce;
	size_t idx;
	int rc;
	uint64_t before, after, diff;

	(void)flags;

	if (!cherigc_initialized)
		return (CHERIGC_FREE_NOW);

	if (CHERIGC_ISINGC)
		return (CHERIGC_FREE_NOW);
	CHERIGC_ENTERGC;

	before = cherigc_gettime();

	/* Save registers. */
	cherigc_get_regs();

	cherigc_printf("GC free: p=%p, tid=%d\n",
	    p, cherigc_gettid());

	if (p == NULL) {
		rc = CHERIGC_FREE_DEFER;
		goto ret;
	}

	/* Just for debugging, to catch test failures and things. */
	cherigc_assert(p != NULL, "");
	/* The GC actually requires alignment. */
	cherigc_assert(((uintptr_t)p & (CHERIGC_MINSIZE - 1)) == 0, "%zu",
	    CHERIGC_MINSIZE);

	/*
	 * If the object doesn't exist, it may have been allocated before
	 * the GC was initialized, so let it go.
	 */
	rc = cherigc_get_object_start(p, &ce, &idx);
	if (rc != 0) {
		rc = CHERIGC_FREE_NOW;
		goto ret;
	}

	cherigc_assert(cherigc_revoke(p) == 0, "");

	rc = CHERIGC_FREE_DEFER;
ret:
	cherigc_printf("(%sdeferring %p)\n", rc == CHERIGC_FREE_DEFER ? "" : "not ", p);
	cherigc_put_regs();
	CHERIGC_LEAVEGC;
	after = cherigc_gettime();

	diff = after - before;
	//cherigc_time_printf(diff, "pause");
	cherigc->gc_pausetime += diff;
	//cherigc_time_printf(cherigc->gc_pausetime, "total pause");
	return (rc);
}

__capability void *
cherigc_malloc(size_t sz)
{
	__capability void *cp;
	void *p;

	p = malloc(sz);
	cp = cheri_ptr(p, sz);
	return (cp);
}

int
cherigc_collect(void)
{
	int rc;

	CHERIGC_ENTERGC;
	cherigc_get_regs();

	cherigc_printf("collection time!\n");
	printf("vmap_update: %d\n", cherigc_vmap_update(&cherigc->gc_cv,
	    &cherigc->gc_cvi));
	cherigc_vmap_print(&cherigc->gc_cv, &cherigc->gc_cvi, 0,
	    CHERIGC_FL_USED_ONLY | CHERIGC_FL_AMAP_COMPACT);

	rc = cherigc_mark_all(NULL, NULL);
	if (rc != 0)
		goto ret;

	cherigc_sweep();

	/* Empty revoked objects list. */
	cherigc->gc_revoked.cs_idx = 0;

	/* Empty unmanaged objects list. */
	cherigc->gc_unmanaged.cs_idx = 0;

	rc = 0;
ret:
	cherigc_put_regs();
	CHERIGC_LEAVEGC;
	return (rc);
}

int
cherigc_revoke(void *p)
{
	struct cherigc_vment *ce;
	void *q;
	size_t idx, sz;
	int rc;

	rc = cherigc_get_object_start(p, &ce, &idx);
	if (rc != 0)
		return (rc);
	rc = cherigc_get_size(p, &q, &sz);
	cherigc_assert(rc == 0, "");

	if (ce->ce_gctype == CHERIGC_VMENT_PAGE_AMAP) {
		/*
		 * XXX: Decide policy here. Simple option is to just call
		 * cherigc_collect on isfull.
		 */
		cherigc_assert(!cherigc_stack_isfull(&cherigc->gc_revoked),
		    "");
		cherigc_assert(cherigc_stack_push(&cherigc->gc_revoked,
		    p, sz, 0) == 0, "");
	} else
		ce->ce_gctype |= CHERIGC_VMENT_PAGE_REVOKE;

	cherigc->gc_nrevoke++;

	return (0);
}

int
cherigc_ctl(int cmd, int key, void *val)
{
	int iswrite;

	iswrite = 0;
#define	KEY_RW(var, type) do {						\
		if (iswrite)						\
			(var) = *(type *)val;				\
		else							\
			*(type *)val = (var);				\
} while (0)

	switch (cmd) {
	case CHERIGC_CTL_SET:
		iswrite = 1;
	case CHERIGC_CTL_GET:
		switch (key) {
		case CHERIGC_KEY_IGNORE:
			KEY_RW(cherigc->gc_ignore, int);
			break;
		case CHERIGC_KEY_NALLOC:
			*(size_t *)val = cherigc->gc_nalloc;
			break;
		case CHERIGC_KEY_REVOKE_DEBUGGING:
			KEY_RW(cherigc->gc_revoke_debugging, int);
			break;
		case CHERIGC_KEY_TRACK_UNMANAGED:
			KEY_RW(cherigc->gc_track_unmanaged, int);
			break;
		default:
			return (-1);
		}
		break;
	default:
		return (-1);
	}

	return (0);
}

int
cherigc_push_roots(struct cherigc_caps *cc, cherigc_examine_fn *fn,
    void *ctx)
{

	return cherigc_mark_children(cc->cc_cap, cc->cc_size, fn, ctx);
}

int
cherigc_mark_children(void *p, size_t sz, cherigc_examine_fn *fn,
    void *ctx)
{
	char *alignp, *end, *childp;
	int rc, tag;

	alignp = CHERIGC_ALIGNUP(p);
	end = (char *)p + sz;
	for (childp = alignp; childp < end; childp += CHERIGC_CAPSIZE) {
		tag = CHERIGC_PTR_GETTAG((void *)childp);
		if (tag)
			cherigc_printf("tag at childp=%p base=%zx\n", childp, CHERIGC_PTR_GETBASE((void *)childp));
		if (fn != NULL && tag)
			(*fn)(childp, ctx);
		rc = cherigc_push_root(childp);
		if (rc != 0)
			return (rc);
	}

	return (0);
}

int
cherigc_pushable(void *p)
{

	/* Don't push invalid capabilities. */
	if (!CHERIGC_PTR_GETTAG(p))
		return (0);

	/* Don't push the unlimited capability or NULL capabilities. */
	if (CHERIGC_PTR_GETBASE(p) == 0)
		return (0);

	return (1);
}

int
cherigc_stack_pop(struct cherigc_stack *cs, void **p, size_t *sz,
    uint64_t *flags)
{

	if (cs->cs_idx == 0)
		return (-1);

	cs->cs_idx--;
	*p = cs->cs_stack[cs->cs_idx].cse_ptr;
	*sz = cs->cs_stack[cs->cs_idx].cse_size;
	*flags = cs->cs_stack[cs->cs_idx].cse_flags;
	return (0);
}

int
cherigc_stack_push(struct cherigc_stack *cs, void *p, size_t sz,
    uint64_t flags)
{
	void *t;
	size_t cs_size;

	if (cs->cs_idx * sizeof(*cs->cs_stack) == cs->cs_size) {
		if (cs->cs_size == 0)
			cs_size = CHERIGC_PAGESIZE;
		else
			cs_size = 2 * cs->cs_size;
		t = realloc(cs->cs_stack, cs_size);
		if (t == NULL) {
			cherigc_printf("cherigc_stack too large: %zu\n",
			    sz);
			return (-1);
		}
		cs->cs_stack = t;
		cs->cs_size = cs_size;
	}

	cs->cs_stack[cs->cs_idx].cse_ptr = p;
	cs->cs_stack[cs->cs_idx].cse_size = sz;
	cs->cs_stack[cs->cs_idx].cse_flags = flags;
	cs->cs_idx++;

	return (0);
}

int
cherigc_stack_isfull(struct cherigc_stack *cs)
{

	if (cs->cs_idx * sizeof(*cs->cs_stack) == cs->cs_size)
		return (1);
	else
		return (0);
}

int
cherigc_push_root(void *p)
{
	struct cherigc_vment *ce;
	void *q;
	size_t idx, sz;
	int isrevoked, rc;
	uint8_t ent;

	q = (void *)CHERIGC_PTR_GETBASE(p);

	if (!cherigc_pushable(p))
		return (0);

	/*
	 * If the object is already marked, we don't push it to the mark
	 * stack again; if it is not marked, we push it to the mark stack,
	 * and mark it. If the object is revoked, we then invalidate the
	 * capability pointing to it.
	 *
	 * Objects differ in how we check for and set the mark and revoke
	 * flags based on their type. There are three basic types: small,
	 * large and unmanaged. For unmanaged objects: 1) we don't have a
	 * revoke bit, 2) marking them is slow and is only necessary to
	 * avoid cycles, and 3) they are never swept.
	 */

	/*
	 * XXX: Merge this into one call to a get_size that also returns ce
	 * and idx.
	 */
	rc = cherigc_get_object_start(q, &ce, &idx);
	if (rc != 0) {
		/* Unmanaged object. */
		if (!cherigc->gc_track_unmanaged)
			return (0);
		sz = CHERIGC_PTR_GETLEN(p);
		cherigc_printf("unmanaged root %p, size %zu\n", q, sz);
		if (cherigc_unmanaged_ismarked(q, sz)) {
			/* Already marked. */
			cherigc_printf("(unmanaged) root %p already marked (unmanaged cycle)\n", q);
		} else {
			/* Unmarked. */
			rc = cherigc_unmanaged_mark_and_push(q, sz);
			if (rc != 0)
				return (rc);
			cherigc_printf("just marked (unmanaged) root %p\n", q);
		}
		return (0);
	}
	rc = cherigc_get_size(q, &q, &sz);
	cherigc_assert(rc == 0, "");

	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP) {
		/* Small object. */
		ent = CHERIGC_AGETENT(&ce->ce_amap, idx);
		q = (void *)(CHERIGC_AMAP_ADDR(idx) + ce->ce_addr);

		if (ent == 0) {
			/*
			 * Root should not be pointing to unused memory;
			 * invalidate.
			 * 
			 * XXX: TODO: Check writable, check still owned by
			 * jemalloc, etc.
			 */
			/*cherigc_printf(
			    "(small) root %p is pointing to unused memory!\n", q);
			CHERIGC_CAP_DEREF(p) = CHERIGC_PTR_CLRTAG(p);*/
		} else if (ent == CHERIGC_AMARK) {
			/* Already marked. */
			cherigc_printf("(small) root %p already marked\n", q);
		} else if (ent == CHERIGC_ASTART) {
			/* Unmarked. */
			CHERIGC_ASETMARK(&ce->ce_amap, idx);
			cherigc->gc_nmark++;
			rc = cherigc_stack_push(
			    &cherigc->gc_mark_stack, q, sz, 0);
			if (rc != 0)
				return (rc);
			cherigc_printf("just marked (small) root %p\n", q);
		} else {
			cherigc_assert(ent == 0 || ent == CHERIGC_AMARK ||
			    ent == CHERIGC_ASTART, "");
		}

		/* Invalidate if revoked. */
		if (ent == CHERIGC_ASTART || ent == CHERIGC_AMARK) {
			isrevoked = cherigc_isrevoked_small(ce, idx);
			if (isrevoked) {
				cherigc_printf("(revoked so invalidating)\n");
				CHERIGC_CAP_DEREF(p) =
				    CHERIGC_PTR_CLRTAG(p);
			}
		}
	} else {
		/* Large object. */
		if (ce->ce_gctype & CHERIGC_VMENT_PAGE_MARK) {
			/* Already marked. */
			cherigc_printf("(large) root %p already marked\n", q);
		} else if (ce->ce_gctype & CHERIGC_VMENT_PAGE_START) {
			/* Unmarked. */
			ce->ce_gctype |= CHERIGC_VMENT_PAGE_MARK;
			cherigc->gc_nmark++;
			rc = cherigc_stack_push(
			    &cherigc->gc_mark_stack, q, sz, 0);
			if (rc != 0)
				return (rc);
			cherigc_printf("just marked (large) root %p\n", q);
		} else {
			cherigc_assert(
			    (ce->ce_gctype & CHERIGC_VMENT_PAGE_START) ||
			    (ce->ce_gctype & CHERIGC_VMENT_PAGE_MARK), "");
		}

		/* Invalidate if revoked. */
		isrevoked = ce->ce_gctype & CHERIGC_VMENT_PAGE_REVOKE;
		if (isrevoked) {
			cherigc_printf("(revoked so invalidating)\n");
			CHERIGC_CAP_DEREF(p) = CHERIGC_PTR_CLRTAG(p);
		}
	}

	return (0);
}

int
cherigc_mark_all(cherigc_examine_fn *fn, void *ctx)
{
	void *p;
	size_t sz;
	int rc;
	uint64_t flags;

	rc = cherigc_get_ts();
	if (rc != 0)
		return (rc);

	/* 1) Push the roots (registers, stack, static data, etc.). */

	cherigc->gc_nmark = 0;
	cherigc_vm_print_stats();

	cherigc_printf("pushing regs (size %zu bytes)\n",
	    cherigc->gc_regs.cc_size);
	rc = cherigc_push_roots(&cherigc->gc_regs, fn, ctx);
	if (rc != 0)
		return (rc);

	cherigc_printf("pushing tstack (size %zu bytes)\n",
	    cherigc->gc_tstack.cc_size);
	rc = cherigc_push_roots(&cherigc->gc_tstack, fn, ctx);
	if (rc != 0)
		return (rc);

	cherigc_printf("pushing stack (%p, %zu bytes)\n",
	    cherigc->gc_stack.cc_cap, cherigc->gc_stack.cc_size);
	cherigc_assert(cherigc->gc_stack.cc_cap != NULL,
	    "expected saved stack (was cherigc_vmap_update called?)");
	rc = cherigc_push_roots(&cherigc->gc_stack, fn, ctx);
	if (rc != 0)
		return (rc);
	/* XXX: TODO: Static data? */

	cherigc_printf("finished pushing roots (marked %zu/%zu objects)\n",
	    cherigc->gc_nmark, cherigc->gc_nalloc);


	/* 2) Recursive mark. */
	for (;;) {
		rc = cherigc_stack_pop(&cherigc->gc_mark_stack, &p, &sz,
		    &flags);
		if (rc != 0) {
			/* Mark stack empty. */
			break;
		}
		if (flags & CHERIGC_STACK_FL_UNMANAGED)
			cherigc_printf("note: %p is unmanaged\n", p);
		cherigc_printf("mark_all: stack_pop %p, %zu bytes\n", p, sz);
		rc = cherigc_mark_children(p, sz, fn, ctx);
		if (rc != 0) {
			cherigc_printf("mark_children failed\n");
			return (rc);
		}
	}
	cherigc_printf("finished recursive mark: marked %zu/%zu objects\n",
	    cherigc->gc_nmark, cherigc->gc_nalloc);
	cherigc_vm_print_stats();

	return (0);
}

int
cherigc_isrevoked_small(struct cherigc_vment *ce, size_t idx)
{
	size_t i;
	uint64_t p, q;
	uint8_t ent;

	/* Expect only to be checking object starts. */
	ent = CHERIGC_AGETENT(&ce->ce_amap, idx);
	cherigc_assert(ent == CHERIGC_ASTART || ent == CHERIGC_AMARK, "");

	p = ce->ce_addr + CHERIGC_AMAP_ADDR(idx);
	for (i = 0; i < cherigc->gc_revoked.cs_idx; i++) {
		q = (uint64_t)cherigc->gc_revoked.cs_stack[i].cse_ptr;
		if (p == q)
			return (1);
	}
	return (0);
}

int
cherigc_unmanaged_ismarked(void *base, size_t sz)
{
	size_t i;
	uint64_t p, q;

	/*
	 * The size is important. If this reference covers a larger region,
	 * then we need to scan the larger size.
	 */

	p = (uint64_t)base;
	for (i = 0; i < cherigc->gc_unmanaged.cs_idx; i++) {
		q = (uint64_t)cherigc->gc_unmanaged.cs_stack[i].cse_ptr;
		if (p == q &&
		    sz <= cherigc->gc_unmanaged.cs_stack[i].cse_size)
			return (1);
	}

	return (0);
}

int
cherigc_unmanaged_mark_and_push(void *base, size_t sz)
{
	struct cherigc_vment *ce;
	int rc;
	size_t off, max;

	/*
	 * Here we atomically mark the unmanaged object and push it to the
	 * mark stack.
	 *
	 * Note that since this object is unmanaged, we should only scan
	 * those pages that are mapped and also readable.
	 *
	 * For the mapped+readable check we use our cached VM page
	 * table stuff.
	 */

	/* XXX: Perhaps just let this grow dynamically. */
	cherigc_assert(!cherigc_stack_isfull(&cherigc->gc_unmanaged), "");

	/* Remember that this has been marked. */
	rc = cherigc_stack_push(&cherigc->gc_unmanaged, base, sz, 0);
	if (rc != 0)
		return (rc);

	cherigc_printf("total bytes to push: %zu\n", sz);

	/*
	 * Push it to the mark stack one page at a time, checking for each
	 * page whether we can read from it using cached VM information.
	 */
#define	CE_GOOD(ce) ((ce) != NULL && ((ce)->ce_prot & CHERIGC_PROT_RD))
#define	UNMANAGED_PUSH(p, sz) do {					\
		rc = cherigc_stack_push(&cherigc->gc_mark_stack, (p),	\
		    (sz), CHERIGC_STACK_FL_UNMANAGED);			\
		if (rc != 0)						\
			return (rc);					\
} while (0)
	off = (uintptr_t)base & CHERIGC_PAGEMASK;
	/* First page. */
	if (off + sz > CHERIGC_PAGESIZE)
		max = CHERIGC_PAGESIZE - off;
	else
		max = sz;
	ce = cherigc_vmap_get(&cherigc->gc_cv, &cherigc->gc_cvi, base);
	if (ce != NULL) cherigc_assert(ce->ce_addr == (uint64_t)base - off, "");
	if (CE_GOOD(ce))
		UNMANAGED_PUSH(base, max);

	if (off + sz > CHERIGC_PAGESIZE) {
		/* Pages that aren't first or last. */
		sz -= CHERIGC_PAGESIZE;
		base = CHERIGC_NEXTPAGE(base);
		for (; sz >= CHERIGC_PAGESIZE; sz -= CHERIGC_PAGESIZE) {
			ce = cherigc_vmap_get(&cherigc->gc_cv,
			    &cherigc->gc_cvi, base);
			if (ce != NULL) cherigc_assert(ce->ce_addr == (uint64_t)base, "");
			if (CE_GOOD(ce))
				UNMANAGED_PUSH(base, CHERIGC_PAGESIZE);
			base = CHERIGC_NEXTPAGE(base);
		}

		/* Last page. */
		if (sz != 0) {
			ce = cherigc_vmap_get(&cherigc->gc_cv,
			    &cherigc->gc_cvi, base);
			if (ce != NULL) cherigc_assert(ce->ce_addr == (uint64_t)base, "");
			if (CE_GOOD(ce))
				UNMANAGED_PUSH(base, sz);
		}
	}

	return (0);
}

void
cherigc_sweep(void)
{
	int large_freecont, small_freecont;

	cherigc_printf("sweeping\n");
	large_freecont = 0;
	small_freecont = 0;
	cherigc_sweep_vmap(&cherigc->gc_cv, &cherigc->gc_cvi, 0,
	    &large_freecont, &small_freecont);
	cherigc_printf("finished sweep (nalloc=%zu nmark=%zu)\n",
	    cherigc->gc_nalloc, cherigc->gc_nmark);

	cherigc_vm_print_stats();
}

void
cherigc_sweep_vment(struct cherigc_vment *ce, int *large_freecont,
    int *small_freecont)
{
	size_t i;
	int isstart, ismark, isused, isrevoked, inobj;
	uint64_t addr;
	uint8_t ent;

	if (ce->ce_gctype & CHERIGC_VMENT_PAGE_AMAP) {
		/* Small objects. */
		*large_freecont = 0;
		inobj = 0;
		for (i = 0; i < CHERIGC_AMAP_NENT; i++) {
			ent = CHERIGC_AGETENT(&ce->ce_amap, i);
			if (ent != 0) {
				addr = ce->ce_addr + CHERIGC_AMAP_ADDR(i);
				ismark = (ent == CHERIGC_AMARK);
				isstart = (ent == CHERIGC_ASTART) || ismark;
				isused = (ent == CHERIGC_AUSED);
				if (isstart) {
					isrevoked =
					    cherigc_isrevoked_small(ce, i);
					if (isrevoked) {
						cherigc_printf("TODO: free REVOKED small object %p (AND ALSO REVOKE IT DURING MARK)\n", (void *)addr);
						/* TODO: jemalloc free */
						if (!cherigc->gc_revoke_debugging) {
							cherigc_free_small(ce, i);
							CHERIGC_ACLRENT(
							    &ce->ce_amap, i);
							*small_freecont = 1;
							cherigc->gc_nalloc--;
							cherigc->gc_nalloc_small--;
							cherigc->gc_nallocbytes -=
							    CHERIGC_MINSIZE;
							cherigc->gc_nrevoke--;
						}
					} else if (ismark) {
						cherigc_printf("small object %p is marked, not freeing\n", (void *)addr);
						CHERIGC_ASETSTART(
						    &ce->ce_amap, i);
						*small_freecont = 0;
						cherigc->gc_nmark--;
					} else {
						cherigc_printf("TODO: free unmarked small object %p\n", (void *)addr);
						/* TODO: jemalloc free */
						cherigc_free_small(ce, i);
						CHERIGC_ACLRENT(
						    &ce->ce_amap, i);
						*small_freecont = 1;
						cherigc->gc_nalloc--;
						cherigc->gc_nalloc_small--;
						cherigc->gc_nallocbytes -=
						    CHERIGC_MINSIZE;
					}
				} else if (isused) {
					/*
					 * If freeing, continue freeing
					 * continuation data.
					 */
					if (*small_freecont) {
						CHERIGC_ACLRENT(
						    &ce->ce_amap, i);
						cherigc->gc_nallocbytes -=
						    CHERIGC_MINSIZE;
					}
				}
			}
		}
	} else {
		/* Large object. */
		*small_freecont = 0;
		if (ce->ce_gctype & CHERIGC_VMENT_PAGE_START) {
			if (ce->ce_gctype & CHERIGC_VMENT_PAGE_REVOKE) {
				cherigc_printf("TODO: free REVOKED large object %p (AND ALSO REVOKE IT DURING MARK)\n", (void *)ce->ce_addr);
				/* TODO: jemalloc free */
				if (!cherigc->gc_revoke_debugging) {
					cherigc_free_large(ce);
					ce->ce_gctype = CHERIGC_VMENT_PAGE_FREE;
					*large_freecont = 1;
					cherigc->gc_nalloc--;
					cherigc->gc_nalloc_large--;
					cherigc->gc_nallocbytes -=
					    CHERIGC_PAGESIZE;
					cherigc->gc_nrevoke--;
				}
			} else if (ce->ce_gctype & CHERIGC_VMENT_PAGE_MARK) {
				cherigc_printf("large object %p is marked, not freeing\n", (void *)ce->ce_addr);
				ce->ce_gctype &= ~CHERIGC_VMENT_PAGE_MARK;
				*large_freecont = 0;
				cherigc->gc_nmark--;
			} else {
				/* Unmarked, unrevoked. */
				cherigc_printf("TODO: free unmarked large object %p\n", (void *)ce->ce_addr);
				/* TODO: jemalloc free */
				cherigc_free_large(ce);
				ce->ce_gctype = CHERIGC_VMENT_PAGE_FREE;
				*large_freecont = 1;
				cherigc->gc_nalloc--;
				cherigc->gc_nalloc_large--;
				cherigc->gc_nallocbytes -=
				    CHERIGC_PAGESIZE;
			}
		} else if (ce->ce_gctype & CHERIGC_VMENT_PAGE_USED) {
			/*
			 * If freeing, continue freeing continuation
			 * data.
			 */
			if (*large_freecont) {
				ce->ce_gctype = CHERIGC_VMENT_PAGE_FREE;
				cherigc->gc_nallocbytes -=
				    CHERIGC_PAGESIZE;
			}
		}
	}
}

void
cherigc_sweep_vmap(struct cherigc_vmap *cv, struct cherigc_vidxs *cvi,
    size_t idx, int *large_freecont, int *small_freecont)
{
	struct cherigc_vidx *ci;
	size_t i;

	ci = &cvi->cvi_ci[idx];
	if (ci->ci_type == CHERIGC_CV_VMENT) {
		for (i = 0; i < ci->ci_size; i++)
			if (cv->cv_vment[i] != NULL)
				cherigc_sweep_vment(cv->cv_vment[i],
				    large_freecont, small_freecont);
	} else {
		for (i = 0; i < ci->ci_size; i++)
			if (cv->cv_vmap[i] != NULL)
				cherigc_sweep_vmap(cv->cv_vmap[i], cvi,
				    idx + 1, large_freecont,
				    small_freecont);
	}
}

int
cherigc_getrefs(void *p)
{
	struct cherigc_getrefs_s s;
	struct cherigc_vment *ce;
	size_t idx;
	int rc;

	rc = cherigc_get_object_start(p, &ce, &idx);
	if (rc != 0) {
		cherigc_printf("cherigc_getrefs: no such object: %p. "
		    "Continuing and assuming this start-of-object.\n", p);
		s.addr = (uint64_t)p;
	} else {
		s.addr = ce->ce_addr;
		if (ce->ce_gctype == CHERIGC_VMENT_PAGE_AMAP)
			s.addr += CHERIGC_AMAP_ADDR(idx);
	}

	s.refs = 0;
	rc = cherigc_mark_all(&cherigc_getrefs_cb, &s);
	if (rc != 0)
		return (-1);

	cherigc_sweep();
	return (s.refs);
}

void
cherigc_getrefs_cb(void *objp, void *ctx)
{
	struct cherigc_getrefs_s *s;
	struct cherigc_vment *ce;
	void *q;
	size_t idx;
	uint64_t addr;
	int rc;

	s = ctx;
	q = (void *)CHERIGC_CAP_DEREF(objp);

	rc = cherigc_get_object_start(q, &ce, &idx);
	if (rc != 0)
		return;
	addr = ce->ce_addr;
	if (ce->ce_gctype == CHERIGC_VMENT_PAGE_AMAP)
		addr += CHERIGC_AMAP_ADDR(idx);
	if (addr == s->addr) {
		cherigc_printf("reference at %p (to: %p)\n", objp, q);
		s->refs++;
	}
}

int
cherigc_get_ts(void)
{

	return (sysarch(CHERI_GET_STACK, &cherigc->gc_ts));
}

int
cherigc_put_ts(void)
{

	return (sysarch(CHERI_SET_STACK, &cherigc->gc_ts));
}

void
cherigc_get_regs(void)
{
	__capability void *c3;

	/*cherigc_printf("save regs at %p\n", cherigc->gc_regs.cc_cap);
	volatile __capability void *reg = cheri_ptr((void *)0xDEADEFFE, 0x12121212);
	__asm__ __volatile__ ("cmove $c4, %0" : : "C"(reg) : "memory", "$c4");*/

	c3 = (__capability void *)cherigc->gc_regs.cc_cap;
	__asm__ __volatile__ (
		"cmove $c3, %0" : : "C"(c3) : "memory", "$c3"
	);
	CHERIGC_SAVE_REGS(3);

	/*size_t i;
	for (i = 0; i < cherigc->gc_regs.cc_size; i += CHERIGC_CAPSIZE) {
		void *p = &((char *)cherigc->gc_regs.cc_cap)[i];
		cherigc_printf("buf[%zu]: %p off=%p t=%d\n", i, (void *)CHERIGC_PTR_GETBASE(p), (void *)CHERIGC_PTR_GETOFFSET(p), CHERIGC_PTR_GETTAG(p));
	}*/
}

void
cherigc_put_regs(void)
{
	__capability void *c3;

	c3 = (__capability void *)cherigc->gc_regs.cc_cap;
	__asm__ __volatile__ (
		"cmove $c3, %0" : : "C"(c3) : "memory", "$c3"
	);
	CHERIGC_RESTORE_REGS(3);
	CHERIGC_INVALIDATE_UNUSED_REGS;
}

void
cherigc_print_tracking(void)
{
	struct cherigc_vment *ce;
	struct cherigc_vmap *cv;
	struct cherigc_amap *ca;
	size_t capsz, i, j, k, npage, pagesz;
	uint64_t pu;

	cv = &cherigc->gc_cv;
	pagesz = CHERIGC_PAGESIZE;
	capsz = CHERIGC_CAPSIZE;

#if 0
	printf("%zu ents\n", cv->cv_nent);
	for (i = 0; i < cv->cv_nent; i++) {
		ce = cv->cv_ent[i];
		if (ce->ce_ap == NULL)
			continue;
		npage = 1 + (ce->ce_end - ce->ce_start) / pagesz;
		pu = ce->ce_start;
		for (j = 0; j < npage; j++) {
			ca = &ce->ce_ap[j];
			if (ca == NULL)
				continue;
			for (k = 0; k < pagesz / capsz; k++) {
				if (CHERIGC_AGETUSED(ca, k)) {
					printf("tracking %p\n",
					    (void *)pu);
				}
				pu += capsz;
			}
		}
	}
#endif
	(void)i; (void)pu; (void)k; (void)j; (void)npage; (void)pagesz; (void)ce; (void)ca;
}

int
cherigc_gettid(void)
{

	return (pthread_getthreadid_np());
}

uint64_t
cherigc_gettime(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
		return (0);
	return ((uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000);
}

void
cherigc_scan_region(void *p, size_t sz)
{
	void *end;

	cherigc_printf("scanning region %p, size %zu\n", p, sz);
	end = (char *)p + sz;
	for (; p != end; p = (char *)p + CHERIGC_CAPSIZE)
		cherigc_scan_ptr(p);
}

void
cherigc_scan_ptr(void *p)
{
	void *base, *q;
	int rc, tag;
	size_t sz;

	tag = CHERIGC_PTR_GETTAG(p);
	if (tag) {
		base = (void *)CHERIGC_PTR_GETBASE(p);
		rc = cherigc_get_size(base, &q, &sz);
		if (rc == 0) {
			cherigc_printf("scan_ptr: found a capability: %p, "
			    "actual base and size: %p, %zu\n", base, q, sz);
		} else {
			cherigc_printf("scan_ptr: %p is unmanaged\n", base);
		}
	}
}

void
cherigc_free_small(struct cherigc_vment *ce, size_t idx)
{
	uint64_t addr;

	addr = ce->ce_addr + CHERIGC_AMAP_ADDR(idx);
	cherigc_free_any((void *)addr);
}

void
cherigc_free_large(struct cherigc_vment *ce)
{

	cherigc_free_any((void *)ce->ce_addr);
}

void
cherigc_free_any(void *p)
{

#ifdef CHERIGC_INVALIDATE_ON_FREE
	void *q;
	uint8_t *c;
	size_t i, sz;
	int rc;

	rc = cherigc_get_size(p, &q, &sz);
	cherigc_assert(rc == 0 && p == q, "rc=%d p=%p q=%p", rc, p, q);
	c = p;
	for (i = 0; i < sz; i++)
		c[i] = (CHERIGC_FREE_FILL >> (8 * (i % 4))) & 0xFF;
#endif

	free(p);
}
